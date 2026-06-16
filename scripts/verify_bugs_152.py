"""Regression: pause closes DataStore active incident; resume+red opens new one (Bug 152)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _alert(ds, tid, ts, old, new, cat="availability"):
    ds.record_alert(
        target_id=tid, label="Node", ip="1.2.3.4", ts=float(ts),
        old_status=old, new_status=new, category=cat,
    )


def _events(conn, tid):
    return conn.execute(
        "SELECT old_status, new_status, category, incident_id "
        "FROM alert_events WHERE target_id=? ORDER BY id",
        (tid,),
    ).fetchall()


def test_pause_resume_red_new_incident_id():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T1"
        base = 1_780_000_000.0
        _alert(ds, tid, base + 0, "green", "red")
        _alert(ds, tid, base + 10, "red", "paused", cat="paused")
        _alert(ds, tid, base + 20, "paused", "gray", cat="resumed")
        _alert(ds, tid, base + 30, "gray", "red")
        ds.flush()

        conn = sqlite3.connect(path)
        rows = _events(conn, tid)
        iids = [r[3] for r in rows if r[3]]
        red_iids = [
            r[3] for r in rows
            if r[1] == "red" and r[2] == "availability"
        ]
        conn.close()
        ds.shutdown()

        ok = (
            len(set(iids)) >= 2
            and len(red_iids) == 2
            and red_iids[0] != red_iids[1]
            and rows[1][3] == rows[0][3]  # pause tags first incident
        )
        print(f"Bug152 pause/resume/red distinct incident_ids -> {ok} "
              f"red_iids={red_iids}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_open_incident_started_at_second_red():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T2"
        base = 1_780_100_000.0
        second_red = base + 30
        _alert(ds, tid, base + 0, "green", "red")
        _alert(ds, tid, base + 10, "red", "paused", cat="paused")
        _alert(ds, tid, base + 20, "paused", "gray", cat="resumed")
        _alert(ds, tid, second_red, "gray", "red")
        ds.flush()

        open_inc = ds.get_open_incidents([tid])
        started = open_inc[tid]["started_at"]
        ds.shutdown()
        delta = started - second_red
        ok = abs(delta) < 0.01
        print(f"Bug152 open started_at second red -> {ok} delta={delta}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_sla_two_outages_after_pause_cycle():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T3"
        base = int(time.time()) - 7200
        _alert(ds, tid, base + 100, "green", "red")
        _alert(ds, tid, base + 200, "red", "paused", cat="paused")
        _alert(ds, tid, base + 300, "paused", "gray", cat="resumed")
        _alert(ds, tid, base + 400, "gray", "red")
        _alert(ds, tid, base + 500, "red", "green", cat="ok")
        ds.flush()

        stats = ds.get_sla_stats(tid, base, base + 3600)
        ov = ds.get_outage_intervals(tid, base, base + 3600)
        ds.shutdown()
        ok = stats["outage_count"] == 2 and len(ov["red"]) == 2
        print(f"Bug152 SLA outage_count=2 -> {ok} count={stats['outage_count']} "
              f"red_segments={len(ov['red'])}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_restore_skips_paused_not_second_red_incident():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T4"
        base = 1_780_200_000.0
        _alert(ds, tid, base + 0, "green", "red")
        _alert(ds, tid, base + 10, "red", "paused", cat="paused")
        ds.flush()
        ds.shutdown()

        ds2 = DataStore(path)
        ds2._schema_ready.wait(timeout=5)
        ok_paused = tid not in ds2._active_incidents

        _alert(ds2, tid, base + 20, "paused", "gray", cat="resumed")
        _alert(ds2, tid, base + 30, "gray", "red")
        ds2.flush()
        ok_active = tid in ds2._active_incidents

        conn = sqlite3.connect(path)
        red_iids = [
            r[0] for r in conn.execute(
                "SELECT incident_id FROM alert_events "
                "WHERE target_id=? AND new_status='red' ORDER BY id",
                (tid,),
            ).fetchall()
        ]
        conn.close()
        ds2.shutdown()

        ok = ok_paused and ok_active and len(red_iids) == 2 and red_iids[0] != red_iids[1]
        print(f"Bug152 restore paused + post-resume red -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_backfill_pause_cycle_distinct_incidents():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        tid = "T5"
        base = 1_780_300_000.0
        events = [
            ("green", "red", base + 0, "availability"),
            ("red", "paused", base + 10, "paused"),
            ("paused", "gray", base + 20, "resumed"),
            ("gray", "red", base + 30, "availability"),
            ("red", "green", base + 40, "ok"),
        ]
        for old, new, ts, cat in events:
            conn.execute(
                "INSERT INTO alert_events "
                "(target_id,label,ip,ts,old_status,new_status,category,incident_id) "
                "VALUES (?,?,?,?,?,?,?,NULL)",
                (tid, "n", "1.2.3.4", ts, old, new, cat),
            )
        conn.commit()
        ds._backfill_incident_ids(conn)
        red_iids = [
            r[0] for r in conn.execute(
                "SELECT incident_id FROM alert_events "
                "WHERE target_id=? AND new_status='red' ORDER BY id",
                (tid,),
            ).fetchall()
        ]
        conn.close()
        ds.shutdown()
        ok = len(red_iids) == 2 and red_iids[0] != red_iids[1]
        print(f"Bug152 backfill pause cycle -> {ok} red_iids={red_iids}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_pause_closes_active_incident():
    with open(DATA_STORE, encoding="utf-8") as f:
        full = f.read()
    block = full.split("def _assign_incident_ids", 1)[1].split(
        "def _rebuild_cum_stats_from_raw", 1)[0]
    restore = full.split("def _restore_active_incidents", 1)[1].split(
        "def _flush", 1)[0]
    ok = (
        "del self._active_incidents[tid]" in block
        and "ns == 'paused' or cat == 'paused'" in block
        and "new_status IN ('red', 'orange')" in restore
    )
    print(f"Bug152 source pause close + restore filter -> {ok}")
    return ok


def main():
    results = [
        ("new_iid", test_pause_resume_red_new_incident_id()),
        ("started_at", test_open_incident_started_at_second_red()),
        ("sla", test_sla_two_outages_after_pause_cycle()),
        ("restore", test_restore_skips_paused_not_second_red_incident()),
        ("backfill", test_backfill_pause_cycle_distinct_incidents()),
        ("source", test_source_pause_closes_active_incident()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 152 checks passed.")


if __name__ == "__main__":
    main()
