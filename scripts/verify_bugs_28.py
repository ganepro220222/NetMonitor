"""Regression checks for bug 28 (alert cleanup preserves status anchor)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_alert(conn, tid, ts, old_s, new_s, iid=None):
    conn.execute(
        "INSERT INTO alert_events "
        "(target_id,label,ip,ts,old_status,new_status,category,incident_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (tid, "n", "1.2.3.4", ts, old_s, new_s, "availability", iid))


def _cleanup_db(ds, path):
    conn = sqlite3.connect(path)
    ds._cleanup(conn)
    conn.close()


def test_ongoing_red_sla_after_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        fault_ts = now - 2 * 86400
        start = now - 12 * 3600
        end = now
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, fault_ts, "green", "red", "inc-1")
        conn.commit()
        conn.close()

        before = ds.get_sla_stats(tid, start, end)
        _cleanup_db(ds, path)
        after = ds.get_sla_stats(tid, start, end)
        ok = (before["uptime_pct"] == 0.0 and before["outage_count"] == 1
              and after["uptime_pct"] == 0.0 and after["outage_count"] == 1)
        print(f"Bug28 SLA: before={before['uptime_pct']} after={after['uptime_pct']} "
              f"oc={after['outage_count']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_ongoing_red_overlay_after_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        fault_ts = now - 2 * 86400
        start = now - 12 * 3600
        end = now
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, fault_ts, "green", "red")
        conn.commit()
        conn.close()

        _cleanup_db(ds, path)
        ov = ds.get_outage_intervals(tid, start, end)
        ok = (len(ov["red"]) == 1 and ov["red"][0]["ongoing"]
              and ov["red"][0]["start"] == start)
        print(f"Bug28 overlay: red={ov['red']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_ongoing_orange_overlay_after_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        fault_ts = now - 2 * 86400
        start = now - 12 * 3600
        end = now
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, fault_ts, "green", "orange")
        conn.commit()
        conn.close()

        _cleanup_db(ds, path)
        ov = ds.get_outage_intervals(tid, start, end)
        ok = len(ov["orange"]) == 1 and ov["orange"][0]["ongoing"]
        print(f"Bug28 orange: orange={ov['orange']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_recovered_old_events_pruned():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, now - 10 * 86400, "green", "red")
        _insert_alert(conn, tid, now - 9 * 86400, "red", "green")
        conn.commit()
        conn.close()

        _cleanup_db(ds, path)
        conn = sqlite3.connect(path)
        n = conn.execute(
            "SELECT COUNT(*) FROM alert_events WHERE target_id=?",
            (tid,)).fetchone()[0]
        conn.close()
        sla = ds.get_sla_stats(tid, now - 3600, now)
        ok = n == 1 and sla["uptime_pct"] == 100.0
        print(f"Bug28 prune: rows={n} uptime={sla['uptime_pct']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_batch_matches_single_after_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, now - 2 * 86400, "green", "red")
        conn.commit()
        conn.close()
        _cleanup_db(ds, path)
        start = now - 12 * 3600
        single = ds.get_sla_stats(tid, start, now)
        batch = ds.get_sla_stats_batch([tid], start, now)[tid]
        ok = (single["uptime_pct"] == batch["uptime_pct"]
              and single["outage_count"] == batch["outage_count"])
        print(f"Bug28 batch: single={single['uptime_pct']} "
              f"batch={batch['uptime_pct']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_incident_restore_after_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds1 = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, tid, now - 2 * 86400, "green", "red", "inc-x")
        conn.commit()
        conn.close()
        _cleanup_db(ds1, path)
        del ds1
        time.sleep(0.2)
        ds2 = DataStore(path, alert_retention_days=1)
        time.sleep(0.3)
        ok = ds2._active_incidents.get(tid) == "inc-x"
        print(f"Bug28 incident: active={ds2._active_incidents.get(tid)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_ongoing_red_sla_after_cleanup(),
        test_ongoing_red_overlay_after_cleanup(),
        test_ongoing_orange_overlay_after_cleanup(),
        test_recovered_old_events_pruned(),
        test_batch_matches_single_after_cleanup(),
        test_incident_restore_after_cleanup(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 28 checks passed.")


if __name__ == "__main__":
    main()
