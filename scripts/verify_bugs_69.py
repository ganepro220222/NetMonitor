"""Regression checks for bug 69 (backfill incident_id unique per outage)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _insert_alerts(conn, tid, events):
    for old_s, new_s, ts in events:
        conn.execute(
            "INSERT INTO alert_events "
            "(target_id, label, ip, ts, old_status, new_status, "
            " category, incident_id) "
            "VALUES (?, 'n', '1.2.3.4', ?, ?, ?, 'availability', NULL)",
            (tid, ts, old_s, new_s),
        )
    conn.commit()


def test_same_second_two_independent_incidents():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        base = 1780506232.0
        _insert_alerts(conn, "TargetA", [
            ("green", "red",   base + 0.0),
            ("red",   "green", base + 0.1),
            ("green", "red",   base + 0.2),
            ("red",   "green", base + 0.3),
        ])
        ds._backfill_incident_ids(conn)
        rows = conn.execute(
            "SELECT id, incident_id FROM alert_events ORDER BY id"
        ).fetchall()
        conn.close()
        ds.shutdown()
        iids = [r[1] for r in rows]
        ok = (
            len(iids) == 4
            and iids[0] == iids[1]
            and iids[2] == iids[3]
            and iids[0] != iids[2]
            and len(set(iids)) == 2
        )
        print(f"Bug69 same-second iids={iids} distinct={set(iids)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_single_incident_red_recovery_share_id():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        base = (int(time.time()) // 3600) * 3600 - 7200
        _insert_alerts(conn, "T", [
            ("green", "red",   base + 10.0),
            ("red",   "green", base + 50.0),
        ])
        ds._backfill_incident_ids(conn)
        rows = conn.execute(
            "SELECT incident_id FROM alert_events ORDER BY id"
        ).fetchall()
        conn.close()
        ds.shutdown()
        ok = len(rows) == 2 and rows[0][0] == rows[1][0] and rows[0][0]
        print(f"Bug69 cross-span shared={rows[0][0] if rows else None} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_backfill_idempotent_stable():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        base = 1780506232.0
        _insert_alerts(conn, "T", [
            ("green", "red",   base),
            ("red",   "green", base + 0.5),
        ])
        ds._backfill_incident_ids(conn)
        first = [r[0] for r in conn.execute(
            "SELECT incident_id FROM alert_events ORDER BY id").fetchall()]
        ds._backfill_incident_ids(conn)
        second = [r[0] for r in conn.execute(
            "SELECT incident_id FROM alert_events ORDER BY id").fetchall()]
        conn.close()
        ds.shutdown()
        ok = first == second and len(first) == 2
        print(f"Bug69 idempotent {first} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_backfill_uses_row_id_suffix():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _backfill_incident_ids", 1)[1].split(
            "def _restore_active_incidents", 1)[0]
    ok = (
        "{rid:08X}" in block
        and block.count("strftime('%Y%m%d%H%M%S')") >= 1
        and "INC-{_dt.fromtimestamp(ts).strftime" not in block
    )
    print(f"Bug69 source rid suffix in backfill -> {ok}")
    return ok


def main():
    results = [
        ("same_second", test_same_second_two_independent_incidents()),
        ("shared_pair", test_single_incident_red_recovery_share_id()),
        ("idempotent", test_backfill_idempotent_stable()),
        ("source", test_source_backfill_uses_row_id_suffix()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 69 checks passed.")


if __name__ == "__main__":
    main()
