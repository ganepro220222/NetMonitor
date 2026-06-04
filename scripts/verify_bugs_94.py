"""Regression checks for bug 94 (alert cleanup keeps left boundary for SLA)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)

DAY = 86400


def _seed_cross_cutoff_fault(ds, tid="T"):
    now = time.time()
    ds.record_alert(
        target_id=tid, label="n", ip="1.2.3.4",
        ts=now - 400 * DAY, old_status="green", new_status="red",
        category="availability")
    ds.record_alert(
        target_id=tid, label="n", ip="1.2.3.4",
        ts=now - 300 * DAY, old_status="red", new_status="green",
        category="ok")
    ds.flush()
    return now


def test_sla_stable_after_alert_cleanup():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, alert_retention_days=365)
        ds._schema_ready.wait(timeout=5)
        tid = "T"
        now = _seed_cross_cutoff_fault(ds, tid)
        start_ts = now - 350 * DAY
        end_ts = now - 250 * DAY

        before = ds.get_sla_stats(tid, start_ts, end_ts)

        conn = sqlite3.connect(path)
        ds._cleanup(conn)
        conn.commit()
        conn.close()
        ds.release_read_conn()

        after = ds.get_sla_stats(tid, start_ts, end_ts)
        rows = sqlite3.connect(path).execute(
            "SELECT old_status, new_status FROM alert_events "
            "WHERE target_id=? ORDER BY ts", (tid,)).fetchall()
        ds.shutdown()

        ok = (
            before.get("uptime_pct") == 50.0
            and before.get("outage_count") == 1
            and after.get("uptime_pct") == 50.0
            and after.get("outage_count") == 1
            and ("green", "red") in rows
            and ("red", "green") in rows
        )
        print(f"Bug94 SLA before={before.get('uptime_pct')}% "
              f"after={after.get('uptime_pct')}% kept={rows} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_cleanup_keeps_left_boundary():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _cleanup(self, conn):", 1)[1].split(
            "def _read_conn", 1)[0]
    ok = (
        "Bug94" in block or "left boundary" in block
        and "UNION" in block
        and "SELECT MAX(id) FROM alert_events WHERE ts<?" in block
    )
    print(f"Bug94 source cleanup UNION anchors -> {ok}")
    return ok


def main():
    results = [
        ("sla", test_sla_stable_after_alert_cleanup()),
        ("source", test_source_cleanup_keeps_left_boundary()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 94 checks passed.")


if __name__ == "__main__":
    main()
