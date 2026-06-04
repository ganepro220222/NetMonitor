"""Regression checks for bug 93 (v11 cum_stats rebuild uses SQL aggregate)."""
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


def test_v11_migration_correct_stats_after_sql_rebuild():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T"
        ts = time.time()
        ds.record_ping(
            target_id=tid, label="n", ip="1.2.3.4", ping_type="http",
            ts=ts, status="green", latency_ms=10.0, loss_rate=0.0,
            probe_success=True)
        ds.record_ping(
            target_id=tid, label="n", ip="1.2.3.4", ping_type="http",
            ts=ts + 1, status="green", latency_ms=1000.0, loss_rate=1.0,
            probe_success=False, failure_reason="status_500")
        ds.flush()
        ds.shutdown()

        conn = sqlite3.connect(path)
        conn.execute(
            "INSERT OR REPLACE INTO cum_stats VALUES (?,?,?,?,?,?)",
            (tid, 2, 1, 505.0, 2, int(time.time())))
        conn.execute("PRAGMA user_version = 10")
        conn.commit()
        conn.close()

        ds2 = DataStore(path)
        ds2._schema_ready.wait(timeout=5)
        cum = ds2.get_cum_stats().get(tid, {})
        ds2.shutdown()
        ok = (
            cum.get("total") == 2
            and cum.get("success") == 1
            and cum.get("latency_avg") == 10.0
            and cum.get("latency_n") == 1
        )
        print(f"Bug93 v11 rebuild cum={cum} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_sql_aggregate_not_fetchall():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _rebuild_cum_stats_from_raw", 1)[1].split(
            "def _update_cum_stats", 1)[0]
    ok = (
        "GROUP BY target_id" in block
        and "_PROBE_OK_SQL" in block
        and "_PROBE_LAT_OK_SQL" in block
        and ".fetchall()" not in block
        and "groups:" not in block
        and "defaultdict(list)" not in block
    )
    print(f"Bug93 source SQL GROUP BY rebuild -> {ok}")
    return ok


def main():
    results = [
        ("stats", test_v11_migration_correct_stats_after_sql_rebuild()),
        ("source", test_source_sql_aggregate_not_fetchall()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 93 checks passed.")
    print("(Also run: python scripts/verify_bugs_91.py python scripts/verify_bugs_90.py)")


if __name__ == "__main__":
    main()
