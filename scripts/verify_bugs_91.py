"""Regression checks for bug 91 (v11 rebuild polluted cum_stats from pings_raw)."""
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


def test_v11_migration_fixes_polluted_cum_stats():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T"
        ts = time.time()
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=ts, status="green", latency_ms=10.0, loss_rate=0.0,
            probe_success=True)
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=ts + 1, status="green", latency_ms=1000.0, loss_rate=1.0,
            probe_success=False, failure_reason="status_500")
        ds.flush()
        ds.shutdown()

        conn = sqlite3.connect(path)
        conn.execute(
            "INSERT OR REPLACE INTO cum_stats "
            "(target_id,total,success,lat_avg,lat_n,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (tid, 2, 1, 505.0, 2, int(time.time())))
        conn.execute("PRAGMA user_version = 10")
        conn.commit()
        conn.close()

        ds2 = DataStore(path)
        ds2._schema_ready.wait(timeout=5)
        conn2 = sqlite3.connect(path)
        ver = conn2.execute("PRAGMA user_version").fetchone()[0]
        conn2.close()
        cum = ds2.get_cum_stats().get(tid, {})
        ds2.shutdown()

        ok = (
            ver >= 11
            and cum.get("total") == 2
            and cum.get("success") == 1
            and cum.get("latency_avg") == 10.0
            and cum.get("latency_n") == 1
            and cum.get("latency_avg") != 505.0
        )
        print(f"Bug91 after reopen: ver={ver} cum={cum} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_v11_rebuild_migration():
    with open(DATA_STORE, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "v10 → v11" in src or "v10 → v11" in src.replace("→", "->")
        and "_rebuild_cum_stats_from_raw" in src
        and "PRAGMA user_version = 11" in src
        and "DELETE FROM cum_stats" in src.split("_rebuild_cum_stats_from_raw", 1)[1]
    )
    print(f"Bug91 source v11 rebuild migration -> {ok}")
    return ok


def main():
    results = [
        ("migrate", test_v11_migration_fixes_polluted_cum_stats()),
        ("source", test_source_v11_rebuild_migration()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 91 checks passed.")
    print("(Also run: python scripts/verify_bugs_90.py)")


if __name__ == "__main__":
    main()
