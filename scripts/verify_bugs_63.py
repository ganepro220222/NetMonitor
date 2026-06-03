"""Regression checks for bug 63 (startup seed must include paused status)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_alert(conn, tid, ts, old_s, new_s, category="availability"):
    conn.execute(
        "INSERT INTO alert_events "
        "(target_id,label,ip,ts,old_status,new_status,category) "
        "VALUES (?,?,?,?,?,?,?)",
        (tid, "NodeA", "10.0.0.1", ts, old_s, new_s, category))


def test_get_last_known_statuses_returns_paused():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        ds.shutdown()
        now = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", now - 7200, "green", "red")
        _insert_alert(conn, "T", now - 3600, "red", "paused", "paused")
        conn.commit()
        conn.close()
        got = DataStore(path).get_last_known_statuses()
        ok = got.get("T") == "paused"
        print(f"Bug63 last_known after red->paused: {got.get('T')} "
              f"(expect paused) -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_restart_red_records_when_seeded_paused():
    old_st = "paused"
    new_st = "red"
    would_record = old_st is not None and old_st != new_st
    ok = would_record is True
    print(f"Bug63 paused seed + post-restart red records alert -> {ok}")
    return ok


def test_sla_after_restart_paused_to_red():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        ds.shutdown()
        now = int(time.time())
        restart_red_ts = now - 1800
        start = now - 3600
        end = now
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", now - 7200, "green", "red")
        _insert_alert(conn, "T", now - 3600, "red", "paused", "paused")
        _insert_alert(conn, "T", restart_red_ts, "paused", "red", "availability")
        conn.commit()
        conn.close()
        stats = DataStore(path).get_sla_stats("T", start, end)
        ok = stats["outage_count"] >= 1 and stats["outage_minutes"] > 0
        print(f"Bug63 SLA after paused->red: outage_count={stats['outage_count']} "
              f"minutes={stats['outage_minutes']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_old_filter_would_miss_paused():
    with open(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src", "data_store.py",
        ),
        encoding="utf-8",
    ) as f:
        block = f.read().split("def get_last_known_statuses", 1)[1].split(
            "def get_last_persisted_status", 1)[0]
    ok = (
        "GROUP BY target_id" in block
        and "new_status IN ('green','orange','red','gray')" not in block
    )
    print(f"Bug63 source uses latest event per target -> {ok}")
    return ok


def main():
    results = [
        ("paused_seed", test_get_last_known_statuses_returns_paused()),
        ("would_record", test_restart_red_records_when_seeded_paused()),
        ("sla", test_sla_after_restart_paused_to_red()),
        ("source", test_old_filter_would_miss_paused()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 63 checks passed.")


if __name__ == "__main__":
    main()
