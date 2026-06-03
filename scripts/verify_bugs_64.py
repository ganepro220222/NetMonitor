"""Regression checks for bug 64 (zero-duration outages must not count)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_alert(conn, tid, ts, old_s, new_s):
    conn.execute(
        "INSERT INTO alert_events "
        "(target_id,label,ip,ts,old_status,new_status,category) "
        "VALUES (?,?,?,?,?,?,?)",
        (tid, "n", "1.2.3.4", ts, old_s, new_s, "availability"))


def _setup_ds(path):
    ds = DataStore(path)
    ds._schema_ready.wait(timeout=5)
    ds.shutdown()
    return DataStore(path)


def test_zero_duration_recovery_at_window_start():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start = int(time.time()) - 3600
        end = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", start - 100, "green", "red")
        _insert_alert(conn, "T", start, "red", "green")
        conn.commit()
        conn.close()
        single = ds.get_sla_stats("T", start, end)
        batch = ds.get_sla_stats_batch(["T"], start, end)["T"]
        ok = (
            single["outage_count"] == 0
            and single["outage_minutes"] == 0.0
            and single["uptime_pct"] == 100.0
            and batch == single
        )
        print(f"Bug64 recovery at start: single={single} batch={batch} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_zero_duration_fault_at_window_end():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start = int(time.time()) - 3600
        end = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", end, "green", "red")
        conn.commit()
        conn.close()
        single = ds.get_sla_stats("T", start, end)
        batch = ds.get_sla_stats_batch(["T"], start, end)["T"]
        ok = (
            single["outage_count"] == 0
            and single["outage_minutes"] == 0.0
            and batch["outage_count"] == 0
        )
        print(f"Bug64 fault at end: single={single} batch={batch} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_positive_duration_outage_still_counts():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start = int(time.time()) - 3600
        end = int(time.time())
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", start + 10, "green", "red")
        _insert_alert(conn, "T", start + 70, "red", "green")
        conn.commit()
        conn.close()
        single = ds.get_sla_stats("T", start, end)
        batch = ds.get_sla_stats_batch(["T"], start, end)["T"]
        ok = (
            single["outage_count"] == 1
            and single["outage_minutes"] > 0
            and batch["outage_count"] == 1
            and batch["outage_minutes"] > 0
        )
        print(f"Bug64 positive outage: single={single} batch={batch} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_uses_compute_outage_stats():
    with open(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src", "data_store.py",
        ),
        encoding="utf-8",
    ) as f:
        text = f.read()
    ok = (
        "def _compute_outage_stats(" in text
        and "_compute_outage_stats(" in text.split("def get_sla_stats_batch", 1)[0]
        and "if dur > 0:" in text.split("def _compute_outage_stats", 1)[1].split(
            "def get_sla_stats(", 1)[0]
        and "if status_at_start == \"red\":\n                outage_count = 1" not in text
    )
    print(f"Bug64 shared helper dur>0 gate -> {ok}")
    return ok


def main():
    results = [
        ("start_recovery", test_zero_duration_recovery_at_window_start()),
        ("end_fault", test_zero_duration_fault_at_window_end()),
        ("positive", test_positive_duration_outage_still_counts()),
        ("source", test_source_uses_compute_outage_stats()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 64 checks passed.")


if __name__ == "__main__":
    main()
