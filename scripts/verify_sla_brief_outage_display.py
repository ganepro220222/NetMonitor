"""Regression: brief SLA outages must not show as 100% uptime / 无中断."""
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


def _window(days=7):
    end = int(time.time())
    start = end - days * 86400
    return start, end


def test_brief_outage_not_hidden():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start, end = _window(7)
        fault_start = start + 3600
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", fault_start, "green", "red")
        _insert_alert(conn, "T", fault_start + 4, "red", "green")
        conn.commit()
        conn.close()

        single = ds.get_sla_stats("T", start, end)
        batch = ds.get_sla_stats_batch(["T"], start, end)["T"]
        ok = (
            single["outage_count"] == 1
            and single["outage_seconds"] == 4.0
            and single["uptime_pct"] < 100.0
            and single["uptime_pct"] >= 99.99
            and batch == single
        )
        print(f"brief 4s outage: {single} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_subsecond_outage_not_hidden():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start, end = _window(7)
        fault_start = float(start + 3600)
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", fault_start, "green", "red")
        _insert_alert(conn, "T", fault_start + 1.5, "red", "green")
        conn.commit()
        conn.close()

        single = ds.get_sla_stats("T", start, end)
        ok = (
            single["outage_count"] == 1
            and single["outage_seconds"] == 1.5
            and single["uptime_pct"] < 100.0
        )
        print(f"brief 1.5s outage: uptime={single['uptime_pct']} "
              f"seconds={single['outage_seconds']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_zero_duration_still_clean():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start, end = _window(1)
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", start - 100, "green", "red")
        _insert_alert(conn, "T", start, "red", "green")
        conn.commit()
        conn.close()

        single = ds.get_sla_stats("T", start, end)
        ok = (
            single["outage_count"] == 0
            and single["outage_seconds"] == 0.0
            and single["outage_minutes"] == 0.0
            and single["uptime_pct"] == 100.0
        )
        print(f"zero-duration boundary: {single} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_long_outage_unchanged():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = _setup_ds(path)
        start, end = _window(1)
        conn = sqlite3.connect(path)
        _insert_alert(conn, "T", start + 10, "green", "red")
        _insert_alert(conn, "T", start + 70, "red", "green")
        conn.commit()
        conn.close()

        single = ds.get_sla_stats("T", start, end)
        ok = (
            single["outage_count"] == 1
            and single["outage_seconds"] == 60.0
            and single["outage_minutes"] == 1.0
            and single["uptime_pct"] < 100.0
        )
        print(f"60s outage: {single} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        ("brief_4s", test_brief_outage_not_hidden()),
        ("brief_1.5s", test_subsecond_outage_not_hidden()),
        ("zero_duration", test_zero_duration_still_clean()),
        ("long_60s", test_long_outage_unchanged()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("PASS verify_sla_brief_outage_display")


if __name__ == "__main__":
    main()
