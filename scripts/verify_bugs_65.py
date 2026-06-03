"""Regression checks for bug 65 (alert_events ts keeps sub-second precision)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def test_record_alert_preserves_subsecond_ts():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        ds.record_alert(
            target_id="T", label="n", ip="1.2.3.4",
            ts=base + 10.10, old_status="green", new_status="red",
            category="availability")
        ds.record_alert(
            target_id="T", label="n", ip="1.2.3.4",
            ts=base + 10.70, old_status="red", new_status="green",
            category="ok")
        time.sleep(0.8)
        ds.shutdown()
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT ts FROM alert_events WHERE target_id='T' ORDER BY ts"
        ).fetchall()
        conn.close()
        ok = len(rows) == 2 and abs(rows[1][0] - rows[0][0] - 0.6) < 0.01
        print(f"Bug65 stored ts delta={rows[1][0]-rows[0][0]:.2f} (expect~0.6) -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_sla_counts_subsecond_outage():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        ds.record_alert(
            target_id="T", label="n", ip="1.2.3.4",
            ts=base + 10.10, old_status="green", new_status="red",
            category="availability")
        ds.record_alert(
            target_id="T", label="n", ip="1.2.3.4",
            ts=base + 10.70, old_status="red", new_status="green",
            category="ok")
        time.sleep(0.8)
        single = ds.get_sla_stats("T", base, base + 120)
        batch = ds.get_sla_stats_batch(["T"], base, base + 120)["T"]
        ds.shutdown()
        ok = (
            single["outage_count"] == 1
            and single["uptime_pct"] < 100.0
            and batch["outage_count"] == 1
            and batch["uptime_pct"] < 100.0
        )
        print(f"Bug65 SLA single={single} batch={batch} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_float_ts_and_real_schema():
    with open(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src", "data_store.py",
        ),
        encoding="utf-8",
    ) as f:
        text = f.read()
    alert_block = text.split("def record_alert", 1)[1].split(
        "def on_target_removed", 1)[0]
    ok = (
        '"ts": float(ts), "old_status"' in alert_block
        and "ts             REAL    NOT NULL" in text
        and '"ts": int(ts), "old_status"' not in alert_block
    )
    print(f"Bug65 source float(ts) + REAL schema -> {ok}")
    return ok


def main():
    results = [
        ("stored_ts", test_record_alert_preserves_subsecond_ts()),
        ("sla", test_sla_counts_subsecond_outage()),
        ("source", test_source_float_ts_and_real_schema()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 65 checks passed.")


if __name__ == "__main__":
    main()
