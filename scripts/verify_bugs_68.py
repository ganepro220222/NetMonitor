"""Regression checks for bug 68 (SLA current-hour window keeps float bounds)."""
import os
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _ping(ds, tid, ts, lat=12.0):
    ds.record_ping(
        target_id=tid, label="n", ip="1.2.3.4", ping_type="icmp",
        ts=ts, status="green", latency_ms=lat, loss_rate=0.0,
    )


def test_sla_current_second_subsecond_ping():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        hour = (int(time.time()) // 3600) * 3600
        now = hour + 100.90
        ping_ts = hour + 100.80
        with patch("src.data_store.time.time", return_value=now):
            ds = DataStore(path)
            ds._schema_ready.wait(timeout=5)
            _ping(ds, "T", ping_ts)
            ds.flush()
            raw = ds.get_history("T", hour, now, use_hourly=False)
            single = ds.get_sla_stats("T", hour, now)
            batch = ds.get_sla_stats_batch(["T"], hour, now)["T"]
            ds.shutdown()
        ok = (
            len(raw) == 1
            and abs(raw[0]["ts"] - ping_ts) < 0.01
            and single["sample_n"] == 1
            and single["lat_avg"] == 12.0
            and single["lat_max"] == 12.0
            and single["lat_p95"] == 12.0
            and batch["sample_n"] == 1
            and batch["lat_avg"] == 12.0
        )
        print(f"Bug68 raw={len(raw)} single={single} batch={batch} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_sla_start_boundary_float():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        hour = (int(time.time()) // 3600) * 3600
        now = hour + 100.90
        start = hour + 100.50
        with patch("src.data_store.time.time", return_value=now):
            ds = DataStore(path)
            ds._schema_ready.wait(timeout=5)
            _ping(ds, "T", hour + 100.20, lat=5.0)
            _ping(ds, "T", hour + 100.80, lat=12.0)
            ds.flush()
            stats = ds.get_sla_stats("T", start, now)
            ds.shutdown()
        ok = (
            stats["sample_n"] == 1
            and stats["lat_avg"] == 12.0
        )
        print(f"Bug68 start boundary sample_n={stats['sample_n']} "
              f"lat_avg={stats['lat_avg']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_float_current_hour_window():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    ch_block = text.split("def _current_hour_bucket", 1)[1].split(
        "def _merge_sla_latency", 1)[0]
    sla_block = text.split("def get_sla_stats", 1)[1].split(
        "def get_sla_stats_batch", 1)[0]
    batch_block = text.split("def get_sla_stats_batch", 1)[1].split(
        "def get_outage_intervals", 1)[0]
    bounded = text.split("def _bounded_hourly_buckets", 1)[1].split(
        "def _bounded_hourly_buckets_for_targets", 1)[0]
    ok = (
        "now = time.time()" in ch_block
        and "int(time.time())" not in ch_block
        and "max(float(start_ts)" in ch_block
        and "min(float(end_ts), now)" in ch_block
        and "start_f = float(start_ts)" in bounded
        and "int(start_ts), int(end_ts)" not in sla_block
        and "int(start_ts), int(end_ts)" not in batch_block
    )
    print(f"Bug68 source float SLA window -> {ok}")
    return ok


def main():
    results = [
        ("subsecond", test_sla_current_second_subsecond_ping()),
        ("start_bound", test_sla_start_boundary_float()),
        ("source", test_source_float_current_hour_window()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 68 checks passed.")


if __name__ == "__main__":
    main()
