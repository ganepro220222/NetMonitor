"""Regression checks for bug 67 (raw hourly fallback includes last sub-second)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _ping(ds, tid, ts, lat=12.5):
    ds.record_ping(
        target_id=tid, label="n", ip="1.2.3.4", ping_type="icmp",
        ts=ts, status="green", latency_ms=lat, loss_rate=0.0,
    )


def test_last_subsecond_in_full_hour_bucket():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        hour = (int(time.time()) // 3600) * 3600 - 7200
        _ping(ds, "T", hour + 3599.50)
        ds.flush()
        hist = ds.get_history("T", hour, hour + 3600, use_hourly=True)
        ds.shutdown()
        ok = (
            len(hist) == 1
            and hist[0]["hour_ts"] == hour
            and hist[0]["sample_n"] == 1
        )
        print(f"Bug67 hour-end ping bucket sample_n={hist[0]['sample_n'] if hist else None} "
              f"len={len(hist)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_hour_boundary_exclusive():
    """hour+3600.0 must not bleed into the previous hour bucket."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        hour = (int(time.time()) // 3600) * 3600 - 7200
        _ping(ds, "T", hour + 3599.50, lat=10.0)
        _ping(ds, "T", hour + 3600.0, lat=99.0)
        ds.flush()
        hist_wide = ds.get_history("T", hour, hour + 7200, use_hourly=True)
        ds.shutdown()
        by_hour = {b["hour_ts"]: b for b in hist_wide}
        prev_b = by_hour.get(hour)
        next_b = by_hour.get(hour + 3600)
        ok = (
            prev_b is not None
            and prev_b["sample_n"] == 1
            and next_b is not None
            and next_b["sample_n"] == 1
            and prev_b["lat_avg"] == 10.0
            and next_b["lat_avg"] == 99.0
        )
        print(f"Bug67 boundary prev_n={prev_b['sample_n'] if prev_b else None} "
              f"next_n={next_b['sample_n'] if next_b else None} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_half_open_raw_buckets_query():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _raw_buckets_for_hours", 1)[1].split(
            "def _raw_retention_cutoff", 1)[0]
    ok = (
        "max(hours) + 3600" in block
        and "max(hours) + 3599" not in block
        and "ts >= ? AND ts < ?" in block
        and "float(range_lo)" in block
        and "float(range_hi)" in block
    )
    print(f"Bug67 source half-open [h,h+3600) query -> {ok}")
    return ok


def main():
    results = [
        ("last_subsecond", test_last_subsecond_in_full_hour_bucket()),
        ("boundary", test_hour_boundary_exclusive()),
        ("source", test_source_half_open_raw_buckets_query()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 67 checks passed.")


if __name__ == "__main__":
    main()
