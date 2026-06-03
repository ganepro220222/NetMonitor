"""Regression checks for bug 83 (latency stats exclude failed probes with RTT)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore, _PROBE_LAT_OK_SQL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")

ROWS_9_1 = [(10.0, "green", None, 1)] * 9 + [(150.0, "green", "status_500", 0)]


def test_compute_hourly_bucket_lat_only_success():
    bucket = DataStore._compute_hourly_bucket(ROWS_9_1)
    ok = (
        bucket
        and bucket["success_n"] == 9
        and bucket["lat_avg"] == 10.0
        and bucket["lat_max"] == 10.0
        and bucket["lat_p95"] == 10.0
    )
    print(f"Bug83 _compute_hourly_bucket: avg={bucket and bucket.get('lat_avg')} "
          f"max={bucket and bucket.get('lat_max')} p95={bucket and bucket.get('lat_p95')} "
          f"-> {ok}")
    return ok


def test_raw_window_bucket_and_p95():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = float(int(time.time())) - 300
        for i, (lat, ok, fr) in enumerate(
                [(10.0, True, None)] * 9 + [(150.0, False, "status_500")]):
            ds.record_ping(
                target_id="T", label="n", ip="1.2.3.4", ping_type="http",
                ts=base + i, status="green",
                latency_ms=lat, loss_rate=0.0 if ok else 1.0,
                probe_success=ok, failure_reason=fr,
            )
        ds.flush()
        conn = sqlite3.connect(path)
        hour = int(base // 3600) * 3600
        bucket = ds._raw_window_bucket(conn, "T", hour, base, base + 20)
        p95 = ds._global_lat_p95_sql(conn, "T", base, base + 20)
        conn.close()
        ds.shutdown()
        ok = (
            bucket
            and bucket["success_n"] == 9
            and bucket["lat_avg"] == 10.0
            and bucket["lat_max"] == 10.0
            and p95 == 10.0
        )
        print(f"Bug83 raw_window+p95: avg={bucket and bucket.get('lat_avg')} "
              f"p95={p95} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_dashboard_sla_waveform_aligned():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = float(int(time.time())) - 120
        for i, (lat, ok, fr) in enumerate(
                [(10.0, True, None)] * 9 + [(150.0, False, "status_500")]):
            ds.record_ping(
                target_id="T", label="n", ip="1.2.3.4", ping_type="http",
                ts=base + i * 0.5, status="green",
                latency_ms=lat, loss_rate=0.0 if ok else 1.0,
                probe_success=ok, failure_reason=fr,
            )
        ds.flush()
        start, end = int(base), int(base) + 60
        dash = ds.get_dashboard_stats_batch(["T"], start, end)["T"]
        sla = ds.get_sla_stats("T", start, end)
        wf = ds.get_waveform("T", start, end)
        ds.shutdown()
        ok = (
            dash["success"] == 9 and dash["total"] == 10
            and dash["lat_avg"] == 10.0 and dash["lat_max"] == 10.0
            and dash["lat_p95"] == 10.0
            and sla.get("sample_n") == 10
            and wf["summary"]["avg_ms"] == 10.0
            and wf["summary"]["max_ms"] == 10.0
        )
        print(f"Bug83 dash={dash} wf_avg={wf['summary'].get('avg_ms')} "
              f"wf_max={wf['summary'].get('max_ms')} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_probe_lat_ok_sql():
    with open(DATA_STORE, encoding="utf-8") as f:
        src = f.read()
    raw_blk = src.split("def _raw_window_bucket", 1)[1].split(
        "def _raw_covers_window_start", 1)[0]
    p95_blk = src.split("def _global_lat_p95_sql", 1)[1].split(
        "def _rollup_latency_for_window", 1)[0]
    ok = (
        "_PROBE_LAT_OK_SQL" in src
        and "_PROBE_LAT_OK_SQL" in raw_blk
        and "_PROBE_LAT_OK_SQL" in p95_blk
        and "MAX(latency_ms)" not in raw_blk.split("_PROBE_LAT_OK_SQL", 1)[0]
    )
    print(f"Bug83 source _PROBE_LAT_OK_SQL wired -> {ok}")
    return ok


def main():
    results = [
        ("hourly", test_compute_hourly_bucket_lat_only_success()),
        ("raw_p95", test_raw_window_bucket_and_p95()),
        ("aligned", test_dashboard_sla_waveform_aligned()),
        ("source", test_source_probe_lat_ok_sql()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 83 checks passed.")
    print("(Also run: python scripts/verify_bugs_82.py python scripts/verify_bugs_74.py)")


if __name__ == "__main__":
    main()
