"""Regression checks for bug 76 (global P95, not weighted hourly P95 average)."""
import math
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


def test_two_hour_global_p95():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        h1 = (int(time.time()) // 3600) * 3600 - 7200
        h2 = h1 + 3600
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        rows = []
        for i in range(100):
            rows.append(("T", h1 + 10.0 + i * 0.01, "green", 10.0))
        for i in range(90):
            rows.append(("T", h2 + 10.0 + i * 0.01, "green", 10.0))
        for i in range(10):
            rows.append(("T", h2 + 20.0 + i * 0.01, "green", 1000.0))
        conn.executemany(
            "INSERT INTO pings_raw (target_id, ts, status, latency_ms) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        conn.close()

        start = h1
        end = h2 + 3600
        dash = ds.get_dashboard_stats_batch(["T"], start, end)
        sla = ds.get_sla_stats("T", start, end)
        ds.shutdown()

        d = dash["T"]
        lat_n = 200
        exact_p95 = 10.0
        ok = (
            d["total"] == 200
            and d["success"] == 200
            and d["lat_avg"] == 59.5
            and d["lat_max"] == 1000.0
            and d["lat_p95"] == exact_p95
            and d["lat_p95"] != 505.0
            and sla["lat_p95"] == exact_p95
        )
        print(f"Bug76 dashboard={d} sla_p95={sla['lat_p95']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_pre_retention_p95_is_none():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        ds._schema_ready.wait(timeout=5)
        now = int(time.time())
        start = now - 30 * 86400
        end = now - 29 * 86400
        old_hour = (start // 3600) * 3600
        conn = sqlite3.connect(path)
        conn.execute(
            "INSERT INTO pings_hourly "
            "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,lat_min,lat_p95,loss_rate) "
            "VALUES ('T',?,100,100,10.0,10.0,10.0,10.0,0)",
            (old_hour,),
        )
        conn.commit()
        conn.close()
        batch = ds.get_dashboard_stats_batch(["T"], start, end)
        ds.shutdown()
        ok = batch["T"]["lat_p95"] is None
        print(f"Bug76 pre-retention p95={batch['T']['lat_p95']} (expect None) -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_no_weighted_hourly_p95():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    rollup = text.split("def _rollup_hourly_buckets", 1)[1].split(
        "def _current_hour_bucket", 1)[0]
    dash = text.split("def get_dashboard_stats_batch", 1)[1].split(
        "def get_sla_stats", 1)[0]
    ok = (
        "p95_pairs" not in rollup
        and "sum(v * n for v, n in p95_pairs)" not in text
        and "_rollup_latency_for_window" in text
        and "_global_lat_p95_sql" in text
        and "_rollup_latency_for_window" in dash
        and "get_dashboard_stats_batch" in text
    )
    print(f"Bug76 source global p95 path -> {ok}")
    return ok


def main():
    results = [
        ("two_hour", test_two_hour_global_p95()),
        ("pre_retention", test_pre_retention_p95_is_none()),
        ("source", test_source_no_weighted_hourly_p95()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 76 checks passed.")


if __name__ == "__main__":
    main()
