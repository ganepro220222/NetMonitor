"""Regression checks for bug 75 (raw window p95 via SQL offset, not lat_max)."""
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


def test_large_window_p95_not_lat_max():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        hour = (int(time.time()) // 3600) * 3600
        win_start = float(hour)
        win_end = hour + 3599.9
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        conn = sqlite3.connect(path)
        rows = []
        base_ts = hour + 1.0
        for i in range(19001):
            rows.append(("T", base_ts + i * 0.001, "green", 10.0))
        for i in range(1000):
            rows.append(("T", base_ts + 19.001 + i * 0.001, "green", 1000.0))
        conn.executemany(
            "INSERT INTO pings_raw (target_id, ts, status, latency_ms) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        conn.close()

        start = hour
        end = hour + 3600
        batch = ds.get_dashboard_stats_batch(["T"], start, end)
        ds.shutdown()

        s = batch["T"]
        lat_n = 20001
        exact_idx = min(lat_n - 1, max(0, math.ceil(lat_n * 0.95) - 1))
        lats = [10.0] * 19001 + [1000.0] * 1000
        exact_p95 = sorted(lats)[exact_idx]
        ok = (
            s["total"] == 20001
            and s["lat_max"] == 1000.0
            and s["lat_p95"] == exact_p95
            and s["lat_p95"] == 10.0
            and s["lat_p95"] != s["lat_max"]
        )
        print(f"Bug75 n={s['total']} p95={s['lat_p95']} max={s['lat_max']} "
              f"exact={exact_p95} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_sql_p95_offset():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    block = text.split("def _raw_window_bucket", 1)[1].split(
        "def _hourly_row_to_bucket", 1)[0]
    ok = (
        "ORDER BY latency_ms ASC LIMIT 1 OFFSET" in block
        and "lat_p95 = lat_max" not in block
        and "math.ceil(lat_n * 0.95)" in block
    )
    print(f"Bug75 source SQL p95 offset -> {ok}")
    return ok


def main():
    results = [
        ("p95_large", test_large_window_p95_not_lat_max()),
        ("source", test_source_sql_p95_offset()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 75 checks passed.")


if __name__ == "__main__":
    main()
