"""Regression checks for bug 74 (/api/stats avoids full raw fetchall)."""
import math
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.capacity import MAX_TARGETS
from src.config_manager import MIN_PING_INTERVAL_S
from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _legacy_python_stats(rows):
    total = len(rows)
    success = sum(1 for r in rows if r["status"] in ("green", "orange"))
    lats = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
    if lats:
        idx = min(len(lats) - 1, max(0, math.ceil(len(lats) * 0.95) - 1))
        lat_p95 = sorted(lats)[idx]
    else:
        lat_p95 = None
    lat_avg = sum(lats) / len(lats) if lats else None
    lat_max = max(lats) if lats else None
    return {
        "total": total, "success": success,
        "lat_avg": round(lat_avg, 1) if lat_avg is not None else None,
        "lat_max": round(lat_max, 1) if lat_max is not None else None,
        "lat_p95": round(lat_p95, 1) if lat_p95 is not None else None,
    }


def test_capacity_row_estimate():
    interval = MIN_PING_INTERVAL_S
    per_1h = int(3600 / interval)
    per_24h = int(86400 / interval)
    max_1h = per_1h * MAX_TARGETS
    max_24h = per_24h * MAX_TARGETS
    ok = (
        interval == 0.05
        and MAX_TARGETS == 30
        and per_1h == 72000
        and max_1h == 2160000
        and per_24h == 1728000
        and max_24h == 51840000
    )
    print(f"Bug74 1h rows/target={per_1h} 30nodes={max_1h} "
          f"24h 30nodes={max_24h} -> {ok}")
    return ok


def test_api_stats_uses_batch_not_get_history():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def api_stats():", 1)[1].split(
            "def api_waveform_export():", 1)[0]
    ok = (
        "get_dashboard_stats_batch" in block
        and "get_history(" not in block
        and "should_use_hourly" not in block
    )
    print(f"Bug74 /api/stats batch path -> {ok}")
    return ok


def test_raw_window_bucket_sql_aggregate():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    block = text.split("def _raw_window_bucket", 1)[1].split(
        "def _hourly_row_to_bucket", 1)[0]
    ok = (
        "SELECT COUNT(*)" in block
        and "latency_ms, status FROM pings_raw" not in block
        and "RAW_P95_FETCH_LIMIT" in text
    )
    print(f"Bug74 _raw_window_bucket SQL aggregate -> {ok}")
    return ok


def test_dashboard_stats_matches_small_raw():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = float(int(time.time())) - 120
        for i, lat in enumerate([10.0, 20.0, 30.0, 40.0, 50.0]):
            ds.record_ping(
                target_id="T", label="n", ip="1.2.3.4", ping_type="icmp",
                ts=base + i * 0.5, status="green", latency_ms=lat,
                loss_rate=0.0)
        ds.record_ping(
            target_id="T2", label="n", ip="1.2.3.5", ping_type="icmp",
            ts=base + 1.0, status="red", latency_ms=None, loss_rate=1.0)
        ds.flush()
        start = int(base)
        end = int(base) + 60
        batch = ds.get_dashboard_stats_batch(["T", "T2"], start, end)
        rows_t = ds.get_history("T", start, end, use_hourly=False)
        rows_t2 = ds.get_history("T2", start, end, use_hourly=False)
        ds.shutdown()
        legacy_t = _legacy_python_stats(rows_t)
        legacy_t2 = _legacy_python_stats(rows_t2)
        ok = batch["T"] == legacy_t and batch["T2"] == legacy_t2
        print(f"Bug74 batch T={batch['T']} legacy={legacy_t} "
              f"T2={batch['T2']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        ("capacity", test_capacity_row_estimate()),
        ("api_stats", test_api_stats_uses_batch_not_get_history()),
        ("sql_bucket", test_raw_window_bucket_sql_aggregate()),
        ("consistency", test_dashboard_stats_matches_small_raw()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 74 checks passed.")


if __name__ == "__main__":
    main()
