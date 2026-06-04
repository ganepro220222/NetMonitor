"""Regression checks for bug 101 (SLA P95 requires full raw coverage)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _seed_hourly_only_gap(path: str, tid: str = "T"):
    now = time.time()
    start = now - 3 * 86400
    end = now
    with sqlite3.connect(path) as conn:
        hour_lo = int(start) // 3600 * 3600
        for i in range(50):
            ht = hour_lo + i * 3600
            if ht > int(end):
                break
            conn.execute(
                "INSERT INTO pings_hourly "
                "(target_id, hour_ts, sample_n, success_n, lat_avg, lat_max, "
                "lat_min, lat_p95, loss_rate) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (tid, ht, 2, 2, 1000.0, 1000.0, 1000.0, 1000.0, 0.0),
            )
        for j in range(5):
            conn.execute(
                "INSERT INTO pings_raw "
                "(target_id, ts, status, latency_ms, loss_rate, probe_success) "
                "VALUES (?,?,?,?,?,?)",
                (tid, now - j * 60, "green", 2.0, 0.0, 1),
            )
        conn.commit()
    return start, end


def test_hourly_without_full_raw_skips_p95():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=8)
        ds._schema_ready.wait(timeout=5)
        start, end = _seed_hourly_only_gap(path)
        sla = ds.get_sla_stats("T", start, end)
        ok = (
            sla.get("sample_n", 0) >= 50
            and sla.get("lat_avg") is not None
            and sla["lat_avg"] > 100
            and sla.get("lat_p95") is None
            and sla.get("p95_from_raw") is False
        )
        print(f"Bug101 partial raw: sample_n={sla.get('sample_n')} "
              f"avg={sla.get('lat_avg')} p95={sla.get('lat_p95')} "
              f"flag={sla.get('p95_from_raw')} -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_full_raw_coverage_allows_p95():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=8)
        ds._schema_ready.wait(timeout=5)
        base = int(time.time()) - 3600
        for i in range(20):
            ds.record_ping(
                target_id="T2", label="n", ip="1.2.3.4", ping_type="icmp",
                ts=base + i * 10, status="green",
                latency_ms=float(10 + i), loss_rate=0.0, probe_success=True)
        ds.flush()
        end = base + 200
        sla = ds.get_sla_stats("T2", base, end)
        ok = (
            sla.get("sample_n") == 20
            and sla.get("p95_from_raw") is True
            and sla.get("lat_p95") is not None
        )
        print(f"Bug101 full raw: n={sla.get('sample_n')} p95={sla.get('lat_p95')} "
              f"flag={sla.get('p95_from_raw')} -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_raw_count_equals_total():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _rollup_latency_for_window", 1)[1].split(
            "def _hourly_row_to_bucket", 1)[0]
    ok = (
        "_raw_probe_count_in_window" in block
        and "== total" in block
        and 'merged["p95_from_raw"]' in block
    )
    print(f"Bug101 source raw count gate -> {ok}")
    return ok


def test_api_uses_per_target_flag():
    with open(os.path.join(ROOT, "src", "web_server.py"), encoding="utf-8") as f:
        block = f.read().split('def api_sla():', 1)[1].split('def api_stats', 1)[0]
    ok = "_raw_covers_window_start(start)" not in block
    print(f"Bug101 api_sla no global p95 flag -> {ok}")
    return ok


def main():
    results = [
        ("gap", test_hourly_without_full_raw_skips_p95()),
        ("full", test_full_raw_coverage_allows_p95()),
        ("source", test_source_raw_count_equals_total()),
        ("api", test_api_uses_per_target_flag()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 101 checks passed.")


if __name__ == "__main__":
    main()
