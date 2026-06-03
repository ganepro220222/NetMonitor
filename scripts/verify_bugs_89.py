"""Regression checks for bug 89 (Excel raw summary latency uses probe_success)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def test_excel_raw_summary_matches_dashboard_sla():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        end_ts = int(time.time())
        start_ts = end_ts - 1800
        tid = "T"
        base = float(start_ts) + 10
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=base, status="green", latency_ms=10.0, loss_rate=0.0,
            probe_success=True)
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=base + 1, status="green", latency_ms=1000.0, loss_rate=1.0,
            probe_success=False, failure_reason="status_500")
        ds.flush()

        dash = ds.get_dashboard_stats_batch([tid], start_ts, end_ts)[tid]
        sla = ds.get_sla_stats(tid, start_ts, end_ts)

        import openpyxl

        xfd, xpath = tempfile.mkstemp(suffix=".xlsx")
        os.close(xfd)
        ds.export_excel(
            xpath, [tid], start_ts, end_ts,
            {tid: {"label": "node", "ip": "1.2.3.4", "ping_type": "http"}})
        row = list(openpyxl.load_workbook(xpath)["汇总"].iter_rows(
            min_row=2, max_row=2, values_only=True))[0]
        os.unlink(xpath)
        ds.shutdown()

        # 节点, IP, type, total, success, rate%, avg, max
        total, success, rate, avg_lat, max_lat = row[3:8]
        ok = (
            total == 2 and success == 1 and rate == 50
            and avg_lat == 10 and max_lat == 10
            and dash["lat_avg"] == 10.0 and dash["lat_max"] == 10.0
            and sla["lat_avg"] == 10.0 and sla["lat_max"] == 10.0
        )
        print(f"Bug89 excel row={list(row)} dash={dash} sla_lat={sla.get('lat_avg')} "
              f"-> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_raw_lats_use_row_probe_success():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("else:", 1)
    # raw branch in export summary (after hourly branch)
    raw = block[-1].split("rate    = round", 1)[0]
    ok = (
        raw.count("row_probe_success") >= 2
        and "lats = [" in raw
        and "if r[\"latency_ms\"] is not None]" not in raw.split("lats = [", 1)[1].split("maxlats", 1)[0]
    )
    print(f"Bug89 source raw lats filtered by probe_success -> {ok}")
    return ok


def main():
    results = [
        ("excel", test_excel_raw_summary_matches_dashboard_sla()),
        ("source", test_source_raw_lats_use_row_probe_success()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 89 checks passed.")


if __name__ == "__main__":
    main()
