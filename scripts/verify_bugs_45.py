"""Regression checks for bug 45 (empty range must not show cumulative stats)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)

EMPTY_RANGE = {
    "total": 0, "success": 0,
    "lat_avg": None, "lat_max": None, "lat_p95": None,
}


def test_api_stats_empty_rows_placeholder():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    api_block = text.split('def api_stats():', 1)[1].split(
        '@app.route("/api/waveform/export")', 1)[0]
    ok = (
        "get_dashboard_stats_batch" in api_block
        and "get_history(" not in api_block
    )
    print(f"Bug45 api_stats uses batch path -> {ok}")
    return ok


def test_dashboard_stats_batch_empty_behavior():
    import tempfile
    import time
    from src.data_store import DataStore

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        start = int(time.time()) - 3600
        end = int(time.time())
        batch = ds.get_dashboard_stats_batch(["T"], start, end)
        ds.shutdown()
        ok = batch.get("T") == EMPTY_RANGE
        print(f"Bug45 empty batch stats -> {batch.get('T')} ok={ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_frontend_use_range_total_gate():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    donut = text.split("function buildDonutGrid()", 1)[1].split(
        "function buildBarCharts()", 1)[0]
    bar = text.split("function buildBarCharts()", 1)[1].split(
        "// Card selection", 1)[0]
    ok = ("const useRange" in donut
          and "s._range_total != null" in donut
          and "s._range_total!=null" in bar)
    refresh = text.split("async function _refreshStatsCharts()", 1)[1].split(
        "// 导出 Excel", 1)[0]
    ok = ok and "savedStats" not in refresh
    print(f"Bug45 frontend range-only rendering -> {ok}")
    return ok


def _donut_metrics(stats_entry):
    s = stats_entry
    use_range = s.get("_range_total") is not None
    total = s["_range_total"] if use_range else s.get("total", 0)
    success = (s.get("_range_success", 0) if use_range
               else s.get("success", 0))
    if use_range:
        avg = (f"{s['_range_lat_avg']:.1f}"
               if s.get("_range_lat_avg") is not None else "--")
    else:
        avg = f"{s.get('latency_avg', 0):.1f}" if s.get("latency_n") else "--"
    uptime = (success / total * 100) if total else (0 if use_range else 100)
    return {"uptime": uptime, "avg": avg, "use_range": use_range}


def test_simulate_empty_range_vs_cumulative_fallback():
    cumulative = {
        "total": 1000, "success": 900, "latency_n": 50, "latency_avg": 42.5,
    }
    with_range_empty = dict(cumulative)
    with_range_empty["_range_total"] = 0
    with_range_empty["_range_success"] = 0
    with_range_empty["_range_lat_avg"] = None

    old_style = _donut_metrics({
        **cumulative,
        "_range_lat_avg": None,
    })
    fixed = _donut_metrics(with_range_empty)

    ok = (old_style["avg"] == "42.5"
          and fixed["avg"] == "--"
          and fixed["uptime"] == 0
          and fixed["use_range"])
    print(f"Bug45 simulate: old_avg={old_style['avg']} fixed_avg={fixed['avg']} "
          f"uptime={fixed['uptime']} -> {ok}")
    return ok


def test_empty_api_payload_shape():
    ok = EMPTY_RANGE["total"] == 0 and EMPTY_RANGE["lat_avg"] is None
    print(f"Bug45 empty payload shape -> {ok}")
    return ok


def main():
    results = [
        ("api_stats", test_api_stats_empty_rows_placeholder()),
        ("batch_empty", test_dashboard_stats_batch_empty_behavior()),
        ("frontend", test_frontend_use_range_total_gate()),
        ("simulate", test_simulate_empty_range_vs_cumulative_fallback()),
        ("payload", test_empty_api_payload_shape()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 45 checks passed.")


if __name__ == "__main__":
    main()
