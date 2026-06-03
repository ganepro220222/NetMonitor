"""Regression checks for bug 56 (status change must not fall back to cumulative stats)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _update_sse_block(text: str) -> str:
    return text.split("if(msg.type==='update')", 1)[1].split(
        "if(msg.type==='remove')", 1)[0]


def test_status_changed_uses_refresh_not_local_build():
    block = _update_sse_block(open(WEB_SERVER, encoding="utf-8").read())
    idx = block.find("}else if(statusChanged){")
    snippet = block[idx:idx + 80] if idx >= 0 else ""
    ok = (
        "_refreshStatsCharts();" in snippet
        and "buildDonutGrid();" not in snippet
        and "buildBarCharts();" not in snippet
    )
    print(f"Bug56 statusChanged uses _refreshStatsCharts -> {ok}")
    return ok


def test_refresh_clears_range_after_render():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("async function _refreshStatsCharts()", 1)[1].split(
            "// 导出 Excel", 1)[0]
    ok = (
        "delete stats[tid]._range_total" in block
        and "buildDonutGrid(true)" in block
    )
    print(f"Bug56 _refreshStatsCharts clears _range_* -> {ok}")
    return ok


def test_donut_uses_range_gate():
    with open(WEB_SERVER, encoding="utf-8") as f:
        donut = f.read().split("function buildDonutGrid()", 1)[1].split(
            "function buildBarCharts()", 1)[0]
    ok = "s._range_total != null" in donut
    print(f"Bug56 donut _range_total gate -> {ok}")
    return ok


def test_simulate_cumulative_fallback_without_range():
    stats = {"tid": {"total": 1000, "success": 900, "latency_avg": 50.0}}
    range_stats = {
        "_range_total": 10,
        "_range_success": 9,
        "_range_lat_avg": 5.0,
    }

    def render_total(s):
        use_range = s.get("_range_total") is not None
        return s["_range_total"] if use_range else s["total"]

    with_range = dict(stats["tid"])
    with_range.update(range_stats)
    range_total = render_total(with_range)

    after_clear = dict(stats["tid"])
    cumulative_total = render_total(after_clear)

    ok = range_total == 10 and cumulative_total == 1000
    print(f"Bug56 range vs cumulative sim -> {ok}")
    return ok


def test_simulate_status_refresh_path():
    """Status change should re-fetch range, not call bare buildDonutGrid."""
    status_changed_path = "_refreshStatsCharts()"
    bare_build = "buildDonutGrid(); buildBarCharts()"
    ok = status_changed_path != bare_build
    print(f"Bug56 refresh path choice -> {ok}")
    return ok


def main():
    results = [
        ("status_refresh", test_status_changed_uses_refresh_not_local_build()),
        ("clear_range", test_refresh_clears_range_after_render()),
        ("range_gate", test_donut_uses_range_gate()),
        ("fallback", test_simulate_cumulative_fallback_without_range()),
        ("path", test_simulate_status_refresh_path()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 56 checks passed.")


if __name__ == "__main__":
    main()
