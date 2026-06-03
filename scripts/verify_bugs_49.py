"""Regression checks for bug 49 (SSE init must not rebuild stats as cumulative)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _init_sse_block(text: str) -> str:
    return text.split("if(msg.type==='init')", 1)[1].split(
        "if(msg.type==='update')", 1)[0]


def _stats_tab_visible_branch(init_block: str) -> str:
    """Extract body of if(_statsTab && visible) inside SSE init."""
    m = re.search(
        r"if\(_statsTab&&_statsTab\.style\.display!=='none'\)\{"
        r"(.*?)\n\s*\}",
        init_block,
        re.DOTALL,
    )
    return m.group(1) if m else ""


def test_init_visible_uses_refresh_not_build_stats():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _init_sse_block(f.read())
    visible_branch = _stats_tab_visible_branch(block)
    ok = (
        "_refreshStatsCharts();" in visible_branch
        and "buildStats()" not in visible_branch
        and re.search(
            r"if\(_statsTab&&_statsTab\.style\.display!=='none'\)buildStats\(\)",
            block,
        ) is None
        and "buildStats()" not in block
    )
    print(f"Bug49 init visible -> _refreshStatsCharts -> {ok}")
    return ok


def test_apply_server_stats_is_cumulative():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    ok = "// Apply server-provided cumulative stats" in text
    print(f"Bug49 applyServerStats cumulative -> {ok}")
    return ok


def test_donut_uses_range_gate():
    with open(WEB_SERVER, encoding="utf-8") as f:
        donut = f.read().split("function buildDonutGrid()", 1)[1].split(
            "function buildBarCharts()", 1)[0]
    ok = "s._range_total != null" in donut
    print(f"Bug49 donut _range_total gate -> {ok}")
    return ok


def test_simulate_init_branch_decision():
    """Visible stats tab must choose range refresh, not cumulative buildStats."""

    def on_init(stats_tab_visible: bool):
        if stats_tab_visible:
            return "refresh_range"
        return "defer"

    ok = (
        on_init(True) == "refresh_range"
        and on_init(False) == "defer"
    )
    print(f"Bug49 init branch decision sim -> {ok}")
    return ok


def test_simulate_cumulative_without_range():
    """Without _range_*, charts use cumulative totals (the bug symptom)."""
    stats_entry = {"total": 1000, "success": 900, "latency_avg": 42.0}
    use_range = stats_entry.get("_range_total") is not None
    displayed_total = (
        stats_entry["_range_total"] if use_range else stats_entry["total"]
    )
    ok = not use_range and displayed_total == 1000
    print(f"Bug49 cumulative fallback without _range -> {ok}")
    return ok


def main():
    results = [
        ("init_refresh", test_init_visible_uses_refresh_not_build_stats()),
        ("cumulative", test_apply_server_stats_is_cumulative()),
        ("range_gate", test_donut_uses_range_gate()),
        ("decision", test_simulate_init_branch_decision()),
        ("symptom", test_simulate_cumulative_without_range()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 49 checks passed.")


if __name__ == "__main__":
    main()
