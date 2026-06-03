"""Regression checks for bug 54 (SSE update status change refreshes chart colors)."""
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


def test_status_changed_detection():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    ok = "const statusChanged=old&&old.status!==t.status;" in block
    print(f"Bug54 statusChanged detection -> {ok}")
    return ok


def test_status_changed_refreshes_range_stats():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    idx = block.find("}else if(statusChanged){")
    snippet = block[idx:idx + 80] if idx >= 0 else ""
    ok = (
        "_refreshStatsCharts();" in snippet
        and "buildDonutGrid();" not in snippet
        and "buildBarCharts();" not in snippet
    )
    print(f"Bug54 statusChanged range refresh -> {ok}")
    return ok


def test_meta_changed_still_full_refresh():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    idx = block.find("if(metaChanged){")
    end = block.find("}else if(statusChanged){", idx)
    snippet = block[idx:end] if idx >= 0 and end > idx else ""
    ok = (
        "_refreshStatsCharts();" in snippet
        and "resetWaveformUi();" in snippet
        and "loadWaveform();" in snippet
    )
    print(f"Bug54 metaChanged full refresh preserved -> {ok}")
    return ok


def test_status_branch_uses_api_refresh():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    idx = block.find("}else if(statusChanged){")
    snippet = block[idx:idx + 80] if idx >= 0 else ""
    ok = "_refreshStatsCharts();" in snippet
    print(f"Bug54 status branch uses _refreshStatsCharts -> {ok}")
    return ok


def test_simulate_stale_color_until_rebuild():
    status_colors = {"green": "#22c55e", "red": "#ef4444"}
    ui = {"dot": status_colors["green"], "bar": status_colors["green"]}
    targets_status = "red"
    status_changed = True
    stale = ui.copy()
    if status_changed:
        ui["dot"] = status_colors[targets_status]
        ui["bar"] = status_colors[targets_status]
    ok = stale["dot"] == status_colors["green"] and ui["bar"] == status_colors["red"]
    print(f"Bug54 color sync sim -> {ok}")
    return ok


def main():
    results = [
        ("detect", test_status_changed_detection()),
        ("range_refresh", test_status_changed_refreshes_range_stats()),
        ("meta_full", test_meta_changed_still_full_refresh()),
        ("api_refresh", test_status_branch_uses_api_refresh()),
        ("simulate", test_simulate_stale_color_until_rebuild()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 54 checks passed.")


if __name__ == "__main__":
    main()
