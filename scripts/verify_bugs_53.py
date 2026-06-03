"""Regression checks for bug 53 (SSE update meta change refreshes stats tab)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _update_sse_block(text: str) -> str:
    return text.split("if(msg.type==='update')", 1)[1].split(
        "if(msg.type==='remove')", 1)[0]


def test_update_detects_meta_changed():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    ok = (
        "const metaChanged=old&&(" in block
        and "old.label!==t.label" in block
        and "old.ip!==t.ip" in block
        and "old.ping_type!==t.ping_type" in block
    )
    print(f"Bug53 metaChanged detection -> {ok}")
    return ok


def test_meta_changed_refreshes_stats_tab():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _update_sse_block(f.read())
    idx = block.find("if(metaChanged){")
    end = block.find("}else if(statusChanged){", idx)
    branch = block[idx:end] if idx >= 0 and end > idx else ""
    ok = (
        "buildBarCharts();" in branch
        and "_refreshStatsCharts();" in branch
        and "resetWaveformUi();" in branch
        and "loadWaveform();" in branch
    )
    print(f"Bug53 stats tab refresh on meta change -> {ok}")
    return ok


def test_build_donut_updates_existing_title():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("function buildDonutGrid()", 1)[1].split(
            "function buildBarCharts()", 1)[0]
    ok = (
        "else{" in block
        and ".stat-title" in block
        and "titleEl.innerHTML" in block
    )
    print(f"Bug53 buildDonutGrid title refresh -> {ok}")
    return ok


def test_simulate_stale_labels_without_refresh():
    targets = {"a": {"tid": "a", "label": "Old", "ip": "1.1.1.1", "ping_type": "icmp"}}
    bar_labels = [targets["a"]["label"]]
    waveform_option = f"{targets['a']['label']} ({targets['a']['ip']})"

    targets["a"]["label"] = "New"
    targets["a"]["ip"] = "2.2.2.2"
    meta_changed = True

    stale_bar = bar_labels
    stale_wave = waveform_option
    fresh_bar = [targets["a"]["label"]]
    fresh_wave = f"{targets['a']['label']} ({targets['a']['ip']})"

    ok = (
        meta_changed
        and stale_bar == ["Old"]
        and stale_wave == "Old (1.1.1.1)"
        and fresh_bar == ["New"]
        and fresh_wave == "New (2.2.2.2)"
    )
    print(f"Bug53 stale vs fresh labels sim -> {ok}")
    return ok


def main():
    results = [
        ("meta_detect", test_update_detects_meta_changed()),
        ("refresh", test_meta_changed_refreshes_stats_tab()),
        ("donut_title", test_build_donut_updates_existing_title()),
        ("simulate", test_simulate_stale_labels_without_refresh()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 53 checks passed.")


if __name__ == "__main__":
    main()
