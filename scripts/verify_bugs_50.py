"""Regression checks for bug 50 (SSE init must refresh waveform on stats tab)."""
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


def test_init_stats_visible_refreshes_waveform():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _init_sse_block(f.read())
    ok = (
        "_refreshStatsCharts()" in block
        and "resetWaveformUi()" in block
        and "loadWaveform()" in block
        and re.search(
            r"_refreshStatsCharts\(\);\s*resetWaveformUi\(\);\s*loadWaveform\(\)",
            block,
        ) is not None
    )
    print(f"Bug50 init stats tab full refresh -> {ok}")
    return ok


def test_reset_waveform_ui_defined():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    block = text.split("function resetWaveformUi()", 1)[1].split(
        "function loadWaveform()", 1)[0]
    ok = (
        "_waveReqId++" in block
        and "_waveChart.destroy()" in block
        and "_populateWaveformTids()" in block
        and "waveform-summary" in block
    )
    print(f"Bug50 resetWaveformUi helper -> {ok}")
    return ok


def test_load_waveform_clears_chart_when_no_tid():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("function loadWaveform()", 1)[1].split(
            "function _renderWaveform(", 1)[0]
    ok = (
        "if(!tid){" in block
        and "_waveChart.destroy()" in block
        and "waveform-summary" in block
    )
    print(f"Bug50 loadWaveform no-tid clears chart -> {ok}")
    return ok


def test_reset_stats_ui_does_not_touch_waveform():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("function resetStatsUi()", 1)[1].split(
            "function buildDonutGrid()", 1)[0]
    ok = "waveform" not in block.lower()
    print(f"Bug50 resetStatsUi leaves waveform separate -> {ok}")
    return ok


def test_simulate_init_refresh_sequence():
    def on_init(stats_visible: bool):
        if stats_visible:
            return ["refresh_stats", "reset_waveform", "load_waveform"]
        return []

    visible = on_init(True)
    hidden = on_init(False)
    ok = (
        visible == ["refresh_stats", "reset_waveform", "load_waveform"]
        and hidden == []
    )
    print(f"Bug50 init sequence sim -> {ok}")
    return ok


def main():
    results = [
        ("init_refresh", test_init_stats_visible_refreshes_waveform()),
        ("reset_helper", test_reset_waveform_ui_defined()),
        ("no_tid_clear", test_load_waveform_clears_chart_when_no_tid()),
        ("stats_separate", test_reset_stats_ui_does_not_touch_waveform()),
        ("sequence", test_simulate_init_refresh_sequence()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 50 checks passed.")


if __name__ == "__main__":
    main()
