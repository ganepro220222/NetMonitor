"""Regression checks for bug 52 (SSE remove must refresh stats tab charts)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _remove_sse_block(text: str) -> str:
    return text.split("if(msg.type==='remove')", 1)[1].split(
        "if(msg.type==='port_status')", 1)[0]


def _stats_tab_visible_branch(remove_block: str) -> str:
    m = re.search(
        r"if\(_statsTabRm&&_statsTabRm\.style\.display!=='none'\)\{"
        r"(.*?)\n\s*\}",
        remove_block,
        re.DOTALL,
    )
    return m.group(1) if m else ""


def test_remove_stats_visible_refreshes_all():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = _remove_sse_block(f.read())
    branch = _stats_tab_visible_branch(block)
    ok = (
        "purgeDonutTarget(msg.tid)" in block
        and "buildBarCharts();" in branch
        and "_refreshStatsCharts();" in branch
        and "resetWaveformUi();" in branch
        and "loadWaveform();" in branch
        and re.search(
            r"buildBarCharts\(\);\s*_refreshStatsCharts\(\);\s*"
            r"resetWaveformUi\(\);\s*loadWaveform\(\)",
            branch,
        ) is not None
    )
    print(f"Bug52 remove stats tab full refresh -> {ok}")
    return ok


def test_purge_donut_does_not_touch_bar_or_waveform():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("function purgeDonutTarget(", 1)[1].split(
            "function resetStatsUi()", 1)[0]
    low = block.lower()
    ok = "barchart" not in low and "waveform" not in low
    print(f"Bug52 purgeDonutTarget scope -> {ok}")
    return ok


def test_simulate_stale_bar_without_refresh():
    targets = {"A": {"tid": "A", "label": "A", "ping_type": "icmp"}}
    stats = {"A": {"total": 10, "success": 9, "latency_avg": 5.0}}
    bar_charts = {"icmp": {"labels": ["A"], "data": [5.0]}}

    def build_bar_labels():
        tids = [
            tid for tid in stats
            if tid in targets
            and (targets[tid].get("ping_type") or "icmp") == "icmp"
        ]
        return [targets[tid]["label"] for tid in tids]

    before = build_bar_labels()
    del targets["A"]
    del stats["A"]
    without_refresh = bar_charts["icmp"]["labels"]
    after = build_bar_labels()
    ok = before == ["A"] and without_refresh == ["A"] and after == []
    print(f"Bug52 stale bar until rebuild sim -> {ok}")
    return ok


def test_simulate_refresh_after_remove():
    targets = {"A": {"tid": "A", "label": "A", "ping_type": "icmp"}}
    stats = {"A": {"total": 10}}
    del targets["A"]
    del stats["A"]
    labels = [
        targets[t]["label"]
        for t in stats
        if t in targets
    ]
    ok = labels == []
    print(f"Bug52 labels after remove+rebuild sim -> {ok}")
    return ok


def main():
    results = [
        ("remove_refresh", test_remove_stats_visible_refreshes_all()),
        ("purge_scope", test_purge_donut_does_not_touch_bar_or_waveform()),
        ("stale_bar", test_simulate_stale_bar_without_refresh()),
        ("rebuild", test_simulate_refresh_after_remove()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 52 checks passed.")


if __name__ == "__main__":
    main()
