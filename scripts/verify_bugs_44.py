"""Regression checks for bug 44 (init resets bar charts on stats tab)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_reset_stats_ui_clears_bar_charts():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    fn = text.split("function resetStatsUi()", 1)[1].split("function buildDonutGrid", 1)[0]
    ok = ("barCharts" in fn
          and "barCharts[key].destroy()" in fn
          and "bar-empty" in fn
          and "bar-icmp-group" in fn)
    print(f"Bug44 resetStatsUi clears barCharts -> {ok}")
    return ok


def test_init_refreshes_stats_tab_when_visible():
    with open(WEB_SERVER, encoding="utf-8") as f:
        init_block = f.read().split("if(msg.type==='init')", 1)[1].split(
            "if(msg.type==='update')", 1)[0]
    ok = (
        "resetStatsUi();" in init_block
        and "tab-stats" in init_block
        and "_refreshStatsCharts();" in init_block
        and "resetWaveformUi();" in init_block
        and "loadWaveform();" in init_block
        and "if(_statsTab&&_statsTab.style.display!=='none')buildStats()" not in init_block
        and re.search(
            r"if\(_statsTab&&_statsTab\.style\.display!=='none'\)\{"
            r"\s*_refreshStatsCharts\(\);\s*resetWaveformUi\(\);\s*loadWaveform\(\);",
            init_block,
        ) is not None
    )
    print(f"Bug44 init refreshes stats tab -> {ok}")
    return ok


def _simulate_reset_stats_ui(bar_charts, stats, dom, bar_groups_visible, bar_empty):
    bar_charts.clear()
    stats.clear()
    dom.clear()
    for g in bar_groups_visible:
        bar_groups_visible[g] = False
    bar_empty[0] = True


def _simulate_build_bar_charts(bar_charts, stats, targets, bar_groups_visible, bar_empty):
    tids = [tid for tid in stats if tid in targets]
    if not tids:
        return
    bar_groups_visible["icmp"] = True
    bar_empty[0] = False
    bar_charts["icmp"] = {"labels": [targets[t]["label"] for t in tids]}


def _simulate_init_fixed(bar_charts, stats, targets, dom, groups, empty, server_stats, server_targets):
    targets.clear()
    _simulate_reset_stats_ui(bar_charts, stats, dom, groups, empty)
    for tid, s in server_stats.items():
        stats[tid] = dict(s)
    for t in server_targets:
        targets[t["tid"]] = t
    if True:  # stats tab visible
        _simulate_build_bar_charts(bar_charts, stats, targets, groups, empty)


def _simulate_init_old(bar_charts, stats, targets, dom, groups, empty, server_stats, server_targets):
    targets.clear()
    stats.clear()  # Bug43 fixed - but bar not cleared in old Bug44
    for tid, s in server_stats.items():
        stats.setdefault(tid, {}).update(s)
    for t in server_targets:
        targets[t["tid"]] = t
    # barCharts and groups unchanged from before


def test_init_fixed_clears_stale_bar_labels():
    bar_charts = {"icmp": {"labels": ["DeletedNode"]}}
    stats = {}
    targets = {}
    dom = {}
    groups = {"icmp": True}
    empty = [False]

    _simulate_init_fixed(bar_charts, stats, targets, dom, groups, empty, {}, [])
    ok = (not bar_charts.get("icmp")
          or "DeletedNode" not in str(bar_charts.get("icmp")))
    ok = ok and not groups["icmp"] and empty[0]
    print(f"Bug44 simulate fixed: bar={bar_charts} groups={groups} empty={empty[0]} -> {ok}")
    return ok


def test_init_old_keeps_stale_bar():
    bar_charts = {"icmp": {"labels": ["DeletedNode"]}}
    stats = {"A": {"total": 1}}
    targets = {}
    groups = {"icmp": True}
    empty = [False]

    _simulate_init_old(bar_charts, stats, targets, {}, groups, empty, {}, [])
    ok = bar_charts["icmp"]["labels"] == ["DeletedNode"] and groups["icmp"]
    print(f"Bug44 simulate old (control): staleRemains={ok} -> {ok}")
    return ok


def main():
    results = [
        ("resetStatsUi", test_reset_stats_ui_clears_bar_charts()),
        ("init refresh", test_init_refreshes_stats_tab_when_visible()),
        ("fixed simulate", test_init_fixed_clears_stale_bar_labels()),
        ("old control", test_init_old_keeps_stale_bar()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 44 checks passed.")


if __name__ == "__main__":
    main()
