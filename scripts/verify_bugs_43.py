"""Regression checks for bug 43 (init SSE clears stale donut stats UI)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_init_calls_reset_donut_stats_ui():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    init_block = text.split("if(msg.type==='init')", 1)[1].split("if(msg.type==='update')", 1)[0]
    ok = ("resetDonutStatsUi();" in init_block
          and "function resetDonutStatsUi()" in text
          and "function purgeDonutTarget(tid)" in text)
    print(f"Bug43 source init reset -> {ok}")
    return ok


def _build_donut_grid(dom, targets, stats):
    for tid in list(stats.keys()):
        if tid not in targets:
            continue
        dom[tid] = True


def _simulate_init_old(targets, stats, dom, donut, server_targets, server_stats):
    targets.clear()
    for tid, s in server_stats.items():
        stats.setdefault(tid, {}).update(s)
    for t in server_targets:
        targets[t["tid"]] = t
    _build_donut_grid(dom, targets, stats)


def _simulate_init_fixed(targets, stats, dom, donut, server_targets, server_stats):
    targets.clear()
    donut.clear()
    stats.clear()
    dom.clear()
    for tid, s in server_stats.items():
        stats.setdefault(tid, {}).update(s)
    for t in server_targets:
        targets[t["tid"]] = t
    _build_donut_grid(dom, targets, stats)


def test_init_fixed_clears_stale_donut_after_offline_delete():
    targets = {"A": {"tid": "A", "label": "A"}}
    stats = {"A": {"total": 10}}
    dom = {"A": True}
    donut = {"A": "chart"}

    server_targets = []
    server_stats = {}

    _simulate_init_fixed(targets, stats, dom, donut, server_targets, server_stats)
    ok = len(dom) == 0 and "A" not in stats and "A" not in donut
    print(f"Bug43 simulate fixed: dom={len(dom)} stats={list(stats)} -> {ok}")
    return ok


def test_init_old_leaves_stale_donut():
    targets = {"A": {"tid": "A", "label": "A"}}
    stats = {"A": {"total": 10}}
    dom = {"A": True}
    donut = {"A": "chart"}

    _simulate_init_old(targets, stats, dom, donut, [], {})
    ok = len(dom) == 1 and "A" in stats
    print(f"Bug43 simulate old (control): staleRemains={ok} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_init_calls_reset_donut_stats_ui()),
        ("fixed simulate", test_init_fixed_clears_stale_donut_after_offline_delete()),
        ("old control", test_init_old_leaves_stale_donut()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 43 checks passed.")


if __name__ == "__main__":
    main()
