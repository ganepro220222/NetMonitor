"""Regression checks for bug 42 (remove donut stat-card DOM on SSE remove)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_remove_branch_removes_stat_card_dom():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    ok = ("msg.type==='remove'" in text
          and "closest('.stat-card')" in text
          and "_statCard.remove()" in text)
    print(f"Bug42 source remove+stat-card cleanup -> {ok}")
    return ok


def _simulate_old_remove(dom, targets, stats, donut_charts, tid):
    targets.pop(tid, None)
    stats.pop(tid, None)
    donut_charts.pop(tid, None)


def _simulate_fixed_remove(dom, targets, stats, donut_charts, tid):
    _simulate_old_remove(dom, targets, stats, donut_charts, tid)
    dom.pop(tid, None)


def _build_donut_grid(dom, targets, stats):
    for tid in list(stats.keys()):
        if tid not in targets:
            continue
        dom[tid] = True


def test_stale_card_removed_after_sse_remove():
    targets = {"A": {"label": "A"}}
    stats = {"A": {"total": 1}}
    donut = {"A": "chart"}
    dom = {}

    _build_donut_grid(dom, targets, stats)
    before = len(dom)
    _simulate_fixed_remove(dom, targets, stats, donut, "A")
    _build_donut_grid(dom, targets, stats)
    after = len(dom)
    ok = before == 1 and after == 0
    print(f"Bug42 simulate fixed: before={before} after={after} -> {ok}")
    return ok


def test_old_logic_leaves_stale_card():
    targets = {"A": {"label": "A"}}
    stats = {"A": {"total": 1}}
    donut = {"A": "chart"}
    dom = {}

    _build_donut_grid(dom, targets, stats)
    _simulate_old_remove(dom, targets, stats, donut, "A")
    _build_donut_grid(dom, targets, stats)
    ok = len(dom) == 1
    print(f"Bug42 simulate old (control): staleRemains={ok} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_remove_branch_removes_stat_card_dom()),
        ("fixed simulate", test_stale_card_removed_after_sse_remove()),
        ("old control", test_old_logic_leaves_stale_card()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 42 checks passed.")


if __name__ == "__main__":
    main()
