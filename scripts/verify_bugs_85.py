"""Regression checks for bug 85 (no duplicate urgent+full-scan traceroute per tick)."""
import os
import re
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import _TracerouteScheduler

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_source_tick_top_drain_seeds_full_scan():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def _loop(self):", 1)[1].split(
            "def _run_one(self", 1)[0]
    ok = (
        "already_traced = self._drain_urgent()" in block
        and "traced_this_pass = set(already_traced)" in block
        and "traced_this_pass = set()" not in block
    )
    print(f"Bug85 tick-top drain seeds full-scan dedupe -> {ok}")
    return ok


def test_same_tick_no_duplicate_after_pre_drain():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=0)
    with sched._targets_lock:
        sched._targets = {
            "T1": {"ip": "10.0.0.1", "probe_ports": [80]},
            "T2": {"ip": "10.0.0.2", "probe_ports": [80]},
        }
    sched.request_now("T1")
    calls = []
    sched._run_one = lambda tid, info: calls.append(tid)

    pre = sched._drain_urgent()
    snap = dict(sched._targets)
    traced = set(pre)
    for tid, info in snap.items():
        traced |= sched._drain_urgent()
        if tid in traced:
            continue
        sched._run_one(tid, info)
        traced.add(tid)

    ok = calls == ["T1", "T2"] and calls.count("T1") == 1
    print(f"Bug85 one tick: pre={pre} calls={calls} T1_runs={calls.count('T1')} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_tick_top_drain_seeds_full_scan()),
        ("no_dup", test_same_tick_no_duplicate_after_pre_drain()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 85 checks passed.")
    print("(Also run: python scripts/verify_bugs_84.py)")


if __name__ == "__main__":
    main()
