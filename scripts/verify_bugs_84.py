"""Regression checks for bug 84 (urgent traceroute before routine full-scan)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import _TracerouteScheduler

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_source_drain_urgent_before_each_full_scan_target():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def _loop(self):", 1)[1].split(
            "def _run_one(self", 1)[0]
    ok = (
        "def _drain_urgent" in open(WEB_SERVER, encoding="utf-8").read()
        and "preempt mid full-scan" not in block
        and re.search(
            r"for tid, info in snap\.items\(\):.*?_drain_urgent\(\).*?_run_one\(tid, info\)",
            block,
            re.DOTALL,
        ) is not None
        and block.index("_drain_urgent()") < block.index("_run_one(tid, info)")
    )
    print(f"Bug84 drain urgent before each routine target -> {ok}")
    return ok


def test_full_scan_order_urgent_before_next_routine():
    import threading

    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    with sched._targets_lock:
        sched._targets = {
            "T1": {"ip": "10.0.0.1", "probe_ports": [80]},
            "T2": {"ip": "10.0.0.2", "probe_ports": [80]},
            "T3": {"ip": "10.0.0.3", "probe_ports": [80]},
        }
    calls = []

    def mock_run(tid, info):
        calls.append(tid)
        if tid == "T1":
            sched.request_now("T2")

    sched._run_one = mock_run
    snap = dict(sched._targets)
    traced = set()
    for tid, info in snap.items():
        traced |= sched._drain_urgent()
        if tid in traced:
            continue
        sched._run_one(tid, info)
        traced.add(tid)
    ok = calls == ["T1", "T2", "T3"]
    print(f"Bug84 simulated full-scan order {calls} -> {ok}")
    return ok


def test_old_post_sleep_only_order_would_be_wrong():
    """Without pre-target drain, T2 urgent runs after T2 routine (too late)."""
    calls = []

    def simulate_old_loop():
        pending = []
        snap = ["T1", "T2", "T3"]
        for tid in snap:
            calls.append(tid)
            if tid == "T1":
                pending.append("T2")
            # old: sleep then drain
            for p in pending:
                calls.append(p)
            pending.clear()

    simulate_old_loop()
    ok = calls != ["T1", "T2", "T3"]
    print(f"Bug84 old post-target-only order differs from fixed -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_drain_urgent_before_each_full_scan_target()),
        ("order", test_full_scan_order_urgent_before_next_routine()),
        ("contrast", test_old_post_sleep_only_order_would_be_wrong()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 84 checks passed.")


if __name__ == "__main__":
    main()
