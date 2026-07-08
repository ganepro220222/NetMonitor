"""Regression: urgent tracert bounded concurrency pool (Batch 1)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import _TracerouteScheduler

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_source_bounded_pool():
    with open(WEB_SERVER, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "URGENT_MAX_CONCURRENT = 8" in src
        and "def _drain_urgent_pending" in src
        and "_urgent_sem = threading.BoundedSemaphore" in src
        and "_urgent_pending" in src
    )
    print(f"urgent pool source markers -> {ok}")
    return ok


def test_pool_caps_concurrency_and_drains_pending():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    n_targets = 12
    with sched._targets_lock:
        sched._targets = {
            f"T{i}": {"ip": f"10.0.0.{i}", "probe_ports": [80]}
            for i in range(1, n_targets + 1)
        }

    active = threading.Lock()
    count = [0]
    max_parallel = [0]
    completed = threading.Event()
    done_count = [0]

    def mock_run(tid, info, *, urgent=False):
        with active:
            count[0] += 1
            max_parallel[0] = max(max_parallel[0], count[0])
        time.sleep(0.12)
        with active:
            count[0] -= 1
            done_count[0] += 1
            if done_count[0] >= n_targets:
                completed.set()

    sched._run_one = mock_run
    for i in range(1, n_targets + 1):
        sched.request_now(f"T{i}")

    completed.wait(timeout=8.0)
    ok = (
        max_parallel[0] <= sched.URGENT_MAX_CONCURRENT
        and done_count[0] == n_targets
    )
    print(
        f"urgent pool cap max_parallel={max_parallel[0]} "
        f"limit={sched.URGENT_MAX_CONCURRENT} done={done_count[0]} -> {ok}"
    )
    return ok


def test_pending_dedupes_same_tid():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    with sched._targets_lock:
        sched._targets = {"T1": {"ip": "10.0.0.1", "probe_ports": [80]}}

    gate = threading.Event()
    starts = []

    def mock_run(tid, info, *, urgent=False):
        starts.append(tid)
        gate.wait(timeout=2.0)

    sched._run_one = mock_run
    # Fill the pool so T1 must queue.
    for i in range(sched.URGENT_MAX_CONCURRENT):
        with sched._targets_lock:
            sched._targets[f"F{i}"] = {"ip": f"10.0.0.{i}", "probe_ports": [80]}
        sched.request_now(f"F{i}")
    time.sleep(0.05)
    ok1 = sched._spawn_urgent("T1")
    ok2 = sched._spawn_urgent("T1")
    gate.set()
    time.sleep(0.2)
    ok = ok1 and not ok2 and starts.count("T1") == 1
    print(f"pending same-tid dedupe ok1={ok1} ok2={ok2} starts={starts.count('T1')} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_bounded_pool()),
        ("cap", test_pool_caps_concurrency_and_drains_pending()),
        ("dedupe", test_pending_dedupes_same_tid()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All urgent trace pool checks passed.")


if __name__ == "__main__":
    main()
