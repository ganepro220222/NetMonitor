"""Regression: urgent tracert spawns immediately in parallel (Bug 84 evolution)."""
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


def test_source_spawn_urgent_not_queued():
    with open(WEB_SERVER, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def _spawn_urgent" in src
        and "def _drain_urgent" not in src
        and "self._spawn_urgent(tid)" in src
        and "Urgent traces spawn immediately" in src
    )
    print(f"Bug84 urgent spawn API (no queue drain) -> {ok}")
    return ok


def test_request_now_spawns_parallel_threads():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    with sched._targets_lock:
        sched._targets = {
            "T1": {"ip": "10.0.0.1", "probe_ports": [80]},
            "T2": {"ip": "10.0.0.2", "probe_ports": [80]},
            "T3": {"ip": "10.0.0.3", "probe_ports": [80]},
        }
    started = threading.Event()
    active = threading.Lock()
    count = [0]
    max_parallel = [0]

    def mock_run(tid, info, *, urgent=False):
        with active:
            count[0] += 1
            max_parallel[0] = max(max_parallel[0], count[0])
        started.set()
        time.sleep(0.15)
        with active:
            count[0] -= 1

    sched._run_one = mock_run
    sched.request_now("T1")
    sched.request_now("T2")
    sched.request_now("T3")
    started.wait(timeout=2.0)
    deadline = time.time() + 1.0
    while time.time() < deadline and max_parallel[0] < 2:
        time.sleep(0.02)
    ok = max_parallel[0] >= 2
    print(f"Bug84 parallel urgent threads max_parallel={max_parallel[0]} -> {ok}")
    return ok


def test_same_tid_deduped_while_inflight():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    with sched._targets_lock:
        sched._targets = {"T1": {"ip": "10.0.0.1", "probe_ports": [80]}}
    calls = []
    gate = threading.Event()

    def mock_run(tid, info, *, urgent=False):
        calls.append("start")
        gate.wait(timeout=2.0)
        calls.append("end")

    sched._run_one = mock_run
    ok1 = sched._spawn_urgent("T1")
    ok2 = sched._spawn_urgent("T1")
    time.sleep(0.05)
    gate.set()
    time.sleep(0.1)
    ok = ok1 and not ok2 and calls.count("start") == 1
    print(f"Bug84 same-tid inflight dedupe calls={calls} ok1={ok1} ok2={ok2} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_spawn_urgent_not_queued()),
        ("parallel", test_request_now_spawns_parallel_threads()),
        ("dedupe", test_same_tid_deduped_while_inflight()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 84 checks passed.")


if __name__ == "__main__":
    main()
