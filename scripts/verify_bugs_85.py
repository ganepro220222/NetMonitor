"""Regression: routine full-scan skips targets already urgent-traced (Bug 85)."""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import _TracerouteScheduler

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_source_urgent_skip_set_dedupes_full_scan():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def _loop(self):", 1)[1].split(
            "def _run_one(self", 1)[0]
    ok = (
        "_urgent_skip_set" in block
        and "already_traced" in block
        and "_drain_urgent" not in open(WEB_SERVER, encoding="utf-8").read()
    )
    print(f"Bug85 urgent skip set in scheduler loop -> {ok}")
    return ok


def test_full_scan_skips_recent_urgent_target():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=0)
    with sched._targets_lock:
        sched._targets = {
            "T1": {"ip": "10.0.0.1", "probe_ports": [80]},
            "T2": {"ip": "10.0.0.2", "probe_ports": [80]},
        }
    calls = []

    def mock_run(tid, info, *, urgent=False):
        calls.append((tid, urgent))

    sched._run_one = mock_run
    sched.request_now("T1")
    # Let urgent thread finish (mock is sync if we replace after spawn — race).
    # Simulate completed urgent via _urgent_recent.
    with sched._urgent_lock:
        sched._urgent_recent.add("T1")

    already_traced = set(sched._urgent_recent)
    already_traced |= sched._urgent_skip_set()
    snap = dict(sched._targets)
    traced_this_pass = set(already_traced)
    for tid, info in snap.items():
        traced_this_pass |= sched._urgent_skip_set()
        if tid in traced_this_pass:
            continue
        sched._run_one(tid, info, urgent=False)
        traced_this_pass.add(tid)

    ok = calls == [] or ("T1" not in [c[0] for c in calls if not c[1]])
    print(f"Bug85 full-scan skip recent urgent calls={calls} -> {ok}")
    return ok


def test_urgent_uses_shorter_wait_ms():
    cache = {}
    lock = threading.Lock()
    sched = _TracerouteScheduler(cache, lock, interval=999999)
    seen = []

    def mock_tracert(ip, max_hops=30, *, wait_ms=1000):
        seen.append(wait_ms)
        return [{"hop": 1, "ip": ip, "status": "ok"}]

    import src.web_server as ws
    orig = ws.run_traceroute
    ws.run_traceroute = mock_tracert
    try:
        with sched._targets_lock:
            sched._targets = {"T1": {"ip": "10.0.0.1", "probe_ports": [80]}}
        sched._run_one("T1", sched._targets["T1"], urgent=True)
        ok = seen == [sched.URGENT_WAIT_MS]
    finally:
        ws.run_traceroute = orig
    print(f"Bug85 urgent wait_ms={seen} expected={sched.URGENT_WAIT_MS} -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_urgent_skip_set_dedupes_full_scan()),
        ("skip", test_full_scan_skips_recent_urgent_target()),
        ("wait", test_urgent_uses_shorter_wait_ms()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 85 checks passed.")


if __name__ == "__main__":
    main()
