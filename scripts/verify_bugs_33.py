"""Regression checks for bug 33 (red partial recovery to orange)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import TargetMonitor, PingResult

CFG = {
    "window_size": 10,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _snap(mon):
    return {
        "loss": mon._consecutive_loss,
        "recovery_counter": mon._recovery_counter,
        "pending_natural": mon._pending_natural,
        "status": mon._status,
        "category": mon._last_category,
    }


def _run(initial, probes):
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status=initial)
    out = []
    for success, latency in probes:
        r = PingResult(success=success, latency_ms=latency if success else None)
        mon._compute_state(r)
        row = _snap(mon)
        row["success"] = success
        out.append(row)
    return out


def test_red_first_success_goes_orange():
    seq = _run("red", [(True, 10)])
    ok = seq[0]["status"] == "orange" and seq[0]["recovery_counter"] == 1
    print(f"Bug33 red→ok: {seq[0]} -> {ok}")
    return ok


def test_intermittent_stays_orange():
    pattern = [(True, 10)] * 4 + [(False, None)]
    seq = []
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status="red")
    for _ in range(3):
        for success, lat in pattern:
            r = PingResult(success=success, latency_ms=lat if success else None)
            mon._compute_state(r)
            row = _snap(mon)
            row["success"] = success
            seq.append(row)
    statuses = {r["status"] for r in seq}
    ok = statuses == {"orange"}
    for i, row in enumerate(seq, 1):
        print(f"  {i} {'OK' if row['success'] else 'FAIL':4} {row}")
    print(f"Bug33 loop: seen={statuses} -> {ok}")
    return ok


def test_orange_five_success_green():
    seq = _run("orange", [(True, 10)] * 5)
    ok = seq[-1]["status"] == "green"
    print(f"Bug33 orange→green: last={seq[-1]} -> {ok}")
    return ok


def test_orange_loss_red_back_to_red():
    seq = _run("orange", [(False, None)] * 5)
    ok = seq[-1]["status"] == "red"
    print(f"Bug33 orange→red: last={seq[-1]} -> {ok}")
    return ok


def test_red_five_success_green():
    seq = _run("red", [(True, 10)] * 5)
    ok = seq[-1]["status"] == "green"
    print(f"Bug33 red→green: last={seq[-1]} -> {ok}")
    return ok


def _run_sub(script):
    r = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), script)],
        capture_output=True, text=True)
    return r.returncode == 0


def main():
    results = [
        ("red→orange", test_red_first_success_goes_orange()),
        ("intermittent", test_intermittent_stays_orange()),
        ("orange→green", test_orange_five_success_green()),
        ("orange→red", test_orange_loss_red_back_to_red()),
        ("red→green", test_red_five_success_green()),
        ("Bug31", _run_sub("verify_bugs_31.py")),
        ("Bug32", _run_sub("verify_bugs_32.py")),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 33 checks passed.")


if __name__ == "__main__":
    main()
