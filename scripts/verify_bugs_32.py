"""Regression checks for bug 32 (failure resets recovery debounce)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import TargetMonitor, PingResult

RECOVERY_CFG = {
    "window_size": 10,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _run(cfg, initial, probes):
    mon = TargetMonitor("t", "1.2.3.4", cfg, lambda *a, **k: None,
                        initial_status=initial)
    out = []
    for success, latency in probes:
        r = PingResult(success=success, latency_ms=latency)
        st = mon._compute_state(r)
        out.append({
            "success": success,
            "loss": mon._consecutive_loss,
            "recovery_counter": mon._recovery_counter,
            "pending_natural": mon._pending_natural,
            "status": st.status,
            "category": st.alert_category,
        })
    return out


def test_red_recovery_interrupted_by_failure():
    seq = _run(RECOVERY_CFG, "red", [
        (True, 10), (True, 10), (False, None), (True, 10), (True, 10),
    ])
    for i, row in enumerate(seq, 1):
        print(f"  {i} {row}")
    last = seq[-1]
    # After Bug33 partial recovery, successes leave red for orange;
    # failure still resets the green-recovery counter (Bug32).
    ok = last["status"] == "orange" and last["recovery_counter"] == 2
    print(f"Bug32 red interrupt: status={last['status']} rc="
          f"{last['recovery_counter']} -> {ok}")
    return ok


def test_red_five_consecutive_success_recovers():
    seq = _run(RECOVERY_CFG, "red", [(True, 10)] * 5)
    last = seq[-1]
    ok = last["status"] == "green" and last["category"] == "ok"
    print(f"Bug32 red recover: status={last['status']} -> {ok}")
    return ok


def test_orange_recovery_interrupted():
    seq = _run(RECOVERY_CFG, "orange", [
        (True, 10), (False, None), (True, 10),
    ])
    last = seq[-1]
    ok = last["status"] == "orange" and last["recovery_counter"] == 1
    print(f"Bug32 orange: status={last['status']} rc={last['recovery_counter']} "
          f"-> {ok}")
    return ok


def test_red_single_failure_stays_red():
    seq = _run(RECOVERY_CFG, "red", [(False, None)])
    last = seq[-1]
    ok = last["status"] == "red" and last["recovery_counter"] == 0
    print(f"Bug32 single fail: status={last['status']} rc={last['recovery_counter']} "
          f"-> {ok}")
    return ok


def test_bug31_still_passes():
    import subprocess
    r = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__),
                                      "verify_bugs_31.py")],
        capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"Bug31 reg: exit={r.returncode} -> {ok}")
    return ok


def main():
    results = [
        test_red_recovery_interrupted_by_failure(),
        test_red_five_consecutive_success_recovers(),
        test_orange_recovery_interrupted(),
        test_red_single_failure_stays_red(),
        test_bug31_still_passes(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 32 checks passed.")


if __name__ == "__main__":
    main()
