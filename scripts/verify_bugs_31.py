"""Regression checks for bug 31 (probe failure resets high-lat streak)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import TargetMonitor, PingResult

CFG = {
    "consecutive_loss_orange": 10,
    "consecutive_loss_red": 20,
    "latency_warn_ms": 100,
    "consecutive_lat_orange": 3,
    "recovery_count": 1,
    "window_size": 10,
}


def _run(probes):
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status="green")
    out = []
    for success, latency in probes:
        r = PingResult(success=success, latency_ms=latency)
        st = mon._compute_state(r)
        out.append({
            "input_success": success,
            "latency": latency,
            "consecutive_high_lat": mon._consecutive_high_lat,
            "consecutive_loss": mon._consecutive_loss,
            "status": st.status,
            "category": st.alert_category,
        })
    return out


def test_failure_breaks_high_lat_streak():
    seq = _run([(True, 150), (True, 160), (False, None), (True, 170)])
    last = seq[-1]
    ok = (last["status"] == "green" and last["category"] == "ok"
          and last["consecutive_high_lat"] == 1)
    for i, row in enumerate(seq, 1):
        print(f"  {i} {row}")
    print(f"Bug31 break: status={last['status']} high_lat="
          f"{last['consecutive_high_lat']} -> {ok}")
    return ok


def test_three_high_lat_orange():
    seq = _run([(True, 150), (True, 160), (True, 170)])
    last = seq[-1]
    ok = last["status"] == "orange" and last["category"] == "performance"
    print(f"Bug31 three high: status={last['status']} cat={last['category']} -> {ok}")
    return ok


def test_low_lat_breaks_streak():
    seq = _run([(True, 150), (True, 160), (True, 50), (True, 170)])
    last = seq[-1]
    ok = (last["status"] == "green" and last["consecutive_high_lat"] == 1)
    print(f"Bug31 low break: status={last['status']} high_lat="
          f"{last['consecutive_high_lat']} -> {ok}")
    return ok


def test_failures_only_affect_loss():
    seq = _run([(False, None), (False, None), (False, None)])
    last = seq[-1]
    ok = (last["consecutive_loss"] == 3
          and last["consecutive_high_lat"] == 0
          and last["status"] == "green")
    print(f"Bug31 loss only: loss={last['consecutive_loss']} "
          f"high_lat={last['consecutive_high_lat']} status={last['status']} -> {ok}")
    return ok


def main():
    results = [
        test_failure_breaks_high_lat_streak(),
        test_three_high_lat_orange(),
        test_low_lat_breaks_streak(),
        test_failures_only_affect_loss(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 31 checks passed.")


if __name__ == "__main__":
    main()
