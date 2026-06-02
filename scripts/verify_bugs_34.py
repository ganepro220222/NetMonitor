"""Regression checks for bug 34 (red recovery respects natural state/category)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import TargetMonitor, PingResult

LAT_CFG = {
    "window_size": 10,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 100,
    "consecutive_lat_orange": 1,
    "recovery_count": 5,
}


def _cfg(**overrides):
    c = dict(LAT_CFG)
    c.update(overrides)
    return c


def _one(cfg, initial, latency_ms):
    mon = TargetMonitor("t", "1.2.3.4", cfg, lambda *a, **k: None,
                        initial_status=initial)
    r = PingResult(success=True, latency_ms=latency_ms)
    mon._compute_state(r)
    return {
        "status": mon._status,
        "category": mon._last_category,
        "high_lat": mon._consecutive_high_lat,
        "recovery_counter": mon._recovery_counter,
    }


def _run(cfg, initial, probes):
    mon = TargetMonitor("t", "1.2.3.4", cfg, lambda *a, **k: None,
                        initial_status=initial)
    out = []
    for success, latency in probes:
        r = PingResult(success=success, latency_ms=latency if success else None)
        mon._compute_state(r)
        out.append({
            "status": mon._status,
            "category": mon._last_category,
            "recovery_counter": mon._recovery_counter,
        })
    return out


def test_k1_red_high_lat_orange_performance():
    row = _one(_cfg(recovery_count=1), "red", 500)
    ok = row["status"] == "orange" and row["category"] == "performance"
    print(f"Bug34 K=1 high-lat: {row} -> {ok}")
    return ok


def test_k5_red_high_lat_orange_performance():
    row = _one(_cfg(recovery_count=5), "red", 500)
    ok = (row["status"] == "orange" and row["category"] == "performance"
          and row["recovery_counter"] == 0)
    print(f"Bug34 K=5 high-lat: {row} -> {ok}")
    return ok


def test_k1_red_healthy_green():
    row = _one(_cfg(recovery_count=1), "red", 10)
    ok = row["status"] == "green" and row["category"] == "ok"
    print(f"Bug34 K=1 healthy: {row} -> {ok}")
    return ok


def test_k5_red_healthy_partial_availability():
    row = _one(_cfg(recovery_count=5), "red", 10)
    ok = (row["status"] == "orange" and row["category"] == "availability"
          and row["recovery_counter"] == 1)
    print(f"Bug34 K=5 healthy: {row} -> {ok}")
    return ok


def test_orange_stays_performance_on_high_lat():
    cfg = _cfg(recovery_count=5)
    seq = _run(cfg, "orange", [(True, 500)] * 3)
    ok = all(r["status"] == "orange" and r["category"] == "performance" for r in seq)
    print(f"Bug34 orange high-lat hold: last={seq[-1]} -> {ok}")
    return ok


def test_orange_healthy_k_to_green():
    k = 5
    seq = _run(_cfg(recovery_count=k), "orange", [(True, 10)] * k)
    ok = seq[-1]["status"] == "green" and seq[-1]["category"] == "ok"
    print(f"Bug34 orange→green: last={seq[-1]} -> {ok}")
    return ok


def test_orange_fail_r_to_red():
    r = LAT_CFG["consecutive_loss_red"]
    seq = _run(_cfg(), "orange", [(False, None)] * r)
    ok = seq[-1]["status"] == "red" and seq[-1]["category"] == "availability"
    print(f"Bug34 orange→red: last={seq[-1]} -> {ok}")
    return ok


def test_red_healthy_interrupt_stays_orange():
    seq = _run(_cfg(recovery_count=5), "red",
               [(True, 10), (True, 10), (False, None), (True, 10)])
    last = seq[-1]
    ok = last["status"] == "orange" and last["recovery_counter"] == 1
    print(f"Bug34 red healthy interrupt: last={last} -> {ok}")
    return ok


def test_red_healthy_k_green():
    k = 5
    seq = _run(_cfg(recovery_count=k), "red", [(True, 10)] * k)
    ok = seq[-1]["status"] == "green" and seq[-1]["category"] == "ok"
    print(f"Bug34 red→green healthy: last={seq[-1]} -> {ok}")
    return ok


def _run_sub(script):
    r = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), script)],
        capture_output=True, text=True)
    if r.returncode != 0 and r.stderr:
        print(r.stderr[-2000:])
    return r.returncode == 0


def main():
    results = [
        ("K=1 high-lat", test_k1_red_high_lat_orange_performance()),
        ("K=5 high-lat", test_k5_red_high_lat_orange_performance()),
        ("K=1 healthy", test_k1_red_healthy_green()),
        ("K=5 healthy partial", test_k5_red_healthy_partial_availability()),
        ("orange perf hold", test_orange_stays_performance_on_high_lat()),
        ("orange→green", test_orange_healthy_k_to_green()),
        ("orange→red", test_orange_fail_r_to_red()),
        ("red interrupt", test_red_healthy_interrupt_stays_orange()),
        ("red→green", test_red_healthy_k_green()),
        ("Bug31", _run_sub("verify_bugs_31.py")),
        ("Bug32", _run_sub("verify_bugs_32.py")),
        ("Bug33", _run_sub("verify_bugs_33.py")),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 34 checks passed.")


if __name__ == "__main__":
    main()
