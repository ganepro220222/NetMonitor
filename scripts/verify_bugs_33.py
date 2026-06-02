"""Regression checks for bug 33 (red partial recovery, parameterized K/O/R)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import TargetMonitor, PingResult

BASE_CFG = {
    "window_size": 10,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _cfg(**overrides):
    c = dict(BASE_CFG)
    c.update(overrides)
    return c


def _snap(mon):
    return {
        "loss": mon._consecutive_loss,
        "recovery_counter": mon._recovery_counter,
        "pending_natural": mon._pending_natural,
        "status": mon._status,
        "category": mon._last_category,
    }


def _run(cfg, initial, probes):
    mon = TargetMonitor("t", "1.2.3.4", cfg, lambda *a, **k: None,
                        initial_status=initial)
    out = []
    for success, latency in probes:
        r = PingResult(success=success, latency_ms=latency if success else None)
        mon._compute_state(r)
        row = _snap(mon)
        row["success"] = success
        out.append(row)
    return out


def _alternating_pattern(k, cycles=3):
    """Success/fail alternation: max consecutive success is always 1 (< K for K>1)."""
    probes = []
    for _ in range(cycles):
        for _ in range(k - 1):
            probes.append((True, 10))
            probes.append((False, None))
        probes.append((True, 10))
        probes.append((False, None))
    return probes


def test_red_first_success_goes_orange():
    k = BASE_CFG["recovery_count"]
    seq = _run(_cfg(), "red", [(True, 10)])
    ok = seq[0]["status"] == "orange" and seq[0]["recovery_counter"] == 1
    print(f"Bug33 K={k} red→ok: {seq[0]} -> {ok}")
    return ok


def test_red_k1_direct_green():
    seq = _run(_cfg(recovery_count=1), "red", [(True, 10)])
    ok = seq[0]["status"] == "green" and seq[0]["category"] == "ok"
    print(f"Bug33 K=1 red→green: {seq[0]} -> {ok}")
    return ok


def test_red_k3_three_success_green():
    k = 3
    seq = _run(_cfg(recovery_count=k), "red", [(True, 10)] * k)
    ok = seq[-1]["status"] == "green"
    print(f"Bug33 K={k} red→{k}×ok: last={seq[-1]} -> {ok}")
    return ok


def test_intermittent_stays_orange_k5():
    k = BASE_CFG["recovery_count"]
    burst = k - 1
    pattern = [(True, 10)] * burst + [(False, None)]
    seq = []
    mon = TargetMonitor("t", "1.2.3.4", _cfg(), lambda *a, **k: None,
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
    print(f"Bug33 K={k} burst={burst}+fail loop: seen={statuses} -> {ok}")
    return ok


def test_alternating_stays_orange_k5():
    k = BASE_CFG["recovery_count"]
    seq = _run(_cfg(), "red", _alternating_pattern(k, cycles=4))
    statuses = {r["status"] for r in seq}
    ok = statuses == {"orange"}
    print(f"Bug33 K={k} alternating: seen={statuses} n={len(seq)} -> {ok}")
    return ok


def test_orange_intermittent_stays_orange():
    k = BASE_CFG["recovery_count"]
    seq = _run(_cfg(), "orange",
               [(True, 10)] * 2 + [(False, None)] + [(True, 10)] * 2)
    ok = all(r["status"] == "orange" for r in seq)
    last = seq[-1]
    ok = ok and last["recovery_counter"] == 2
    print(f"Bug33 orange 2+fail+2: last={last} -> {ok}")
    return ok


def test_orange_k_success_green():
    k = BASE_CFG["recovery_count"]
    seq = _run(_cfg(), "orange", [(True, 10)] * k)
    ok = seq[-1]["status"] == "green"
    print(f"Bug33 orange→{k}×ok: last={seq[-1]} -> {ok}")
    return ok


def test_orange_loss_red_back_to_red():
    r = BASE_CFG["consecutive_loss_red"]
    seq = _run(_cfg(), "orange", [(False, None)] * r)
    ok = seq[-1]["status"] == "red"
    print(f"Bug33 orange→{r}×fail: last={seq[-1]} -> {ok}")
    return ok


def test_red_k_success_green():
    k = BASE_CFG["recovery_count"]
    seq = _run(_cfg(), "red", [(True, 10)] * k)
    ok = seq[-1]["status"] == "green"
    print(f"Bug33 red→{k}×ok: last={seq[-1]} -> {ok}")
    return ok


def _run_sub(script):
    r = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), script)],
        capture_output=True, text=True)
    return r.returncode == 0


def main():
    results = [
        ("K=5 red→orange", test_red_first_success_goes_orange()),
        ("K=1 red→green", test_red_k1_direct_green()),
        ("K=3 red→green", test_red_k3_three_success_green()),
        ("K=5 intermittent", test_intermittent_stays_orange_k5()),
        ("K=5 alternating", test_alternating_stays_orange_k5()),
        ("orange intermittent", test_orange_intermittent_stays_orange()),
        ("orange→green", test_orange_k_success_green()),
        ("orange→red", test_orange_loss_red_back_to_red()),
        ("red→green", test_red_k_success_green()),
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
