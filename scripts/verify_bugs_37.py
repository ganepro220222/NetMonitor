"""Regression checks for bug 37 (reject huge finite ping_interval)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import (
    MAX_PING_INTERVAL_S,
    is_valid_ping_interval,
    normalize_ping_interval,
)
from src.ping_engine import PingResult, TargetMonitor


def test_bounds_validation():
    cases = [
        (120, True),
        (121, False),
        (1e20, False),
        (1e300, False),
        (0.05, True),
    ]
    ok = all(is_valid_ping_interval(v) == expect for v, expect in cases)
    for v, expect in cases:
        print(f"  valid({v!r})={is_valid_ping_interval(v)} expect={expect}")
    print(f"Bug37 is_valid: -> {ok}")
    return ok


def test_normalize_upper_clamp():
    cases = [
        (120, 120.0),
        (121, MAX_PING_INTERVAL_S),
        (1e300, MAX_PING_INTERVAL_S),
        (0.005, 0.05),
    ]
    ok = True
    for raw, expected in cases:
        got = normalize_ping_interval(raw)
        if got != expected:
            print(f"  normalize({raw!r}) -> {got}, expected {expected}")
            ok = False
    print(f"Bug37 normalize: -> {ok}")
    return ok


class _FastMonitor(TargetMonitor):
    def _do_ping(self) -> PingResult:
        return PingResult(success=True, latency_ms=1.0)


def test_thread_survives_huge_finite_interval():
    calls = []
    cfg = {
        "window_size": 10,
        "ping_interval": 1e300,
        "consecutive_loss_orange": 3,
        "consecutive_loss_red": 5,
        "latency_warn_ms": 1000,
        "consecutive_lat_orange": 3,
        "recovery_count": 5,
    }
    mon = _FastMonitor("t", "127.0.0.1", cfg, lambda s: calls.append(1))
    mon.start()
    time.sleep(0.5)
    alive = mon._thread.is_alive()
    n = len(calls)
    mon.stop()
    mon._thread.join(timeout=3.0)
    ok = alive and n >= 1 and mon._thread.is_alive() is False
    print(f"Bug37 thread 1e300: alive_after_wait={alive} callbacks={n} "
          f"joined={not mon._thread.is_alive()} -> {ok}")
    return ok


def main():
    results = [
        ("bounds", test_bounds_validation()),
        ("normalize", test_normalize_upper_clamp()),
        ("thread survives", test_thread_survives_huge_finite_interval()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 37 checks passed.")


if __name__ == "__main__":
    main()
