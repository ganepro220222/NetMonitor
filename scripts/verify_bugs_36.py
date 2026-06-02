"""Regression checks for bug 36 (reject inf/nan ping_interval)."""
import math
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import (
    MIN_PING_INTERVAL_S,
    is_valid_ping_interval,
    normalize_ping_interval,
)
from src.ping_engine import PingResult, TargetMonitor


def test_normalize_non_finite():
    cases = [
        ("inf", 1.0),
        ("-inf", 1.0),
        ("nan", 1.0),
        (0.005, MIN_PING_INTERVAL_S),
        (0.05, 0.05),
        (1.0, 1.0),
    ]
    ok = True
    for raw, expected in cases:
        got = normalize_ping_interval(raw)
        if got != expected:
            print(f"  normalize({raw!r}) -> {got}, expected {expected}")
            ok = False
    print(f"Bug36 normalize: -> {ok}")
    return ok


def test_dialog_validation():
    cases = [
        (float("inf"), False),
        (float("nan"), False),
        (0.05, True),
        (0.049, False),
        (1.0, True),
    ]
    ok = all(is_valid_ping_interval(iv) == expect for iv, expect in cases)
    print(f"Bug36 dialog-like: {cases} -> {ok}")
    return ok


class _FastMonitor(TargetMonitor):
    def _do_ping(self) -> PingResult:
        return PingResult(success=True, latency_ms=1.0)


def test_thread_survives_inf_interval():
    calls = []
    cfg = {
        "window_size": 10,
        "ping_interval": float("inf"),
        "consecutive_loss_orange": 3,
        "consecutive_loss_red": 5,
        "latency_warn_ms": 1000,
        "consecutive_lat_orange": 3,
        "recovery_count": 5,
    }
    mon = _FastMonitor("t", "127.0.0.1", cfg, lambda s: calls.append(1))
    mon.start()
    time.sleep(2.5)
    alive = mon._thread.is_alive()
    n = len(calls)
    mon.stop()
    mon._thread.join(timeout=3.0)
    ok = alive and n >= 2
    print(f"Bug36 thread inf interval: alive={alive} callbacks={n} -> {ok}")
    return ok


def main():
    results = [
        ("normalize", test_normalize_non_finite()),
        ("dialog bounds", test_dialog_validation()),
        ("thread survives", test_thread_survives_inf_interval()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 36 checks passed.")


if __name__ == "__main__":
    main()
