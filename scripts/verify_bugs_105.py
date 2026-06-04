"""Regression checks for bug 105 (HTTP default latency_warn must not inherit global 150ms)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor, PingEngine, PingResult, TargetMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")

_GLOBAL = {
    "window_size": 10,
    "ping_interval": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 150,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _merge_http_settings(custom=None):
    merged = dict(_GLOBAL)
    if custom:
        merged.update(custom)
    PingEngine._strip_global_latency_warn_for_http(
        merged, "https", custom)
    return merged


def _orange_after_n(mon, latency_ms, n=3):
    state = None
    for _ in range(n):
        state = mon._compute_state(
            PingResult(success=True, latency_ms=latency_ms))
    return state


def test_default_http_uses_2000_not_150():
    cfg = _merge_http_settings()
    ok_missing = "latency_warn_ms" not in cfg
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    state = _orange_after_n(mon, 500)
    no_orange = state.status != "orange"
    print(f"Bug105 default https 500ms x3 not orange -> {ok_missing and no_orange}")
    return ok_missing and no_orange


def test_high_lat_still_oranges_at_2000():
    cfg = _merge_http_settings()
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    state = _orange_after_n(mon, 2500)
    ok = state.status == "orange" and state.alert_category == "performance"
    print(f"Bug105 2500ms x3 performance orange -> {ok}")
    return ok


def test_per_target_override_kept():
    cfg = _merge_http_settings({"latency_warn_ms": 300})
    ok_key = cfg.get("latency_warn_ms") == 300
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    state = _orange_after_n(mon, 350)
    ok = ok_key and state.status == "orange" and state.alert_category == "performance"
    print(f"Bug105 per-target 300ms override -> {ok}")
    return ok


def test_icmp_still_uses_global_150():
    merged = dict(_GLOBAL)
    PingEngine._strip_global_latency_warn_for_http(merged, "icmp", None)
    ok = merged.get("latency_warn_ms") == 150
    mon = TargetMonitor("t", "8.8.8.8", merged, lambda s: None)
    state = _orange_after_n(mon, 200)
    ok = ok and state.status == "orange" and state.alert_category == "performance"
    print(f"Bug105 icmp still 150ms threshold -> {ok}")
    return ok


def test_add_target_source_strip():
    with open(PING_ENGINE, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_strip_global_latency_warn_for_http" in src
        and "merged.pop(\"latency_warn_ms\", None)" in src
        and "isinstance(m, HTTPMonitor)" in src
    )
    print(f"Bug105 source helpers present -> {ok}")
    return ok


def main():
    results = [
        ("default_2000", test_default_http_uses_2000_not_150()),
        ("high_lat_orange", test_high_lat_still_oranges_at_2000()),
        ("per_target", test_per_target_override_kept()),
        ("icmp_150", test_icmp_still_uses_global_150()),
        ("source", test_add_target_source_strip()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 105 checks passed.")


if __name__ == "__main__":
    main()
