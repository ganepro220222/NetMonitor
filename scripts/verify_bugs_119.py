"""Regression checks for bug 119.

HTTP latency-warn threshold becomes a dedicated global setting
(http_latency_warn_ms, default 2000), separate from the ICMP/TCP/DNS
latency_warn_ms (150).  TCP's dead DEFAULT_WARN_LAT=200 constant is
removed so it transparently shares the global 150 with ICMP/DNS.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import (
    HTTPMonitor, TCPMonitor, TargetMonitor, PingEngine, PingResult)
from src.host_validation import effective_latency_warn_ms_hint

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")
CONFIG_MGR = os.path.join(ROOT, "src", "config_manager.py")
SETTINGS_DIALOG = os.path.join(ROOT, "src", "ui", "settings_dialog.py")

_GLOBAL = {
    "window_size": 10,
    "ping_interval": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 150,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _merge(ping_type, custom=None, extra_global=None):
    merged = dict(_GLOBAL)
    if extra_global:
        merged.update(extra_global)
    if custom:
        merged.update(custom)
    PingEngine._strip_global_latency_warn_for_http(merged, ping_type, custom)
    return merged


def _orange_after_n(mon, latency_ms, n=3):
    state = None
    for _ in range(n):
        state = mon._compute_state(
            PingResult(success=True, latency_ms=latency_ms))
    return state


def test_config_default_2000():
    with open(CONFIG_MGR, encoding="utf-8") as f:
        ok = '"http_latency_warn_ms": 2000' in f.read()
    print(f"Bug119 config default http_latency_warn_ms=2000 -> {ok}")
    return ok


def test_http_uses_global_http_warn():
    # Global http_latency_warn_ms=500 -> HTTP oranges at 600ms (not silent to 2000).
    cfg = _merge("https", extra_global={"http_latency_warn_ms": 500})
    ok_key = cfg.get("latency_warn_ms") == 500
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    state = _orange_after_n(mon, 600)
    ok = ok_key and state.status == "orange" and state.alert_category == "performance"
    print(f"Bug119 HTTP uses global http_latency_warn_ms=500 -> {ok}")
    return ok


def test_http_falls_back_2000_when_absent():
    # No global http key -> drop latency_warn_ms -> HTTPMonitor.DEFAULT_WARN_LAT (2000).
    cfg = _merge("https")
    ok_missing = "latency_warn_ms" not in cfg
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    not_orange = _orange_after_n(mon, 600).status != "orange"
    orange_hi = _orange_after_n(mon, 2500).status == "orange"
    ok = ok_missing and not_orange and orange_hi
    print(f"Bug119 HTTP falls back to 2000 when global absent -> {ok}")
    return ok


def test_per_target_override_still_wins():
    cfg = _merge("https", custom={"latency_warn_ms": 300},
                 extra_global={"http_latency_warn_ms": 500})
    ok_key = cfg.get("latency_warn_ms") == 300
    mon = HTTPMonitor("t", "example.com", cfg, lambda s: None)
    state = _orange_after_n(mon, 350)
    ok = ok_key and state.status == "orange"
    print(f"Bug119 per-target override beats global http -> {ok}")
    return ok


def test_tcp_shares_global_150():
    # TCP must NOT carry its own DEFAULT_WARN_LAT; it inherits the base 150.
    no_override = "DEFAULT_WARN_LAT" not in TCPMonitor.__dict__
    same_as_base = (TCPMonitor.DEFAULT_WARN_LAT
                    == TargetMonitor.DEFAULT_WARN_LAT == 150)
    cfg = _merge("tcp")                 # tcp keeps global latency_warn_ms=150
    ok_key = cfg.get("latency_warn_ms") == 150
    mon = TCPMonitor("t", "1.2.3.4", cfg, lambda s: None)
    state = _orange_after_n(mon, 200)
    ok = (no_override and same_as_base and ok_key
          and state.status == "orange" and state.alert_category == "performance")
    print(f"Bug119 TCP shares global 150, dead 200 removed -> {ok}")
    return ok


def test_hint_http_reads_global():
    h_http = effective_latency_warn_ms_hint("https", {"http_latency_warn_ms": 888})
    h_icmp = effective_latency_warn_ms_hint("icmp", {"latency_warn_ms": 150})
    ok = h_http == "888" and h_icmp == "150"
    print(f"Bug119 hint http reads global={h_http}, icmp=150 -> {ok}")
    return ok


def test_source_wiring():
    with open(PING_ENGINE, encoding="utf-8") as f:
        eng = f.read()
    with open(SETTINGS_DIALOG, encoding="utf-8") as f:
        dlg = f.read()
    ok = (
        eng.count("http_latency_warn_ms") >= 3      # strip + update_global + update_thresholds
        and "DEFAULT_WARN_LAT = 200\n" not in eng   # TCP dead code gone (not HTTP's =2000)
        and "http_latency_warn_ms" in dlg           # settings panel exposes it
    )
    print(f"Bug119 source wired (>=3 engine sites, TCP 200 gone, panel field) -> {ok}")
    return ok


def main():
    results = [
        ("config_default", test_config_default_2000()),
        ("http_global", test_http_uses_global_http_warn()),
        ("http_fallback", test_http_falls_back_2000_when_absent()),
        ("per_target", test_per_target_override_still_wins()),
        ("tcp_150", test_tcp_shares_global_150()),
        ("hint", test_hint_http_reads_global()),
        ("source", test_source_wiring()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 119 checks passed.")


if __name__ == "__main__":
    main()
