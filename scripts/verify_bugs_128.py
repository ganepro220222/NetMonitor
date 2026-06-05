"""Regression checks for bug 128 (HTTP status_code not stale on timeout)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor, PingResult, TargetMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")

_CFG = {
    "window_size": 10,
    "consecutive_loss_orange": 1,
    "consecutive_loss_red": 5,
    "recovery_count": 1,
    "latency_warn_ms": 2000,
    "consecutive_lat_orange": 3,
}


def test_timeout_after_status_500_no_stale_code():
    mon = HTTPMonitor(
        "h1", "example.com", _CFG, lambda s: None, initial_status="green")
    s1 = mon._compute_state(PingResult(
        success=False, latency_ms=123.0, status_code=500,
        failure_reason="status_500"))
    s2 = mon._compute_state(PingResult(
        success=False, latency_ms=None, status_code=None,
        failure_reason="recv_timeout"))
    ok = (
        s1.status_code == 500
        and s1.failure_reason == "status_500"
        and s1.response_latency_ms == 123.0
        and s2.failure_reason == "recv_timeout"
        and s2.status_code is None
        and s2.response_latency_ms is None
    )
    print(f"Bug128 recv_timeout after 500 clears status_code -> {ok}")
    return ok


def test_keyword_ok_not_stale_on_timeout():
    mon = HTTPMonitor("h2", "example.com", _CFG, lambda s: None,
                      initial_status="green")
    mon._compute_state(PingResult(
        success=False, latency_ms=50.0, status_code=200,
        failure_reason="keyword_not_found", keyword_ok=False))
    s2 = mon._compute_state(PingResult(
        success=False, latency_ms=None, status_code=None,
        failure_reason="recv_timeout", keyword_ok=None))
    ok = s2.keyword_ok is None
    print(f"Bug128 recv_timeout after keyword fail clears keyword_ok -> {ok}")
    return ok


def test_status_500_still_has_code_and_response_latency():
    mon = TargetMonitor("t", "1.2.3.4", _CFG, lambda s: None,
                        initial_status="green")
    state = mon._compute_state(PingResult(
        success=False, latency_ms=88.0, status_code=500,
        failure_reason="status_500"))
    ok = (
        state.status_code == 500
        and state.response_latency_ms == 88.0
        and state.failure_reason == "status_500"
    )
    print(f"Bug128 status_500 keeps this-probe code + response_latency -> {ok}")
    return ok


def test_source_uses_latest_not_last_cache():
    with open(PING_ENGINE, encoding="utf-8") as f:
        src = f.read()
    ret = src.split("return TargetState(", 1)[1].split("probe_success", 1)[0]
    ok = (
        "status_code      = latest.status_code" in ret
        and "keyword_ok       = latest.keyword_ok" in ret
        and "status_code      = self._last_status_code" not in ret
        and "keyword_ok       = self._last_keyword_ok" not in ret
    )
    print(f"Bug128 TargetState uses latest probe fields -> {ok}")
    return ok


def main():
    results = [
        ("stale_code", test_timeout_after_status_500_no_stale_code()),
        ("keyword", test_keyword_ok_not_stale_on_timeout()),
        ("status_500", test_status_500_still_has_code_and_response_latency()),
        ("source", test_source_uses_latest_not_last_cache()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 128 checks passed.")


if __name__ == "__main__":
    main()
