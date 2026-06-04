"""Regression checks for bug 122 (failed probe measured latency preserved)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import PingResult, TargetMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")
WEB = os.path.join(ROOT, "src", "web_server.py")
IP_CARD = os.path.join(ROOT, "src", "ui", "ip_card.py")

CFG = {
    "window_size": 10,
    "ping_interval": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def test_failed_probe_with_latency():
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status="green")
    state = mon._compute_state(
        PingResult(success=False, latency_ms=123.4,
                   failure_reason="status_500", status_code=500))
    ok = (
        state.latency_ms is None
        and state.response_latency_ms == 123.4
        and state.probe_success is False
        and state.failure_reason == "status_500"
    )
    print(f"Bug122 failed probe keeps response_latency_ms=123.4 -> {ok}")
    return ok


def test_success_probe_no_response_latency():
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status="green")
    state = mon._compute_state(
        PingResult(success=True, latency_ms=50.0))
    ok = (
        state.latency_ms == 50.0
        and state.response_latency_ms is None
        and state.probe_success is True
    )
    print(f"Bug122 success probe latency_ms only -> {ok}")
    return ok


def test_source_wiring():
    with open(PING_ENGINE, encoding="utf-8") as f:
        pe = f.read()
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        mw = f.read()
    with open(WEB, encoding="utf-8") as f:
        web = f.read()
    with open(IP_CARD, encoding="utf-8") as f:
        card = f.read()
    ok = (
        "response_latency_ms" in pe
        and "_resp_lat" in pe
        and "state.response_latency_ms" in mw
        and "_persist_lat = state.latency_ms" in mw
        and "response_latency_ms=state.response_latency_ms" in mw
        and "function measuredFailMs" in web
        and "response_latency_ms" in web
        and "response_latency_ms" in card
    )
    print(f"Bug122 source wired across engine/UI/web -> {ok}")
    return ok


def main():
    results = [
        ("fail_lat", test_failed_probe_with_latency()),
        ("success", test_success_probe_no_response_latency()),
        ("source", test_source_wiring()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 122 checks passed.")


if __name__ == "__main__":
    main()
