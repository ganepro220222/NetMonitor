"""Regression checks for bug A (bad HTTP port freeze) and bug B (Web uptime drift)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor, PingResult
from src.web_server import WebServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")

_HTTP_CFG = {
    "window_size": 10,
    "ping_interval": 0.05,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 2000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
    "http_url": "http://example.com:99999/",
}


def test_bad_port_returns_ping_result_not_raise():
    mon = HTTPMonitor("t", "example.com", dict(_HTTP_CFG), lambda s: None)
    try:
        result = mon._do_ping()
    except ValueError:
        print("BugA _do_ping raised ValueError -> False")
        return False
    ok = (
        isinstance(result, PingResult)
        and result.success is False
        and result.failure_reason == "invalid_url"
    )
    print(f"BugA bad port PingResult invalid_url -> {ok}")
    return ok


def test_bad_port_run_loop_emits_state():
    states = []

    def on_change(st):
        states.append(st)

    mon = HTTPMonitor("t", "example.com", dict(_HTTP_CFG), on_change)
    mon.start()
    time.sleep(0.35)
    mon.stop()
    mon.join(timeout=2.0)
    ok = len(states) >= 1
    print(f"BugA run_loop callbacks={len(states)} -> {ok}")
    return ok


def test_web_meta_sync_payload_and_server_stats():
    ws = WebServer(port=18765)
    ws._running = True
    ws.update_target(
        "t1", "n", "1.2.3.4", "green",
        latency_ms=None, jitter_ms=None, loss_rate=0.0,
        probe_success=True, is_probe_result=False)
    payload = ws._targets.get("t1", {})
    srv_stats = ws._stats.get("t1")
    ok = (
        payload.get("is_probe_result") is False
        and srv_stats is None
    )
    print(f"BugB payload flag + server skip: keys={list(payload.keys())} "
          f"stats={srv_stats} -> {ok}")
    return ok


def test_accumstat_skips_meta_sync():
    with open(WEB_SERVER, encoding="utf-8") as f:
        js = f.read().split("function accumStat(t){", 1)[1].split(
            "// Apply server-provided cumulative stats", 1)[0]
    ok = "is_probe_result===false" in js.replace(" ", "")
    print(f"BugB accumStat guards meta-sync -> {ok}")
    return ok


def test_source_http_port_invalid_url_guard():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _do_single_request", 1)[1].split(
            "def _do_ping", 1)[0]
    ok = (
        "except ValueError" in block
        and "explicit_port" in block
        and 'failure_reason="invalid_url"' in block
        or "failure_reason=\"invalid_url\"" in block
    )
    print(f"BugA source port ValueError -> invalid_url -> {ok}")
    return ok


def test_source_update_target_exports_flag():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def update_target(self", 1)[1].split(
            "def remove_target", 1)[0]
    ok = "is_probe_result" in block and "is_probe_result" in block.split("data = ", 1)[1]
    print(f"BugB source update_target payload flag -> {ok}")
    return ok


def test_gitignore_ignores_pycache():
    path = os.path.join(ROOT, ".gitignore")
    ok = os.path.isfile(path)
    if ok:
        with open(path, encoding="utf-8") as f:
            body = f.read()
        ok = "__pycache__/" in body and "*.pyc" in body
    print(f"Bug hygiene .gitignore present -> {ok}")
    return ok


def main():
    results = [
        ("bad_port_result", test_bad_port_returns_ping_result_not_raise()),
        ("bad_port_callback", test_bad_port_run_loop_emits_state()),
        ("web_meta", test_web_meta_sync_payload_and_server_stats()),
        ("accumstat", test_accumstat_skips_meta_sync()),
        ("source_http", test_source_http_port_invalid_url_guard()),
        ("source_web", test_source_update_target_exports_flag()),
        ("gitignore", test_gitignore_ignores_pycache()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 96 (A/B + gitignore) checks passed.")


if __name__ == "__main__":
    main()
