"""Regression checks for trace_policy (Bug 141).

Layer-aware traceroute gating: endpoint failures must not trigger misleading
path traces / webhook break summaries.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG
from src.trace_policy import (
    failure_layer,
    should_request_traceroute,
    summarize_for_alert,
    trace_skip_summary,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def _alerter(**cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_Cfg(**cfg_kw))
    return a


def test_icmp_network_layer():
    cases = [("icmp", "no_reply"), ("icmp", "timeout"), ("icmp", "error:x")]
    ok = all(failure_layer(pt, fr) == "network" for pt, fr in cases)
    ok = ok and all(should_request_traceroute(pt, fr) for pt, fr in cases)
    print(f"Bug141 ICMP network layer -> {ok}")
    return ok


def test_tcp_endpoint_skips_trace():
    cases = [
        ("tcp", "tcp_timeout"),
        ("tcp", "connection_refused"),
        ("tcp", "tcp_failed:reset"),
        ("tcp", "invalid_port"),
    ]
    ok = all(not should_request_traceroute(pt, fr) for pt, fr in cases)
    ok = ok and failure_layer("tcp", "invalid_port") == "config"
    print(f"Bug141 TCP endpoint skips trace -> {ok}")
    return ok


def test_http_endpoint_skips_trace():
    cases = [
        ("http", "http_timeout"),
        ("https", "status_503"),
        ("https", "tls_failed:cert"),
        ("http", "dns_failed:name"),
        ("http", "keyword_not_found"),
    ]
    ok = all(not should_request_traceroute(pt, fr) for pt, fr in cases)
    print(f"Bug141 HTTP/HTTPS endpoint skips trace -> {ok}")
    return ok


def test_dns_endpoint_skips_trace():
    cases = [
        ("dns", "dns_timeout"),
        ("dns", "nxdomain"),
        ("dns", "dns_hijack:1.2.3.4"),
        ("dns", "dns_no_domain"),
    ]
    ok = all(not should_request_traceroute(pt, fr) for pt, fr in cases)
    print(f"Bug141 DNS endpoint skips trace -> {ok}")
    return ok


def test_icmp_filtered_summary():
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": None, "status": "break"},
    ]
    tcp_checks = [{"port": 443, "success": True}]
    s = summarize_for_alert(
        hops, ping_type="tcp", failure_reason="no_reply",
        tcp_checks=tcp_checks)
    ok = ("过滤 ICMP" in s["text"] and s.get("break_at") is None)
    print(f"Bug141 ICMP filtered summary -> {ok}")
    return ok


def test_tcp_incident_skips_trace_fields():
    a = _alerter()
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="tcp", failure_reason="tcp_timeout")
    inc = a._webhook_incidents["t1"]
    ok = (
        not inc.trace_applicable
        and inc.last_trace_summary.get("skipped")
        and "未执行路径追踪" in inc.last_trace_summary["text"]
    )
    print(f"Bug141 TCP incident skip fields -> {ok}")
    return ok


def test_icmp_incident_allows_trace():
    a = _alerter()
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="icmp", failure_reason="no_reply")
    inc = a._webhook_incidents["t1"]
    ok = inc.trace_applicable and inc.last_trace_summary is None
    print(f"Bug141 ICMP incident allows trace -> {ok}")
    return ok


def test_traceroute_result_ignored_when_not_applicable():
    a = _alerter(webhook_url="http://127.0.0.1:9/hook")
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="tcp", failure_reason="connection_refused")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": 1.0, "hops": [{"hop": 1, "status": "break", "ip": "9.9.9.9"}],
        "route_changed": True,
        "tcp_checks": [],
    })
    ok = len(calls) == 0
    print(f"Bug141 ignore traceroute result when N/A -> {ok}")
    return ok


def test_refresh_blocked_for_endpoint_incident():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_include_trace=True,
        webhook_trace_update_enabled=True,
        webhook_trace_refresh_interval_min=15,
    )
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="http", failure_reason="status_500")
    requested = []
    a._trace_request_callback = lambda tid: requested.append(tid)
    a._maybe_request_trace_refresh(
        {"tid": "t1", "label": "GW", "ip": "10.0.0.1",
         "started_at": 0, "current_status": "red",
         "reminder_count": 1, "last_trace_at": 0,
         "last_trace_summary": {}, "last_trace_signature": None},
        999999.0)
    ok = len(requested) == 0
    print(f"Bug141 refresh blocked for endpoint -> {ok}")
    return ok


def test_wiring():
    with open(WEB_SERVER, encoding="utf-8") as f:
        ws = f.read()
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        am = f.read()
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        mw = f.read()
    ok = (
        "should_request_traceroute" in ws
        and "trace_applicable" in am
        and "ping_type=self._target_ping_types" in mw
        and "summarize_for_alert" in am
    )
    print(f"Bug141 wiring -> {ok}")
    return ok


def main():
    results = [
        ("icmp_net", test_icmp_network_layer()),
        ("tcp_skip", test_tcp_endpoint_skips_trace()),
        ("http_skip", test_http_endpoint_skips_trace()),
        ("dns_skip", test_dns_endpoint_skips_trace()),
        ("icmp_filt", test_icmp_filtered_summary()),
        ("tcp_inc", test_tcp_incident_skips_trace_fields()),
        ("icmp_inc", test_icmp_incident_allows_trace()),
        ("ignore_cb", test_traceroute_result_ignored_when_not_applicable()),
        ("no_refresh", test_refresh_blocked_for_endpoint_incident()),
        ("wire", test_wiring()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 141 checks passed.")


if __name__ == "__main__":
    main()
