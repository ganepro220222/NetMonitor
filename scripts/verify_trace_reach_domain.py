"""Regression: domain targets must match traceroute last_ok IP (reach detection)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.trace_policy import (
    summarize_for_alert,
    trace_reached_target,
    format_path_ok_while_probe_fails,
)
from src.traceroute_summary import summarize_break


def _hops_to_target(last_ip: str, n: int = 20):
    hops = []
    for i in range(1, n):
        hops.append({"hop": i, "ip": f"10.0.0.{i}", "status": "ok"})
    hops.append({"hop": n, "ip": last_ip, "status": "ok"})
    return hops


def test_domain_reaches_resolved_ip():
    hops = _hops_to_target("47.108.166.19", 20)
    base = summarize_break(hops)
    ok = trace_reached_target(
        base,
        "www.gzstv.com",
        resolve_ip="47.108.166.19",
    )
    print(f"trace_reached_target domain+resolve_ip -> {ok}")
    return ok


def test_domain_alert_summary_not_firewall_branch():
    hops = _hops_to_target("47.108.166.19", 20)
    summary = summarize_for_alert(
        hops,
        ping_type="icmp",
        failure_reason="timeout",
        target_ip="www.gzstv.com",
        resolve_ip="47.108.166.19",
    )
    text = summary.get("text") or ""
    ok = (
        summary.get("reached") is True
        and "路由追踪可达目标" in text
        and "建议查防火墙" not in text
        and "未确认到达" not in text
    )
    print(f"domain alert summary branch -> {ok} ({text[:80]}...)")
    return ok


def test_ip_literal_still_works():
    hops = _hops_to_target("192.0.2.1", 6)
    base = summarize_break(hops)
    ok = trace_reached_target(base, "192.0.2.1")
    text = format_path_ok_while_probe_fails(
        base, ping_type="icmp", failure_reason="timeout",
        target_ip="192.0.2.1",
    )
    ok = ok and "路由追踪可达目标" in text
    print(f"ip literal reach -> {ok}")
    return ok


def test_real_break_still_reports_unreached():
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": None, "status": "break", "error": "timed out"},
    ]
    summary = summarize_for_alert(
        hops,
        ping_type="icmp",
        failure_reason="timeout",
        target_ip="203.0.113.9",
    )
    text = summary.get("text") or ""
    ok = (
        summary.get("reached") is False
        and summary.get("break_at") is not None
        and "中断" in text
    )
    print(f"real break unreached -> {ok}")
    return ok


def main():
    results = [
        ("reach", test_domain_reaches_resolved_ip()),
        ("summary", test_domain_alert_summary_not_firewall_branch()),
        ("ip", test_ip_literal_still_works()),
        ("break", test_real_break_still_reports_unreached()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All trace reach domain checks passed.")


if __name__ == "__main__":
    main()
