"""Regression: webhook incident probe fields update on orange->red (Bug 148)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_orange_back_to_red_updates_failure_reason():
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="http", failure_reason="status_500")
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="http", failure_reason="connection_refused")
    inc = a._webhook_incidents["t1"]
    snap = a._snapshot_incident(inc)
    extra = a._build_reminder_extra(snap)
    inc_fields = extra["incident"]
    text = AlertManager._format_webhook_text(
        "🔴", "告警仍未恢复", "alert_reminder",
        "GW", "10.0.0.1", "red", "连接仍未恢复", "2026-01-01 00:00:00",
        extra)
    ok = (
        inc.failure_reason == "connection_refused"
        and inc_fields.get("failure_reason_text") == "TCP 连接被拒绝"
        and "TCP 连接被拒绝" in text
        and "HTTP 状态 500" not in text
    )
    print(f"Bug148 orange->red updates failure_reason -> {ok}")
    return ok


def test_probe_change_resets_stale_trace_skip():
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="http", failure_reason="status_500")
    inc = a._webhook_incidents["t1"]
    ok_skip = inc.trace_applicable is False and inc.last_trace_summary is not None
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="icmp", failure_reason="no_reply")
    inc = a._webhook_incidents["t1"]
    ok = (
        ok_skip
        and inc.trace_applicable is True
        and inc.last_trace_summary is None
        and inc.last_trace_signature is None
    )
    print(f"Bug148 probe change clears stale trace summary -> {ok}")
    return ok


def main():
    results = [
        ("failure_reason", test_orange_back_to_red_updates_failure_reason()),
        ("trace_reset", test_probe_change_resets_stale_trace_skip()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 148 checks passed.")


if __name__ == "__main__":
    main()
