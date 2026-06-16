"""Regression: diagnostic_update webhook includes probe context (Bug 146)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_diagnostic_update_has_probe_fields():
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(type("C", (), {"get_setting": lambda _s, k: {
        "webhook_trace_update_enabled": True,
        "webhook_trace_change_only": True,
        "webhook_include_trace": True,
    }.get(k)})())
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="icmp", failure_reason="no_reply")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a.on_traceroute_result({
        "tid": "t1", "ip": "10.0.0.1", "ts": time.time(),
        "hops": [{"hop": 1, "status": "ok", "ip": "10.0.0.1"}],
    })
    ok = bool(calls) and calls[0]["event"] == "diagnostic_update"
    inc = calls[0]["extra"]["incident"] if ok else {}
    ok = ok and inc.get("ping_type_label") == "ICMP"
    ok = ok and inc.get("failure_reason_text") == "ICMP 无响应"
    text = AlertManager._format_webhook_text(
        "🧭", "故障诊断更新", "diagnostic_update",
        "GW", "10.0.0.1", "red", "msg", "2026-01-01 00:00:00",
        calls[0]["extra"])
    ok = ok and "探测类型：ICMP" in text and "失败原因：ICMP 无响应" in text
    print(f"Bug146 diagnostic_update probe fields -> {ok}")
    return ok


def main():
    if not test_diagnostic_update_has_probe_fields():
        sys.exit(1)
    print("All bug 146 checks passed.")


if __name__ == "__main__":
    main()
