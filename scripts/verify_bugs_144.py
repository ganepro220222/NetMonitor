"""Regression: webhook duration / failure-reason labels (Bug 144)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def _fmt(event, extra, message="连接中断", status="red"):
    return AlertManager._format_webhook_text(
        "🔴", "网络监控告警", event, "电信DNS", "202.98.198.167",
        status, message, "2026-06-13 22:17:07", extra)


def test_alert_red_zero_duration():
    extra = {
        "incident": {
            "started_at": "2026-06-13 22:17:07",
            "duration_seconds": 0,
            "duration_text": "0 秒",
            "ping_type_label": "DNS",
            "failure_reason_text": "DNS 查询超时",
            "recovered": False,
        },
        "trace": {"summary": "未执行路径追踪（DNS 查询超时，与 traceroute 无直接对应）"},
    }
    text = _fmt("alert_red", extra)
    ok = (
        "故障开始：2026-06-13 22:17:07" in text
        and "已持续：0 秒" not in text
        and "失败原因：DNS 查询超时" in text
    )
    print(f"Bug144 alert_red skips 0-sec duration -> {ok}")
    return ok


def test_recovery_duration_label():
    extra = {
        "incident": {
            "started_at": "2026-06-13 22:17:07",
            "recovered_at": "2026-06-13 22:17:25",
            "duration_seconds": 18,
            "duration_text": "18 秒",
            "ping_type_label": "DNS",
            "failure_reason_text": "DNS 查询超时",
            "recovered": True,
        },
        "trace": {"summary": "未执行路径追踪（DNS 查询超时，与 traceroute 无直接对应）"},
    }
    text = _fmt("recovery", extra, message="连接已恢复正常", status="green")
    ok = (
        "故障历时：18 秒" in text
        and "已持续：18 秒" not in text
        and "故障原因：DNS 查询超时" in text
        and "失败原因：" not in text
        and "恢复时间：2026-06-13 22:17:25" in text
    )
    print(f"Bug144 recovery uses 故障历时/故障原因 -> {ok}")
    return ok


def test_reminder_keeps_ongoing_label():
    extra = {
        "incident": {
            "started_at": "2026-06-13 22:17:07",
            "duration_seconds": 300,
            "duration_text": "5 分钟",
            "reminder_count": 2,
            "failure_reason_text": "DNS 查询超时",
            "recovered": False,
        },
        "trace": {},
    }
    text = _fmt("alert_reminder", extra, message="连接仍未恢复")
    ok = "已持续：5 分钟" in text and "失败原因：DNS 查询超时" in text
    print(f"Bug144 reminder keeps 已持续/失败原因 -> {ok}")
    return ok


def test_alert_red_with_real_duration():
    extra = {
        "incident": {
            "started_at": "2026-06-13 22:17:07",
            "duration_seconds": 3,
            "duration_text": "3 秒",
            "failure_reason_text": "DNS 查询超时",
            "recovered": False,
        },
        "trace": {},
    }
    text = _fmt("alert_red", extra)
    ok = "已持续：3 秒" in text and "开始时间：" not in text
    print(f"Bug144 alert_red shows duration when >=1s -> {ok}")
    return ok


def main():
    results = [
        test_alert_red_zero_duration(),
        test_recovery_duration_label(),
        test_reminder_keeps_ongoing_label(),
        test_alert_red_with_real_duration(),
    ]
    if not all(results):
        print("FAILED")
        sys.exit(1)
    print("All bug 144 checks passed.")


if __name__ == "__main__":
    main()
