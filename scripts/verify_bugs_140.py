"""Regression checks for diagnostic trace refresh default (Bug 140)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_DIALOG = os.path.join(ROOT, "src", "ui", "settings_dialog.py")
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")
_HOOK_URL = "http://127.0.0.1:9/hook"


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


def test_default_is_15():
    ok = DEFAULT_CONFIG["settings"]["webhook_trace_refresh_interval_min"] == 15
    print(f"Bug140 default trace refresh 15 min -> {ok}")
    return ok


def test_fallback_is_15():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    ok = 'webhook_trace_refresh_interval_min", 15)' in src
    print(f"Bug140 alert_manager fallback 15 -> {ok}")
    return ok


def test_settings_help_text():
    with open(SETTINGS_DIALOG, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "诊断刷新间隔" in src
        and "默认 15" in src
        and "重复提醒后可" in src
        and "宜 2–3 倍间隔" in src
        and "关闭仍推 Webhook" in src
        and "不带路径、不发诊断更新" in src
    )
    print(f"Bug140 settings dialog help text -> {ok}")
    return ok


def test_refresh_throttle_at_15min():
    """15-min gate blocks a second refresh request inside the window."""
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=5,
        webhook_url=_HOOK_URL,
        webhook_include_trace=True,
        webhook_trace_update_enabled=True,
        webhook_trace_refresh_interval_min=15,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    calls = []
    a._trace_request_callback = lambda tid: calls.append(tid)
    now = time.time()
    a._maybe_request_trace_refresh(
        {"tid": "t1", "label": "GW", "ip": "10.0.0.1",
         "started_at": now - 60, "current_status": "red",
         "reminder_count": 1, "last_trace_at": 0,
         "last_trace_summary": None, "last_trace_signature": None},
        now)
    first = len(calls)
    a._maybe_request_trace_refresh(
        {"tid": "t1", "label": "GW", "ip": "10.0.0.1",
         "started_at": now - 60, "current_status": "red",
         "reminder_count": 1, "last_trace_at": 0,
         "last_trace_summary": None, "last_trace_signature": None},
        now + 60)
    ok = first == 1 and len(calls) == 1
    print(f"Bug140 15-min throttle blocks early re-request -> {ok}")
    return ok


def main():
    results = [
        ("default", test_default_is_15()),
        ("fallback", test_fallback_is_15()),
        ("help", test_settings_help_text()),
        ("throttle", test_refresh_throttle_at_15min()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 140 checks passed.")


if __name__ == "__main__":
    main()
