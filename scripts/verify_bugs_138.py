"""Regression checks for webhook reminder interval bounds (Bug 138).

Default 5 min, range 3–120 min.  Min=3 must not break reminder/aggregate logic.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG, _sanitize_settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


def test_default_interval():
    ok = DEFAULT_CONFIG["settings"]["webhook_reminder_interval_min"] == 5
    print(f"Bug138 default interval 5 min -> {ok}")
    return ok


def test_sanitize_bounds():
    out = _sanitize_settings({
        "webhook_reminder_interval_min": 2,
        "webhook_trace_refresh_interval_min": 99999,
    })
    ok = (
        out.get("webhook_reminder_interval_min") == 3
        and out.get("webhook_trace_refresh_interval_min") == 120
    )
    print(f"Bug138 sanitize clamp 2->3, 99999->120 -> {ok}")
    return ok


def test_reminder_at_min_interval():
    """interval_min=3 (UI floor) fires reminder when due — no extra gates."""
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=3,
        webhook_url=_HOOK_URL,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = time.time() - 3 * 60 - 5
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug138 reminder fires at 3 min interval -> {ok}")
    return ok


def test_reminder_before_min_interval():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=3,
        webhook_url=_HOOK_URL,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = not any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug138 no reminder before 3 min interval -> {ok}")
    return ok


def test_aggregate_throttle_respects_min_interval():
    """Aggregate throttle uses same interval_sec — min=3 must not bypass it."""
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=3,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=2,
        webhook_url=_HOOK_URL,
    )
    a.on_status_change("t0", "N0", "10.0.0.1", "red")
    a.on_status_change("t1", "N1", "10.0.0.2", "red")
    now = time.time()
    for tid in ("t0", "t1"):
        a._webhook_incidents[tid].last_reminder_at = now - 3 * 60 - 5
    a._last_aggregate_reminder_at = now - 3 * 60 - 5
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    first = sum(1 for c in calls if c["event"] == "alert_reminder_aggregate")
    for tid in ("t0", "t1"):
        a._webhook_incidents[tid].last_reminder_at = 0
    a._tick_webhook_reminders()
    second = (
        sum(1 for c in calls if c["event"] == "alert_reminder_aggregate") - first
    )
    ok = first == 1 and second == 0
    print(f"Bug138 aggregate throttle at 3 min -> {ok} (first={first} throttled={second})")
    return ok


def test_settings_dialog_range():
    path = os.path.join(ROOT, "src", "ui", "settings_dialog.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    ok = (
        '"webhook_reminder_interval_min", "重复提醒间隔 (分钟)", "int", 3, 120'
        in src
        and '"webhook_trace_refresh_interval_min", "诊断刷新间隔 (分钟)", "int", 5, 120'
        in src
    )
    print(f"Bug138 settings dialog ranges -> {ok}")
    return ok


def main():
    results = [
        ("default", test_default_interval()),
        ("sanitize", test_sanitize_bounds()),
        ("fires_3", test_reminder_at_min_interval()),
        ("no_early", test_reminder_before_min_interval()),
        ("agg_3", test_aggregate_throttle_respects_min_interval()),
        ("ui", test_settings_dialog_range()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 138 checks passed.")


if __name__ == "__main__":
    main()
