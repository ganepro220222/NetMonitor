"""Regression checks for Phase 4.3 aggregate webhook reminders."""
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


def _open_red(a, tid, label, ip):
    a.on_status_change(tid, label, ip, "red")
    if tid in a._webhook_incidents:
        a._webhook_incidents[tid].last_reminder_at = 0


def _install_push_capture(a, calls):
    """Mock _push_webhook; resolve aggregate rebuild() like deferred delivery."""
    def _capture(**kw):
        entry = {k: v for k, v in kw.items() if k != "rebuild"}
        rebuild = kw.get("rebuild")
        if rebuild is not None:
            rebuilt = rebuild()
            if rebuilt is None:
                return
            extra, message, target = rebuilt
            entry["extra"] = extra
            entry["message"] = message
            entry["target"] = target
        calls.append(entry)
    a._push_webhook = _capture


def test_config_aggregate_defaults():
    s = DEFAULT_CONFIG["settings"]
    ok = (
        s.get("webhook_reminder_aggregate_enabled") is False
        and s.get("webhook_reminder_aggregate_threshold") == 3
    )
    print(f"Bug133 aggregate config defaults -> {ok}")
    return ok


def test_sanitize_aggregate_threshold():
    out = _sanitize_settings({
        "webhook_reminder_aggregate_threshold": 1,
        "webhook_reminder_aggregate_enabled": True,
    })
    ok = (
        out.get("webhook_reminder_aggregate_threshold") == 2
        and out.get("webhook_reminder_aggregate_enabled") is True
    )
    print(f"Bug133 sanitize threshold min 2 -> {ok}")
    return ok


def test_two_red_individual_reminders():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    _open_red(a, "t1", "A", "10.0.0.1")
    _open_red(a, "t2", "B", "10.0.0.2")
    calls = []
    _install_push_capture(a, calls)
    a._tick_webhook_reminders()
    ind = [c for c in calls if c["event"] == "alert_reminder"]
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    ok = len(ind) == 2 and len(agg) == 0
    print(f"Bug133 2 red -> individual x2 -> {ok}")
    return ok


def test_three_red_aggregate_reminder():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    _open_red(a, "t1", "A", "10.0.0.1")
    _open_red(a, "t2", "B", "10.0.0.2")
    _open_red(a, "t3", "C", "10.0.0.3")
    calls = []
    _install_push_capture(a, calls)
    a._tick_webhook_reminders()
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    ind = [c for c in calls if c["event"] == "alert_reminder"]
    ok = len(agg) == 1 and len(ind) == 0 and agg[0]["extra"]["aggregate"]["count"] == 3
    print(f"Bug133 3 red -> aggregate x1 -> {ok}")
    return ok


def test_aggregate_updates_last_reminder_no_immediate_repeat():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    for i in range(3):
        _open_red(a, f"t{i}", f"N{i}", f"10.0.0.{i+1}")
    calls = []
    _install_push_capture(a, calls)
    a._tick_webhook_reminders()
    first = len(calls)
    a._tick_webhook_reminders()
    second = len(calls)
    ok = first == 1 and second == 1
    print(f"Bug133 aggregate no immediate repeat -> {ok} ({first}/{second})")
    return ok


def test_recovery_reduces_aggregate_count():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    for i in range(3):
        _open_red(a, f"t{i}", f"N{i}", f"10.0.0.{i+1}")
    a.on_status_change("t2", "B", "10.0.0.2", "green")
    for tid in ("t0", "t2"):
        if tid in a._webhook_incidents:
            a._webhook_incidents[tid].last_reminder_at = 0
    for tid in ("t0", "t1"):
        if tid in a._webhook_incidents:
            a._webhook_incidents[tid].last_reminder_at = 0
    calls = []
    _install_push_capture(a, calls)
    a._tick_webhook_reminders()
    ind = [c for c in calls if c["event"] == "alert_reminder"]
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    ok = len(ind) == 2 and len(agg) == 0
    print(f"Bug133 after 1 recovery 2 red -> individual -> {ok}")
    return ok


def test_aggregate_lists_longest_first():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=2,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    now = time.time()
    _open_red(a, "short", "Short", "1.1.1.1")
    _open_red(a, "long", "Long", "2.2.2.2")
    a._webhook_incidents["short"].started_at = now - 60
    a._webhook_incidents["long"].started_at = now - 3600
    calls = []
    _install_push_capture(a, calls)
    a._tick_webhook_reminders()
    nodes = calls[0]["extra"]["aggregate"]["nodes"]
    ok = nodes[0]["target"] == "Long" and nodes[1]["target"] == "Short"
    print(f"Bug133 aggregate sorted by duration -> {ok}")
    return ok


def main():
    results = [
        ("defaults", test_config_aggregate_defaults()),
        ("sanitize", test_sanitize_aggregate_threshold()),
        ("two_ind", test_two_red_individual_reminders()),
        ("three_agg", test_three_red_aggregate_reminder()),
        ("no_repeat", test_aggregate_updates_last_reminder_no_immediate_repeat()),
        ("recovery_split", test_recovery_reduces_aggregate_count()),
        ("sort_dur", test_aggregate_lists_longest_first()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 133 checks passed.")


if __name__ == "__main__":
    main()
