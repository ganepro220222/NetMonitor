"""Regression checks for webhook reminder + traceroute diagnostic webhooks."""
import ast
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG, _sanitize_settings
from src.traceroute_summary import summarize_break, trace_signature

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")
SETTINGS_DIALOG = os.path.join(ROOT, "src", "ui", "settings_dialog.py")
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


def test_config_defaults():
    s = DEFAULT_CONFIG["settings"]
    keys = (
        "webhook_reminder_enabled",
        "webhook_reminder_interval_min",
        "webhook_reminder_max_count",
        "webhook_include_trace",
        "webhook_trace_update_enabled",
        "webhook_trace_refresh_interval_min",
        "webhook_trace_change_only",
    )
    ok = all(k in s for k in keys)
    print(f"Bug131 config defaults present -> {ok}")
    return ok


def test_sanitize_reminder_interval():
    out = _sanitize_settings({
        "webhook_reminder_interval_min": 99999,
        "webhook_reminder_max_count": -5,
        "webhook_trace_refresh_interval_min": 1,
        "webhook_reminder_enabled": True,
    })
    ok = (
        out.get("webhook_reminder_interval_min") == 1440
        and out.get("webhook_reminder_max_count") == 0
        and out.get("webhook_trace_refresh_interval_min") == 5
        and out.get("webhook_reminder_enabled") is True
    )
    print(f"Bug131 sanitize reminder ranges -> {ok}")
    return ok


def test_settings_dialog_has_keys():
    with open(SETTINGS_DIALOG, encoding="utf-8") as f:
        src = f.read()
    ok = all(k in src for k in (
        "webhook_reminder_enabled",
        "webhook_trace_change_only",
    ))
    print(f"Bug131 settings dialog fields -> {ok}")
    return ok


def test_red_creates_incident():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    ok = "t1" in a._webhook_incidents
    print(f"Bug131 red creates incident -> {ok}")
    return ok


def test_reminder_not_before_interval():
    a = _alerter(webhook_reminder_enabled=True,
                 webhook_reminder_interval_min=30)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = not any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug131 no reminder before interval -> {ok}")
    return ok


def test_reminder_after_interval():
    a = _alerter(webhook_reminder_enabled=True,
                 webhook_reminder_interval_min=1,
                 webhook_url=_HOOK_URL)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = 0
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug131 reminder after interval -> {ok}")
    return ok


def test_recovery_closes_incident():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    ok = "t1" not in a._webhook_incidents
    print(f"Bug131 recovery closes incident -> {ok}")
    return ok


def test_pause_drops_incident():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_target_paused("t1")
    ok = "t1" not in a._webhook_incidents
    print(f"Bug131 pause drops incident -> {ok}")
    return ok


def test_delete_drops_incident():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_target_removed("t1")
    ok = "t1" not in a._webhook_incidents
    print(f"Bug131 delete drops incident -> {ok}")
    return ok


def test_trace_after_recovery_ignored():
    a = _alerter(webhook_trace_update_enabled=True)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    hops = [{"hop": 1, "status": "ok", "ip": "1.1.1.1"}]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops,
    })
    ok = not any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug131 trace after recovery ignored -> {ok}")
    return ok


def test_first_trace_sends_diagnostic_update():
    a = _alerter(webhook_trace_update_enabled=True,
                 webhook_trace_change_only=True)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    hops = [
        {"hop": 1, "status": "ok", "ip": "10.0.0.1"},
        {"hop": 2, "status": "break", "ip": None},
    ]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops, "route_changed": False,
    })
    ok = any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug131 first trace diagnostic_update -> {ok}")
    return ok


def test_same_signature_no_repeat_when_change_only():
    a = _alerter(webhook_trace_update_enabled=True,
                 webhook_trace_change_only=True)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    hops = [
        {"hop": 1, "status": "ok", "ip": "10.0.0.1"},
        {"hop": 2, "status": "break", "ip": None},
    ]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops,
    })
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops,
    })
    ok = not any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug131 same signature no repeat -> {ok}")
    return ok


def test_changed_signature_sends_update():
    a = _alerter(webhook_trace_update_enabled=True,
                 webhook_trace_change_only=True)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(),
        "hops": [{"hop": 1, "status": "ok", "ip": "10.0.0.1"}],
    })
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    hops2 = [
        {"hop": 1, "status": "ok", "ip": "10.0.0.1"},
        {"hop": 2, "status": "break", "ip": None},
    ]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops2,
    })
    ok = any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug131 changed signature sends update -> {ok}")
    return ok


def test_trace_refresh_requested_on_reminder():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_url=_HOOK_URL,
        webhook_include_trace=True,
        webhook_trace_update_enabled=True,
        webhook_trace_refresh_interval_min=5,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = 0
    requested = []
    a.set_trace_request_callback(lambda tid: requested.append(tid))
    a._tick_webhook_reminders()
    ok = requested == ["t1"]
    print(f"Bug131 reminder requests trace refresh -> {ok}")
    return ok


def _attr_names(node) -> set:
    return {a.attr for a in ast.walk(node) if isinstance(a, ast.Attribute)}


def test_scheduler_callback_outside_lock():
    """The traceroute result callback must run AFTER `with self._lock:` is
    released — a blocking callback under the cache lock would stall every
    scheduler commit.  Verify structurally (web_server can't be imported
    without Flask) that the `if committed and self._result_callback:` block
    is a TOP-LEVEL statement of _run_one (not nested inside the lock block),
    comes after the lock block, and spawns a daemon thread for the callback.
    """
    with open(WEB_SERVER, encoding="utf-8") as f:
        tree = ast.parse(f.read())

    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_run_one"), None)
    if fn is None:
        print("Bug131 scheduler callback async -> False (no _run_one)")
        return False

    lock_idx = cb_idx = None
    for i, stmt in enumerate(fn.body):          # direct children only
        if isinstance(stmt, ast.With) and any(
                "_lock" in _attr_names(item.context_expr) for item in stmt.items):
            if lock_idx is None:
                lock_idx = i
        if isinstance(stmt, ast.If) and "_result_callback" in _attr_names(stmt.test):
            cb_idx = i

    ok = lock_idx is not None and cb_idx is not None and cb_idx > lock_idx
    if ok:
        cb_if = fn.body[cb_idx]
        names = {n.id for n in ast.walk(cb_if) if isinstance(n, ast.Name)}
        ok = "threading" in names and "Thread" in _attr_names(cb_if)
    print(f"Bug131 scheduler callback async (top-level, after lock) -> {ok}")
    return ok


def test_summarize_break_shared():
    hops = [
        {"hop": 1, "status": "ok", "ip": "10.0.0.1"},
        {"hop": 2, "status": "break", "ip": None},
    ]
    s = summarize_break(hops)
    sig = trace_signature(s)
    ok = s.get("reached") is False and sig[3] == 2
    print(f"Bug131 summarize_break + signature -> {ok}")
    return ok


def test_recovery_extra_has_duration():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    inc.started_at = time.time() - 120
    closed = a._close_webhook_incident("t1")
    extra = a._build_recovery_extra(closed)
    ok = (
        extra is not None
        and extra["incident"]["recovered"] is True
        and extra["incident"]["duration_seconds"] >= 120
    )
    print(f"Bug131 recovery extra duration -> {ok}")
    return ok


def test_sound_disabled_webhook_reminder_still_works():
    a = _alerter(enabled=False, webhook_reminder_enabled=True,
                 webhook_reminder_interval_min=1,
                 webhook_url=_HOOK_URL)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = 0
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug131 sound off still reminders -> {ok}")
    return ok


def main():
    results = [
        ("defaults", test_config_defaults()),
        ("sanitize", test_sanitize_reminder_interval()),
        ("settings_ui", test_settings_dialog_has_keys()),
        ("red_incident", test_red_creates_incident()),
        ("no_early_reminder", test_reminder_not_before_interval()),
        ("reminder_due", test_reminder_after_interval()),
        ("recovery_close", test_recovery_closes_incident()),
        ("pause_drop", test_pause_drops_incident()),
        ("delete_drop", test_delete_drops_incident()),
        ("trace_after_green", test_trace_after_recovery_ignored()),
        ("first_diag", test_first_trace_sends_diagnostic_update()),
        ("no_dup_sig", test_same_signature_no_repeat_when_change_only()),
        ("changed_sig", test_changed_signature_sends_update()),
        ("trace_refresh", test_trace_refresh_requested_on_reminder()),
        ("cb_async", test_scheduler_callback_outside_lock()),
        ("summary", test_summarize_break_shared()),
        ("recovery_extra", test_recovery_extra_has_duration()),
        ("sound_off", test_sound_disabled_webhook_reminder_still_works()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 131 checks passed.")


if __name__ == "__main__":
    main()
