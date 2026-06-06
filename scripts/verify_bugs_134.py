"""Regression checks for webhook hygiene fixes (A–F observations)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager, WebhookIncident
from src.config_manager import DEFAULT_CONFIG, _sanitize_settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")


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


def test_web_ack_ui_wired():
    with open(WEB_SERVER, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "ackTarget" in src
        and "/api/alerts/ack" in src
        and "buildAckBtnHtml" in src
        and "data-ack-tid" in src
    )
    print(f"Bug134 Web ACK button + API call -> {ok}")
    return ok


def test_webhook_events_removed():
    ok = (
        "webhook_events" not in DEFAULT_CONFIG["settings"]
        and "webhook_events" not in _sanitize_settings(
            {"webhook_events": ["red", "green"]})
    )
    print(f"Bug134 webhook_events legacy dropped -> {ok}")
    return ok


def test_empty_url_no_reminder_count_burn():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_max_count=2,
        webhook_url="",
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = 0
    a._tick_webhook_reminders()
    inc = a._webhook_incidents["t1"]
    ok = inc.reminder_count == 0 and inc.last_reminder_at == 0
    print(f"Bug134 empty URL no counter burn -> {ok}")
    return ok


def test_include_trace_off_blocks_diagnostic():
    a = _alerter(
        webhook_trace_update_enabled=True,
        webhook_include_trace=False,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    hops = [{"hop": 1, "status": "ok", "ip": "10.0.0.1"}]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops,
    })
    ok = not any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug134 include_trace off blocks diagnostic -> {ok}")
    return ok


def test_no_dead_last_trace_update_field():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    ok = "last_trace_update_sent_at" not in src
    print(f"Bug134 dead field removed -> {ok}")
    return ok


def test_run_one_docstring_mentions_label():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def _run_one", 1)[1].split('if isinstance(target_info, str)', 1)[0]
    ok = '"label"' in block or "'label'" in block
    print(f"Bug134 _run_one doc mentions label -> {ok}")
    return ok


def test_url_set_reminder_still_works():
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_max_count=0,
        webhook_url="http://127.0.0.1:9/hook",
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a._webhook_incidents["t1"].last_reminder_at = 0
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    inc = a._webhook_incidents["t1"]
    ok = inc.reminder_count == 1 and any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug134 URL set reminder still works -> {ok}")
    return ok


def main():
    results = [
        ("web_ack", test_web_ack_ui_wired()),
        ("events_drop", test_webhook_events_removed()),
        ("no_burn", test_empty_url_no_reminder_count_burn()),
        ("trace_gate", test_include_trace_off_blocks_diagnostic()),
        ("dead_field", test_no_dead_last_trace_update_field()),
        ("doc_label", test_run_one_docstring_mentions_label()),
        ("reminder_ok", test_url_set_reminder_still_works()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 134 checks passed.")


if __name__ == "__main__":
    main()
