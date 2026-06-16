"""Regression checks for the reminder_count ordinal in webhook reminders.

Guards commit d8b4575 (off-by-one reminder_count).  _tick_webhook_reminders
must bump reminder_count BEFORE snapshotting a due incident, so the first
repeat reminder carries reminder_count=1 — not 0 — in the webhook text
("提醒次数：1") and in the custom-JSON payload (incident.reminder_count for
individual reminders, and every node of extra.aggregate.nodes).

This coverage originally lived in verify_bugs_134.py; it was lost when that
file was repurposed for the webhook-hygiene checks, leaving d8b4575
unguarded (reintroducing the snapshot-before-increment order keeps the rest
of the suite green).  Restored here, adapted for the url_ok gate (a
webhook_url must be configured or no reminder fires).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOK_URL = "http://127.0.0.1:9/hook"


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def _alerter(**cfg_kw):
    from scripts.webhook_test_util import make_alerter
    cfg = dict(webhook_url=_HOOK_URL)
    cfg.update(cfg_kw)
    a, disp, ds = make_alerter(**cfg)
    return a, disp


def _install_push_capture(a, calls, disp=None):
    from scripts.webhook_test_util import install_push_capture
    return install_push_capture(a, calls, disp)


def _open_red(a, tid, label, ip):
    a.on_status_change(tid, label, ip, "red")
    if tid in a._webhook_incidents:
        a._webhook_incidents[tid].last_reminder_at = 0


def test_individual_first_reminder_count_is_one():
    a, disp = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    _open_red(a, "t1", "GW", "10.0.0.1")
    calls = []
    flush = _install_push_capture(a, calls, disp)
    a._tick_webhook_reminders()
    flush()
    rem = [c for c in calls if c["event"] == "alert_reminder"]
    ok = len(rem) == 1 and rem[0]["extra"]["incident"]["reminder_count"] == 1
    got = rem[0]["extra"]["incident"]["reminder_count"] if rem else None
    print(f"Bug137 first individual reminder count == 1 -> {ok} (got {got})")
    return ok


def test_individual_reminder_count_increments():
    a, disp = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    _open_red(a, "t1", "GW", "10.0.0.1")
    captured = []
    flush = _install_push_capture(a, captured, disp)
    a._tick_webhook_reminders()
    flush()
    counts = [c["extra"]["incident"]["reminder_count"]
              for c in captured if c.get("event") == "alert_reminder"]
    a._webhook_incidents["t1"].last_reminder_at = 0
    a._tick_webhook_reminders()
    flush()
    counts = [c["extra"]["incident"]["reminder_count"]
              for c in captured if c.get("event") == "alert_reminder"]
    ok = counts == [1, 2]
    print(f"Bug137 individual reminder count 1 then 2 -> {ok} ({counts})")
    return ok


def test_reminder_count_in_text_payload():
    """企业微信/钉钉/飞书 text path: '提醒次数：1' on the first reminder."""
    a, disp = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    _open_red(a, "t1", "GW", "10.0.0.1")
    captured = {}

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, **kw):
        captured["text"] = AlertManager._format_webhook_text(
            "🔴", "告警仍未恢复", event, target, ip,
            status, message, "2026-01-01 00:00:00", extra,
            event_ts=kw.get("event_ts"), queued_ts=kw.get("queued_ts"),
            sent_ts=kw.get("sent_ts"), attempt=kw.get("attempt", 1))

    a._send_webhook = staticmethod(_send)
    a._tick_webhook_reminders()
    for _ in range(8):
        disp._tick()
        time.sleep(0.02)
    text = captured.get("text", "")
    ok = "提醒次数：1" in text and "提醒次数：0" not in text
    print(f"Bug137 text payload shows 提醒次数：1 -> {ok}")
    return ok


def test_aggregate_nodes_reminder_count_is_one():
    a, disp = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    for i in range(3):
        _open_red(a, f"t{i}", f"N{i}", f"10.0.0.{i+1}")
    calls = []
    flush = _install_push_capture(a, calls, disp)
    a._tick_webhook_reminders()
    flush()
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    ok = (
        len(agg) == 1
        and all(n["reminder_count"] == 1
                for n in agg[0]["extra"]["aggregate"]["nodes"])
    )
    counts = ([n["reminder_count"] for n in agg[0]["extra"]["aggregate"]["nodes"]]
              if agg else None)
    print(f"Bug137 aggregate nodes count == 1 -> {ok} ({counts})")
    return ok


def test_non_due_node_keeps_actual_count_in_aggregate():
    """A node reminded once, then not yet due again, must still report its
    real count (1) when listed in an aggregate triggered by other nodes —
    not get spuriously bumped, and not snapshot a stale pre-increment 0."""
    a, disp = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=30,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )
    now = time.time()
    for i in range(3):
        a.on_status_change(f"t{i}", f"N{i}", f"10.0.0.{i+1}", "red")
    # t0 already reminded once and is NOT due; t1/t2 are overdue.
    a._webhook_incidents["t0"].reminder_count = 1
    a._webhook_incidents["t0"].last_reminder_at = now      # not due
    a._webhook_incidents["t1"].last_reminder_at = 0        # due
    a._webhook_incidents["t2"].last_reminder_at = 0        # due
    calls = []
    flush = _install_push_capture(a, calls, disp)
    a._tick_webhook_reminders()
    flush()
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    nodes = ({n["tid"]: n["reminder_count"]
              for n in agg[0]["extra"]["aggregate"]["nodes"]} if agg else {})
    # t0 stays at its actual 1 (not re-bumped); t1/t2 become 1 (first repeat).
    ok = nodes.get("t0") == 1 and nodes.get("t1") == 1 and nodes.get("t2") == 1
    print(f"Bug137 non-due node keeps real count -> {ok} ({nodes})")
    return ok


def main():
    results = [
        ("individual_first", test_individual_first_reminder_count_is_one()),
        ("individual_incr", test_individual_reminder_count_increments()),
        ("text_payload", test_reminder_count_in_text_payload()),
        ("aggregate_nodes", test_aggregate_nodes_reminder_count_is_one()),
        ("non_due_keep", test_non_due_node_keeps_actual_count_in_aggregate()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 137 checks passed.")


if __name__ == "__main__":
    main()
