"""Regression checks for aggregate webhook reminder throttling.

The multi-node aggregate reminder exists to avoid a group-message storm
("避免群消息风暴").  But _tick_webhook_reminders fired a full aggregate
every time ANY single incident came due, and an aggregate already lists
every open-red node.  When incidents come due on different 30s ticks
(the normal case — nodes rarely fail in the same second), that produced
one full aggregate per node per interval, i.e. the storm the feature was
meant to prevent.

Fix: throttle the aggregate push to at most one per reminder interval via
_last_aggregate_reminder_at.  These tests pin: staggered due events emit a
single aggregate per interval window, and the aggregate re-arms after the
interval elapses.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTERVAL_MIN = 30
INTERVAL_SEC = INTERVAL_MIN * 60
# _tick_webhook_reminders only advances/sends when a webhook_url is set
# (the url_ok gate added in the hygiene refactor), so every reminder test
# must configure one or no reminder ever fires.
_HOOK_URL = "http://127.0.0.1:9/hook"


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def _alerter(**cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_Cfg(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=INTERVAL_MIN,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=3,
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        **cfg_kw))
    return a


def _open(a, n):
    for i in range(n):
        a.on_status_change(f"t{i}", f"N{i}", f"10.0.0.{i+1}", "red")


def _count_agg(calls):
    return sum(1 for c in calls if c["event"] == "alert_reminder_aggregate")


def test_staggered_due_single_aggregate_per_interval():
    a = _alerter()
    _open(a, 3)
    now = time.time()
    # Only t0 is overdue right now; t1/t2 came red recently (not due).
    a._webhook_incidents["t0"].last_reminder_at = now - INTERVAL_SEC - 5
    a._webhook_incidents["t1"].last_reminder_at = now - 60
    a._webhook_incidents["t2"].last_reminder_at = now - 60
    a._last_aggregate_reminder_at = now - INTERVAL_SEC - 5
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)

    a._tick_webhook_reminders()                     # tick A: t0 due
    agg_a = _count_agg(calls)
    a._webhook_incidents["t1"].last_reminder_at = 0  # tick B: t1 now due
    a._tick_webhook_reminders()
    agg_b = _count_agg(calls) - agg_a
    a._webhook_incidents["t2"].last_reminder_at = 0  # tick C: t2 now due
    a._tick_webhook_reminders()
    agg_c = _count_agg(calls) - agg_a - agg_b

    ok = agg_a == 1 and agg_b == 0 and agg_c == 0
    print(f"Bug135 staggered due -> single aggregate -> {ok} "
          f"(A={agg_a} B={agg_b} C={agg_c})")
    return ok


def test_aggregate_rearms_after_interval():
    a = _alerter()
    _open(a, 3)
    now = time.time()
    for i in range(3):
        a._webhook_incidents[f"t{i}"].last_reminder_at = 0
    a._last_aggregate_reminder_at = now - INTERVAL_SEC - 5  # last agg long ago
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)

    a._tick_webhook_reminders()                     # fires (re-armed)
    first = _count_agg(calls)
    # Immediately tick again with all due: throttled (no time elapsed).
    for i in range(3):
        a._webhook_incidents[f"t{i}"].last_reminder_at = 0
    a._tick_webhook_reminders()
    second = _count_agg(calls) - first
    # Simulate a full interval passing: re-arm and force due again.
    a._last_aggregate_reminder_at = time.time() - INTERVAL_SEC - 5
    for i in range(3):
        a._webhook_incidents[f"t{i}"].last_reminder_at = 0
    a._tick_webhook_reminders()
    third = _count_agg(calls) - first - second

    ok = first == 1 and second == 0 and third == 1
    print(f"Bug135 aggregate re-arms after interval -> {ok} "
          f"(first={first} throttled={second} rearmed={third})")
    return ok


def test_simultaneous_outage_still_single_aggregate():
    """Sanity: the common correlated-failure case (all due together) stays
    a single aggregate — the throttle does not change it."""
    a = _alerter()
    _open(a, 4)
    for i in range(4):
        a._webhook_incidents[f"t{i}"].last_reminder_at = 0
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    agg = [c for c in calls if c["event"] == "alert_reminder_aggregate"]
    ok = len(agg) == 1 and agg[0]["extra"]["aggregate"]["count"] == 4
    print(f"Bug135 simultaneous outage single aggregate -> {ok}")
    return ok


def main():
    results = [
        ("staggered", test_staggered_due_single_aggregate_per_interval()),
        ("rearm", test_aggregate_rearms_after_interval()),
        ("simultaneous", test_simultaneous_outage_still_single_aggregate()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 135 checks passed.")


if __name__ == "__main__":
    main()
