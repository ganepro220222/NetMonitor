"""Regression checks for per-target webhook delivery-worker cleanup.

_ensure_webhook_worker spawns one queue.Queue + one daemon thread per
order_key (the target id) and the original code never reclaimed them.
on_target_removed dropped the incident but left the queue, its worker
thread, and the _webhook_valid_seq entry alive forever — an unbounded
thread/memory leak under add/remove churn (tids are fresh UUIDs).

These tests pin: a removed target reclaims its queue, seq entry, and
worker thread; a recovery webhook queued before deletion is still
delivered (drained ahead of the stop sentinel); and the bounded aggregate
worker is untouched.

(Numbered 150 because the upstream took 149 for an unrelated test.)
"""
import os
import sys
import threading
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
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    cfg = dict(webhook_url=_HOOK_URL)
    cfg.update(cfg_kw)
    a.set_config(_Cfg(**cfg))
    # Never hit the network; just record the gated deliveries.
    a._sent = []
    a._send_webhook = lambda *args, **kw: a._sent.append(args[1] if len(args) > 1 else None)
    return a


def _worker_threads():
    return {t for t in threading.enumerate() if t.name.startswith("webhook-q-")}


def test_remove_reclaims_queue_seq_thread():
    a = _alerter()
    base = _worker_threads()
    n = 25
    for i in range(n):
        tid = f"t{i}"
        a.on_status_change(tid, f"N{i}", f"10.0.0.{i % 250}", "red")
    # Each red target must have spun up exactly one delivery worker.
    created = _worker_threads() - base
    spun_up = len(a._webhook_queues) == n and len(created) == n
    for i in range(n):
        a.on_target_removed(f"t{i}")
    # Let the stop sentinels drain and workers exit.
    deadline = time.time() + 3.0
    while time.time() < deadline and (_worker_threads() - base):
        time.sleep(0.05)
    leaked_threads = _worker_threads() - base
    ok = (
        spun_up
        and len(a._webhook_queues) == 0
        and len(a._webhook_valid_seq) == 0
        and len(leaked_threads) == 0
    )
    print(f"Bug150 remove reclaims queue/seq/thread -> {ok} "
          f"(spun_up={spun_up} q={len(a._webhook_queues)} "
          f"seq={len(a._webhook_valid_seq)} leaked={len(leaked_threads)})")
    return ok


def test_recovery_before_remove_still_delivered():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")     # alert_red queued
    a.on_status_change("t1", "GW", "10.0.0.1", "green")   # recovery queued (gate=None)
    a.on_target_removed("t1")                              # sentinel after both
    deadline = time.time() + 3.0
    while time.time() < deadline and ("recovery" not in a._sent):
        time.sleep(0.05)
    ok = "recovery" in a._sent
    print(f"Bug150 recovery before remove still delivered -> {ok} (sent={a._sent})")
    return ok


def test_aggregate_worker_not_dropped_by_remove():
    """The fixed-key '_aggregate_' worker is bounded; removing a target must
    not tear it down."""
    a = _alerter(
        webhook_reminder_enabled=True,
        webhook_reminder_interval_min=1,
        webhook_reminder_aggregate_enabled=True,
        webhook_reminder_aggregate_threshold=2,
    )
    for i in range(3):
        a.on_status_change(f"t{i}", f"N{i}", f"10.0.0.{i+1}", "red")
        a._webhook_incidents[f"t{i}"].last_reminder_at = 0
    a._tick_webhook_reminders()              # creates the '_aggregate_' worker
    time.sleep(0.1)
    had_agg = "_aggregate_" in a._webhook_queues
    a.on_target_removed("t0")                # must not touch '_aggregate_'
    ok = had_agg and "_aggregate_" in a._webhook_queues
    print(f"Bug150 aggregate worker survives target removal -> {ok}")
    return ok


def main():
    results = [
        ("reclaim", test_remove_reclaims_queue_seq_thread()),
        ("recovery_kept", test_recovery_before_remove_still_delivered()),
        ("aggregate_kept", test_aggregate_worker_not_dropped_by_remove()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 150 checks passed.")


if __name__ == "__main__":
    main()
