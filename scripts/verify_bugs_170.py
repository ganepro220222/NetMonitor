"""Regression: reclaim per-send webhook cancel tracking (Finding 1).

_cancel_inflight_outbox_sends records a per-delivery epoch bump + a cancelled
flag for every send that is in flight when an ACK/pause/remove fires.  Those
entries are keyed by the unique (uuid4) delivery_id and were never reclaimed,
so _webhook_send_epochs / _webhook_send_cancelled grew without bound over a
long-running process.  The dispatcher must release them once the delivery is
finalized.
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter


def _row_by_id(ds, delivery_id):
    return next((r for r in ds.get_webhook_deliveries(limit=200)
                 if r["delivery_id"] == delivery_id), None)


def test_cancel_during_send_reclaims_tracking():
    # ACK cancels in-flight reminder/diagnostic sends (not alert_red), so the
    # in-flight delivery here is a reminder.
    a, disp, ds = make_alerter(
        webhook_include_trace=False, webhook_trace_update_enabled=False)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    # Mark the auto alert_red delivered so it doesn't hold the order_key head.
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='delivered', "
            "delivered_ts=?, updated_at=? WHERE target_id=? AND event='alert_red'",
            (time.time(), time.time(), "t1"))
        conn.commit()

    did = "rem-cancel-race"
    rem_gate = ("reminder", "t1", inc.push_seq)
    ds.enqueue_webhook_outbox(
        delivery_id=did, target_id="t1", incident_id=inc.incident_id,
        incident_seq=inc.push_seq, event="alert_reminder", order_key="t1",
        payload={
            "event": "alert_reminder", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接仍未恢复",
            "extra": a._build_reminder_extra(a._snapshot_incident(inc)),
            "gate": list(rem_gate), "event_ts": time.time(),
        },
        event_ts=time.time(), max_attempts=12)
    row = dict(_row_by_id(ds, did))
    row["payload_json"] = json.dumps(row.pop("payload", {}), ensure_ascii=False)

    entered = threading.Event()
    release = threading.Event()
    real_send = a._send_webhook

    def _blocking_send(*args, **kwargs):
        entered.set()
        release.wait(timeout=5)
        return real_send(*args, **kwargs)

    a._send_webhook = _blocking_send
    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    t.start()
    assert entered.wait(timeout=5), "dispatcher did not reach _send_webhook"
    a.acknowledge_incident("t1")           # cancels the in-flight reminder
    tracked_mid = (len(a._webhook_send_epochs) >= 1
                   or len(a._webhook_send_cancelled) >= 1)
    release.set()
    t.join(timeout=5)

    leaked = len(a._webhook_send_epochs) + len(a._webhook_send_cancelled)
    ok = tracked_mid and leaked == 0
    print(f"Bug170 cancel-during-send reclaims tracking -> {ok} "
          f"(tracked_mid={tracked_mid}, leaked_after={leaked})")
    return ok


def test_normal_delivery_leaves_no_tracking():
    """A send with no cancel must not accumulate tracking either."""
    a, disp, ds = make_alerter(
        webhook_include_trace=False, webhook_trace_update_enabled=False)
    a._send_webhook = staticmethod(lambda *args, **kw: None)  # no network
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    for _ in range(8):
        disp._tick()
        time.sleep(0.02)
    leaked = len(a._webhook_send_epochs) + len(a._webhook_send_cancelled)
    ok = leaked == 0
    print(f"Bug170 normal delivery leaves no tracking -> {ok} (leaked={leaked})")
    return ok


def main():
    results = [
        ("cancel_reclaim", test_cancel_during_send_reclaims_tracking()),
        ("normal_clean", test_normal_delivery_leaves_no_tracking()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 170 checks passed.")


if __name__ == "__main__":
    main()
