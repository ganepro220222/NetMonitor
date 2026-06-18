"""Reproduce Bug184: post-HTTP verify fail after HTTP side effect, no red supersede."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC


def _row(ds, delivery_id):
    row = next(
        (r for r in ds.get_webhook_deliveries(limit=20)
         if r["delivery_id"] == delivery_id), {})
    return (
        row.get("event", ""),
        row.get("delivery_state", ""),
        row.get("last_error", ""),
    )


def main():
    import src.alert_manager as am
    from scripts.webhook_test_util import make_alerter

    side_effect_count = [0]

    class _FakeHttpCtx:
        def __init__(self, alert_manager):
            self._a = alert_manager

        def __enter__(self):
            side_effect_count[0] += 1
            with self._a._webhook_incident_lock:
                self._a._webhook_valid_seq["t"] = 2
            return self

        def __exit__(self, *args):
            return False

    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "GW", "ip": "10.0.0.1"}])
    now = time.time()
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 30
    future_retry = now + 300
    extra = {
        "incident": {
            "started_at": "2026-06-16 10:00:00",
            "recovered_at": "2026-06-16 10:05:00",
            "duration_text": "5 分钟",
            "recovered": True,
        },
    }
    ds.enqueue_webhook_outbox(
        delivery_id="red", target_id="t", incident_id="INC",
        incident_seq=1, event="alert_red", order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t", 1], "event_ts": red_ts,
        },
        event_ts=red_ts, max_attempts=0,
    )
    ds.enqueue_webhook_outbox(
        delivery_id="rec", target_id="t", incident_id="INC",
        incident_seq=1, event="recovery", order_key="t",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": extra, "gate": ["recovery", "t", 1], "event_ts": now,
        },
        event_ts=now, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=?, "
            "attempt_count=3, last_error='timeout', delivery_state='pending' "
            "WHERE delivery_id='red'",
            (red_ts, future_retry))
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? "
            "WHERE delivery_id='rec'",
            (now,))
        conn.commit()
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    orig = am._ORIGINAL_HTTP_OPEN
    am._ORIGINAL_HTTP_OPEN = lambda req, timeout=10: _FakeHttpCtx(a)
    try:
        disp._tick()
    finally:
        am._ORIGINAL_HTTP_OPEN = orig

    rec = _row(ds, "rec")
    red = _row(ds, "red")
    bug = (
        side_effect_count[0] == 1
        and rec == ("recovery", "dropped_stale", "gate")
        and red == ("alert_red", "dropped_stale", "superseded_by_closed_summary")
    )
    print(f"side_effect_count= {side_effect_count[0]}")
    print(f"rec= {rec}")
    print(f"red= {red}")
    print("BUG184_FIXED_REAL_PATH" if bug else "BUG_NOT_FIXED")
    sys.exit(0 if bug else 1)


if __name__ == "__main__":
    main()
