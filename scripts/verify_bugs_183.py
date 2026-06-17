"""Regression: post-send gate fail must still supersede red after closed-summary sent."""
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


def test_post_send_gate_fail_still_supersedes_red():
    from scripts.webhook_test_util import make_alerter
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

    sent = []

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, **kw):
        sent.append((event, target, kw.get("delivery_id", "")))
        with a._webhook_incident_lock:
            a._webhook_valid_seq["t"] = 2

    a._send_webhook = _send
    disp._tick()

    rec = _row(ds, "rec")
    red = _row(ds, "red")
    ok = (
        sent == [("incident_closed_summary", "GW", "rec")]
        and rec == ("recovery", "dropped_stale", "gate_or_rebuild")
        and red == ("alert_red", "dropped_stale", "superseded_by_closed_summary")
    )
    print(
        f"Bug183 post_send_gate_fail_supersedes_red -> {ok} sent={sent} "
        f"rec={rec} red={red}")
    return ok


def main():
    ok = test_post_send_gate_fail_still_supersedes_red()
    if not ok:
        print("FAILED")
        sys.exit(1)
    print("All bug 183 checks passed.")


if __name__ == "__main__":
    main()
