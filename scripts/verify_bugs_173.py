"""Regression: closed-summary unblock must not accelerate recovery retry backoff."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC


def _setup_red_and_future_recovery(ds, a, *, now, future_retry):
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 30
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
            "extra": extra, "gate": None, "event_ts": now,
        },
        event_ts=now, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=?, "
            "attempt_count=3, last_error='red timeout', delivery_state='pending' "
            "WHERE delivery_id='red'",
            (red_ts, future_retry))
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=?, attempt_count=1, "
            "last_error='closed summary timeout', delivery_state='pending' "
            "WHERE delivery_id='rec'",
            (future_retry,))
        conn.commit()
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1


def test_future_recovery_not_accelerated():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter()
    now = time.time()
    future_retry = now + 300
    _setup_red_and_future_recovery(ds, a, now=now, future_retry=future_retry)

    due_before = ds.fetch_deliverable_webhook_outbox(now, limit=10)
    dropped = ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
    due_after = ds.fetch_deliverable_webhook_outbox(now, limit=10)
    rec = next(r for r in ds.get_webhook_deliveries(limit=10)
               if r["delivery_id"] == "rec")
    ok = (
        due_before == []
        and dropped == 1
        and due_after == []
        and rec["delivery_state"] == "pending"
        and abs(float(rec["next_attempt_ts"]) - future_retry) < 1
    )
    print(
        f"Bug173 future recovery not accelerated -> {ok} "
        f"dropped={dropped} due_after={len(due_after)} "
        f"rec_next={rec['next_attempt_ts']}")
    return ok


def test_dispatch_respects_recovery_backoff():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter()
    now = time.time()
    future_retry = now + 300
    _setup_red_and_future_recovery(ds, a, now=now, future_retry=future_retry)
    sent = []

    def _send(*args, **kwargs):
        sent.append((args[1], kwargs.get("delivery_id"), kwargs.get("attempt")))

    a._send_webhook = _send
    disp._tick()
    rec = next(r for r in ds.get_webhook_deliveries(limit=10)
               if r["delivery_id"] == "rec")
    ok = sent == [] and rec["delivery_state"] == "pending"
    print(f"Bug173 dispatch respects recovery backoff -> {ok} sent={sent}")
    return ok


def main():
    results = [
        ("direct", test_future_recovery_not_accelerated()),
        ("dispatch", test_dispatch_respects_recovery_backoff()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 173 checks passed.")


if __name__ == "__main__":
    main()
