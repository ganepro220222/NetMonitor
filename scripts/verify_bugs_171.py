"""Regression: diagnostic_update long backoff must not block due closed-summary."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC, WebhookOutboxDispatcher


def _setup_rows(ds, a, *, now, future_retry):
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
        delivery_id="diag", target_id="t", incident_id="INC",
        incident_seq=1, event="diagnostic_update", order_key="t",
        payload={
            "event": "diagnostic_update", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "诊断更新", "extra": {},
            "gate": ["incident", "t", 1], "event_ts": red_ts + 1,
        },
        event_ts=red_ts + 1, max_attempts=8,
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
            "attempt_count=3, last_error='timeout', delivery_state='pending' "
            "WHERE delivery_id='red'",
            (red_ts, future_retry))
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=?, attempt_count=2, "
            "last_error='timeout', delivery_state='pending' "
            "WHERE delivery_id='diag'",
            (future_retry,))
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? "
            "WHERE delivery_id='rec'",
            (now,))
        conn.commit()
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1


def test_diag_backoff_unblock_fetch():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter()
    now = time.time()
    future_retry = now + 300
    _setup_rows(ds, a, now=now, future_retry=future_retry)

    dropped = ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
    due = ds.fetch_deliverable_webhook_outbox(now, limit=10)
    rows = {r["delivery_id"]: r for r in ds.get_webhook_deliveries(limit=10)}
    ok = (
        dropped >= 2
        and len(due) == 1
        and due[0]["delivery_id"] == "rec"
        and rows["red"]["delivery_state"] == "dropped_stale"
        and rows["diag"]["delivery_state"] == "dropped_stale"
    )
    print(
        f"Bug171 diag backoff unblock fetch -> {ok} dropped={dropped} "
        f"due={[r['delivery_id'] for r in due]} "
        f"red={rows['red']['delivery_state']} diag={rows['diag']['delivery_state']}")
    return ok


def test_diag_backoff_dispatch_closed_summary():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter()
    now = time.time()
    future_retry = now + 300
    _setup_rows(ds, a, now=now, future_retry=future_retry)
    sent = []

    def _send(*args, **kwargs):
        sent.append(args[1])

    a._send_webhook = _send
    disp._tick()
    ok = sent == ["incident_closed_summary"]
    print(f"Bug171 diag backoff dispatch -> {ok} sent={sent}")
    return ok


def main():
    results = [
        ("fetch", test_diag_backoff_unblock_fetch()),
        ("dispatch", test_diag_backoff_dispatch_closed_summary()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 171 checks passed.")


if __name__ == "__main__":
    main()
