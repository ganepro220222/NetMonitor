"""Regression: recovery unblocked when red in long backoff (Bug 163)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC, WebhookOutboxDispatcher

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")
WEBHOOK_OUTBOX = os.path.join(ROOT, "src", "webhook_outbox.py")


def test_recovery_unblocked_after_red_backoff():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter()
    now = time.time()
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 30
    red_id = a._make_delivery_id()
    rec_id = a._make_delivery_id()
    extra = {
        "incident": {
            "started_at": "2026-06-16 10:00:00",
            "recovered_at": "2026-06-16 10:05:00",
            "duration_text": "5 分钟",
            "recovered": True,
        },
    }
    ds.enqueue_webhook_outbox(
        delivery_id=red_id, target_id="t1", incident_id="INC1",
        incident_seq=1, event="alert_red", order_key="t1",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t1", 1], "event_ts": red_ts,
        },
        event_ts=red_ts, max_attempts=0,
    )
    ds.enqueue_webhook_outbox(
        delivery_id=rec_id, target_id="t1", incident_id="INC1",
        incident_seq=1, event="recovery", order_key="t1",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": extra, "gate": None, "event_ts": now,
        },
        event_ts=now, max_attempts=0,
    )
    future_retry = now + 300
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=?, "
            "attempt_count=3, last_error='timeout', delivery_state='pending' "
            "WHERE delivery_id=?",
            (red_ts, future_retry, red_id))
        conn.commit()

    due_before = ds.fetch_deliverable_webhook_outbox(now, limit=10)
    ok_blocked = due_before == []

    dropped = ds.drop_red_blocked_closed_summary(
        now, CLOSED_SUMMARY_DELAY_SEC)
    due_after = ds.fetch_deliverable_webhook_outbox(now, limit=10)
    ok_unblocked = (
        dropped == 1
        and len(due_after) == 1
        and due_after[0]["event"] == "recovery"
    )

    sent = []

    def _send(*args, **kwargs):
        sent.append({"event": args[1]})

    a._send_webhook = staticmethod(_send)
    disp._tick()
    ok_delivered = sent and sent[0]["event"] == "incident_closed_summary"

    ok = ok_blocked and ok_unblocked and ok_delivered
    print(
        f"Bug163 recovery unblocked after red backoff -> {ok} "
        f"due_before={len(due_before)} dropped={dropped} "
        f"due_after={[r['event'] for r in due_after]} sent={[s['event'] for s in sent]}"
    )
    return ok


def test_source_drop_red_blocked_closed_summary():
    with open(DATA_STORE, encoding="utf-8") as f:
        ds_src = f.read()
    with open(WEBHOOK_OUTBOX, encoding="utf-8") as f:
        wo_src = f.read()
    ok = (
        "def drop_red_blocked_closed_summary" in ds_src
        and "drop_red_blocked_closed_summary(now" in wo_src
    )
    print(f"Bug163 source unblock before fetch -> {ok}")
    return ok


def main():
    results = [
        ("unblock", test_recovery_unblocked_after_red_backoff()),
        ("source", test_source_drop_red_blocked_closed_summary()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 163 checks passed.")


if __name__ == "__main__":
    main()
