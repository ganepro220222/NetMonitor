"""Regression: delivered outbox rows must persist actual attempt_count."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter


def _row(ds, delivery_id):
    return next(
        r for r in ds.get_webhook_deliveries(limit=50)
        if r["delivery_id"] == delivery_id)


def test_first_success_attempt_count():
    a, disp, ds = make_alerter()
    sent = []
    now = time.time()

    a._send_webhook = lambda *args, **kw: sent.append(
        (kw.get("delivery_id"), kw.get("attempt")))

    ds.enqueue_webhook_outbox(
        delivery_id="first-success",
        target_id="t1",
        incident_id="INC1",
        incident_seq=1,
        event="alert_red",
        order_key="t1",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t1", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t1"] = 1

    disp._tick()
    row = _row(ds, "first-success")
    ok = (
        sent == [("first-success", 1)]
        and row["delivery_state"] == "delivered"
        and int(row["attempt_count"]) == 1
    )
    print(
        f"Bug169 first success -> {ok} sent={sent} "
        f"stored={row['attempt_count']} state={row['delivery_state']}")
    return ok


def test_retry_success_attempt_count():
    a, disp, ds = make_alerter()
    sent = []
    now = time.time()
    calls = {"n": 0}

    def _send(*_a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("one-shot")
        sent.append((kw.get("delivery_id"), kw.get("attempt")))

    a._send_webhook = _send

    ds.enqueue_webhook_outbox(
        delivery_id="retry-success",
        target_id="t2",
        incident_id="INC2",
        incident_seq=1,
        event="alert_red",
        order_key="t2",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.2",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t2", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t2"] = 1

    disp._tick()
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? "
            "WHERE delivery_id='retry-success'",
            (time.time(),))
        conn.commit()
    disp._tick()

    row = _row(ds, "retry-success")
    ok = (
        sent == [("retry-success", 2)]
        and row["delivery_state"] == "delivered"
        and int(row["attempt_count"]) == 2
    )
    print(
        f"Bug169 retry success -> {ok} sent={sent} "
        f"stored={row['attempt_count']} state={row['delivery_state']}")
    return ok


def main():
    results = [
        ("first", test_first_success_attempt_count()),
        ("retry", test_retry_success_attempt_count()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 169 checks passed.")


if __name__ == "__main__":
    main()
