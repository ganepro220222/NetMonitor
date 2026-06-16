"""Regression: stale sending outbox rows recovered after restart."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter
from src.data_store import DataStore
from src.webhook_outbox import WebhookOutboxDispatcher


def _row_state(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=50)
    row = next(r for r in rows if r["delivery_id"] == delivery_id)
    return row["delivery_state"], row.get("last_error", "")


def test_restart_recovers_stale_sending_head():
    td = tempfile.mkdtemp()
    db = os.path.join(td, "t.db")
    now = time.time()
    ds = DataStore(db_path=db)
    ds._schema_ready.wait(timeout=5)

    ds.enqueue_webhook_outbox(
        delivery_id="stuck-head",
        target_id="t",
        incident_id="INC1",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    ds.enqueue_webhook_outbox(
        delivery_id="blocked-next",
        target_id="t",
        incident_id="INC1",
        incident_seq=1,
        event="recovery",
        order_key="t",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": {}, "gate": None, "event_ts": now + 1,
        },
        event_ts=now + 1,
        max_attempts=0,
    )
    assert ds.claim_webhook_outbox("stuck-head", now)
    stuck_before, _ = _row_state(ds, "stuck-head")
    next_before, _ = _row_state(ds, "blocked-next")
    assert stuck_before == "sending"
    assert next_before == "pending"

    ds.shutdown()
    ds2 = DataStore(db_path=db)
    ds2._schema_ready.wait(timeout=5)
    a, disp, _ = make_alerter(ds=ds2)
    sent = []

    def _send(*_a, **_k):
        sent.append(_a[1] if len(_a) > 1 else None)

    a._send_webhook = _send
    disp.start()
    for _ in range(3):
        disp._tick()
        time.sleep(0.02)

    stuck_after, stuck_err = _row_state(ds2, "stuck-head")
    next_after, _ = _row_state(ds2, "blocked-next")
    due = ds2.fetch_deliverable_webhook_outbox(time.time(), limit=10)
    ok = (
        stuck_before == "sending"
        and next_before == "pending"
        and stuck_after == "delivered"
        and next_after == "delivered"
        and "alert_red" in sent
        and "recovery" in sent
        and len(due) >= 0
    )
    print(
        f"Bug166 restart stale sending -> {ok} "
        f"before=({stuck_before},{next_before}) "
        f"after=({stuck_after},{next_after}) sent={sent} err={stuck_err!r}")
    ds2.shutdown()
    return ok


def test_lease_recovers_without_restart():
    td = tempfile.mkdtemp()
    db = os.path.join(td, "t.db")
    now = time.time()
    ds = DataStore(db_path=db)
    ds._schema_ready.wait(timeout=5)
    ds.enqueue_webhook_outbox(
        delivery_id="lease-stuck",
        target_id="t2",
        incident_id="INC2",
        incident_seq=1,
        event="alert_red",
        order_key="t2",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.2",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t2", 1], "event_ts": now - 300,
        },
        event_ts=now - 300,
        max_attempts=0,
    )
    ds.claim_webhook_outbox("lease-stuck", now - 200)
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET last_attempt_ts=? WHERE delivery_id=?",
            (now - 200, "lease-stuck"))
        conn.commit()
    recovered = ds.recover_stale_sending_webhook_outbox(now, 120.0)
    state, err = _row_state(ds, "lease-stuck")
    ok = recovered == 1 and state == "pending" and err == "stale_sending_recovered"
    print(f"Bug166 lease recovery -> {ok} recovered={recovered} state={state}")
    ds.shutdown()
    return ok


def main():
    results = [
        ("restart", test_restart_recovers_stale_sending_head()),
        ("lease", test_lease_recovers_without_restart()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 166 checks passed.")


if __name__ == "__main__":
    main()
