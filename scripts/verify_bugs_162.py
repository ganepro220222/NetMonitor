"""Regression: outbox red/recovery lookups scoped by incident_id (Bug 162)."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import (
    WebhookOutboxDispatcher,
    CLOSED_SUMMARY_DELAY_SEC,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")
WEBHOOK_OUTBOX = os.path.join(ROOT, "src", "webhook_outbox.py")


def _mk_store():
    from scripts.webhook_test_util import make_alerter
    import tempfile
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    a, disp, _ = make_alerter(ds=ds)
    return a, disp, ds, td


def test_old_red_does_not_convert_new_recovery():
    a, disp, ds, _td = _mk_store()
    now = time.time()
    old_red_id = a._make_delivery_id()
    new_rec_id = a._make_delivery_id()
    ds.enqueue_webhook_outbox(
        delivery_id=old_red_id, target_id="t1", incident_id="INC_A",
        incident_seq=1, event="alert_red", order_key="t1",
        payload={
            "event": "alert_red", "target": "Old", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t1", 1], "event_ts": now - 120,
        },
        event_ts=now - 120, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='dropped_stale', "
            "last_error='superseded_by_closed_summary', updated_at=? "
            "WHERE delivery_id=?",
            (now, old_red_id))
        conn.commit()
    recovery_payload = {
        "event": "recovery", "target": "New", "ip": "10.0.0.1",
        "status": "green", "message": "连接已恢复正常",
        "extra": {
            "incident": {
                "started_at": "2026-06-16 10:00:00",
                "recovered_at": "2026-06-16 10:05:00",
                "duration_text": "5 分钟",
                "recovered": True,
            },
        },
        "gate": None, "event_ts": now,
    }
    ds.enqueue_webhook_outbox(
        delivery_id=new_rec_id, target_id="t1", incident_id="INC_B",
        incident_seq=2, event="recovery", order_key="t1",
        payload=recovery_payload, event_ts=now, max_attempts=0,
    )
    row = ds.get_webhook_deliveries(incident_id="INC_B", limit=1)[0]
    prepared = a.prepare_outbox_delivery(row, now)
    ok = prepared is not None and prepared[0] == "recovery"
    print(f"Bug162 old red does not convert new recovery -> {ok} "
          f"event={prepared[0] if prepared else None}")
    return ok


def test_old_recovery_does_not_drop_new_red():
    a, disp, ds, _td = _mk_store()
    now = time.time()
    old_rec_id = a._make_delivery_id()
    new_red_id = a._make_delivery_id()
    ds.enqueue_webhook_outbox(
        delivery_id=old_rec_id, target_id="t1", incident_id="INC_A",
        incident_seq=1, event="recovery", order_key="t1",
        payload={
            "event": "recovery", "target": "Old", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": {}, "gate": None, "event_ts": now - 200,
        },
        event_ts=now - 200, max_attempts=0,
    )
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 10
    ds.enqueue_webhook_outbox(
        delivery_id=new_red_id, target_id="t1", incident_id="INC_B",
        incident_seq=2, event="alert_red", order_key="t1",
        payload={
            "event": "alert_red", "target": "New", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t1", 2], "event_ts": red_ts,
        },
        event_ts=red_ts, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=?, "
            "attempt_count=1, last_error='fail' WHERE delivery_id=?",
            (red_ts, now, new_red_id))
        conn.commit()
    row = ds.get_webhook_deliveries(incident_id="INC_B", limit=1)[0]
    disp = WebhookOutboxDispatcher(a)
    disp._handle_failure(row, now, "simulated failure")
    updated = ds.get_webhook_deliveries(incident_id="INC_B", limit=1)[0]
    ok = (
        updated["delivery_state"] == "pending"
        and updated.get("last_error") == "simulated failure"
    )
    print(f"Bug162 old recovery does not drop new red -> {ok} "
          f"state={updated['delivery_state']} error={updated.get('last_error')}")
    return ok


def test_source_incident_id_scoped_queries():
    with open(DATA_STORE, encoding="utf-8") as f:
        ds_src = f.read()
    with open(WEBHOOK_OUTBOX, encoding="utf-8") as f:
        wo_src = f.read()
    red_fn = ds_src.split("def find_undelivered_alert_red", 1)[1].split(
        "def drop_pending_webhook_for_target", 1)[0]
    rec_fn = ds_src.split("def find_pending_recovery", 1)[1].split(
        "def get_last_known_statuses", 1)[0]
    ok = (
        "AND incident_id=?" in red_fn
        and "incident_id or \"\"" in red_fn
        and "AND incident_id=?" in rec_fn
        and "row.get(\"incident_id\")" in wo_src
    )
    print(f"Bug162 source incident_id scoped queries -> {ok}")
    return ok


def main():
    results = [
        ("recovery", test_old_red_does_not_convert_new_recovery()),
        ("red_retry", test_old_recovery_does_not_drop_new_red()),
        ("source", test_source_incident_id_scoped_queries()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 162 checks passed.")


if __name__ == "__main__":
    main()
