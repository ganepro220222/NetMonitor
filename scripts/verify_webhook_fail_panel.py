"""Regression: webhook problem deliveries API for failure detail panel."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def test_problem_deliveries_api_fields():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="WH-PENDING-1",
        target_id="t1",
        incident_id="INC1",
        incident_seq=1,
        event="alert_red",
        order_key="t1",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET last_error='timeout', attempt_count=2, "
            "next_attempt_ts=? WHERE delivery_id='WH-PENDING-1'",
            (now + 60,))
        conn.commit()

    rows = ds.get_webhook_problem_deliveries(limit=10)
    ok = len(rows) == 1
    row = rows[0] if rows else {}
    required = (
        "delivery_id", "target_id", "event", "delivery_state", "attempt_count",
        "last_error", "next_attempt_ts", "first_queued_ts", "payload_summary",
        "target_label",
    )
    for key in required:
        ok = ok and key in row
    ok = ok and row.get("delivery_id") == "WH-PENDING-1"
    ok = ok and row.get("delivery_state") == "pending"
    ok = ok and "GW" in (row.get("payload_summary") or "")
    print(f"webhook problem API fields -> {ok} row_keys={list(row.keys())}")
    return ok


def test_delivered_excluded():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="WH-DONE",
        target_id="t2",
        incident_id="INC2",
        incident_seq=1,
        event="recovery",
        order_key="t2",
        payload={"event": "recovery", "target": "GW", "ip": "10.0.0.2",
                 "status": "green", "message": "ok", "event_ts": now},
        event_ts=now,
        max_attempts=0,
    )
    ds.finish_webhook_outbox("WH-DONE", state="delivered", now=now)
    rows = ds.get_webhook_problem_deliveries(limit=10)
    ok = rows == []
    print(f"webhook problem excludes delivered -> {ok}")
    return ok


def main():
    results = [
        ("fields", test_problem_deliveries_api_fields()),
        ("exclude_delivered", test_delivered_excluded()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook fail panel API checks passed.")


if __name__ == "__main__":
    main()
