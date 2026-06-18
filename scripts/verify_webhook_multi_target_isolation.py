"""Regression: webhook queue selection isolation (DataStore layer).

Verifies fetch_deliverable_webhook_outbox semantics:
  - a target in long backoff does not appear as deliverable
  - other targets with due rows are still returned
  - within one order_key only the FIFO head is deliverable

End-to-end cross-target HTTP delivery is covered by review_round3.
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def test_fetch_deliverable_respects_per_order_key():
    """Head-of-line: one row per order_key, stuck targets don't block others."""
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    now = time.time()
    payload = json.dumps({
        "event": "alert_red", "target": "T", "ip": "10.0.0.1",
        "status": "red", "message": "test", "event_ts": now,
    })

    conn = ds._outbox_write_conn()
    # Target A: stuck in long backoff (next_attempt_ts far in future)
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("D-STUCK", "A", "INC-A", 1, "alert_red", "A",
         payload, now, now, now + 99999, now, None, 3, 5,
         "pending", "timeout", now, now))
    # Target B: due now
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("D-DUE", "B", "INC-B", 1, "alert_red", "B",
         payload, now, now, now, now, None, 0, 3,
         "pending", "", now, now))
    conn.commit()

    rows = ds.fetch_deliverable_webhook_outbox(now, limit=50)
    ids = [r["delivery_id"] for r in rows]

    # Stuck target (backoff) should NOT appear, due target SHOULD
    stuck_absent = "D-STUCK" not in ids
    due_present = "D-DUE" in ids
    ok = stuck_absent and due_present
    print(f"  fetch_deliverable isolation: {ok}  returned={ids}")
    return ok


def test_per_target_ordering_preserved():
    """Within one order_key, events must be delivered in FIFO order."""
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    now = time.time()
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "ordering", "event_ts": now,
    })

    conn = ds._outbox_write_conn()
    # Enqueue red, recovery, red in order for same target
    for i, (did, evt) in enumerate([
        ("D-ORD-1", "alert_red"),
        ("D-ORD-2", "recovery"),
        ("D-ORD-3", "alert_red"),
    ]):
        p = json.dumps({**json.loads(payload), "event": evt})
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, "GW", "INC-GW", 1, evt, "GW",
             p, now, now + i * 0.001, now, now, None, 0, 0,
             "pending", "", now, now))
    conn.commit()

    # Should return only the oldest (first) row: D-ORD-1 (alert_red)
    rows = ds.fetch_deliverable_webhook_outbox(now + 1, limit=50)
    head_ids = [r["delivery_id"] for r in rows]
    head_events = [r["event"] for r in rows]

    only_oldest = head_ids == ["D-ORD-1"]
    oldest_is_red = head_events == ["alert_red"] if head_events else False
    ok = only_oldest and oldest_is_red
    print(f"  per-target ordering: {ok}  head={head_ids} events={head_events}")
    return ok


def main():
    results = [
        ("fetch_isolation", test_fetch_deliverable_respects_per_order_key()),
        ("per_target_ordering", test_per_target_ordering_preserved()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All multi-target isolation checks passed.")


if __name__ == "__main__":
    main()
