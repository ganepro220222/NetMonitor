"""Regression: webhook outbox retention policy guardrail.

Current behavior (as of Round 6):
  - _cleanup_webhook_outbox() deletes old terminal rows
  - pending / sending are NEVER deleted by cleanup
  - config: db_webhook_outbox_retention_days (default 90, range 7-3650)
  - delivered uses COALESCE(delivered_ts, updated_at)
  - dropped_stale / failed_permanent use updated_at
  - ops stats/problem API only show recent terminal rows (7d window)
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_row(ds, delivery_id, state, age_days, last_error=""):
    now = time.time()
    ts = now - age_days * 86400
    import json
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "retention", "event_ts": ts,
    })
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload=json.loads(payload),
        event_ts=ts,
        max_attempts=3,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        if state == "delivered":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='delivered', "
                "delivered_ts=?, updated_at=? WHERE delivery_id=?",
                (ts, ts, delivery_id))
        elif state == "pending":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='pending', "
                "updated_at=?, next_attempt_ts=?, last_error=? "
                "WHERE delivery_id=?", (ts, now + 60, last_error, delivery_id))
        else:
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state=?, updated_at=?, "
                "last_error=? WHERE delivery_id=?",
                (state, ts, last_error or state, delivery_id))
        conn.commit()


def _count(ds):
    conn = ds._read_conn()
    total = conn.execute("SELECT COUNT(*) FROM webhook_outbox").fetchone()[0]
    by_state = {
        r[0]: r[1]
        for r in conn.execute(
            "SELECT delivery_state, COUNT(*) FROM webhook_outbox "
            "GROUP BY delivery_state").fetchall()
    }
    return int(total), by_state


def test_cleanup_old_terminal_rows():
    td = tempfile.mkdtemp()
    ds = DataStore(
        db_path=os.path.join(td, "t.db"),
        webhook_outbox_retention_days=1,
    )
    ds._schema_ready.wait(timeout=5)

    # Old terminal rows (400 days old) — should be deleted
    _insert_row(ds, "old-del", "delivered", age_days=400)
    _insert_row(ds, "old-drop", "dropped_stale", age_days=400,
                last_error="gate")
    _insert_row(ds, "old-fail", "failed_permanent", age_days=400,
                last_error="max_attempts")
    # Fresh row — should survive
    _insert_row(ds, "fresh-pend", "pending", age_days=0)

    before_total, before_states = _count(ds)
    conn = ds._outbox_write_conn()
    ds._cleanup(conn)
    after_total, after_states = _count(ds)

    # 3 old terminal deleted, 1 fresh pending survives
    ok = (before_total == 4
          and after_total == 1
          and after_states.get("pending") == 1
          and "delivered" not in after_states
          and "dropped_stale" not in after_states
          and "failed_permanent" not in after_states)
    print(f"  cleanup old terminal: {ok}  "
          f"before={before_states} after={after_states}")
    return ok


def test_pending_sending_never_cleaned():
    td = tempfile.mkdtemp()
    ds = DataStore(
        db_path=os.path.join(td, "t.db"),
        webhook_outbox_retention_days=1,
    )
    ds._schema_ready.wait(timeout=5)

    # Old pending row (400 days) — should survive cleanup
    _insert_row(ds, "old-pending", "pending", age_days=400,
                last_error="still retrying")

    # Also insert an old sending row
    now = time.time()
    old_ts = now - 400 * 86400
    import json
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "sending", "event_ts": old_ts,
    })
    ds.enqueue_webhook_outbox(
        delivery_id="old-sending",
        target_id="t", incident_id="INC", incident_seq=1,
        event="alert_red", order_key="t",
        payload=json.loads(payload), event_ts=old_ts, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='sending', "
            "updated_at=? WHERE delivery_id=?",
            (old_ts, "old-sending"))
        conn.commit()

    before_total, before_states = _count(ds)
    conn = ds._outbox_write_conn()
    ds._cleanup(conn)
    after_total, after_states = _count(ds)

    ok = (before_total == 2
          and after_total == 2
          and after_states.get("pending") == 1
          and after_states.get("sending") == 1)
    print(f"  pending/sending protected: {ok}  "
          f"before={before_states} after={after_states}")
    return ok


def test_retention_config_defaults():
    """Verify default retention_days is in valid range."""
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    val = ds._webhook_outbox_retention_days
    ok = 7 <= val <= 3650
    print(f"  default retention_days={val} (range 7-3650): {ok}")
    return ok


def test_stats_exclude_stale_terminal():
    """Stats/problem API only show terminal rows within ops window (~7d)."""
    td = tempfile.mkdtemp()
    ds = DataStore(
        db_path=os.path.join(td, "t.db"),
        webhook_outbox_retention_days=90,
    )
    ds._schema_ready.wait(timeout=5)

    _insert_row(ds, "stale-fail", "failed_permanent", age_days=400,
                last_error="timeout")
    _insert_row(ds, "fresh-fail", "failed_permanent", age_days=1,
                last_error="timeout")
    _insert_row(ds, "fresh-pend", "pending", age_days=0)

    stats = ds.get_webhook_delivery_stats()
    problems = ds.get_webhook_problem_deliveries(limit=20)
    problem_ids = {r["delivery_id"] for r in problems}

    ok = (stats.get("failed_permanent", 0) == 1
          and stats.get("pending", 0) == 1
          and "stale-fail" not in problem_ids
          and "fresh-fail" in problem_ids
          and "fresh-pend" in problem_ids)
    print(f"  ops views exclude stale: {ok}  "
          f"stats={stats} problems={sorted(problem_ids)}")
    return ok


def main():
    results = [
        ("cleanup_old_terminal", test_cleanup_old_terminal_rows()),
        ("protect_pending_sending", test_pending_sending_never_cleaned()),
        ("retention_config", test_retention_config_defaults()),
        ("stats_exclude_stale", test_stats_exclude_stale_terminal()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook retention policy checks passed.")


if __name__ == "__main__":
    main()
