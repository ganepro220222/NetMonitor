"""Regression: webhook_outbox terminal retention cleanup and ops stats."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


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


def _insert_row(ds, *, delivery_id, state, age_days, last_error=""):
    now = time.time()
    ts = now - age_days * 86400
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "msg", "event_ts": ts,
        },
        event_ts=ts,
        max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        if state == "delivered":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='delivered', "
                "delivered_ts=?, updated_at=?, last_error=? "
                "WHERE delivery_id=?",
                (ts, ts, last_error, delivery_id))
        elif state == "pending":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='pending', "
                "updated_at=?, next_attempt_ts=?, last_error=? "
                "WHERE delivery_id=?",
                (ts, now + 60, last_error, delivery_id))
        else:
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state=?, updated_at=?, "
                "last_error=? WHERE delivery_id=?",
                (state, ts, last_error or state, delivery_id))
        conn.commit()


def test_cleanup_old_terminal_rows():
    td = tempfile.mkdtemp()
    ds = DataStore(
        db_path=os.path.join(td, "t.db"),
        raw_retention_days=1,
        hourly_retention_days=1,
        alert_retention_days=1,
        traceroute_retention_days=1,
        diag_retention_days=1,
        webhook_outbox_retention_days=1,
    )
    ds._schema_ready.wait(timeout=5)
    _insert_row(ds, delivery_id="old-del", state="delivered", age_days=400)
    _insert_row(ds, delivery_id="old-drop", state="dropped_stale",
                age_days=400, last_error="gate_or_rebuild")
    _insert_row(ds, delivery_id="old-fail", state="failed_permanent",
                age_days=400, last_error="timeout")
    _insert_row(ds, delivery_id="new-pend", state="pending", age_days=0)
    before_total, before_states = _count(ds)
    conn = ds._outbox_write_conn()
    ds._cleanup(conn)
    after_total, after_states = _count(ds)
    ok = (
        before_total == 4
        and before_states.get("delivered") == 1
        and before_states.get("dropped_stale") == 1
        and before_states.get("failed_permanent") == 1
        and before_states.get("pending") == 1
        and after_total == 1
        and after_states.get("pending") == 1
        and "delivered" not in after_states
    )
    print(
        f"cleanup old terminal -> {ok} before={before_states} after={after_states}")
    return ok


def test_stats_and_problem_exclude_stale_history():
    td = tempfile.mkdtemp()
    ds = DataStore(
        db_path=os.path.join(td, "t.db"),
        webhook_outbox_retention_days=90,
    )
    ds._schema_ready.wait(timeout=5)
    _insert_row(ds, delivery_id="stale-fail", state="failed_permanent",
                age_days=400, last_error="timeout")
    _insert_row(ds, delivery_id="fresh-fail", state="failed_permanent",
                age_days=1, last_error="timeout")
    _insert_row(ds, delivery_id="fresh-pend", state="pending", age_days=0)
    stats = ds.get_webhook_delivery_stats()
    problems = ds.get_webhook_problem_deliveries(limit=20)
    problem_ids = {r["delivery_id"] for r in problems}
    ok = (
        stats.get("failed_permanent", 0) == 1
        and stats.get("pending", 0) == 1
        and "stale-fail" not in problem_ids
        and "fresh-fail" in problem_ids
        and "fresh-pend" in problem_ids
    )
    print(
        f"ops stats/problem exclude stale -> {ok} stats={stats} "
        f"problems={sorted(problem_ids)}")
    return ok


def main():
    results = [
        ("cleanup", test_cleanup_old_terminal_rows()),
        ("ops_views", test_stats_and_problem_exclude_stale_history()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook outbox retention checks passed.")


if __name__ == "__main__":
    main()
