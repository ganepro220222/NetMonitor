"""Regression: webhook fail pill visibility matches problem API semantics."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _pill_visible(stats: dict, failures: list) -> bool:
    """Mirror refreshWebhookFailBanner() show/hide logic."""
    return bool(failures) or bool(stats.get("pending", 0))


def test_dropped_stale_only_shows_pill():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="D-DROP",
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "gate fail", "event_ts": now,
        },
        event_ts=now,
        max_attempts=3,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='dropped_stale', "
            "last_error='gate_or_rebuild', updated_at=? "
            "WHERE delivery_id='D-DROP'",
            (now,))
        conn.commit()

    stats = ds.get_webhook_delivery_stats()
    failures = ds.get_last_webhook_failures(5)
    problems = ds.get_webhook_problem_deliveries(limit=100)
    visible = _pill_visible(stats, failures)

    ok = (
        len(problems) == 1
        and stats.get("dropped_stale") == 1
        and len(failures) == 1
        and failures[0].get("state") == "dropped_stale"
        and visible
    )
    print(f"  dropped_stale only shows pill: {ok}  "
          f"stats={stats} failures={failures} visible={visible}")
    return ok


def test_dropped_stale_without_error_hidden():
    """dropped_stale with empty last_error is not a problem row or pill driver."""
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="D-SILENT",
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="recovery",
        order_key="t",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "ok", "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='dropped_stale', "
            "last_error='', updated_at=? WHERE delivery_id='D-SILENT'",
            (now,))
        conn.commit()

    stats = ds.get_webhook_delivery_stats()
    failures = ds.get_last_webhook_failures(5)
    problems = ds.get_webhook_problem_deliveries(limit=100)
    visible = _pill_visible(stats, failures)

    ok = problems == [] and failures == [] and not visible
    print(f"  silent dropped_stale hidden: {ok}  "
          f"problems={len(problems)} failures={len(failures)}")
    return ok


def test_pending_without_error_still_shows_pill():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="D-PEND",
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "retry", "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )

    stats = ds.get_webhook_delivery_stats()
    failures = ds.get_last_webhook_failures(5)
    visible = _pill_visible(stats, failures)
    ok = stats.get("pending") == 1 and visible
    print(f"  pending without last_error shows pill: {ok}  visible={visible}")
    return ok


def main():
    results = [
        ("dropped_stale_pill", test_dropped_stale_only_shows_pill()),
        ("silent_dropped_hidden", test_dropped_stale_without_error_hidden()),
        ("pending_pill", test_pending_without_error_still_shows_pill()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook fail pill visibility checks passed.")


if __name__ == "__main__":
    main()
