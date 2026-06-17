"""Regression: gated recovery gate failure must not falsely supersede alert_red."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC, WebhookOutboxDispatcher


def _row_state(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=20)
    row = next((r for r in rows if r["delivery_id"] == delivery_id), {})
    return row.get("delivery_state", ""), row.get("last_error", "")


def test_gated_recovery_config_broken_no_false_supersede():
    from scripts.webhook_test_util import make_alerter
    from src.alert_manager import AlertManager
    from src.data_store import DataStore
    import tempfile

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    now = time.time()
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 30
    future_retry = now + 300
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
        delivery_id="rec", target_id="t", incident_id="INC",
        incident_seq=1, event="recovery", order_key="t",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": extra, "gate": ["recovery", "t", 1], "event_ts": now,
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
            "UPDATE webhook_outbox SET next_attempt_ts=? "
            "WHERE delivery_id='rec'",
            (now,))
        conn.commit()

    class _BrokenCfg:
        def get_setting(self, k):
            return {"webhook_url": "http://127.0.0.1:9/hook"}.get(k)

        def get_targets(self):
            raise RuntimeError("config broken")

    a = AlertManager(enabled=False, assets_dir=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets"))
    a.set_config(_BrokenCfg())
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    sent = []
    exc = []

    def _send(*args, **kwargs):
        sent.append((args[1], args[2], kwargs.get("delivery_id", "")))

    a._send_webhook = _send

    try:
        disp._tick()
    except Exception as e:
        exc.append(repr(e))

    rec_state = _row_state(ds, "rec")
    red_state = _row_state(ds, "red")
    ok = (
        not sent
        and not exc
        and rec_state[0] == "dropped_stale"
        and red_state[1] != "superseded_by_closed_summary"
    )
    print(
        f"Bug182 gated_recovery_config_broken -> {ok} sent={sent} exc={exc} "
        f"states={{'rec': {rec_state!r}, 'red': {red_state!r}}}")
    return ok


def test_gated_recovery_success_supersedes_red():
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "GW", "ip": "10.0.0.1"}])
    now = time.time()
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 30
    future_retry = now + 300
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
        delivery_id="rec", target_id="t", incident_id="INC",
        incident_seq=1, event="recovery", order_key="t",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": extra, "gate": ["recovery", "t", 1], "event_ts": now,
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
            "UPDATE webhook_outbox SET next_attempt_ts=? "
            "WHERE delivery_id='rec'",
            (now,))
        conn.commit()
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    sent = []

    def _send(*args, **kwargs):
        sent.append(args[1])

    a._send_webhook = _send
    disp._tick()
    red_state = _row_state(ds, "red")
    ok = (
        sent == ["incident_closed_summary"]
        and red_state == ("dropped_stale", "superseded_by_closed_summary")
    )
    print(
        f"Bug182 gated_recovery_success_supersedes_red -> {ok} sent={sent} "
        f"red={red_state}")
    return ok


def main():
    results = [
        ("config_broken", test_gated_recovery_config_broken_no_false_supersede()),
        ("success_supersedes", test_gated_recovery_success_supersedes_red()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 182 checks passed.")


if __name__ == "__main__":
    main()
