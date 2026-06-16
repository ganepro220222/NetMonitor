"""Regression: ACK/pause/remove must abort gated reminder before network send."""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter


def _outbox_row(ds, delivery_id: str) -> dict:
    rows = ds.get_webhook_deliveries(limit=100)
    row = next(r for r in rows if r["delivery_id"] == delivery_id)
    row = dict(row)
    row["payload_json"] = json.dumps(row.pop("payload", {}), ensure_ascii=False)
    return row


def _race_scenario(*, action: str, delivery_id: str):
    """Dispatcher enters _send_webhook; main thread ACK/pause/remove during block."""
    a, disp, ds = make_alerter()
    sent = []
    entered = threading.Event()
    release = threading.Event()
    rem_gate = None

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, *, event_ts=None, queued_ts=None, sent_ts=None,
              attempt=1, delivery_id="", gate=None):
        entered.set()
        release.wait(timeout=5)
        a.assert_outbox_webhook_send_allowed(delivery_id=delivery_id, gate=gate)
        sent.append((event, delivery_id))

    a._send_webhook = _send
    a.on_status_change("race", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["race"]
    rem_gate = ("reminder", "race", inc.push_seq)
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='delivered', "
            "delivered_ts=?, updated_at=? "
            "WHERE target_id='race' AND event='alert_red'",
            (time.time(), time.time()))
        conn.commit()
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id="race",
        incident_id=inc.incident_id,
        incident_seq=inc.push_seq,
        event="alert_reminder",
        order_key="race",
        payload={
            "event": "alert_reminder",
            "target": "GW",
            "ip": "10.0.0.1",
            "status": "red",
            "message": "连接仍未恢复",
            "extra": a._build_reminder_extra(a._snapshot_incident(inc)),
            "gate": list(rem_gate),
            "event_ts": time.time(),
        },
        event_ts=time.time(),
        max_attempts=12,
    )
    row = _outbox_row(ds, delivery_id)

    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    t.start()
    assert entered.wait(timeout=5), "dispatcher did not reach _send_webhook"

    if action == "ack":
        assert a.acknowledge_incident("race")
        expected_error = "acknowledged"
    elif action == "pause":
        a.on_target_paused("race")
        expected_error = "target_paused"
    else:
        a.on_target_removed("race")
        expected_error = "target_removed"

    release.set()
    t.join(timeout=5)

    rem = _outbox_row(ds, delivery_id)
    return {
        "action": action,
        "sent": sent,
        "rows": [(rem["delivery_id"], rem["delivery_state"], rem["last_error"])],
        "expected_error": expected_error,
    }


def _check_during_send(r):
    ok = (
        r["sent"] == []
        and r["rows"][0][1] == "dropped_stale"
        and r["rows"][0][2] == r["expected_error"]
    )
    print(f"Bug165 {r['action']} during _send_webhook -> {ok} {r}")
    return ok


def test_ack_during_send():
    return _check_during_send(
        _race_scenario(action="ack", delivery_id="ack-during_send"))


def test_pause_during_send():
    return _check_during_send(
        _race_scenario(action="pause", delivery_id="pause-during_send"))


def test_remove_during_send():
    return _check_during_send(
        _race_scenario(action="remove", delivery_id="remove-during_send"))


def main():
    results = [
        ("ack_during_send", test_ack_during_send()),
        ("pause_during_send", test_pause_during_send()),
        ("remove_during_send", test_remove_during_send()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 165 checks passed.")


if __name__ == "__main__":
    main()
