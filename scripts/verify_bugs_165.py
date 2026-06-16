"""Regression: ACK/pause must win race over in-flight gated reminder delivery."""
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
    """Dispatcher passes gate and blocks in _send_webhook; main thread ACK/pause."""
    a, disp, ds = make_alerter()
    sent = []
    gate = threading.Event()
    release = threading.Event()

    def _send(*_a, **_k):
        gate.set()
        release.wait(timeout=5)
        inc = a._webhook_incidents.get("race")
        sent.append({
            "event": _a[1],
            "delivery_id": _k.get("delivery_id"),
            "acked": bool(inc and inc.acknowledged),
            "incident_exists": inc is not None,
        })

    a._send_webhook = staticmethod(_send)
    a.on_status_change("race", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["race"]
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
            "gate": ["reminder", "race", inc.push_seq],
            "event_ts": time.time(),
        },
        event_ts=time.time(),
        max_attempts=12,
    )
    row = _outbox_row(ds, delivery_id)

    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    t.start()
    assert gate.wait(timeout=5), "dispatcher did not reach _send_webhook"

    if action == "ack":
        ok = a.acknowledge_incident("race")
        assert ok
    else:
        a.on_target_paused("race")

    release.set()
    t.join(timeout=5)

    rem = _outbox_row(ds, delivery_id)
    return {
        "action": action,
        "sent": sent,
        "rows": [(rem["delivery_id"], rem["delivery_state"], rem["last_error"])],
    }


def test_ack_race():
    r = _race_scenario(action="ack", delivery_id="ack-rem")
    ok = (
        r["rows"] == [("ack-rem", "dropped_stale", "acknowledged")]
        or (r["rows"][0][1] == "dropped_stale" and r["rows"][0][2] in (
            "acknowledged", "gate_or_rebuild"))
    )
    print(f"Bug165 ACK race -> {ok} {r}")
    return ok


def test_pause_race():
    r = _race_scenario(action="pause", delivery_id="pause-rem")
    ok = (
        r["rows"] == [("pause-rem", "dropped_stale", "target_paused")]
        or (r["rows"][0][1] == "dropped_stale" and r["rows"][0][2] in (
            "target_paused", "gate_or_rebuild"))
    )
    print(f"Bug165 pause race -> {ok} {r}")
    return ok


def main():
    results = [
        ("ack_race", test_ack_race()),
        ("pause_race", test_pause_race()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 165 checks passed.")


if __name__ == "__main__":
    main()
