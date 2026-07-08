"""Regression: clear stale diagnostic/reminder when a new incident opens (B0)."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")


def _flush(disp, n=10, delay=0.02):
    for _ in range(n):
        disp._tick()
        time.sleep(delay)


def _get_row(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=50)
    for r in rows:
        if r.get("delivery_id") == delivery_id:
            return r
    return {}


def test_source_new_incident_aux_cleanup():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def _clear_stale_aux_outbox_for_new_incident" in src
        and "stale_incident_aux_cleared" in src
        and "diagnostic_update\", \"alert_reminder\"" in src
        and "if is_new:" in src
        and "_clear_stale_aux_outbox_for_new_incident(target_id)" in src
        and "will_new_incident" in src
    )
    print(f"source new-incident aux cleanup hook -> {ok}")
    return ok


def test_stale_diagnostic_dropped_on_new_incident():
    a, disp, ds = make_alerter(
        targets=[{"id": "t1", "label": "GW", "ip": "10.0.0.1"}])
    delivered = []
    a._send_webhook = (
        lambda url, event, target, ip, status, message, ts_str,
        extra=None, **kw: delivered.append(event))

    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    _flush(disp)
    ok_first = "alert_red" in delivered

    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="D-DIAG-OLD",
        target_id="t1",
        incident_id="INC-OLD",
        incident_seq=1,
        event="diagnostic_update",
        order_key="t1",
        payload={
            "event": "diagnostic_update", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "old diag", "extra": {},
            "gate": ["diagnostic_update", "t1", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=8,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=?, last_error='fail' "
            "WHERE delivery_id=?",
            (now + 300, "D-DIAG-OLD"))
        conn.commit()

    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    delivered.clear()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    diag = _get_row(ds, "D-DIAG-OLD")
    ok_drop = diag.get("delivery_state") == "dropped_stale"
    ok_err = diag.get("last_error") == "stale_incident_aux_cleared"

    _flush(disp, n=12)
    ok_order = delivered == ["recovery", "alert_red"]
    ok = ok_first and ok_drop and ok_err and ok_order
    print(
        f"stale diagnostic cleared -> {ok} "
        f"drop={ok_drop} order={delivered}"
    )
    return ok


def test_short_flap_alert_red_not_dropped():
    a, disp, ds = make_alerter(
        targets=[{"id": "t1", "label": "GW", "ip": "10.0.0.1"}])
    delivered = []
    a._send_webhook = (
        lambda url, event, target, ip, status, message, ts_str,
        extra=None, **kw: delivered.append(event))

    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    seq = a._webhook_incidents["t1"].push_seq
    rows = ds.get_webhook_deliveries(target_id="t1", limit=5)
    red_id = next(r["delivery_id"] for r in rows if r["event"] == "alert_red")

    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    ok_gate = a._webhook_gate_ok(("alert_red", "t1", seq))
    _flush(disp, n=12)
    red1 = _get_row(ds, red_id)
    ok = (
        ok_gate
        and red1.get("delivery_state") == "delivered"
        and "alert_red" in delivered
        and "recovery" in delivered
        and delivered.index("alert_red") < delivered.index("recovery")
    )
    print(f"short flap keeps first alert_red -> {ok} delivered={delivered}")
    return ok


def test_reminder_also_cleared():
    a, disp, ds = make_alerter(
        targets=[{"id": "t1", "label": "GW", "ip": "10.0.0.1"}])
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="D-REM-OLD",
        target_id="t1",
        incident_id="INC-OLD",
        incident_seq=1,
        event="alert_reminder",
        order_key="t1",
        payload={
            "event": "alert_reminder", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "old reminder", "extra": {},
            "gate": ["reminder", "t1", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=12,
    )
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    rem = _get_row(ds, "D-REM-OLD")
    ok = (
        rem.get("delivery_state") == "dropped_stale"
        and rem.get("last_error") == "stale_incident_aux_cleared"
    )
    print(f"stale reminder cleared on new incident -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_new_incident_aux_cleanup()),
        ("diag", test_stale_diagnostic_dropped_on_new_incident()),
        ("flap", test_short_flap_alert_red_not_dropped()),
        ("reminder", test_reminder_also_cleared()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All stale outbox on new incident checks passed.")


if __name__ == "__main__":
    main()
