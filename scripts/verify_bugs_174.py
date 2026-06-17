"""Regression: restart seq reuse + deleted-target alert_red gate (Bugs 174)."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter, install_push_capture
from src.alert_manager import AlertManager
from src.data_store import DataStore


def _mk_store():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    return ds, td


def _row(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=200)
    row = next(r for r in rows if r["delivery_id"] == delivery_id)
    row = dict(row)
    row["payload_json"] = json.dumps(row.pop("payload", {}), ensure_ascii=False)
    return row


def _insert_open_red(ds, *, tid="t"):
    started = time.time() - 600
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1",
        ts=started, old_status="green", new_status="red",
        category="availability", failure_reason="no_reply", ping_type="icmp")
    ds.flush()
    time.sleep(0.25)
    open_inc = ds.get_open_incidents([tid])
    return open_inc[tid]["incident_id"]


def test_restart_stale_gates_blocked():
    """Old pending rows for a superseded incident must not survive reseed."""
    ds, _ = _mk_store()
    open_iid = _insert_open_red(ds)
    superseded_iid = f"{open_iid}-OLD"
    seq = 1
    for ev, gate in (
        ("alert_red", ("alert_red", "t", seq)),
        ("alert_reminder", ("reminder", "t", seq)),
        ("diagnostic_update", ("incident", "t", seq)),
    ):
        ds.enqueue_webhook_outbox(
            delivery_id=f"OLD-{ev}",
            target_id="t",
            incident_id=superseded_iid,
            incident_seq=seq,
            event=ev,
            order_key="t",
            payload={
                "event": ev,
                "target": "GW", "ip": "10.0.0.1", "status": "red",
                "message": "stale", "gate": list(gate), "event_ts": time.time(),
            },
            event_ts=time.time(),
            max_attempts=12,
        )

    a2, _, _ = make_alerter(ds=ds)
    a2.reseed_webhook_incidents(
        [{"id": "t", "label": "GW", "ip": "10.0.0.1"}], set())

    ok = True
    for did in ("OLD-alert_red", "OLD-alert_reminder", "OLD-diagnostic_update"):
        st = ds.get_webhook_outbox_delivery_state(did)
        ok = ok and st == "dropped_stale"
    open_inc = ds.get_open_incidents(["t"])
    ok = ok and open_inc["t"]["incident_id"] == open_iid
    print(f"Bug174 restart stale rows dropped -> {ok}")
    return ok


def test_restart_open_incident_no_duplicate_catchup():
    """Pending alert_red for open incident: no second catch-up enqueue."""
    ds, _ = _mk_store()
    iid = _insert_open_red(ds)

    a1, _, _ = make_alerter(ds=ds)
    a1.reseed_webhook_incidents(
        [{"id": "t", "label": "GW", "ip": "10.0.0.1"}], set())
    pending_before = sum(
        1 for r in ds.get_webhook_deliveries(limit=50)
        if r.get("event") == "alert_red"
        and r.get("delivery_state") in ("pending", "sending"))

    a2, _, _ = make_alerter(ds=ds)
    a2.reseed_webhook_incidents(
        [{"id": "t", "label": "GW", "ip": "10.0.0.1"}], set())
    pending_after = sum(
        1 for r in ds.get_webhook_deliveries(limit=50)
        if r.get("event") == "alert_red"
        and r.get("delivery_state") in ("pending", "sending"))
    ok = pending_after == pending_before and pending_before >= 1
    print(f"Bug174 no duplicate catch-up alert_red -> {ok} ({pending_before}->{pending_after})")
    return ok


def test_deleted_target_alert_red_blocked():
    ds, _ = _mk_store()
    a, disp, ds = make_alerter()
    calls = []
    flush = install_push_capture(a, calls, disp)

    ds.enqueue_webhook_outbox(
        delivery_id="DEL-RED",
        target_id="deleted",
        incident_id="inc-old",
        incident_seq=1,
        event="alert_red",
        order_key="deleted",
        payload={
            "event": "alert_red",
            "target": "gone", "ip": "1.2.3.4", "status": "red",
            "message": "stale", "gate": ["alert_red", "deleted", 1],
            "event_ts": time.time(),
        },
        event_ts=time.time(),
        max_attempts=0,
    )
    a.reseed_webhook_incidents(
        [{"id": "alive", "label": "OK", "ip": "10.0.0.2"}], set())
    flush(6)
    st = ds.get_webhook_outbox_delivery_state("DEL-RED")
    ok = st == "dropped_stale" and not any(
        c.get("event") == "alert_red" for c in calls)
    print(f"Bug174 deleted target alert_red blocked -> {ok} state={st}")
    return ok


def test_short_flap_alert_red_still_delivers():
    a, disp, _ = make_alerter()
    calls = []
    flush = install_push_capture(a, calls, disp)
    a.on_status_change("t", "GW", "10.0.0.1", "red")
    seq = a._webhook_incidents["t"].push_seq
    a.on_status_change("t", "GW", "10.0.0.1", "green")
    ok_gate = a._webhook_gate_ok(("alert_red", "t", seq))
    flush(10)
    ok = (
        ok_gate
        and "alert_red" in [c["event"] for c in calls]
        and "recovery" in [c["event"] for c in calls]
    )
    print(f"Bug174 short flap alert_red still delivers -> {ok}")
    return ok


def test_deleted_target_failed_red_stops_retrying():
    ds, _ = _mk_store()
    a, disp, ds = make_alerter()
    attempts = []

    def fail_send(*args, **kwargs):
        attempts.append(1)
        raise OSError("network down")

    a._send_webhook = staticmethod(fail_send)
    ds.enqueue_webhook_outbox(
        delivery_id="DEL-FAIL",
        target_id="deleted",
        incident_id="inc-x",
        incident_seq=1,
        event="alert_red",
        order_key="deleted",
        payload={
            "event": "alert_red",
            "target": "gone", "ip": "1.2.3.4", "status": "red",
            "message": "stale", "gate": ["alert_red", "deleted", 1],
            "event_ts": time.time(),
        },
        event_ts=time.time(),
        max_attempts=0,
    )
    a.reseed_webhook_incidents(
        [{"id": "alive", "label": "OK", "ip": "10.0.0.2"}], set())
    for _ in range(4):
        disp._tick()
        time.sleep(0.02)
    st = ds.get_webhook_outbox_delivery_state("DEL-FAIL")
    ok = st == "dropped_stale" and len(attempts) == 0
    print(f"Bug174 deleted target no infinite retry -> {ok} attempts={len(attempts)}")
    return ok


def main():
    results = [
        ("stale_gates", test_restart_stale_gates_blocked()),
        ("no_dup_catchup", test_restart_open_incident_no_duplicate_catchup()),
        ("deleted_red", test_deleted_target_alert_red_blocked()),
        ("short_flap", test_short_flap_alert_red_still_delivers()),
        ("no_infinite_retry", test_deleted_target_failed_red_stops_retrying()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 174 checks passed.")


if __name__ == "__main__":
    main()
