"""Regression checks for webhook reseed catch-up + delivery ordering (Bug 145)."""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _mk_store():
    td = tempfile.mkdtemp()
    db = os.path.join(td, "t.db")
    ds = DataStore(db_path=db)
    ds._schema_ready.wait(timeout=5)
    return ds, td


def _cfg():
    return type("C", (), {"get_setting": lambda _s, k: {
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_reminder_enabled": False,
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }.get(k)})()


def _alerter(ds=None):
    from scripts.webhook_test_util import make_alerter
    a, disp, ds = make_alerter(ds=ds)
    return a, disp


def _flush_outbox(a, disp, n=8, delay=0.02):
    for _ in range(n):
        disp._tick()
        time.sleep(delay)


def _insert_open_red(ds, *, tid="t1", started=None, fr="no_reply", pt="icmp"):
    started = started or (time.time() - 1800)
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1",
        ts=started, old_status="green", new_status="red",
        category="availability", failure_reason=fr, ping_type=pt)
    ds.flush()
    time.sleep(0.25)


def test_reseed_sends_catchup_alert_red():
    ds, _ = _mk_store()
    started = time.time() - 1800
    _insert_open_red(ds, started=started, fr="no_reply")
    a, disp = _alerter(ds)
    delivered = []
    a._send_webhook = staticmethod(
        lambda *a, **k: delivered.append({"event": a[1], "message": a[5]}))
    n = a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    _flush_outbox(a, disp)
    ok = (
        n == 1
        and any(d["event"] == "alert_red" for d in delivered)
        and any("重启后续报" in d["message"] for d in delivered)
    )
    print(f"Bug145 reseed catch-up alert_red -> {ok}")
    return ok


def test_reseed_restores_probe_fields():
    ds, _ = _mk_store()
    _insert_open_red(ds, fr="no_reply", pt="icmp")
    open_inc = ds.get_open_incidents(["t1"])
    ok = (
        open_inc["t1"].get("failure_reason") == "no_reply"
        and open_inc["t1"].get("ping_type") == "icmp"
    )
    a, disp = _alerter(ds)
    a.reseed_webhook_incidents([{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    inc = a._webhook_incidents["t1"]
    ok = ok and inc.failure_reason == "no_reply" and inc.ping_type == "icmp"
    print(f"Bug145 reseed probe fields -> {ok}")
    return ok


def test_stale_alert_red_dropped_after_new_incident():
    a, _disp = _alerter()
    order = []
    a._send_webhook = staticmethod(
        lambda *args, **kw: order.append(args[1]))
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    first_seq = a._webhook_incidents["t1"].push_seq
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    new_seq = a._webhook_incidents["t1"].push_seq
    ok_gate_old = not a._webhook_gate_ok(("alert_red", "t1", first_seq))
    ok_gate_new = a._webhook_gate_ok(("alert_red", "t1", new_seq))
    ok = ok_gate_old and ok_gate_new and new_seq > first_seq
    print(f"Bug145 stale seq invalidated on reopen -> {ok}")
    return ok


def test_delivery_order_red_before_recovery():
    a, disp = _alerter()
    order = []
    barrier = threading.Event()

    def slow_send(url, event, target, ip, status, message, ts_str, extra=None, **kw):
        if event == "alert_red":
            barrier.wait(timeout=2)
        order.append(event)

    a._send_webhook = staticmethod(slow_send)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    barrier.set()
    _flush_outbox(a, disp, n=12)
    ok = order == ["alert_red", "recovery"]
    print(f"Bug145 per-target queue order -> {ok} ({order})")
    return ok


def test_short_flap_alert_red_still_delivers():
    a, disp = _alerter()
    delivered = []
    a._send_webhook = staticmethod(
        lambda *args, **kw: delivered.append(args[1]))
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    seq = a._webhook_incidents["t1"].push_seq
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    ok_gate = a._webhook_gate_ok(("alert_red", "t1", seq))
    _flush_outbox(a, disp, n=12)
    ok = ok_gate and "alert_red" in delivered and "recovery" in delivered
    print(f"Bug145 short flap alert_red + recovery -> {ok}")
    return ok


def main():
    results = [
        ("catchup", test_reseed_sends_catchup_alert_red()),
        ("probe", test_reseed_restores_probe_fields()),
        ("stale", test_stale_alert_red_dropped_after_new_incident()),
        ("order", test_delivery_order_red_before_recovery()),
        ("flap", test_short_flap_alert_red_still_delivers()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 145 checks passed.")


if __name__ == "__main__":
    main()
