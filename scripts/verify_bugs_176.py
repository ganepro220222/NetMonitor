"""Regression: ungated/malformed gate fail-closed + stale target cache (Bugs 176-178)."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter
from src.alert_manager import AlertManager
from src.data_store import DataStore


def _mk_store():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    return ds, td


def _enqueue(ds, *, delivery_id, target_id="deleted", event="alert_red",
             gate=None, payload_event=None):
    now = time.time()
    payload = {
        "event": payload_event or event,
        "target": "gone", "ip": "1.2.3.4", "status": "red",
        "message": "stale", "event_ts": now,
    }
    if gate is not None:
        payload["gate"] = gate
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id=target_id,
        incident_id="inc-old",
        incident_seq=1,
        event=event,
        order_key=target_id,
        payload=payload,
        event_ts=now,
        max_attempts=0,
    )


def _tick_capture(a, disp, ds, delivery_id):
    calls = []
    exc = []

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, **kw):
        calls.append((event, target, kw.get("delivery_id", "")))

    a._send_webhook = staticmethod(_send)

    def _tick():
        try:
            disp._tick()
        except Exception as e:
            exc.append(repr(e))

    return _send, _tick, calls, exc


def _state(ds, delivery_id):
    st = ds.get_webhook_outbox_delivery_state(delivery_id)
    rows = ds.get_webhook_deliveries(limit=50)
    row = next((r for r in rows if r["delivery_id"] == delivery_id), {})
    return st, row.get("last_error", "")


def test_ungated_deleted_no_get_targets():
    ds, _ = _mk_store()
    _enqueue(ds, delivery_id="ungated_no_cfg")
    a, disp, _ = make_alerter(ds=ds)
    _send, tick, calls, exc = _tick_capture(a, disp, ds, "ungated_no_cfg")
    tick()
    state, err = _state(ds, "ungated_no_cfg")
    ok = not calls and state == "dropped_stale" and err == "gate_or_rebuild" and not exc
    print(f"Bug176 ungated no get_targets -> {ok} calls={calls} state={state!r} err={err!r}")
    return ok


def test_ungated_deleted_empty_get_targets():
    ds, _ = _mk_store()
    _enqueue(ds, delivery_id="ungated_empty_cfg")
    a, disp, _ = make_alerter(ds=ds, targets=[])
    _send, tick, calls, exc = _tick_capture(a, disp, ds, "ungated_empty_cfg")
    tick()
    state, err = _state(ds, "ungated_empty_cfg")
    ok = not calls and state == "dropped_stale" and err == "target_orphan" and not exc
    print(f"Bug176 ungated empty get_targets -> {ok} calls={calls} state={state!r} err={err!r}")
    return ok


def test_ungated_deleted_get_targets_raises():
    ds, _ = _mk_store()
    _enqueue(ds, delivery_id="ungated_cfg_raises")

    class _Cfg:
        def get_setting(self, k):
            return {"webhook_url": "http://127.0.0.1:9/hook"}.get(k)

        def get_targets(self):
            raise RuntimeError("config broken")

    a = AlertManager(enabled=False, assets_dir=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets"))
    a.set_config(_Cfg())
    a.set_data_store(ds)
    from src.webhook_outbox import WebhookOutboxDispatcher
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)

    _send, tick, calls, exc = _tick_capture(a, disp, ds, "ungated_cfg_raises")
    tick()
    state, err = _state(ds, "ungated_cfg_raises")
    ok = not calls and state == "dropped_stale" and not exc
    print(f"Bug176 ungated get_targets raises -> {ok} calls={calls} state={state!r} err={err!r}")
    return ok


def test_malformed_gate_short_no_crash():
    ds, _ = _mk_store()
    cases = [
        ("mg_empty", []),
        ("mg_one", ["alert_red"]),
        ("mg_two", ["alert_red", "deleted"]),
    ]
    ok = True
    for did, gate in cases:
        _enqueue(ds, delivery_id=did, gate=gate)
        a, disp, _ = make_alerter(ds=ds)
        _send, tick, calls, exc = _tick_capture(a, disp, ds, did)
        tick()
        state, err = _state(ds, did)
        case_ok = not calls and not exc and state == "dropped_stale"
        ok = ok and case_ok
        print(f"  {did} exc={exc} state={state!r} err={err!r} -> {case_ok}")
    print(f"Bug177 malformed short gate -> {ok}")
    return ok


def test_malformed_gate_fail_open_kinds():
    ds, _ = _mk_store()
    cases = [
        ("mg_str", "alert_red"),
        ("mg_unknown", ["unknown", "deleted", 1]),
        ("mg_dict", {"kind": "alert_red"}),
    ]
    ok = True
    for did, gate in cases:
        _enqueue(ds, delivery_id=did, gate=gate)
        a, disp, _ = make_alerter(ds=ds)
        _send, tick, calls, exc = _tick_capture(a, disp, ds, did)
        tick()
        state, err = _state(ds, did)
        case_ok = not calls and not exc and state == "dropped_stale"
        ok = ok and case_ok
        print(f"  {did} calls={calls} state={state!r} -> {case_ok}")
    print(f"Bug177 malformed/unknown gate fail-closed -> {ok}")
    return ok


def test_recovery_has_gate_on_status_change():
    a, disp, ds = make_alerter()
    a.on_status_change("t", "GW", "10.0.0.1", "red")
    a.on_status_change("t", "GW", "10.0.0.1", "green")
    rows = [r for r in ds.get_webhook_deliveries(limit=20) if r["event"] == "recovery"]
    ok = len(rows) == 1 and rows[0]["payload"].get("gate", [None])[0] == "recovery"
    print(f"Bug176 recovery enqueued with gate -> {ok} gate={rows[0]['payload'].get('gate') if rows else None}")
    return ok


def test_stale_known_cache_cleared_on_config_failure():
    ds, _ = _mk_store()
    a, _, _ = make_alerter(
        ds=ds, targets=[{"id": "alive", "label": "A", "ip": "1.1.1.1"}])
    a.reseed_webhook_incidents(
        [{"id": "alive", "label": "A", "ip": "1.1.1.1"}], set())
    a._webhook_known_targets.add("deleted")

    class _Broken:
        def get_setting(self, k):
            return {"webhook_url": "http://127.0.0.1:9/hook"}.get(k)

        def get_targets(self):
            raise RuntimeError("broken")

    a.set_config(_Broken())
    a._webhook_outbox_baselines_restored = False
    a.ensure_webhook_outbox_baselines()
    ok = (
        not a._webhook_known_targets_initialized
        and "deleted" not in a._webhook_known_targets
        and "alive" not in a._webhook_known_targets
        and not a._webhook_target_known("deleted")
    )
    print(f"Bug178 stale cache cleared on config failure -> {ok} known={a._webhook_known_targets}")
    return ok


def main():
    results = [
        ("ungated_no_cfg", test_ungated_deleted_no_get_targets()),
        ("ungated_empty_cfg", test_ungated_deleted_empty_get_targets()),
        ("ungated_cfg_raises", test_ungated_deleted_get_targets_raises()),
        ("malformed_short", test_malformed_gate_short_no_crash()),
        ("malformed_kinds", test_malformed_gate_fail_open_kinds()),
        ("recovery_gate", test_recovery_has_gate_on_status_change()),
        ("stale_cache", test_stale_known_cache_cleared_on_config_failure()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 176 checks passed.")


if __name__ == "__main__":
    main()
