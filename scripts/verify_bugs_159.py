"""Regression: reminder gate red-only + live Web ACK sync (post-158 review)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.web_server import WebServer, FLASK_AVAILABLE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")


def _cfg(**overrides):
    base = {
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_reminder_enabled": True,
        "webhook_reminder_interval_min": 1,
        "webhook_reminder_max_count": 0,
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }
    base.update(overrides)
    return type("C", (), {"get_setting": lambda _s, k: base.get(k)})()


def _alerter(**cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_cfg(**cfg_kw))
    return a


def test_reminder_gate_blocks_after_orange():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    gate = ("reminder", "t1", inc.push_seq)
    ok_before = a._webhook_gate_ok(gate)
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    ok_after = a._webhook_gate_ok(gate)
    ok = ok_before and not ok_after and inc.current_status == "orange"
    print(f"Bug159 reminder gate after orange -> {ok}")
    return ok


def test_deferred_reminder_dropped_after_orange():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    gate = ("reminder", "t1", inc.push_seq)
    delivered = []

    def _deliver():
        if not a._webhook_gate_ok(gate):
            return
        delivered.append("alert_reminder")

    a._ensure_webhook_worker("t1").put(_deliver)
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    a._webhook_queues["t1"].join()
    ok = delivered == []
    print(f"Bug159 deferred reminder dropped after orange -> {ok} got={delivered}")
    return ok


def test_incident_gate_allows_orange_diagnostic():
    a = _alerter(webhook_trace_update_enabled=True)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    gate = ("incident", "t1", inc.push_seq)
    ok = a._webhook_gate_ok(gate) and inc.current_status == "orange"
    print(f"Bug159 incident gate allows orange diagnostic -> {ok}")
    return ok


def test_targets_for_client_live_ack():
    if not FLASK_AVAILABLE:
        print("Bug159 live ack on read -> skipped (no Flask)")
        return True
    ack_state = {"t1": False}

    ws = WebServer(port=0)
    ws._running = True
    ws.set_incident_ack_status_fn(lambda tid: ack_state.get(tid, False))
    ws.update_target(
        tid="t1", label="GW", ip="10.0.0.1", status="red",
        latency_ms=None, jitter_ms=None, loss_rate=1.0,
    )
    ok_initial = ws._targets["t1"]["incident_acknowledged"] is False
    rows_before = ws._targets_for_client()
    ok_before = rows_before[0]["incident_acknowledged"] is False

    ack_state["t1"] = True
    ok_cache_stale = ws._targets["t1"]["incident_acknowledged"] is False
    rows_after = ws._targets_for_client()
    ok_live = rows_after[0]["incident_acknowledged"] is True

    ok = ok_initial and ok_before and ok_cache_stale and ok_live
    print(f"Bug159 /api/status live ack without update_target -> {ok}")
    return ok


def test_sync_target_ack_status_updates_cache():
    if not FLASK_AVAILABLE:
        print("Bug159 sync_target_ack_status -> skipped (no Flask)")
        return True
    ack_state = {"t1": False}

    ws = WebServer(port=0)
    ws._running = True
    ws.set_incident_ack_status_fn(lambda tid: ack_state.get(tid, False))
    ws.update_target(
        tid="t1", label="GW", ip="10.0.0.1", status="red",
        latency_ms=None, jitter_ms=None, loss_rate=1.0,
    )
    ack_state["t1"] = True
    ws.sync_target_ack_status("t1")
    ok = ws._targets["t1"]["incident_acknowledged"] is True
    print(f"Bug159 sync_target_ack_status cache -> {ok}")
    return ok


def test_source_reminder_gate_and_live_ack():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        am = f.read()
    with open(WEB_SERVER, encoding="utf-8") as f:
        ws = f.read()
    gate = am.split("def _webhook_gate_ok", 1)[1].split(
        "def _ensure_webhook_worker", 1)[0]
    ok = (
        'gate=("reminder"' in am
        and 'kind == "reminder"' in gate
        and "current_status == \"red\"" in gate
        and "current_status in (\"red\", \"orange\")" in gate
        and "_targets_for_client" in ws
        and "sync_target_ack_status" in ws
        and "self._targets_for_client()" in ws
    )
    print(f"Bug159 source reminder gate + live ack -> {ok}")
    return ok


def main():
    results = [
        ("orange_gate", test_reminder_gate_blocks_after_orange()),
        ("deferred_orange", test_deferred_reminder_dropped_after_orange()),
        ("diag_orange", test_incident_gate_allows_orange_diagnostic()),
        ("live_ack", test_targets_for_client_live_ack()),
        ("sync_ack", test_sync_target_ack_status_updates_cache()),
        ("source", test_source_reminder_gate_and_live_ack()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 159 checks passed.")


if __name__ == "__main__":
    main()
