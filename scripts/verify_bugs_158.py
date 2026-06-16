"""Regression: deferred reminder gate + aggregate rebuild + Web ACK sync (Bug 158)."""
import os
import sys
import time

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
        "webhook_reminder_aggregate_enabled": True,
        "webhook_reminder_aggregate_threshold": 2,
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }
    base.update(overrides)
    return type("C", (), {"get_setting": lambda _s, k: base.get(k)})()


def _alerter(**cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_cfg(**cfg_kw))
    return a


def _install_push_capture(a, calls):
    def _capture(**kw):
        entry = {k: v for k, v in kw.items() if k != "rebuild"}
        rebuild = kw.get("rebuild")
        if rebuild is not None:
            rebuilt = rebuild()
            if rebuilt is None:
                return
            extra, message, target = rebuilt
            entry["extra"] = extra
            entry["message"] = message
            entry["target"] = target
        calls.append(entry)
    a._push_webhook = _capture


def test_individual_gate_blocks_after_ack():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    gate = ("incident", "t1", inc.push_seq)
    ok_before = a._webhook_gate_ok(gate)
    a.acknowledge_incident("t1")
    ok_after = a._webhook_gate_ok(gate)
    ok = ok_before and not ok_after
    print(f"Bug158 individual gate after ACK -> {ok}")
    return ok


def test_deferred_individual_reminder_dropped_after_ack():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    gate = ("incident", "t1", inc.push_seq)
    delivered = []

    def _deliver():
        if not a._webhook_gate_ok(gate):
            return
        delivered.append("alert_reminder")

    a._ensure_webhook_worker("t1").put(_deliver)
    a.acknowledge_incident("t1")
    a._webhook_queues["t1"].join()
    ok = delivered == []
    print(f"Bug158 deferred individual reminder dropped -> {ok} got={delivered}")
    return ok


def test_aggregate_payload_excludes_acked_node():
    a = _alerter(webhook_reminder_aggregate_threshold=1)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t2", "GW2", "10.0.0.2", "red")
    snaps = [
        a._snapshot_incident(a._webhook_incidents["t1"]),
        a._snapshot_incident(a._webhook_incidents["t2"]),
    ]
    a.acknowledge_incident("t1")
    sent = []
    _install_push_capture(a, sent)
    a._push_aggregate_reminder(snaps, time.time())
    nodes = sent[0]["extra"]["aggregate"]["nodes"] if sent else []
    tids = [n["tid"] for n in nodes]
    ok = sent and "t1" not in tids and "t2" in tids and len(tids) == 1
    print(f"Bug158 aggregate excludes ACK node -> {ok} tids={tids}")
    return ok


def test_aggregate_payload_excludes_recovered_node():
    a = _alerter(webhook_reminder_aggregate_threshold=1)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t2", "GW2", "10.0.0.2", "red")
    snaps = [
        a._snapshot_incident(a._webhook_incidents["t1"]),
        a._snapshot_incident(a._webhook_incidents["t2"]),
    ]
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    sent = []
    _install_push_capture(a, sent)
    a._push_aggregate_reminder(snaps, time.time())
    nodes = sent[0]["extra"]["aggregate"]["nodes"] if sent else []
    tids = [n["tid"] for n in nodes]
    ok = sent and "t1" not in tids and "t2" in tids
    print(f"Bug158 aggregate excludes recovered node -> {ok} tids={tids}")
    return ok


def test_web_update_target_carries_ack_status():
    if not FLASK_AVAILABLE:
        print("Bug158 web ack field -> skipped (no Flask)")
        return True
    ws = WebServer(port=0)
    ws._running = True
    ws.set_incident_ack_status_fn(lambda tid: tid == "t1")
    ws.update_target(
        tid="t1", label="GW", ip="10.0.0.1", status="red",
        latency_ms=None, jitter_ms=None, loss_rate=1.0,
    )
    ok_red = ws._targets["t1"].get("incident_acknowledged") is True
    ws.update_target(
        tid="t2", label="GW2", ip="10.0.0.2", status="red",
        latency_ms=None, jitter_ms=None, loss_rate=1.0,
    )
    ok_other = ws._targets["t2"].get("incident_acknowledged") is False
    ws.update_target(
        tid="t1", label="GW", ip="10.0.0.1", status="green",
        latency_ms=1.0, jitter_ms=0.0, loss_rate=0.0,
    )
    ok_green = ws._targets["t1"].get("incident_acknowledged") is False
    ok = ok_red and ok_other and ok_green
    print(f"Bug158 web incident_acknowledged field -> {ok}")
    return ok


def test_source_gate_and_aggregate_rebuild():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        am = f.read()
    with open(WEB_SERVER, encoding="utf-8") as f:
        ws = f.read()
    gate = am.split("def _webhook_gate_ok", 1)[1].split(
        "def _ensure_webhook_worker", 1)[0]
    agg = am.split("def _push_aggregate_reminder", 1)[1].split(
        "def _build_aggregate_reminder_extra", 1)[0]
    ok = (
        "if inc.acknowledged:" in gate
        and "_eligible_red_reminder_snaps" in am
        and "rebuild=rebuild" in agg
        and "incident_acknowledged" in ws
        and "set_incident_ack_status_fn" in ws
    )
    print(f"Bug158 source gate + web ack field -> {ok}")
    return ok


def main():
    results = [
        ("gate", test_individual_gate_blocks_after_ack()),
        ("deferred", test_deferred_individual_reminder_dropped_after_ack()),
        ("agg_ack", test_aggregate_payload_excludes_acked_node()),
        ("agg_rec", test_aggregate_payload_excludes_recovered_node()),
        ("web_field", test_web_update_target_carries_ack_status()),
        ("source", test_source_gate_and_aggregate_rebuild()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 158 checks passed.")


if __name__ == "__main__":
    main()
