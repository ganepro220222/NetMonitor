"""Regression: reliable webhook outbox delivery (Phases 1-4)."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import (
    WebhookOutboxDispatcher,
    compute_next_attempt_ts,
    CLOSED_SUMMARY_DELAY_SEC,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")
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


def _mk_store():
    td = tempfile.mkdtemp()
    db = os.path.join(td, "t.db")
    ds = DataStore(db_path=db)
    ds._schema_ready.wait(timeout=5)
    return ds, td


def _alerter(ds=None, **cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_cfg(**cfg_kw))
    if ds:
        a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    return a, disp


def _capture_send(a):
    sent = []

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, **kw):
        sent.append({
            "event": event, "target": target, "message": message,
            "extra": extra, **kw,
        })

    a._send_webhook = staticmethod(_send)
    return sent


def _tick(disp, n=5, delay=0.03):
    for _ in range(n):
        disp._tick()
        time.sleep(delay)


def test_red_retry_success():
    ds, _ = _mk_store()
    a, disp = _alerter(ds)
    attempts = []

    def _send(*_a, **_k):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("connection refused")

    a._send_webhook = staticmethod(_send)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    disp._tick()
    rows = ds.get_webhook_deliveries(target_id="t1", limit=1)
    ok_first = (
        rows and rows[0]["delivery_state"] == "pending"
        and int(rows[0]["attempt_count"]) >= 1
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? WHERE target_id='t1'",
            (time.time(),))
        conn.commit()
    disp._tick()
    rows2 = ds.get_webhook_deliveries(target_id="t1", limit=1)
    ok = ok_first and rows2 and rows2[0]["delivery_state"] == "delivered"
    print(f"Bug161 red retry success -> {ok}")
    return ok


def test_reminder_dropped_after_ack():
    ds, _ = _mk_store()
    a, disp = _alerter(ds)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents["t1"]
    a._push_webhook(
        event="alert_reminder", target="GW", ip="10.0.0.1", status="red",
        message="连接仍未恢复",
        extra=a._build_reminder_extra(a._snapshot_incident(inc)),
        order_key="t1",
        gate=("reminder", "t1", inc.push_seq),
    )
    a.acknowledge_incident("t1")
    _capture_send(a)
    _tick(disp, 3)
    rows = [
        r for r in ds.get_webhook_deliveries(target_id="t1", limit=20)
        if r.get("event") == "alert_reminder"
    ]
    ok = rows and all(r["delivery_state"] == "dropped_stale" for r in rows)
    print(f"Bug161 reminder dropped after ACK -> {ok}")
    return ok


def test_aggregate_live_rebuild():
    ds, _ = _mk_store()
    a, disp = _alerter(ds, webhook_reminder_aggregate_threshold=1)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t2", "GW2", "10.0.0.2", "red")
    a.acknowledge_incident("t1")
    sent = _capture_send(a)
    tid_seq = [
        (a._webhook_incidents["t1"].tid, a._webhook_incidents["t1"].push_seq),
        (a._webhook_incidents["t2"].tid, a._webhook_incidents["t2"].push_seq),
    ]
    a._push_webhook(
        event="alert_reminder_aggregate",
        target="汇总", ip="", status="red", message="",
        order_key="_aggregate_",
        rebuild_spec={
            "type": "aggregate",
            "tid_seq_pairs": tid_seq,
            "threshold": 1,
        },
    )
    _tick(disp, 3)
    ok = any(s["event"] == "alert_reminder_aggregate" for s in sent)
    if ok:
        agg = next(s for s in sent if s["event"] == "alert_reminder_aggregate")
        nodes = (agg.get("extra") or {}).get("aggregate", {}).get("nodes", [])
        tids = [n["tid"] for n in nodes]
        ok = "t1" not in tids and "t2" in tids
    print(f"Bug161 aggregate live rebuild -> {ok}")
    return ok


def test_closed_summary_not_late_red():
    ds, _ = _mk_store()
    a, disp = _alerter(ds)
    sent = []

    def _send(*args, **kwargs):
        if args[1] == "alert_red":
            raise OSError("simulated failure")
        sent.append({"event": args[1]})

    a._send_webhook = staticmethod(_send)
    now = time.time()
    red_ts = now - CLOSED_SUMMARY_DELAY_SEC - 10
    extra = {
        "incident": {
            "started_at": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(red_ts)),
            "recovered_at": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "duration_text": "1 分钟",
            "recovered": True,
        },
        "trace": {},
    }
    red_id = a._make_delivery_id()
    rec_id = a._make_delivery_id()
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t1"] = 1
    ds.enqueue_webhook_outbox(
        delivery_id=red_id, target_id="t1", incident_id="INC1",
        incident_seq=1, event="alert_red", order_key="t1",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "连接中断", "extra": {},
            "gate": ["alert_red", "t1", 1], "event_ts": red_ts,
        },
        event_ts=red_ts, max_attempts=0,
    )
    ds.enqueue_webhook_outbox(
        delivery_id=rec_id, target_id="t1", incident_id="INC1",
        incident_seq=1, event="recovery", order_key="t1",
        payload={
            "event": "recovery", "target": "GW", "ip": "10.0.0.1",
            "status": "green", "message": "连接已恢复正常",
            "extra": extra, "gate": None, "event_ts": now,
        },
        event_ts=now, max_attempts=0,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=?, "
            "attempt_count=1, last_error='fail', delivery_state='pending' "
            "WHERE delivery_id=?",
            (red_ts, time.time(), red_id))
        conn.commit()
    _tick(disp, 6)
    events = [s["event"] for s in sent]
    ok = "alert_red" not in events and "incident_closed_summary" in events
    print(f"Bug161 closed summary not late red -> {ok} events={events}")
    return ok


def test_restart_pending_continues():
    ds, td = _mk_store()
    a, _disp = _alerter(ds)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    pending = ds.get_webhook_delivery_stats().get("pending", 0)
    ds.shutdown()
    ds2 = DataStore(db_path=os.path.join(td, "t.db"))
    ds2._schema_ready.wait(timeout=5)
    a2, disp2 = _alerter(ds2)
    sent = _capture_send(a2)
    _tick(disp2, 3)
    ok = pending >= 1 and any(s["event"] == "alert_red" for s in sent)
    print(f"Bug161 restart pending continues -> {ok}")
    ds2.shutdown()
    return ok


def test_ordering_red_before_recovery():
    ds, _ = _mk_store()
    a, disp = _alerter(ds)
    order = []
    a._send_webhook = staticmethod(
        lambda *a, **k: order.append(a[1]))
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    _tick(disp, 8)
    ok = order.index("alert_red") < order.index("recovery")
    print(f"Bug161 ordering red before recovery -> {ok} order={order}")
    return ok


def test_api_and_schema():
    with open(DATA_STORE, encoding="utf-8") as f:
        ds_src = f.read()
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        am_src = f.read()
    with open(WEB_SERVER, encoding="utf-8") as f:
        ws_src = f.read()
    ok = (
        "webhook_outbox" in ds_src
        and "PRAGMA user_version = 15" in ds_src
        and "enqueue_webhook_outbox" in ds_src
        and "fetch_deliverable_webhook_outbox" in ds_src
        and "prepare_outbox_delivery" in am_src
        and "rebuild_spec" in am_src
        and "incident_closed_summary" in am_src
        and "消息生成" in am_src
        and "/api/webhook/deliveries" in ws_src
        and "/api/webhook/stats" in ws_src
        and "webhook-fail-pill" in ws_src
    )
    print(f"Bug161 source schema + API + format -> {ok}")
    return ok


def main():
    results = [
        ("retry", test_red_retry_success()),
        ("ack_drop", test_reminder_dropped_after_ack()),
        ("agg", test_aggregate_live_rebuild()),
        ("closed", test_closed_summary_not_late_red()),
        ("restart", test_restart_pending_continues()),
        ("order", test_ordering_red_before_recovery()),
        ("source", test_api_and_schema()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 161 checks passed.")


if __name__ == "__main__":
    main()
