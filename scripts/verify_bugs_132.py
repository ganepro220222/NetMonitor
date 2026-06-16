"""Regression checks for Phase 4.1 reseed + Phase 4.2 ACK."""
import os
import sys
import tempfile
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


def _insert_open_red(ds: DataStore, tid="t1", started=None):
    started = started or (time.time() - 3600)
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1",
        ts=started, old_status="green", new_status="red",
        category="loss")
    ds.flush()
    time.sleep(0.2)


def _alerter(ds=None):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    if ds:
        a.set_data_store(ds)
    return a


def test_get_open_incidents_from_db():
    ds, _ = _mk_store()
    started = time.time() - 7200
    _insert_open_red(ds, started=started)
    open_inc = ds.get_open_incidents(["t1"])
    ok = (
        "t1" in open_inc
        and open_inc["t1"]["last_status"] == "red"
        and abs(open_inc["t1"]["started_at"] - started) < 2
    )
    print(f"Bug132 get_open_incidents -> {ok}")
    return ok


def test_green_not_reseeded():
    ds, _ = _mk_store()
    ts = time.time()
    ds.record_alert(target_id="t1", label="GW", ip="10.0.0.1",
                    ts=ts, old_status="red", new_status="green", category="recovery")
    ds.flush()
    time.sleep(0.2)
    ok = ds.get_open_incidents(["t1"]) == {}
    print(f"Bug132 green not open -> {ok}")
    return ok


def test_reseed_sends_catchup_alert_red():
    ds, _ = _mk_store()
    started = time.time() - 1800
    _insert_open_red(ds, started=started)
    from scripts.webhook_test_util import make_alerter, install_push_capture
    a, disp, _ds = make_alerter(ds=ds)
    calls = []
    flush = install_push_capture(a, calls, disp)
    n = a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    flush()
    inc = a._webhook_incidents.get("t1")
    ok = (
        n == 1
        and inc is not None
        and abs(inc.started_at - started) < 2
        and any(c["event"] == "alert_red" for c in calls)
        and any("重启后续报" in c["message"] for c in calls)
    )
    print(f"Bug132 reseed catch-up alert_red -> {ok}")
    return ok


def test_reseed_skips_paused():
    ds, _ = _mk_store()
    _insert_open_red(ds)
    a = _alerter(ds)
    n = a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], {"t1"})
    ok = n == 0 and "t1" not in a._webhook_incidents
    print(f"Bug132 reseed skips paused -> {ok}")
    return ok


def test_reseed_reminder_after_interval():
    ds, _ = _mk_store()
    _insert_open_red(ds)
    a = _alerter(ds)
    a.set_config(type("C", (), {"get_setting": lambda _s, k: {
        "webhook_reminder_enabled": True,
        "webhook_reminder_interval_min": 1,
        "webhook_reminder_max_count": 0,
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }.get(k)})())
    a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    a._webhook_incidents["t1"].last_reminder_at = 0
    a._webhook_incidents["t1"].current_status = "red"
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    ok = any(c["event"] == "alert_reminder" for c in calls)
    print(f"Bug132 reseeded reminder works -> {ok}")
    return ok


def test_ack_stops_reminder_recovery_still_possible():
    ds, _ = _mk_store()
    _insert_open_red(ds)
    a = _alerter(ds)
    a.set_config(type("C", (), {"get_setting": lambda _s, k: {
        "webhook_reminder_enabled": True,
        "webhook_reminder_interval_min": 1,
        "webhook_reminder_max_count": 0,
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }.get(k)})())
    a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    a.acknowledge_incident("t1")
    a._webhook_incidents["t1"].last_reminder_at = 0
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    a._tick_webhook_reminders()
    no_rem = not any(c["event"] == "alert_reminder" for c in calls)
    a.seed_status_tracking({"t1": "red"})
    calls.clear()
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    has_rec = any(c["event"] == "recovery" for c in calls)
    ok = no_rem and has_rec
    print(f"Bug132 ACK stops reminder, recovery sends -> {ok}")
    return ok


def test_ack_blocks_diagnostic_update():
    ds, _ = _mk_store()
    _insert_open_red(ds)
    a = _alerter(ds)
    a.set_config(type("C", (), {"get_setting": lambda _s, k: {
        "webhook_trace_update_enabled": True,
        "webhook_trace_change_only": True,
        "webhook_include_trace": True,
    }.get(k)})())
    a.reseed_webhook_incidents(
        [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}], set())
    a.acknowledge_incident("t1")
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw)
    hops = [{"hop": 1, "status": "ok", "ip": "10.0.0.1"}]
    a.on_traceroute_result({
        "tid": "t1", "label": "GW", "ip": "10.0.0.1",
        "ts": time.time(), "hops": hops,
    })
    ok = not any(c["event"] == "diagnostic_update" for c in calls)
    print(f"Bug132 ACK blocks diagnostic_update -> {ok}")
    return ok


def test_new_incident_after_recovery_not_acked():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.acknowledge_incident("t1")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents.get("t1")
    ok = inc is not None and inc.acknowledged is False
    print(f"Bug132 new incident clears ACK -> {ok}")
    return ok


def test_acknowledge_alarm_does_not_ack_incident():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.acknowledge_alarm()
    inc = a._webhook_incidents.get("t1")
    ok = inc is not None and inc.acknowledged is False
    print(f"Bug132 sound ACK != incident ACK -> {ok}")
    return ok


def test_seed_status_tracking_red():
    a = _alerter()
    a.seed_status_tracking({"t1": "red", "t2": "green"})
    ok = (
        a._last_alert_status.get("t1") == "red"
        and "t1" in a._red_targets
        and "t2" not in a._red_targets
    )
    print(f"Bug132 seed_status_tracking -> {ok}")
    return ok


def main():
    results = [
        ("open_inc", test_get_open_incidents_from_db()),
        ("no_green", test_green_not_reseeded()),
        ("reseed", test_reseed_sends_catchup_alert_red()),
        ("skip_pause", test_reseed_skips_paused()),
        ("reseed_reminder", test_reseed_reminder_after_interval()),
        ("ack_reminder", test_ack_stops_reminder_recovery_still_possible()),
        ("ack_diag", test_ack_blocks_diagnostic_update()),
        ("new_inc", test_new_incident_after_recovery_not_acked()),
        ("sound_sep", test_acknowledge_alarm_does_not_ack_incident()),
        ("seed_track", test_seed_status_tracking_red()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 132 checks passed.")


if __name__ == "__main__":
    main()
