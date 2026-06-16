"""Regression: webhook incident ACK persists across restart (Bug 156)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")


def _cfg(**overrides):
    base = {
        "webhook_reminder_enabled": True,
        "webhook_reminder_interval_min": 1,
        "webhook_reminder_max_count": 0,
        "webhook_url": "http://127.0.0.1:9/hook",
        "webhook_include_trace": False,
        "webhook_trace_update_enabled": False,
    }
    base.update(overrides)
    return type("C", (), {"get_setting": lambda _s, k: base.get(k)})()


def _insert_open_red(ds, tid="t1", started=None):
    started = started or (time.time() - 3600)
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1",
        ts=started, old_status="green", new_status="red",
        category="loss", ping_type="icmp", failure_reason="no_reply",
    )
    ds.flush()
    time.sleep(0.2)


def _alerter(ds):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_data_store(ds)
    a.set_config(_cfg())
    return a


def _reseed(a, tid="t1"):
    return a.reseed_webhook_incidents(
        [{"id": tid, "label": "GW", "ip": "10.0.0.1"}], set())


def _tick_reminders(a):
    calls = []
    a._push_webhook = lambda **kw: calls.append(kw["event"])
    a._webhook_incidents["t1"].last_reminder_at = 0
    a._webhook_incidents["t1"].current_status = "red"
    a._tick_webhook_reminders()
    return calls


def test_ack_persists_across_restart():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds1 = DataStore(path)
        ds1._schema_ready.wait(timeout=5)
        _insert_open_red(ds1)
        a1 = _alerter(ds1)
        _reseed(a1)
        ack0 = a1._webhook_incidents["t1"].acknowledged
        before_ack = _tick_reminders(a1)
        a1.acknowledge_incident("t1")
        ds1.flush()
        ack1 = a1._webhook_incidents["t1"].acknowledged
        after_ack = _tick_reminders(a1)
        ds1.shutdown()

        ds2 = DataStore(path)
        ds2._schema_ready.wait(timeout=5)
        a2 = _alerter(ds2)
        _reseed(a2)
        ack_after = a2._webhook_incidents["t1"].acknowledged
        after_restart = _tick_reminders(a2)
        ds2.shutdown()

        ok = (
            ack0 is False
            and ack1 is True
            and ack_after is True
            and "alert_reminder" in before_ack
            and "alert_reminder" not in after_ack
            and "alert_reminder" not in after_restart
        )
        print(f"Bug156 ACK survives restart -> {ok} "
              f"ack0={ack0} ack1={ack1} ack_after={ack_after}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_recovery_clears_ack_for_new_incident():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        _insert_open_red(ds)
        a = _alerter(ds)
        _reseed(a)
        a.acknowledge_incident("t1")
        ds.flush()
        iid1 = a._webhook_incidents["t1"].incident_id
        a.seed_status_tracking({"t1": "red"})
        a.on_status_change("t1", "GW", "10.0.0.1", "green")
        ds.record_alert(
            target_id="t1", label="GW", ip="10.0.0.1",
            ts=time.time(), old_status="red", new_status="green",
            category="recovery", ping_type="icmp", failure_reason="",
        )
        ds.flush()
        time.sleep(0.3)
        a.on_status_change("t1", "GW", "10.0.0.1", "red")
        ds.record_alert(
            target_id="t1", label="GW", ip="10.0.0.1",
            ts=time.time(), old_status="green", new_status="red",
            category="availability", ping_type="icmp",
            failure_reason="no_reply",
        )
        ds.flush()
        time.sleep(0.3)
        inc2 = a._webhook_incidents.get("t1")
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT 1 FROM webhook_ack WHERE incident_id=?", (iid1,),
        ).fetchone()
        conn.close()
        ds.shutdown()
        ok = (
            inc2 is not None
            and inc2.acknowledged is False
            and inc2.incident_id != iid1
            and row is None
        )
        print(f"Bug156 recovery clears ack for new incident -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_db_row_written_on_ack():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        _insert_open_red(ds)
        a = _alerter(ds)
        _reseed(a)
        iid = a._webhook_incidents["t1"].incident_id
        a.acknowledge_incident("t1")
        ds.flush()
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT target_id FROM webhook_ack WHERE incident_id=?", (iid,),
        ).fetchone()
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        ds.shutdown()
        ok = row is not None and row[0] == "t1" and ver >= 14
        print(f"Bug156 webhook_ack row + schema v14 -> {ok} (ver={ver})")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_persistence_wired():
    with open(DATA_STORE, encoding="utf-8") as f:
        ds_src = f.read()
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        am_src = f.read()
    reseed = am_src.split("def reseed_webhook_incidents", 1)[1].split(
        "def acknowledge_incident", 1)[0]
    ok = (
        "CREATE TABLE IF NOT EXISTS webhook_ack" in ds_src
        and "is_webhook_acknowledged" in ds_src
        and "record_webhook_ack" in ds_src
        and "is_webhook_acknowledged" in reseed
        and "_persist_incident_ack" in am_src
        and "acknowledged=acked" in reseed
    )
    print(f"Bug156 source persistence wired -> {ok}")
    return ok


def main():
    results = [
        ("restart", test_ack_persists_across_restart()),
        ("recovery", test_recovery_clears_ack_for_new_incident()),
        ("db_row", test_db_row_written_on_ack()),
        ("source", test_source_persistence_wired()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 156 checks passed.")


if __name__ == "__main__":
    main()
