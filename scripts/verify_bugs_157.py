"""Regression: drop/pause webhook incident clears persisted ACK (Bug 157)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")


def _cfg():
    return type("C", (), {"get_setting": lambda _s, k: {
        "webhook_url": "http://127.0.0.1:9/hook",
    }.get(k)})()


def _insert_open_red(ds, tid="t1"):
    ds.record_alert(
        target_id=tid, label="GW", ip="10.0.0.1",
        ts=time.time() - 3600, old_status="green", new_status="red",
        category="loss", ping_type="icmp",
    )
    ds.flush()
    time.sleep(0.2)


def _alerter(ds):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_data_store(ds)
    a.set_config(_cfg())
    return a


def _ack_rows(conn):
    return conn.execute(
        "SELECT incident_id, target_id FROM webhook_ack ORDER BY incident_id"
    ).fetchall()


def _setup_acked_incident(path, tid="t1"):
    ds = DataStore(path)
    ds._schema_ready.wait(timeout=5)
    _insert_open_red(ds, tid)
    a = _alerter(ds)
    a.reseed_webhook_incidents(
        [{"id": tid, "label": "GW", "ip": "10.0.0.1"}], set())
    iid = a._webhook_incidents[tid].incident_id
    a.acknowledge_incident(tid)
    ds.flush()
    time.sleep(0.2)
    return ds, a, iid


def test_remove_clears_persisted_ack():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds, a, iid = _setup_acked_incident(path)
        conn = sqlite3.connect(path)
        before = _ack_rows(conn)
        a.on_target_removed("t1")
        ds.flush()
        time.sleep(0.2)
        after = _ack_rows(conn)
        conn.close()
        ds.shutdown()
        ok = len(before) == 1 and before[0][0] == iid and after == []
        print(f"Bug157 remove clears webhook_ack -> {ok} "
              f"before={before} after={after}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_pause_clears_persisted_ack():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds, a, iid = _setup_acked_incident(path)
        conn = sqlite3.connect(path)
        before = _ack_rows(conn)
        a.on_target_paused("t1")
        ds.flush()
        time.sleep(0.2)
        after = _ack_rows(conn)
        conn.close()
        ds.shutdown()
        ok = len(before) == 1 and before[0][0] == iid and after == []
        print(f"Bug157 pause clears webhook_ack -> {ok} "
              f"before={before} after={after}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_drop_clears_ack():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        block = f.read().split("def _drop_webhook_incident", 1)[1].split(
            "@staticmethod", 1)[0]
    ok = "_clear_persisted_incident_ack(inc)" in block
    print(f"Bug157 source drop clears persisted ack -> {ok}")
    return ok


def main():
    results = [
        ("remove", test_remove_clears_persisted_ack()),
        ("pause", test_pause_clears_persisted_ack()),
        ("source", test_source_drop_clears_ack()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 157 checks passed.")


if __name__ == "__main__":
    main()
