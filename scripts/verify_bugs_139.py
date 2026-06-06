"""Regression checks for alert_events category persistence (Bug 139).

Recovery transitions must persist category='ok' (state machine truth), not the
legacy workaround that forced 'availability' on any red-touching transition.
SLA still keys off old_status/new_status, not category.
"""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


def test_main_window_no_red_category_override():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    block = src.split("def _on_state_update", 1)[1].split(
        "def _apply_state_update", 1)[0]
    ok = (
        "state.alert_category" in block
        and "if state.status == \"red\" or old_st == \"red\":" not in block
        and "cat = \"availability\"" not in block
    )
    print(f"Bug139 main_window uses state.alert_category only -> {ok}")
    return ok


def test_recovery_persisted_as_ok():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        ds.record_alert(
            target_id="T", label="GW", ip="10.0.0.1",
            ts=base + 1.0, old_status="green", new_status="red",
            category="availability")
        ds.record_alert(
            target_id="T", label="GW", ip="10.0.0.1",
            ts=base + 10.0, old_status="red", new_status="green",
            category="ok")
        time.sleep(0.5)
        ds.shutdown()
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT old_status, new_status, category FROM alert_events "
            "WHERE target_id='T' ORDER BY ts"
        ).fetchall()
        conn.close()
        ok = (
            len(rows) == 2
            and rows[0] == ("green", "red", "availability")
            and rows[1] == ("red", "green", "ok")
        )
        print(f"Bug139 recovery row category=ok -> {ok} ({rows})")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_sla_with_ok_recovery():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        ds.record_alert(
            target_id="T", label="GW", ip="10.0.0.1",
            ts=base + 10.0, old_status="green", new_status="red",
            category="availability")
        ds.record_alert(
            target_id="T", label="GW", ip="10.0.0.1",
            ts=base + 70.0, old_status="red", new_status="green",
            category="ok")
        time.sleep(0.5)
        stats = ds.get_sla_stats("T", base, base + 120)
        ds.shutdown()
        ok = stats["outage_count"] == 1 and stats["uptime_pct"] < 100.0
        print(f"Bug139 SLA with ok recovery -> {ok} ({stats})")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_red_to_orange_stays_availability():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        ds.record_alert(
            target_id="T", label="GW", ip="10.0.0.1",
            ts=base + 1.0, old_status="red", new_status="orange",
            category="availability")
        time.sleep(0.3)
        ds.shutdown()
        conn = sqlite3.connect(path)
        row = conn.execute(
            "SELECT category FROM alert_events WHERE target_id='T'"
        ).fetchone()
        conn.close()
        ok = row is not None and row[0] == "availability"
        print(f"Bug139 red→orange category=availability -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        ("source", test_main_window_no_red_category_override()),
        ("persist", test_recovery_persisted_as_ok()),
        ("sla", test_sla_with_ok_recovery()),
        ("partial", test_red_to_orange_stays_availability()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 139 checks passed.")


if __name__ == "__main__":
    main()
