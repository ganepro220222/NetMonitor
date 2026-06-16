"""Regression: traceroute fallback must not borrow another incident's row (Bug 153)."""
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _alert(ds, tid, ts, old, new, cat="availability"):
    ds.record_alert(
        target_id=tid, label="Node", ip="1.2.3.4", ts=float(ts),
        old_status=old, new_status=new, category=cat,
    )


def _insert_trace(conn, tid, ts, iid, hop_ip):
    hops = json.dumps([{"ip": hop_ip}])
    conn.execute(
        "INSERT INTO traceroute_logs "
        "(target_id, label, ip, ts, hops, incident_id) "
        "VALUES (?, 'Node', '1.2.3.4', ?, ?, ?)",
        (tid, ts, hops, iid),
    )


def test_fallback_does_not_borrow_other_incident():
    """Exact miss for A must not return B's row in A's time window."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T1"
        base = 1_780_000_000.0
        first_red = base
        second_red = base + 20.0
        _alert(ds, tid, first_red, "green", "red")
        _alert(ds, tid, base + 10, "red", "green", cat="ok")
        _alert(ds, tid, second_red, "green", "red")
        ds.flush()

        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT incident_id, ts FROM alert_events "
            "WHERE target_id=? AND new_status='red' ORDER BY id",
            (tid,),
        ).fetchall()
        first_iid, second_iid = rows[0][0], rows[1][0]
        trace_ts = first_red + 25.0  # inside first incident fallback window
        _insert_trace(conn, tid, trace_ts, second_iid, "2.2.2.2")
        conn.commit()
        conn.close()

        got = ds.get_incident_traceroute(tid, first_red, incident_id=first_iid)
        ok_exact = ds.get_incident_traceroute(
            tid, second_red, incident_id=second_iid,
        ) is not None
        ds.shutdown()

        ok = got is None and ok_exact
        print(f"Bug153 no cross-incident fallback -> {ok} "
              f"first={first_iid} second={second_iid} got={got}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_null_incident_row_still_matches_fallback():
    """Brief-outage race / legacy NULL row still reachable via fallback."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T2"
        red_ts = 1_780_100_000.0
        iid = "INC-TEST-T2-LEGACY"
        conn = sqlite3.connect(path)
        _insert_trace(conn, tid, red_ts + 5.0, None, "9.9.9.9")
        conn.commit()
        conn.close()

        got = ds.get_incident_traceroute(tid, red_ts, incident_id=iid)
        ds.shutdown()
        ok = got is not None and got["hops"][0]["ip"] == "9.9.9.9"
        print(f"Bug153 NULL row fallback still works -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_exact_match_preferred_over_null_in_window():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T3"
        red_ts = 1_780_200_000.0
        iid = "INC-EXACT-T3"
        conn = sqlite3.connect(path)
        _insert_trace(conn, tid, red_ts + 3.0, None, "null-hop")
        _insert_trace(conn, tid, red_ts + 4.0, iid, "exact-hop")
        conn.commit()
        conn.close()

        got = ds.get_incident_traceroute(tid, red_ts, incident_id=iid)
        ds.shutdown()
        ok = got is not None and got["hops"][0]["ip"] == "exact-hop"
        print(f"Bug153 exact match preferred -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_no_incident_id_unrestricted_window():
    """Level-1 callers without incident_id keep unrestricted time window."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T4"
        red_ts = 1_780_300_000.0
        conn = sqlite3.connect(path)
        _insert_trace(conn, tid, red_ts + 2.0, "INC-OTHER", "bound-hop")
        conn.commit()
        conn.close()

        got = ds.get_incident_traceroute(tid, red_ts, incident_id=None)
        ds.shutdown()
        ok = got is not None and got["hops"][0]["ip"] == "bound-hop"
        print(f"Bug153 no incident_id unrestricted fallback -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_fallback_filters_foreign_incident():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def get_incident_traceroute", 1)[1].split(
            "def _traceroute_has_incident_col", 1)[0]
    ok = (
        "incident_id IS NULL OR incident_id = ''" in block
        and "Never borrow another incident" in block
    )
    print(f"Bug153 source fallback filter -> {ok}")
    return ok


def main():
    results = [
        ("cross_incident", test_fallback_does_not_borrow_other_incident()),
        ("null_fallback", test_null_incident_row_still_matches_fallback()),
        ("exact_preferred", test_exact_match_preferred_over_null_in_window()),
        ("no_iid_window", test_no_incident_id_unrestricted_window()),
        ("source", test_source_fallback_filters_foreign_incident()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 153 checks passed.")


if __name__ == "__main__":
    main()
