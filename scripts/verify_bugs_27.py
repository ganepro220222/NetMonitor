"""Regression checks for bug 27 (/api/history raw retention downgrade)."""
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_hourly(conn, tid, hour_ts, lat=42.0, n=60):
    conn.execute(
        "INSERT INTO pings_hourly "
        "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,"
        " lat_min,lat_p95,loss_rate) VALUES (?,?,?,?,?,?,?,?,?)",
        (tid, hour_ts, n, n, lat, lat, lat, lat, 0.0))


def _insert_raw(conn, tid, ts, lat=10.0):
    conn.execute(
        "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
        "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
        (tid, ts, "green", lat, 0.0, None, None, "icmp"))


def _history_client(ds, tid, start, end, dtype=None):
    from src.web_server import WebServer, FLASK_AVAILABLE
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not available")
    w = WebServer(port=8765)
    w.set_data_store(ds)
    w._targets[tid] = {"ip": "1.2.3.4", "label": "node"}
    q = f"/api/history?tid={tid}&start={start}&end={end}"
    if dtype:
        q += f"&type={dtype}"
    with w._app.test_client() as c:
        r = c.get(q)
        return r.status_code, json.loads(r.get_data())


def test_old_1h_default_downgrades():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = ((now - 30 * 86400) // 3600) * 3600
        start_ts = hour_ts + 1800
        end_ts = hour_ts + 3600
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, hour_ts)
        conn.commit()
        conn.close()

        st, raw = _history_client(ds, tid, start_ts, end_ts)
        st2, explicit = _history_client(ds, tid, start_ts, end_ts, "hourly")
        ok = (st == 200 and len(raw) == 1 and raw[0]["sample_n"] == 60
              and st2 == 200 and len(explicit) == 1)
        print(f"Bug27 default: status={st} len={len(raw)} "
              f"hourly_explicit={len(explicit)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_old_1h_explicit_raw_downgrades():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = ((now - 30 * 86400) // 3600) * 3600
        start_ts = hour_ts
        end_ts = hour_ts + 3600
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, hour_ts)
        conn.commit()
        conn.close()

        st, rows = _history_client(ds, tid, start_ts, end_ts, "raw")
        ok = st == 200 and len(rows) == 1 and "hour_ts" in rows[0]
        print(f"Bug27 type=raw: status={st} rows={rows[:1]} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_recent_1h_stays_raw():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        start_ts = now - 3600
        end_ts = now
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, now - 600)
        conn.commit()
        conn.close()

        st, rows = _history_client(ds, tid, start_ts, end_ts)
        ok = st == 200 and len(rows) == 1 and "ts" in rows[0]
        print(f"Bug27 recent: status={st} has_ts={'ts' in rows[0] if rows else False} "
              f"-> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_spanning_cutoff_downgrades():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        old_hour = ((now - 9 * 86400) // 3600) * 3600
        start_ts = old_hour
        end_ts = now - 3600
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, old_hour)
        _insert_raw(conn, tid, now - 7200)
        conn.commit()
        conn.close()

        st, rows = _history_client(ds, tid, start_ts, end_ts)
        ok = st == 200 and len(rows) >= 1 and rows[0].get("hour_ts") == old_hour
        print(f"Bug27 span: status={st} len={len(rows)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_old_1h_default_downgrades(),
        test_old_1h_explicit_raw_downgrades(),
        test_recent_1h_stays_raw(),
        test_spanning_cutoff_downgrades(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 27 checks passed.")


if __name__ == "__main__":
    main()
