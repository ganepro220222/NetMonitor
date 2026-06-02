"""Regression checks for bug 25 (waveform resolution vs raw retention)."""
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


def test_old_24h_hourly_only():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = ((now - 30 * 86400) // 3600) * 3600
        start_ts = hour_ts
        end_ts = hour_ts + 24 * 3600
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, hour_ts)
        conn.commit()
        conn.close()

        wave = ds.get_waveform(tid, start_ts, end_ts)
        hist = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        ok = (wave["resolution"] == "1h" and len(wave["points"]) >= 1
              and wave["summary"]["sample_n"] > 0 and len(hist) >= 1)
        print(f"Bug25 24h: res={wave['resolution']} pts={len(wave['points'])} "
              f"hist={len(hist)} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_old_1h_hourly_only():
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

        wave = ds.get_waveform(tid, start_ts, end_ts)
        ok = wave["resolution"] == "1h" and len(wave["points"]) >= 1
        print(f"Bug25 1h: res={wave['resolution']} pts={len(wave['points'])} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_recent_24h_minute():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        start_ts = now - 24 * 3600
        end_ts = now
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, now - 3600)
        conn.commit()
        conn.close()

        wave = ds.get_waveform(tid, start_ts, end_ts)
        ok = wave["resolution"] == "1m" and len(wave["points"]) >= 1
        print(f"Bug25 recent: res={wave['resolution']} pts={len(wave['points'])} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_spanning_raw_cutoff():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        raw_cutoff = now - 7 * 86400
        old_hour = ((raw_cutoff - 2 * 86400) // 3600) * 3600
        start_ts = old_hour
        end_ts = now - 3600
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, old_hour, lat=42.0)
        _insert_raw(conn, tid, now - 7200, lat=10.0)
        conn.commit()
        conn.close()

        wave = ds.get_waveform(tid, start_ts, end_ts)
        ok = wave["resolution"] == "1h" and any(
            p["ts"] == old_hour for p in wave["points"])
        print(f"Bug25 span: res={wave['resolution']} "
              f"has_old={ok} pts={len(wave['points'])} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug21_empty_partial_slice():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        hour_ts = 1780369200
        start_ts = 1780371000
        end_ts = 1780371900
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, hour_ts + 300, lat=90.0)
        _insert_hourly(conn, tid, hour_ts, lat=90.0, n=1)
        conn.commit()
        conn.close()

        wave = ds.get_waveform(tid, start_ts, start_ts + 50 * 86400)
        pts = [p for p in wave["points"] if p["ts"] == hour_ts]
        ok = not pts and wave["summary"]["sample_n"] == 0
        print(f"Bug21 reg: wave_pts={pts} sample_n={wave['summary']['sample_n']} "
              f"-> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug19_hourly_fallback():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = ((now - 10 * 86400) // 3600) * 3600
        start_ts = hour_ts + 1200
        end_ts = hour_ts + 2400
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, hour_ts)
        conn.commit()
        conn.close()

        wave = ds.get_waveform(tid, hour_ts - 50 * 86400, end_ts)
        pts = [p for p in wave["points"] if p["ts"] == hour_ts]
        ok = pts and pts[0]["sample_n"] == 60
        print(f"Bug19 reg: wave_pt={pts[:1]} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_old_24h_hourly_only(),
        test_old_1h_hourly_only(),
        test_recent_24h_minute(),
        test_spanning_raw_cutoff(),
        test_bug21_empty_partial_slice(),
        test_bug19_hourly_fallback(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 25 checks passed.")


if __name__ == "__main__":
    main()
