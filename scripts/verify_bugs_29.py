"""Regression checks for bug 29 (cutoff-hour partial slice hourly fallback)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _insert_raw(conn, tid, ts, lat):
    conn.execute(
        "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
        "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
        (tid, ts, "green", float(lat), 0.0, None, None, "icmp"))


def _insert_hourly(conn, tid, hour_ts, lat=42.0, n=60):
    conn.execute(
        "INSERT INTO pings_hourly "
        "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,"
        " lat_min,lat_p95,loss_rate) VALUES (?,?,?,?,?,?,?,?,?)",
        (tid, hour_ts, n, n, lat, lat, lat, lat, 0.0))


def test_cutoff_hour_purged_slice_uses_hourly():
    """Slice entirely before raw cutoff; later in-hour raw must not block hourly."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        cutoff = ds._raw_retention_cutoff()
        hour_ts = (cutoff // 3600) * 3600
        win_start = hour_ts
        win_end = cutoff - 1
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, cutoff - 60, 10.0)
        _insert_raw(conn, tid, cutoff + 60, 20.0)
        _insert_hourly(conn, tid, hour_ts, lat=42.0, n=60)
        conn.commit()
        conn.close()
        c = sqlite3.connect(path)
        ds._cleanup(c)
        c.close()

        hist = ds.get_history(tid, win_start, win_end, use_hourly=True)
        sla = ds.get_sla_stats(tid, win_start, win_end)
        wave = ds.get_waveform(tid, win_start - 86400, win_end)
        ok = (len(hist) == 1 and hist[0]["sample_n"] == 60
              and sla["sample_n"] == 60
              and wave["summary"]["sample_n"] == 60)
        print(f"Bug29 purged slice: hist={hist} sla_n={sla['sample_n']} "
              f"wave_n={wave['summary']['sample_n']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_spanning_cutoff_uses_hourly_not_partial_raw():
    """Window crosses cutoff: do not count only post-cutoff raw."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        time.sleep(0.3)
        tid = "t"
        cutoff = ds._raw_retention_cutoff()
        hour_ts = (cutoff // 3600) * 3600
        win_start = max(hour_ts, cutoff - 900)
        win_end = min(hour_ts + 3599, cutoff + 900)
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, cutoff + 120, 99.0)
        _insert_hourly(conn, tid, hour_ts, lat=42.0, n=60)
        conn.commit()
        conn.close()
        c = sqlite3.connect(path)
        ds._cleanup(c)
        c.close()

        hist = ds.get_history(tid, win_start, win_end, use_hourly=True)
        ok = len(hist) == 1 and hist[0]["sample_n"] == 60
        print(f"Bug29 span: hist={hist} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug21_empty_slice_in_retention():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = (now // 3600) * 3600
        start_ts = hour_ts + 1800
        end_ts = hour_ts + 2700
        conn = sqlite3.connect(path)
        _insert_raw(conn, tid, hour_ts + 300, 90.0)
        _insert_hourly(conn, tid, hour_ts, lat=90.0, n=1)
        conn.commit()
        conn.close()
        hist = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        ok = hist == []
        print(f"Bug21 reg: hist={hist} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug19_full_hour_purged():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        now = int(time.time())
        hour_ts = ((now - 10 * 86400) // 3600) * 3600
        start_ts = hour_ts + 600
        end_ts = hour_ts + 2400
        conn = sqlite3.connect(path)
        _insert_hourly(conn, tid, hour_ts)
        conn.commit()
        conn.close()
        hist = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        ok = len(hist) == 1 and hist[0]["sample_n"] == 60
        print(f"Bug19 reg: hist={hist} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_cutoff_hour_purged_slice_uses_hourly(),
        test_spanning_cutoff_uses_hourly_not_partial_raw(),
        test_bug21_empty_slice_in_retention(),
        test_bug19_full_hour_purged(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 29 checks passed.")


if __name__ == "__main__":
    main()
