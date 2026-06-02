"""Regression check for bug 21 (partial slice must not fallback when raw exists)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def test_recent_empty_partial_slice_does_not_fallback():
    """Raw exists in hour but all samples are outside the query window."""
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
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, hour_ts + 300, "green", 90.0, 0.0, None, None, "icmp"))
        conn.execute(
            "INSERT INTO pings_hourly "
            "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,"
            " lat_min,lat_p95,loss_rate) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, hour_ts, 1, 1, 90.0, 90.0, 90.0, 90.0, 0.0))
        conn.commit()
        conn.close()

        hist = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        sla = ds.get_sla_stats(tid, start_ts, end_ts)
        wave = ds.get_waveform(tid, start_ts, start_ts + 50 * 86400)
        pts = [p for p in wave["points"] if p["ts"] == hour_ts]
        ok = (hist == [] and sla["sample_n"] == 0
              and not pts and wave["summary"]["sample_n"] == 0)
        print(f"Bug21: window={start_ts} {end_ts} hist={hist} "
              f"sla_n={sla['sample_n']} wave_pts={pts} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_purged_raw_still_falls_back_hourly():
    """Bug 19 guard: no raw, hourly present → still approximate."""
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
        conn.execute(
            "INSERT INTO pings_hourly "
            "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,"
            " lat_min,lat_p95,loss_rate) VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, hour_ts, 60, 60, 42.0, 42.0, 42.0, 42.0, 0.0))
        conn.commit()
        conn.close()
        hist = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        ok = len(hist) == 1 and hist[0]["sample_n"] == 60
        print(f"Bug21/19: hist={hist} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_recent_empty_partial_slice_does_not_fallback(),
        test_purged_raw_still_falls_back_hourly(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 21 checks passed.")


if __name__ == "__main__":
    main()
