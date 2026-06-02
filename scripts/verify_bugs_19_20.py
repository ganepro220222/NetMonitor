"""Regression checks for bugs 19 (hourly fallback) and 20 (batch SLA SQL)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def test_bug19_hourly_fallback():
    """Partial boundary hour survives when raw is gone but hourly exists."""
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
        sla = ds.get_sla_stats(tid, start_ts, end_ts)
        wave = ds.get_waveform(
            tid, hour_ts - 50 * 86400, end_ts)
        wave_pts = [p for p in wave["points"] if p["ts"] == hour_ts]
        ok = (len(hist) == 1 and hist[0]["sample_n"] == 60
              and sla["sample_n"] == 60
              and abs(sla["lat_avg"] - 42.0) < 0.01
              and wave_pts and wave_pts[0]["sample_n"] == 60)
        print(f"Bug19: hist={hist} sla_n={sla['sample_n']} "
              f"wave_pt={wave_pts[:1]} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _count_selects(ds, target_ids, start_ts, end_ts):
    conn = ds._read_conn()
    counts = {"select": 0, "all": 0}

    def trace(sql, *args):
        counts["all"] += 1
        if sql.strip().upper().startswith("SELECT"):
            counts["select"] += 1

    conn.set_trace_callback(trace)
    t0 = time.time()
    batch = ds.get_sla_stats_batch(target_ids, start_ts, end_ts)
    elapsed = time.time() - t0
    conn.set_trace_callback(None)
    return counts["select"], len(batch), elapsed


def test_bug20_batch_sql_count():
    """30d × 50 targets must not issue per-target-per-hour SELECTs."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        now = int(time.time())
        end_ts = now
        start_ts = end_ts - 30 * 86400
        targets = [f"t{i}" for i in range(50)]
        selects, n, elapsed = _count_selects(ds, targets, start_ts, end_ts)
        ok_empty = (n == 50 and selects < 250)
        print(f"Bug20A: targets=50 days=30 selects={selects} "
              f"elapsed={elapsed:.3f}s -> {ok_empty}")

        conn = sqlite3.connect(path)
        h_lo = (start_ts // 3600) * 3600
        h_hi = (end_ts // 3600) * 3600
        h = h_lo
        nrows = 0
        while h <= h_hi:
            for tid in targets:
                conn.execute(
                    "INSERT INTO pings_hourly "
                    "(target_id,hour_ts,sample_n,success_n,lat_avg,lat_max,"
                    " lat_min,lat_p95,loss_rate) VALUES (?,?,?,?,?,?,?,?,?)",
                    (tid, h, 1, 1, 10.0, 10.0, 10.0, 10.0, 0.0))
                nrows += 1
            h += 3600
        conn.commit()
        conn.close()

        selects2, _, elapsed2 = _count_selects(ds, targets, start_ts, end_ts)
        ok_full = selects2 < 500
        print(f"Bug20B: hourly_rows={nrows} selects={selects2} "
              f"elapsed={elapsed2:.3f}s -> {ok_full}")
        return ok_empty and ok_full
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        ("Bug19", test_bug19_hourly_fallback()),
        ("Bug20", test_bug20_batch_sql_count()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)
    print("All bug 19-20 checks passed.")


if __name__ == "__main__":
    main()
