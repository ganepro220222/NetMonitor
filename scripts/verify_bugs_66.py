"""Regression checks for bug 66 (pings_raw ts keeps sub-second precision)."""
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def _ping(ds, tid, ts, status, lat=10.0):
    ds.record_ping(
        target_id=tid, label="n", ip="1.2.3.4", ping_type="icmp",
        ts=ts, status=status, latency_ms=lat, loss_rate=0.0,
    )


def test_record_ping_preserves_subsecond_ts():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        _ping(ds, "T", base + 10.10, "red", 10.0)
        _ping(ds, "T", base + 10.70, "green", 11.0)
        ds.flush()
        ds.shutdown()
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT ts, status FROM pings_raw WHERE target_id='T' ORDER BY ts"
        ).fetchall()
        conn.close()
        ok = (
            len(rows) == 2
            and abs(rows[1][0] - rows[0][0] - 0.6) < 0.01
            and rows[0][0] != int(rows[0][0])
        )
        print(f"Bug66 stored ts delta={rows[1][0]-rows[0][0]:.2f} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_get_history_preserves_subsecond_order():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = time.time()
        _ping(ds, "T", base + 10.10, "red")
        _ping(ds, "T", base + 10.70, "green")
        ds.flush()
        hist = ds.get_history("T", int(base), int(base) + 120)
        ds.shutdown()
        ok = (
            len(hist) == 2
            and abs(hist[1]["ts"] - hist[0]["ts"] - 0.6) < 0.01
            and hist[0]["status"] == "red"
            and hist[1]["status"] == "green"
        )
        print(f"Bug66 get_history ts/order -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_last_persisted_status_same_second():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = int(time.time()) + 100
        _ping(ds, "T", base + 0.1, "green")
        _ping(ds, "T", base + 0.2, "red")
        _ping(ds, "T", base + 0.3, "green")
        ds.flush()
        last = ds.get_last_persisted_status("T")
        ds.shutdown()
        ok = last == "green"
        print(f"Bug66 get_last_persisted_status={last!r} (expect green) -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_waveform_minute_bucket_floor():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        minute = (int(time.time()) // 60) * 60
        _ping(ds, "T", minute + 10.10, "green", 10.0)
        _ping(ds, "T", minute + 10.70, "green", 20.0)
        ds.flush()
        wf = ds.get_waveform("T", minute - 60, minute + 7200)
        ds.shutdown()
        minute_points = [p for p in wf["points"] if p["ts"] == minute]
        ok = (
            wf["resolution"] == "1m"
            and len(minute_points) == 1
            and minute_points[0]["sample_n"] == 2
        )
        print(f"Bug66 minute bucket ts={minute} n={minute_points[0]['sample_n'] if minute_points else None} "
              f"res={wf['resolution']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_hourly_gap_bucket_floor():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        hour = (int(time.time()) // 3600) * 3600 - 7200
        _ping(ds, "T", hour + 10.50, "green", 5.0)
        _ping(ds, "T", hour + 50.70, "green", 6.0)
        ds.flush()
        ds.shutdown()
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT DISTINCT CAST(ts / 3600 AS INTEGER) * 3600 AS hour_ts "
            "FROM pings_raw WHERE target_id='T'"
        ).fetchall()
        conn.close()
        ok = len(rows) == 1 and rows[0][0] == hour
        print(f"Bug66 hourly gap hours={rows} expect [{hour}] -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_hourly_agg_single_bucket_from_float_raw():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        hour = (int(time.time()) // 3600) * 3600 - 3600
        _ping(ds, "T", hour + 1.05, "green", 1.0)
        _ping(ds, "T", hour + 2.15, "green", 2.0)
        ds.flush()
        ds.shutdown()
        conn = sqlite3.connect(path)
        ds2 = DataStore(path)
        ds2._schema_ready.wait(timeout=5)
        ds2._hourly_agg(conn, backfill_internal_gaps=True)
        row = conn.execute(
            "SELECT sample_n FROM pings_hourly "
            "WHERE target_id='T' AND hour_ts=?",
            (hour,),
        ).fetchone()
        ds2.shutdown()
        conn.close()
        ok = row is not None and row[0] == 2
        print(f"Bug66 hourly_agg sample_n={row} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_float_ts_and_real_schema():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    ping_block = text.split("def record_ping", 1)[1].split(
        "def record_alert", 1)[0]
    ok = (
        '"ts": float(ts), "status"' in ping_block
        and "pings_raw" in text
        and text.split("CREATE TABLE IF NOT EXISTS pings_raw", 1)[1].split(
            "CREATE TABLE IF NOT EXISTS pings_hourly", 1)[0].count(
            "ts             REAL    NOT NULL") >= 1
        and '"ts": int(ts), "status"' not in ping_block
        and "CAST(ts / 60 AS INTEGER) * 60" in text
        and "CAST(ts / 3600 AS INTEGER) * 3600" in text
        and "ORDER BY ts DESC, id DESC LIMIT 1" in text.split(
            "def get_last_persisted_status", 1)[1].split(
            "def get_targets_meta", 1)[0]
    )
    print(f"Bug66 source float(ts) + CAST buckets + stable sort -> {ok}")
    return ok


def main():
    results = [
        ("stored_ts", test_record_ping_preserves_subsecond_ts()),
        ("history", test_get_history_preserves_subsecond_order()),
        ("anchor", test_last_persisted_status_same_second()),
        ("minute", test_waveform_minute_bucket_floor()),
        ("hour_gap", test_hourly_gap_bucket_floor()),
        ("hour_agg", test_hourly_agg_single_bucket_from_float_raw()),
        ("source", test_source_float_ts_and_real_schema()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 66 checks passed.")


if __name__ == "__main__":
    main()
