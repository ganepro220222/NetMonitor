"""Regression checks for bugs 17 (hourly window boundaries) and 18 (chunked cap)."""
import os
import socket
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor
from src.data_store import DataStore


def _insert_raw(conn, tid, ts, latency):
    conn.execute(
        "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
        "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
        (tid, ts, "green", float(latency), 0.0, None, None, "icmp"))


def _rollup_history(rows):
    total = sum(r["sample_n"] for r in rows)
    success = sum(r["success_n"] for r in rows)
    lat_pairs = [(r["lat_avg"], r["success_n"]) for r in rows
                 if r.get("lat_avg") is not None and r["success_n"]]
    w_n = sum(n for _v, n in lat_pairs)
    lat_avg = sum(v * n for v, n in lat_pairs) / w_n if w_n else None
    maxl = [r["lat_max"] for r in rows if r.get("lat_max") is not None]
    return {
        "total": total,
        "success": success,
        "lat_avg": lat_avg,
        "lat_max": max(maxl) if maxl else None,
    }


def test_bug17_repro_a():
    """First overlapping partial historical hour must not be omitted."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        start_ts = 1780281000
        end_ts = 1780372800
        hour0 = (start_ts // 3600) * 3600
        hour1 = hour0 + 3600
        conn = __import__("sqlite3").connect(path)
        _insert_raw(conn, tid, start_ts + 120, 90.0)
        _insert_raw(conn, tid, hour1 + 60, 10.0)
        conn.commit()
        ds._hourly_agg(conn)
        conn.close()

        rows = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        sla = ds.get_sla_stats(tid, start_ts, end_ts)
        agg = _rollup_history(rows)
        ok = (sla["sample_n"] == 2 and agg["total"] == 2
              and abs(sla["lat_avg"] - 50.0) < 0.01)
        print(f"Bug17A: rows={rows} sla_n={sla['sample_n']} "
              f"lat_avg={sla['lat_avg']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug17_repro_b():
    """Final partial historical hour must exclude samples after end_ts."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        tid = "t"
        start_ts = 1780275600
        end_ts = 1780367400
        end_hour = (end_ts // 3600) * 3600
        conn = __import__("sqlite3").connect(path)
        _insert_raw(conn, tid, end_ts - 120, 10.0)
        _insert_raw(conn, tid, end_ts + 120, 90.0)
        conn.commit()
        ds._hourly_agg(conn)
        conn.close()

        rows = ds.get_history(tid, start_ts, end_ts, use_hourly=True)
        sla = ds.get_sla_stats(tid, start_ts, end_ts)
        tail = [r for r in rows if r.get("hour_ts") == end_hour]
        ok = (sla["sample_n"] == 1 and len(tail) == 1
              and tail[0]["sample_n"] == 1
              and abs(sla["lat_avg"] - 10.0) < 0.01)
        print(f"Bug17B: tail={tail} sla={sla} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug18_chunk_memory():
    """Large remote chunk must not be fully buffered before body_limit."""
    body_limit = 1024
    big = b"x" * (2 * 1024 * 1024)
    payload = (
        f"{len(big):x}\r\n".encode() + big + b"\r\n"
        b"0\r\n\r\n"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    sent = {"n": 0}

    def serve():
        c, _ = srv.accept()
        c.sendall(payload)
        sent["n"] = len(payload)
        c.close()

    import threading
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    tracemalloc.start()
    t0 = time.time()
    body, err = HTTPMonitor._read_chunked_body(
        cli, b"", body_limit, time.time() + 30)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    elapsed = time.time() - t0
    cli.close()
    srv.close()

    # Socket should not have pulled the entire 2 MiB chunk into Python.
    ok = (len(body) == body_limit and err is None
          and peak < 512 * 1024 and elapsed < 1.5)
    print(f"Bug18: body_len={len(body)} err={err} peak={peak} "
          f"elapsed={elapsed:.3f}s -> {ok}")
    return ok


def main():
    results = [
        ("Bug17A", test_bug17_repro_a()),
        ("Bug17B", test_bug17_repro_b()),
        ("Bug18", test_bug18_chunk_memory()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", ", ".join(failed))
        sys.exit(1)
    print("All bug 17-18 checks passed.")


if __name__ == "__main__":
    main()
