"""Regression checks for bugs 10-13."""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor
from src.data_store import DataStore
from src.diag_sem import DIAG_TASK_SEM


def test_bug10_chunked_trailer():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Trailer: X-Checksum\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
        b"0\r\n"
        b"X-Checksum: abc\r\n"
        b"\r\n"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    hold = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.sendall(resp)
        hold.wait(timeout=5)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 5,
        "http_success_codes": "2xx",
    }
    r = mon._do_single_request(
        f"http://127.0.0.1:{port}/", 5.0, False, method="GET",
        body_limit=65536, connect_target="127.0.0.1")
    hold.set()
    srv.close()
    ok = r.success and r._body == b"OK"
    print(f"Bug10 trailer: success={r.success} reason={r.failure_reason} body={r._body!r} -> {ok}")
    return ok


def test_bug11_current_hour_stats():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        now = int(time.time())
        ch = (now // 3600) * 3600
        old_hour = ch - 7200
        tid = "t1"
        conn = __import__("sqlite3").connect(path)
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, old_hour + 10, "green", 10.0, 0.0, None, None, "icmp"))
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, ch + 30, "green", 30.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        conn.close()
        start = now - 25 * 3600
        hist = ds.get_history(tid, start, now, use_hourly=True)
        total = sum(r["sample_n"] for r in hist)
        sla = ds.get_sla_stats(tid, start, now)
        batch = ds.get_sla_stats_batch([tid], start, now)[tid]
        expected_avg = 20.0  # (10 + 30) / 2
        ok = (total >= 2 and sla.get("sample_n", 0) >= 2
                and abs(sla.get("lat_avg", 0) - expected_avg) < 0.001
                and abs(batch.get("lat_avg", 0) - expected_avg) < 0.001)
        print(f"Bug11/14: sla_avg={sla.get('lat_avg')} batch_avg={batch.get('lat_avg')} "
              f"expected={expected_avg} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug13_late_old_hour():
    # A raw row that lands in pings_raw AFTER its hour was first
    # aggregated must be folded in on the next _hourly_agg pass.
    #
    # Originally probed at ch-4h.  The 30-node capacity work made
    # _hourly_agg incremental (recompute only the recent
    # RECENT_RECOMPUTE_HOURS=3 completed hours instead of rescanning the
    # whole raw-retention span every tick, which had blocked the writer
    # ~10-15s/hour at 30 targets).  A 4h-old late flush is now
    # intentionally NOT re-absorbed on the routine tick (see
    # verify_capacity_30.py's old-late-flush trade-off test).  That 4h
    # case was never reachable anyway: FLUSH_INTERVAL=60s caps real late
    # arrivals at ~1h (a probe straddling the hour boundary, flushed up
    # to a minute later).  Probe at ch-2h so this still exercises the
    # REAL late-flush guarantee the incremental aggregator upholds.
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path, raw_retention_days=7)
        now = int(time.time())
        ch = (now // 3600) * 3600
        old_hour = ch - 2 * 3600
        tid = "t1"
        conn = __import__("sqlite3").connect(path)
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, old_hour + 10, "green", 10.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        row1 = conn.execute(
            "SELECT sample_n, lat_avg FROM pings_hourly WHERE target_id=? AND hour_ts=?",
            (tid, old_hour)).fetchone()
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, old_hour + 20, "green", 20.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        row2 = conn.execute(
            "SELECT sample_n, lat_avg FROM pings_hourly WHERE target_id=? AND hour_ts=?",
            (tid, old_hour)).fetchone()
        conn.close()
        ok = row1 == (1, 10.0) and row2 == (2, 15.0)
        print(f"Bug13: before={row1} after={row2} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        test_bug10_chunked_trailer(),
        test_bug11_current_hour_stats(),
        test_bug13_late_old_hour(),
    ]
    print("ALL PASS" if all(results) else "SOME FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
