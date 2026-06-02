"""Regression checks for bugs 14-16."""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor
from src.data_store import DataStore


def test_bug14_sla_merge():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        now = int(time.time())
        ch = (now // 3600) * 3600
        old_hour = ch - 3600
        tid = "t1"
        conn = __import__("sqlite3").connect(path)
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, old_hour + 10, "green", 10.0, 0.0, None, None, "icmp"))
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,"
            "status_code,failure_reason,ping_type) VALUES (?,?,?,?,?,?,?,?)",
            (tid, ch + 10, "green", 30.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        conn.close()
        start = now - 48 * 3600
        sla = ds.get_sla_stats(tid, start, now)
        batch = ds.get_sla_stats_batch([tid], start, now)[tid]
        ok = (abs(sla["lat_avg"] - 20.0) < 0.001
              and abs(batch["lat_avg"] - 20.0) < 0.001)
        print(f"Bug14: sla={sla['lat_avg']} batch={batch['lat_avg']} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug15_large_chunk():
    big = b"OK" + b"x" * (70 * 1024 - 2)
    hdr = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    )
    chunk_hdr = f"{len(big):x}\r\n".encode()
    resp = hdr + chunk_hdr + big + b"\r\n0\r\n\r\n"
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
        "http_timeout": 10,
        "http_success_codes": "2xx",
        "http_keyword": "OK",
        "http_keyword_mode": "contains",
        "http_body_limit_kb": 64,
    }
    r = mon._do_ping()
    hold.set()
    srv.close()
    ok = r.success and r.keyword_ok
    print(f"Bug15: success={r.success} reason={r.failure_reason} kw={r.keyword_ok} -> {ok}")
    return ok


def test_bug16_truncated_zero_chunk():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
        b"0\r\n"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.sendall(resp)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 3,
        "http_success_codes": "2xx",
        "http_keyword": "ERROR",
        "http_keyword_mode": "absent",
    }
    r = mon._do_ping()
    srv.close()
    ok = not r.success and r.failure_reason == "chunked_premature_eof"
    print(f"Bug16: success={r.success} reason={r.failure_reason} -> {ok}")
    return ok


def main():
    results = [
        test_bug14_sla_merge(),
        test_bug15_large_chunk(),
        test_bug16_truncated_zero_chunk(),
    ]
    print("ALL PASS" if all(results) else "SOME FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
