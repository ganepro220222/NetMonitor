"""Quick regression checks for bugs 5-8."""
import socket
import sys
import threading
import time
import sqlite3
import tempfile
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor, PingResult
from src.data_store import DataStore
from src.diag_sem import DIAG_TASK_SEM


def test_bug5_chunked():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
        b"0\r\n\r\n"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    hold = threading.Event()

    def serve():
        conn, _ = srv.accept()
        conn.sendall(resp)
        hold.wait(timeout=5)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 3,
        "http_success_codes": "2xx",
        "http_body_limit_kb": 64,
    }
    r = mon._do_single_request(
        f"http://127.0.0.1:{port}/", 3.0, False, method="GET",
        body_limit=65536, connect_target="127.0.0.1")
    hold.set()
    srv.close()
    ok = r.success and r.failure_reason is None and r._body == b"OK"
    print(f"Bug5 chunked: success={r.success} reason={r.failure_reason} body={r._body!r} -> {ok}")
    return ok


def test_bug6_truncated_cl():
    resp_hdr = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "OK"
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.sendall(resp_hdr.encode())
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 3,
        "http_success_codes": "2xx",
        "http_keyword": "ERROR",
        "http_keyword_mode": "absent",
        "http_body_limit_kb": 64,
    }
    r = mon._do_ping()
    srv.close()
    ok = (not r.success) and r.failure_reason == "body_incomplete"
    print(f"Bug6 absent truncated: success={r.success} reason={r.failure_reason} -> {ok}")
    return ok


def test_bug7_late_hourly():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        time.sleep(0.3)
        now = int(time.time())
        hour = ((now // 3600) - 1) * 3600
        tid = "test-tid"
        conn = sqlite3.connect(path)
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,status_code,failure_reason,ping_type) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (tid, hour + 10, "green", 10.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        row1 = conn.execute(
            "SELECT sample_n, success_n, lat_avg FROM pings_hourly WHERE target_id=? AND hour_ts=?",
            (tid, hour)).fetchone()
        conn.execute(
            "INSERT INTO pings_raw (target_id,ts,status,latency_ms,loss_rate,status_code,failure_reason,ping_type) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (tid, hour + 20, "green", 20.0, 0.0, None, None, "icmp"))
        conn.commit()
        ds._hourly_agg(conn)
        row2 = conn.execute(
            "SELECT sample_n, success_n, lat_avg FROM pings_hourly WHERE target_id=? AND hour_ts=?",
            (tid, hour)).fetchone()
        conn.close()
        ds.flush()
        ok = row1 == (1, 1, 10.0) and row2 == (2, 2, 15.0)
        print(f"Bug7 hourly: first={row1} retry={row2} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bug8_diag_sem():
    if not DIAG_TASK_SEM.acquire(blocking=False):
        print("Bug8: could not acquire sem for test")
        return False
    try:
        from src.web_server import WebServer, FLASK_AVAILABLE
        if not FLASK_AVAILABLE:
            print("Bug8 SKIP no flask")
            return True
        w = WebServer(port=8765)
        w._targets["t1"] = {"ip": "127.0.0.1", "label": "x"}
        calls = []
        import subprocess as sp
        orig = sp.Popen
        def fake_popen(*a, **k):
            calls.append(a)
            class P:
                stdout = iter([b""]).__iter__()
                def wait(self, timeout=None): return 0
                def poll(self): return 0
            return P()
        sp.Popen = fake_popen
        try:
            with w._app.test_client() as c:
                r = c.get("/api/traceroute/quick?tid=t1")
                body = b"".join(r.response)
        finally:
            sp.Popen = orig
        ok = len(calls) == 0 and b"error" in body
        print(f"Bug8 quick trace blocked: popen={len(calls)} has_error={b'error' in body} -> {ok}")
        return ok
    finally:
        DIAG_TASK_SEM.release()


def main():
    results = [
        test_bug5_chunked(),
        test_bug6_truncated_cl(),
        test_bug7_late_hourly(),
        test_bug8_diag_sem(),
    ]
    print("ALL PASS" if all(results) else "SOME FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
