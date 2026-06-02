"""Regression checks for bug 22 (truncated HTTP headers)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor

TRUNCATED_HDR = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
)
COMPLETE_HDR = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)


def _serve_once(payload: bytes):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.sendall(payload)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _probe(port, keyword="", kw_mode="contains", method_hint=None):
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 5,
        "http_success_codes": "2xx",
        "http_body_limit_kb": 64,
    }
    if keyword:
        settings["http_keyword"] = keyword
        settings["http_keyword_mode"] = kw_mode
    mon.settings = settings
    if method_hint == "HEAD":
        mon._preferred_method = "HEAD"
    return mon._do_ping()


def test_head_truncated():
    srv, port = _serve_once(TRUNCATED_HDR)
    try:
        r = _probe(port)
        ok = (not r.success and r.failure_reason == "header_incomplete")
        print(f"Bug22 HEAD: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def test_get_absent_truncated():
    srv, port = _serve_once(TRUNCATED_HDR)
    try:
        r = _probe(port, keyword="ERROR", kw_mode="absent")
        ok = (not r.success and r.failure_reason == "header_incomplete")
        print(f"Bug22 absent: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} kw={r.keyword_ok} -> {ok}")
        return ok
    finally:
        srv.close()


def test_complete_headers_ok():
    srv, port = _serve_once(COMPLETE_HDR)
    try:
        r = _probe(port, method_hint="HEAD")
        ok = r.success and r.status_code == 200
        print(f"Bug22 complete: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def main():
    results = [
        test_head_truncated(),
        test_get_absent_truncated(),
        test_complete_headers_ok(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 22 checks passed.")


if __name__ == "__main__":
    main()
