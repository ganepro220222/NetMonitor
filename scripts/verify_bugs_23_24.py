"""Regression checks for bugs 23-24 and HTTP header parsing (incl. bug 22)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor

PLAIN_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
NON_HTTP = (
    b"NOTHTTP 200 OK\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
TRUNCATED = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
)
HINTS_THEN_200 = (
    b"HTTP/1.1 103 Early Hints\r\n"
    b"Link: </style.css>; rel=preload; as=style\r\n"
    b"\r\n"
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
CONTINUE_THEN_200 = (
    b"HTTP/1.1 100 Continue\r\n"
    b"\r\n"
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


def _probe(port):
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 5,
        "http_success_codes": "2xx",
    }
    mon._preferred_method = "HEAD"
    return mon._do_ping()


def test_bug23_non_http():
    srv, port = _serve_once(NON_HTTP)
    try:
        r = _probe(port)
        ok = (not r.success and r.failure_reason == "bad_response")
        print(f"Bug23: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def test_bug24_103_then_200():
    srv, port = _serve_once(HINTS_THEN_200)
    try:
        r = _probe(port)
        ok = r.success and r.status_code == 200
        print(f"Bug24 103: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def test_bug24_100_then_200():
    srv, port = _serve_once(CONTINUE_THEN_200)
    try:
        r = _probe(port)
        ok = r.success and r.status_code == 200
        print(f"Bug24 100: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def test_plain_200():
    srv, port = _serve_once(PLAIN_200)
    try:
        r = _probe(port)
        ok = r.success and r.status_code == 200
        print(f"plain 200: success={r.success} code={r.status_code} -> {ok}")
        return ok
    finally:
        srv.close()


def test_bug22_truncated():
    srv, port = _serve_once(TRUNCATED)
    try:
        r = _probe(port)
        ok = (not r.success and r.failure_reason == "header_incomplete")
        print(f"Bug22: success={r.success} reason={r.failure_reason} -> {ok}")
        return ok
    finally:
        srv.close()


def main():
    results = [
        test_bug23_non_http(),
        test_bug24_103_then_200(),
        test_bug24_100_then_200(),
        test_plain_200(),
        test_bug22_truncated(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 23-24 checks passed.")


if __name__ == "__main__":
    main()
