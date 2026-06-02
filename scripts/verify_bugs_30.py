"""Regression checks for bug 30 (204/304 no body with keep-alive)."""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor

RESP_204_KA = (
    b"HTTP/1.1 204 No Content\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)
RESP_304_KA = (
    b"HTTP/1.1 304 Not Modified\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)
RESP_200_CLOSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"OK"
)


def _serve_hold(payload: bytes, hold_s: float = 5.0):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    hold = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.sendall(payload)
        hold.wait(timeout=hold_s)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    return srv, port, hold


def _probe(port, keyword="", kw_mode="contains", success="2xx", timeout=3):
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": timeout,
        "http_success_codes": success,
        "http_body_limit_kb": 64,
    }
    if keyword:
        settings["http_keyword"] = keyword
        settings["http_keyword_mode"] = kw_mode
    mon.settings = settings
    t0 = time.time()
    r = mon._do_ping()
    elapsed = time.time() - t0
    return r, elapsed


def test_204_absent_prompt_success():
    srv, port, hold = _serve_hold(RESP_204_KA)
    try:
        r, elapsed = _probe(port, keyword="maintenance", kw_mode="absent")
        hold.set()
        ok = (r.success and r.status_code == 204
              and r.failure_reason is None and elapsed < 1.0)
        print(f"Bug30 204 absent: success={r.success} code={r.status_code} "
              f"reason={r.failure_reason} elapsed={elapsed:.3f}s -> {ok}")
        return ok
    finally:
        srv.close()


def test_204_contains_keyword_not_found():
    srv, port, hold = _serve_hold(RESP_204_KA)
    try:
        r, elapsed = _probe(port, keyword="OK", kw_mode="contains")
        hold.set()
        ok = (not r.success and r.failure_reason == "keyword_not_found"
              and elapsed < 1.0)
        print(f"Bug30 204 contains: success={r.success} reason={r.failure_reason} "
              f"elapsed={elapsed:.3f}s -> {ok}")
        return ok
    finally:
        srv.close()


def test_304_absent_3xx():
    srv, port, hold = _serve_hold(RESP_304_KA)
    try:
        r, elapsed = _probe(port, keyword="error", kw_mode="absent",
                            success="2xx,3xx")
        hold.set()
        ok = r.success and r.status_code == 304 and elapsed < 1.0
        print(f"Bug30 304 absent: success={r.success} code={r.status_code} "
              f"elapsed={elapsed:.3f}s -> {ok}")
        return ok
    finally:
        srv.close()


def test_200_close_eof_still_ok():
    srv, port, hold = _serve_hold(RESP_200_CLOSE, hold_s=1.0)
    try:
        r, elapsed = _probe(port, keyword="OK", kw_mode="contains")
        hold.set()
        ok = r.success and r.keyword_ok and elapsed < 2.0
        print(f"Bug30 200 close: success={r.success} kw={r.keyword_ok} "
              f"elapsed={elapsed:.3f}s -> {ok}")
        return ok
    finally:
        srv.close()


def main():
    results = [
        test_204_absent_prompt_success(),
        test_204_contains_keyword_not_found(),
        test_304_absent_3xx(),
        test_200_close_eof_still_ok(),
    ]
    failed = [i for i, ok in enumerate(results) if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 30 checks passed.")


if __name__ == "__main__":
    main()
