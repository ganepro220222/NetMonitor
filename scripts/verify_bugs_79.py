"""Regression checks for bug 79 (chunked body_limit stops read promptly)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import HTTPMonitor

PING_ENGINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ping_engine.py",
)


def _probe(port, *, keyword="OK", kw_mode="contains", timeout=1.0,
           body_limit_kb=64, hold=None):
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": timeout,
        "http_success_codes": "2xx",
        "http_keyword": keyword,
        "http_keyword_mode": kw_mode,
        "http_body_limit_kb": body_limit_kb,
    }
    t0 = time.time()
    r = mon._do_ping()
    elapsed = time.time() - t0
    return r, elapsed


def test_chunked_stops_at_body_limit_fast():
    chunk_size = 128 * 1024
    payload = b"OK" + b"x" * (70 * 1024 - 2)
    hdr = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        + f"{chunk_size:x}\r\n".encode()
        + payload
    )
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    hold = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.sendall(hdr)
        hold.wait(timeout=5)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    r, elapsed = _probe(port, timeout=1.0, body_limit_kb=64)
    hold.set()
    srv.close()
    ok = (r.success and r.keyword_ok
          and elapsed < 0.2 and (r.latency_ms or 0) < 200)
    print(f"Bug79 chunked stall: success={r.success} kw={r.keyword_ok} "
          f"lat={r.latency_ms}ms elapsed={elapsed:.3f}s -> {ok}")
    return ok


def test_content_length_same_body_fast():
    payload = b"OK" + b"x" * (70 * 1024 - 2)
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 131072\r\n"
        b"\r\n"
        + payload
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
    r, elapsed = _probe(port, timeout=1.0, body_limit_kb=64)
    hold.set()
    srv.close()
    ok = r.success and r.keyword_ok and elapsed < 0.2
    print(f"Bug79 CL stall: lat={r.latency_ms}ms elapsed={elapsed:.3f}s -> {ok}")
    return ok


def test_chunked_bad_size_before_limit_fails():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"ZZZZ\r\n"
        b"OK\r\n"
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
    r, _ = _probe(port, keyword="OK", kw_mode="contains")
    srv.close()
    ok = not r.success and r.failure_reason == "chunked_bad_size"
    print(f"Bug79 bad chunk: reason={r.failure_reason} -> {ok}")
    return ok


def test_source_body_limit_early_return():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _read_chunked_body", 1)[1].split(
            "def _keyword_match", 1)[0]
    ok = (
        "if len(out) >= body_limit:" in block
        and "return out[:body_limit], None" in block
        and "accumulate = False" not in block
    )
    print(f"Bug79 source early return at body_limit -> {ok}")
    return ok


def main():
    results = [
        ("chunked_fast", test_chunked_stops_at_body_limit_fast()),
        ("cl_fast", test_content_length_same_body_fast()),
        ("bad_chunk", test_chunked_bad_size_before_limit_fails()),
        ("source", test_source_body_limit_early_return()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 79 checks passed.")
    print("(Also run: python scripts/verify_bugs_78.py)")


if __name__ == "__main__":
    main()
