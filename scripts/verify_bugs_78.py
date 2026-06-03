"""Regression checks for bug 78 (chunked contains keyword on partial body)."""
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


def _run_server(resp: bytes):
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
    return srv, port


def _probe(port, keyword, kw_mode):
    mon = HTTPMonitor("t", "127.0.0.1", {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": f"http://127.0.0.1:{port}/",
        "http_timeout": 3,
        "http_success_codes": "2xx",
        "http_keyword": keyword,
        "http_keyword_mode": kw_mode,
    }
    return mon._do_ping()


def test_contains_chunked_keyword_in_partial_body():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
    )
    srv, port = _run_server(resp)
    r = _probe(port, "OK", "contains")
    srv.close()
    ok = r.success and r.keyword_ok is True
    print(f"Bug78 contains partial+kw: success={r.success} kw={r.keyword_ok} "
          f"reason={r.failure_reason} -> {ok}")
    return ok


def test_contains_chunked_missing_keyword_fails():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nHELLO\r\n"
    )
    srv, port = _run_server(resp)
    r = _probe(port, "OK", "contains")
    srv.close()
    ok = (not r.success and r.keyword_ok is False
          and r.failure_reason in ("chunked_premature_eof", "keyword_not_found",
                                   "body_incomplete"))
    print(f"Bug78 contains partial no kw: success={r.success} "
          f"reason={r.failure_reason} -> {ok}")
    return ok


def test_absent_chunked_truncated_still_fails():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
        b"0\r\n"
    )
    srv, port = _run_server(resp)
    r = _probe(port, "ERROR", "absent")
    srv.close()
    ok = not r.success and r.failure_reason == "chunked_premature_eof"
    print(f"Bug78 absent truncated: success={r.success} "
          f"reason={r.failure_reason} -> {ok}")
    return ok


def test_complete_chunked_contains_succeeds():
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nOK\r\n"
        b"0\r\n\r\n"
    )
    srv, port = _run_server(resp)
    r = _probe(port, "OK", "contains")
    srv.close()
    ok = r.success and r.keyword_ok is True
    print(f"Bug78 complete chunked: success={r.success} kw={r.keyword_ok} -> {ok}")
    return ok


def test_source_deferred_chunk_failure():
    with open(PING_ENGINE, encoding="utf-8") as f:
        text = f.read()
    single = text.split("def _do_single_request", 1)[1].split(
        "def _is_success", 1)[0]
    chain = text.split("def _try_chain(m: str):", 1)[1].split(
        "result = _try_chain(method)", 1)[0]
    ok = (
        "body_failure_reason = chunk_err" in single
        and "failure_reason=chunk_err" not in single.split("body_failure_reason")[0]
        and "_body_failure_reason" in single
        and "body_fail = getattr(single, \"_body_failure_reason\"" in chain
        and "kw_mode == \"contains\"" in chain
    )
    print(f"Bug78 source deferred chunk + unified framing -> {ok}")
    return ok


def main():
    results = [
        ("contains_ok", test_contains_chunked_keyword_in_partial_body()),
        ("contains_fail", test_contains_chunked_missing_keyword_fails()),
        ("absent_fail", test_absent_chunked_truncated_still_fails()),
        ("complete_ok", test_complete_chunked_contains_succeeds()),
        ("source", test_source_deferred_chunk_failure()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 78 checks passed.")


if __name__ == "__main__":
    main()
