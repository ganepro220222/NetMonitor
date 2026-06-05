"""Regression checks for bug 129 (HTTPMonitor must reject non-HTTP(S) URL schemes)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import _sanitize_target
from src.ping_engine import HTTPMonitor, PingResult

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")

_BASE = {
    "window_size": 10,
    "ping_interval": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 2000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def _ping(url: str, **extra) -> PingResult:
    cfg = {**_BASE, "http_url": url, **extra}
    mon = HTTPMonitor("t", "127.0.0.1", cfg, lambda s: None)
    return mon._do_ping()


def _run_http_server(resp: bytes):
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


def test_ftp_scheme_invalid_url():
    # Scheme is rejected before any TCP connect, so a listening HTTP server
    # on the same port cannot produce a false-positive 200.
    r = _ping("ftp://127.0.0.1:8080/")
    ok = r.success is False and r.failure_reason == "invalid_url"
    print(f"Bug129 ftp:// -> invalid_url (not 200) -> {ok} ({r.success} {r.status_code})")
    return ok


def test_ws_scheme_invalid_url():
    r = _ping("ws://example.com/")
    ok = r.success is False and r.failure_reason == "invalid_url"
    print(f"Bug129 ws:// -> invalid_url -> {ok}")
    return ok


def test_redirect_to_ftp_invalid_url():
    srv, port = _run_http_server(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: ftp://127.0.0.1:2121/\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    r = _ping(
        f"http://127.0.0.1:{port}/",
        http_follow_redirects=True,
        http_success_codes="2xx,3xx",
    )
    srv.close()
    ok = r.success is False and r.failure_reason == "invalid_url"
    print(f"Bug129 redirect Location ftp:// -> invalid_url -> {ok} ({r.failure_reason})")
    return ok


def test_http_scheme_still_allowed():
    r = _ping("http://127.0.0.1:1/")
    ok = r.failure_reason != "invalid_url"
    print(f"Bug129 http:// not rejected by scheme guard -> {ok} (reason={r.failure_reason})")
    return ok


def test_sanitize_preserves_bad_scheme():
    out = _sanitize_target({
        "id": "t1",
        "label": "FTP target",
        "ip": "127.0.0.1",
        "ping_type": "http",
        "http_url": "ftp://127.0.0.1:2121/",
    })
    ok = out.get("http_url") == "ftp://127.0.0.1:2121/"
    print(f"Bug129 sanitize keeps non-HTTP(S) http_url -> {ok}")
    return ok


def test_source_scheme_guard():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _do_single_request", 1)[1].split(
            "host    = parsed.hostname", 1
        )[0]
    ok = (
        'parsed.scheme not in ("http", "https")' in block
        and 'failure_reason="invalid_url"' in block
    )
    print(f"Bug129 source scheme guard before host/port -> {ok}")
    return ok


def main():
    results = [
        ("ftp_scheme", test_ftp_scheme_invalid_url()),
        ("ws_scheme", test_ws_scheme_invalid_url()),
        ("redirect_ftp", test_redirect_to_ftp_invalid_url()),
        ("http_ok", test_http_scheme_still_allowed()),
        ("sanitize_keep", test_sanitize_preserves_bad_scheme()),
        ("source", test_source_scheme_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 129 checks passed.")


if __name__ == "__main__":
    main()
