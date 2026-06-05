"""Regression checks for bug 130 (TCPMonitor must reject out-of-range tcp_port)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import _sanitize_target
from src.ping_engine import TCPMonitor, PingResult

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
    "timeout": 3.0,
}


def _probe(port, **extra) -> PingResult:
    cfg = {**_BASE, "tcp_port": port, **extra}
    mon = TCPMonitor("t", "127.0.0.1", cfg, lambda s: None)
    return mon._do_ping()


def _run_tcp_server(port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.05)
    return srv


def test_99999_invalid_port_not_wrapped_success():
    wrapped = 99999 % 65536  # 34463 on 16-bit truncation
    # Guard rejects before TCP connect, so a listener on the wrapped port
    # cannot turn 99999 into a false-positive success.
    r = _probe(99999)
    ok = r.success is False and r.failure_reason == "invalid_port"
    print(
        f"Bug130 tcp_port=99999 (would wrap to {wrapped}) -> invalid_port -> {ok} "
        f"({r.success} {r.failure_reason})"
    )
    return ok


def test_zero_and_negative_invalid_port():
    r0 = _probe(0)
    rneg = _probe(-1)
    ok = (
        r0.success is False and r0.failure_reason == "invalid_port"
        and rneg.success is False and rneg.failure_reason == "invalid_port"
    )
    print(f"Bug130 tcp_port 0/-1 -> invalid_port -> {ok}")
    return ok


def test_non_numeric_invalid_port():
    mon = TCPMonitor("t", "127.0.0.1", dict(_BASE), lambda s: None)
    mon.settings["tcp_port"] = "abc"
    r = mon._do_ping()
    ok = r.success is False and r.failure_reason == "invalid_port"
    print(f"Bug130 tcp_port 'abc' -> invalid_port -> {ok}")
    return ok


def test_valid_port_still_succeeds():
    port = 34567
    srv = _run_tcp_server(port)
    r = _probe(port)
    srv.close()
    ok = r.success is True and r.failure_reason is None
    print(f"Bug130 tcp_port={port} open listener -> success -> {ok}")
    return ok


def test_sanitize_preserves_bad_tcp_port():
    out = _sanitize_target({
        "id": "t1",
        "label": "TCP bad port",
        "ip": "127.0.0.1",
        "ping_type": "tcp",
        "tcp_port": 99999,
    })
    ok = out.get("tcp_port") == 99999
    print(f"Bug130 sanitize keeps out-of-range tcp_port -> {ok}")
    return ok


def test_source_port_range_guard():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("class TCPMonitor", 1)[1].split(
            "class HTTPMonitor", 1
        )[0]
    ok = (
        'failure_reason="invalid_port"' in block
        and "1 <= port <= 65535" in block
        and "except (TypeError, ValueError)" in block
    )
    print(f"Bug130 source TCP port range guard -> {ok}")
    return ok


def main():
    results = [
        ("99999", test_99999_invalid_port_not_wrapped_success()),
        ("zero_neg", test_zero_and_negative_invalid_port()),
        ("abc", test_non_numeric_invalid_port()),
        ("valid", test_valid_port_still_succeeds()),
        ("sanitize", test_sanitize_preserves_bad_tcp_port()),
        ("source", test_source_port_range_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 130 checks passed.")


if __name__ == "__main__":
    main()
