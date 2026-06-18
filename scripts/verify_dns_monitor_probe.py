"""Regression: DNSMonitor probe paths via local UDP mock (dynamic port)."""
import os
import socket
import struct
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import DNSMonitor, PingResult

_DOMAIN = "test.local"
_CFG = {
    "dns_domain": _DOMAIN,
    "dns_expected": "",
    "timeout": 2.0,
    "window_size": 5,
    "consecutive_loss_orange": 2,
    "consecutive_loss_red": 3,
    "recovery_count": 2,
}


def _skip_name(data: bytes, offset: int) -> int:
    for _ in range(30):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _question_end(query: bytes) -> int:
    offset = 12
    offset = _skip_name(query, offset)
    return offset + 4


def _build_response(query: bytes, *, rcode: int = 0, ips=None) -> bytes:
    qend = _question_end(query)
    question = query[12:qend]
    ancount = 0
    answers = b""
    if rcode == 0 and ips:
        ancount = len(ips)
        for ip in ips:
            answers += (
                b"\xc0\x0c"
                + b"\x00\x01\x00\x01"
                + b"\x00\x00\x00\x3c"
                + b"\x00\x04"
                + socket.inet_aton(ip)
            )
    header = (
        query[:2]
        + bytes([0x81, 0x80 | (rcode & 0x0F)])
        + query[4:6]
        + struct.pack("!H", ancount)
        + b"\x00\x00\x00\x00"
    )
    return header + question + answers


class _MockDNSServer:
    def __init__(self, *, rcode=0, ips=None, silent=False):
        self._rcode = rcode
        self._ips = ips or []
        self._silent = silent
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, _addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if self._silent:
                continue
            try:
                reply = _build_response(
                    data, rcode=self._rcode, ips=self._ips)
                self._sock.sendto(reply, _addr)
            except OSError:
                break

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def _redirect_dns_port(server_port: int):
    _orig_connect = socket.socket.connect

    def _connect(sock, address):
        host, port = address
        if port == 53:
            return _orig_connect(sock, ("127.0.0.1", server_port))
        return _orig_connect(sock, address)

    return patch.object(socket.socket, "connect", _connect)


def _monitor(expected=""):
    cfg = dict(_CFG)
    cfg["dns_expected"] = expected
    return DNSMonitor("dns-t", "127.0.0.1", cfg, lambda *a, **k: None)


def test_dns_success():
    srv = _MockDNSServer(ips=["10.0.0.5"])
    mon = _monitor()
    with _redirect_dns_port(srv.port):
        result = mon._do_ping()
    srv.close()
    ok = result.success and result.latency_ms is not None
    print(f"dns success -> {ok} result={result}")
    return ok


def test_dns_nxdomain():
    srv = _MockDNSServer(rcode=3)
    mon = _monitor()
    with _redirect_dns_port(srv.port):
        result = mon._do_ping()
    srv.close()
    ok = not result.success and result.failure_reason == "nxdomain"
    print(f"dns nxdomain -> {ok} reason={result.failure_reason}")
    return ok


def test_dns_timeout():
    srv = _MockDNSServer(silent=True)
    mon = _monitor()
    with _redirect_dns_port(srv.port):
        result = mon._do_ping()
    srv.close()
    ok = not result.success and result.failure_reason == "dns_timeout"
    print(f"dns timeout -> {ok} reason={result.failure_reason}")
    return ok


def test_dns_hijack():
    srv = _MockDNSServer(ips=["198.51.100.9"])
    mon = _monitor(expected="10.0.0.5")
    with _redirect_dns_port(srv.port):
        result = mon._do_ping()
    srv.close()
    ok = (
        not result.success
        and (result.failure_reason or "").startswith("dns_hijack:")
    )
    print(f"dns hijack mismatch -> {ok} reason={result.failure_reason}")
    return ok


def test_dns_no_domain():
    mon = DNSMonitor(
        "dns-t", "127.0.0.1",
        {**_CFG, "dns_domain": ""},
        lambda *a, **k: None)
    result = mon._do_ping()
    ok = not result.success and result.failure_reason == "dns_no_domain"
    print(f"dns missing domain -> {ok} reason={result.failure_reason}")
    return ok


def test_dns_failure_escalates_state():
    srv = _MockDNSServer(rcode=3)
    mon = _monitor()
    with _redirect_dns_port(srv.port):
        r1 = mon._do_ping()
        s1 = mon._compute_state(r1)
        r2 = mon._do_ping()
        s2 = mon._compute_state(r2)
    srv.close()
    ok = (
        not r1.success
        and s1.status == "green"
        and not r2.success
        and s2.status == "orange"
    )
    print(f"dns failures escalate availability -> {ok} "
          f"states=({s1.status},{s2.status})")
    return ok


def main():
    results = [
        test_dns_success(),
        test_dns_nxdomain(),
        test_dns_timeout(),
        test_dns_hijack(),
        test_dns_no_domain(),
        test_dns_failure_escalates_state(),
    ]
    if all(results):
        print("PASS verify_dns_monitor_probe")
        return 0
    print("FAIL verify_dns_monitor_probe")
    return 1


if __name__ == "__main__":
    sys.exit(main())
