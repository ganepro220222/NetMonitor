"""Regression checks for bug 97 (HTTP explicit :0 must not fall back to default port)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


def _ping(url: str) -> PingResult:
    cfg = {**_BASE, "http_url": url}
    mon = HTTPMonitor("t", "127.0.0.1", cfg, lambda s: None)
    return mon._do_ping()


def test_explicit_port_zero_invalid():
    r = _ping("http://127.0.0.1:0/")
    ok = r.success is False and r.failure_reason == "invalid_url"
    print(f"Bug97 :0 -> invalid_url (not success) -> {ok}")
    return ok


def test_out_of_range_still_invalid():
    r = _ping("http://example.com:99999/")
    ok = r.success is False and r.failure_reason == "invalid_url"
    print(f"Bug97 :99999 still invalid_url -> {ok}")
    return ok


def test_no_port_uses_default_http():
    r = _ping("http://127.0.0.1/")
    ok = r.failure_reason != "invalid_url"
    print(f"Bug97 no explicit port not invalid_url -> {ok} (reason={r.failure_reason})")
    return ok


def test_source_port_range_guard():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _do_single_request", 1)[1].split(
            "timings = {}", 1)[0]
    ok = (
        "explicit_port is None" in block
        and "1 <= explicit_port <= 65535" in block
        and "explicit_port or (" not in block
    )
    print(f"Bug97 source explicit port range guard -> {ok}")
    return ok


def main():
    results = [
        ("port_zero", test_explicit_port_zero_invalid()),
        ("port_99999", test_out_of_range_still_invalid()),
        ("default_port", test_no_port_uses_default_http()),
        ("source", test_source_port_range_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 97 checks passed.")


if __name__ == "__main__":
    main()
