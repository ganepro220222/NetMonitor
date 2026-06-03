"""Regression checks for bug 38 (HTTP connect target host validation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import is_valid_host
from src.ping_engine import HTTPMonitor

BAD_HOST = "not a host with spaces"
GOOD_HOST = "example.com"


def _dialog_would_save(ip: str, ptype: str = "http") -> bool:
    """Mirror Add/EditTargetDialog._confirm host gate after Bug38 fix."""
    if not ip:
        return False
    return is_valid_host(ip)


def test_invalid_host_rejected_by_validator():
    ok = (not is_valid_host(BAD_HOST)
          and is_valid_host(GOOD_HOST))
    print(f"Bug38 is_valid_host: bad={is_valid_host(BAD_HOST)!r} "
          f"good={is_valid_host(GOOD_HOST)!r} -> {ok}")
    return ok


def test_dialog_blocks_invalid_http_connect_target():
    ok = (not _dialog_would_save(BAD_HOST, "http")
          and _dialog_would_save(GOOD_HOST, "http"))
    print(f"Bug38 dialog gate: bad_save={_dialog_would_save(BAD_HOST)} "
          f"good_save={_dialog_would_save(GOOD_HOST)} -> {ok}")
    return ok


def test_http_probe_uses_invalid_ip_as_connect_target():
    mon = HTTPMonitor("t", BAD_HOST, {}, lambda *a, **k: None)
    mon.settings = {
        "http_url": "http://example.com/",
        "http_timeout": 5,
        "http_success_codes": "2xx,3xx",
        "http_verify_ssl": False,
        "http_follow_redirects": False,
        "http_body_limit_kb": 64,
    }
    r = mon._do_ping()
    reason = r.failure_reason or ""
    ok = (not r.success
          and reason.startswith("dns_failed"))
    print(f"Bug38 HTTP probe: success={r.success} reason={reason!r} -> {ok}")
    return ok


def main():
    results = [
        ("validator", test_invalid_host_rejected_by_validator()),
        ("dialog gate", test_dialog_blocks_invalid_http_connect_target()),
        ("runtime dns_failed", test_http_probe_uses_invalid_ip_as_connect_target()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 38 checks passed.")


if __name__ == "__main__":
    main()
