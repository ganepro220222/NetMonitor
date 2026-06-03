"""Regression checks for bug 40 (strict IPv6 literal validation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import is_valid_host

BAD_IPV6 = [":", ":::", "2001:::1", "fe80::1%", "%eth0"]
GOOD_IP = [
    "fe80::1",
    "fe80::1%eth0",
    "2001:db8::1",
    "192.168.1.1",
    "::1",
]
BAD_IPV4 = ["256.1.1.1"]
GOOD_HOST = ["example.com", "nas-server", "good-host.local"]


def test_rejects_malformed_ipv6():
    results = {h: is_valid_host(h) for h in BAD_IPV6}
    ok = not any(results.values())
    print(f"Bug40 bad IPv6: {results} -> {ok}")
    return ok


def test_accepts_valid_ip_literals():
    results = {h: is_valid_host(h) for h in GOOD_IP}
    ok = all(results.values())
    print(f"Bug40 good IP: {results} -> {ok}")
    return ok


def test_rejects_invalid_ipv4():
    ok = not is_valid_host("256.1.1.1")
    print(f"Bug40 256.1.1.1 -> {ok}")
    return ok


def test_hostnames_still_valid():
    results = {h: is_valid_host(h) for h in GOOD_HOST}
    ok = all(results.values())
    print(f"Bug40 hostnames: {results} -> {ok}")
    return ok


def main():
    results = [
        ("bad IPv6", test_rejects_malformed_ipv6()),
        ("good IP", test_accepts_valid_ip_literals()),
        ("bad IPv4", test_rejects_invalid_ipv4()),
        ("hostnames", test_hostnames_still_valid()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 40 checks passed.")


if __name__ == "__main__":
    main()
