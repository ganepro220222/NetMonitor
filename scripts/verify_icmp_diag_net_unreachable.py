"""Regression: icmp_diag parse_ping_output classifies Linux net-unreach correctly."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.icmp_diag import parse_ping_output, ERROR_NET_UNREACH, ERROR_TIMEOUT


def _cases():
    return [
        ("connect: Network is unreachable", "", False, ERROR_NET_UNREACH),
        ("ping: connect: Network is unreachable", "", False, ERROR_NET_UNREACH),
        ("network unreachable", "", False, ERROR_NET_UNREACH),
        ("destination net unreachable", "", False, ERROR_NET_UNREACH),
        ("网络不可达", "", False, ERROR_NET_UNREACH),
    ]


def main():
    ok = True
    for stdout, stderr, is_win, expected in _cases():
        rtt, code = parse_ping_output(stdout, stderr, is_win)
        passed = rtt is None and code == expected
        ok = ok and passed
        print(f"  {stdout!r} -> {code} (expect {expected}) {'OK' if passed else 'FAIL'}")
    # Ensure we did not regress generic timeout classification.
    rtt, code = parse_ping_output("Request timed out", "", False)
    timeout_ok = rtt is None and code == ERROR_TIMEOUT
    ok = ok and timeout_ok
    print(f"  request timed out -> {code} (expect {ERROR_TIMEOUT}) "
          f"{'OK' if timeout_ok else 'FAIL'}")
    if ok:
        print("PASS verify_icmp_diag_net_unreachable")
        return 0
    print("FAIL verify_icmp_diag_net_unreachable")
    return 1


if __name__ == "__main__":
    sys.exit(main())
