"""Regression checks for bug 126 (traceroute preserves rtt_ms=0.0)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRACEROUTE = os.path.join(ROOT, "src", "traceroute_util.py")


def _hop_rtt_ms_from_rtt(rtt):
    """Mirror traceroute_util hop_rec rtt_ms assignment."""
    return round(rtt, 1) if rtt is not None else None


def test_zero_rtt_preserved():
    ok = _hop_rtt_ms_from_rtt(0.0) == 0.0
    print(f"Bug126 rtt=0.0 -> rtt_ms=0.0 -> {ok}")
    return ok


def test_none_rtt_stays_none():
    ok = _hop_rtt_ms_from_rtt(None) is None
    print(f"Bug126 rtt=None -> rtt_ms=None -> {ok}")
    return ok


def test_positive_rtt_rounded():
    ok = _hop_rtt_ms_from_rtt(1.234) == 1.2
    print(f"Bug126 rtt=1.234 -> rtt_ms=1.2 -> {ok}")
    return ok


def test_ok_hop_with_zero_rtt_not_none():
    rtt = 0.0
    hop_ip = "127.0.0.1"
    rtt_ms = _hop_rtt_ms_from_rtt(rtt)
    status = "timeout_raw" if not hop_ip else "ok"
    ok = rtt_ms == 0.0 and status == "ok"
    print(f"Bug126 ok hop with 0ms RTT keeps rtt_ms -> {ok}")
    return ok


def test_source_uses_is_not_none():
    with open(TRACEROUTE, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "round(rtt, 1) if rtt is not None else None" in src
        and "round(rtt, 1) if rtt else None" not in src
    )
    print(f"Bug126 source uses `rtt is not None` -> {ok}")
    return ok


def test_parse_zero_ms_line():
    """Simulate Windows tracert line with explicit 0 ms."""
    rtt_m = re.search(r"[<]?(\d+(?:\.\d+)?)\s*ms",
                      "1    0 ms 0 ms 0 ms 127.0.0.1", re.I)
    rtt = float(rtt_m.group(1)) if rtt_m else None
    rtt_ms = _hop_rtt_ms_from_rtt(rtt)
    ok = rtt == 0.0 and rtt_ms == 0.0
    print(f"Bug126 parsed '0 ms' line keeps rtt_ms=0.0 -> {ok}")
    return ok


def main():
    results = [
        ("zero", test_zero_rtt_preserved()),
        ("none", test_none_rtt_stays_none()),
        ("positive", test_positive_rtt_rounded()),
        ("ok_hop", test_ok_hop_with_zero_rtt_not_none()),
        ("source", test_source_uses_is_not_none()),
        ("parse", test_parse_zero_ms_line()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 126 checks passed.")


if __name__ == "__main__":
    main()
