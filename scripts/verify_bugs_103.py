"""Regression checks for bug 103 (gray card UI + DNS expected IP validation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import normalize_dns_expected_ipv4

IP_CARD = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "ip_card.py",
)
DIALOGS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "dialogs.py",
)
HOST_VALIDATION = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "host_validation.py",
)


def _latency_branch(status, latency_ms, failure_reason):
    """Mirror IPCard.update_status latency branch without customtkinter."""
    if latency_ms is not None:
        return ("latency", latency_ms)
    if status == "gray" and not failure_reason:
        return ("probing", "探测中...")
    return ("failure", failure_reason)


def test_gray_reset_not_timeout_label():
    kind, text = _latency_branch("gray", None, None)
    ok = kind == "probing" and text == "探测中..."
    print(f"Bug103 gray reset branch -> {kind} {text!r} -> {ok}")
    return ok


def test_real_failure_still_red():
    kind, reason = _latency_branch("red", None, "dns_timeout")
    ok = kind == "failure" and reason == "dns_timeout"
    print(f"Bug103 red failure branch -> {ok}")
    return ok


def test_dns_expected_valid_ipv4():
    norm, err = normalize_dns_expected_ipv4(" 1.1.1.1 , 8.8.8.8 ")
    ok = norm == "1.1.1.1,8.8.8.8" and err is None
    print(f"Bug103 valid DNS expected -> {norm} err={err} -> {ok}")
    return ok


def test_dns_expected_rejects_invalid():
    cases = ["abc", "1.1.1.1，8.8.8.8", "1.1.1.1;8.8.8.8", "::1"]
    ok = True
    for raw in cases:
        norm, err = normalize_dns_expected_ipv4(raw)
        if norm is not None or err is None:
            ok = False
            print(f"  should reject {raw!r}: norm={norm} err={err}")
    print(f"Bug103 invalid DNS expected rejected -> {ok}")
    return ok


def test_source_fixes_present():
    with open(IP_CARD, encoding="utf-8") as f:
        ic = f.read()
    with open(DIALOGS, encoding="utf-8") as f:
        dg = f.read()
    with open(HOST_VALIDATION, encoding="utf-8") as f:
        hv = f.read()
    ok = (
        'status == "gray"' in ic and "探测中..." in ic
        and "normalize_dns_expected_ipv4" in dg
        and "def normalize_dns_expected_ipv4" in hv
    )
    print(f"Bug103 source markers -> {ok}")
    return ok


def main():
    results = [
        ("gray", test_gray_reset_not_timeout_label()),
        ("failure", test_real_failure_still_red()),
        ("dns_ok", test_dns_expected_valid_ipv4()),
        ("dns_bad", test_dns_expected_rejects_invalid()),
        ("source", test_source_fixes_present()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 103 checks passed.")


if __name__ == "__main__":
    main()
