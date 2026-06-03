"""Regression checks for bug 39 (per-label hostname validation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import is_valid_host

BAD = [
    "a.-b",
    "a.b-",
    "example.-bad",
    "example.bad-",
    "bad..example",
    "-bad.example",
    "not a host with spaces",
]

GOOD = [
    "a.b",
    "nas-server",
    "good-host.local",
    "example.com",
    "1.2.3.4",
]


def test_rejects_hyphen_label_edges():
    bad_results = {h: is_valid_host(h) for h in BAD}
    ok = not any(bad_results.values())
    print(f"Bug39 bad: {bad_results} -> {ok}")
    return ok


def test_accepts_valid_hosts():
    good_results = {h: is_valid_host(h) for h in GOOD}
    ok = all(good_results.values())
    print(f"Bug39 good: {good_results} -> {ok}")
    return ok


def main():
    results = [
        ("reject bad", test_rejects_hyphen_label_edges()),
        ("accept good", test_accepts_valid_hosts()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 39 checks passed.")


if __name__ == "__main__":
    main()
