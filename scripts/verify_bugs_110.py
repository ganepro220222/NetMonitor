"""Regression checks for bug 110 (HTTP latency_warn placeholder shows 2000ms)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import effective_latency_warn_ms_hint
from src.ping_engine import HTTPMonitor

DIALOGS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "dialogs.py",
)


def test_http_hint_2000():
    hint = effective_latency_warn_ms_hint("https", {"latency_warn_ms": 150})
    ok = hint == str(HTTPMonitor.DEFAULT_WARN_LAT)
    print(f"Bug110 HTTP hint -> {hint} (want 2000) -> {ok}")
    return ok


def test_icmp_uses_global():
    hint = effective_latency_warn_ms_hint("icmp", {"latency_warn_ms": 300})
    ok = hint == "300"
    print(f"Bug110 ICMP hint uses global -> {ok}")
    return ok


def test_dialogs_refresh_on_type_change():
    with open(DIALOGS, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_effective_latency_warn_ms_hint" in src
        and "_refresh_latency_warn_placeholder" in src
        and src.find("_refresh_latency_warn_placeholder")
        < src.find("def _collect_type_result")
    )
    print(f"Bug110 dialogs wired -> {ok}")
    return ok


def test_add_edit_not_hardcoded_150_placeholder():
    with open(DIALOGS, encoding="utf-8") as f:
        src = f.read()
    add = src.split("class AddTargetDialog", 1)[1].split(
        "class EditTargetDialog", 1)[0]
    edit = src.split("class EditTargetDialog", 1)[1]
    ok = (
        "_effective_latency_warn_ms_hint" in add
        and "_effective_latency_warn_ms_hint" in edit
        and '"latency_warn_ms",        150)' not in add
        and '"latency_warn_ms",        150)' not in edit
    )
    print(f"Bug110 no hardcoded 150 wlat placeholder -> {ok}")
    return ok


def main():
    results = [
        ("http_2000", test_http_hint_2000()),
        ("icmp_global", test_icmp_uses_global()),
        ("dialogs", test_dialogs_refresh_on_type_change()),
        ("no_150", test_add_edit_not_hardcoded_150_placeholder()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 110 checks passed.")


if __name__ == "__main__":
    main()
