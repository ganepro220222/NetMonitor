"""Regression checks for bug 106 (HTTP success status codes validation)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.host_validation import normalize_http_success_codes
from src.ping_engine import HTTPMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIALOGS = os.path.join(ROOT, "src", "ui", "dialogs.py")
HOST_VALIDATION = os.path.join(ROOT, "src", "host_validation.py")
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")


def test_valid_specs():
    cases = [
        ("2xx,3xx", "2xx,3xx"),
        (" 200 , 201 ", "200,201"),
        ("2XX, 3xx", "2xx,3xx"),
        ("", "2xx,3xx"),
        ("204,2xx", "204,2xx"),
    ]
    ok = True
    for raw, want in cases:
        norm, err = normalize_http_success_codes(raw)
        if norm != want or err is not None:
            ok = False
            print(f"  valid {raw!r} -> norm={norm} err={err}")
    print(f"Bug106 valid specs -> {ok}")
    return ok


def test_rejects_invalid():
    invalid = ["2x", "200，201", "200-299", "ok", "200,,201", "99", "600"]
    ok = True
    for raw in invalid:
        norm, err = normalize_http_success_codes(raw)
        if norm is not None or err is None:
            ok = False
            print(f"  should reject {raw!r}: norm={norm} err={err}")
    print(f"Bug106 rejects invalid -> {ok}")
    return ok


def test_runtime_fallback_for_legacy_bad_spec():
    """Corrupt on-disk spec must not mark HTTP 200 as failure."""
    ok200 = HTTPMonitor._is_success(200, "2x")
    ok204 = HTTPMonitor._is_success(204, "ok")
    ok301 = HTTPMonitor._is_success(301, "2xx,3xx")
    ok = ok200 and ok204 and ok301
    print(f"Bug106 _is_success fallback for bad spec -> {ok}")
    return ok


def test_runtime_honors_valid_override():
    ok = HTTPMonitor._is_success(404, "404") and not HTTPMonitor._is_success(
        200, "404")
    print(f"Bug106 _is_success honors explicit code -> {ok}")
    return ok


def test_ui_wires_validator():
    with open(DIALOGS, encoding="utf-8") as f:
        dlg = f.read()
    ok = "_normalize_http_success_codes" in dlg and "codes_err" in dlg
    print(f"Bug106 dialogs validation wired -> {ok}")
    return ok


def test_host_validation_module():
    with open(HOST_VALIDATION, encoding="utf-8") as f:
        src = f.read()
    ok = "def normalize_http_success_codes" in src
    print(f"Bug106 host_validation helper -> {ok}")
    return ok


def test_engine_uses_normalize():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _is_success", 1)[1].split("return False", 1)[0]
    ok = "normalize_http_success_codes" in block
    print(f"Bug106 engine defensive normalize -> {ok}")
    return ok


def main():
    results = [
        ("valid", test_valid_specs()),
        ("invalid", test_rejects_invalid()),
        ("fallback", test_runtime_fallback_for_legacy_bad_spec()),
        ("override", test_runtime_honors_valid_override()),
        ("dialogs", test_ui_wires_validator()),
        ("module", test_host_validation_module()),
        ("engine", test_engine_uses_normalize()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 106 checks passed.")


if __name__ == "__main__":
    main()
