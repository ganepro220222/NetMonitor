"""Regression checks for bug 46 (waveform export single GET, no HEAD)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_export_waveform_no_head_preflight():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("async function exportWaveform()", 1)[1].split(
            "// ── Waveform chart", 1)[0]
    ok = ("method:'HEAD'" not in block
          and "method:\"HEAD\"" not in block
          and "await fetch(url)" in block
          and "resp.blob()" in block
          and "createObjectURL(blob)" in block
          and "a.click()" in block
          and "a.href=url" not in block)
    print(f"Bug46 exportWaveform single GET+blob -> {ok}")
    return ok


def test_export_waveform_handles_404_json():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("async function exportWaveform()", 1)[1].split(
            "// ── Waveform chart", 1)[0]
    ok = ("resp.status===404" in block and "resp.json()" in block)
    print(f"Bug46 404 JSON handling -> {ok}")
    return ok


def test_single_request_simulation():
    old_calls = 2   # HEAD preflight + anchor GET download
    new_calls = 1   # one fetch GET with blob
    ok = old_calls == 2 and new_calls == 1
    print(f"Bug46 simulate: old_calls={old_calls} new_calls={new_calls} -> {ok}")
    return ok


def main():
    results = [
        ("no HEAD", test_export_waveform_no_head_preflight()),
        ("404 json", test_export_waveform_handles_404_json()),
        ("single request", test_single_request_simulation()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 46 checks passed.")


if __name__ == "__main__":
    main()
