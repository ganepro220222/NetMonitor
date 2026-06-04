"""Regression checks for bug 117 (waveform chart theme refresh on applyTheme)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_sync_helper_exists():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "function _syncWaveformChartTheme" in src
        and "_waveChart.options.scales" in src.split(
            "function _syncWaveformChartTheme", 1)[1].split(
            "function applyTheme", 1)[0]
    )
    print(f"Bug117 _syncWaveformChartTheme helper -> {ok}")
    return ok


def test_apply_theme_calls_sync():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("function applyTheme(t)", 1)[1].split(
            "function setTheme", 1)[0]
    ok = "_syncWaveformChartTheme(dark)" in block
    print(f"Bug117 applyTheme calls sync -> {ok}")
    return ok


def test_apply_theme_no_reload_waveform():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("function applyTheme(t)", 1)[1].split(
            "function setTheme", 1)[0]
    ok = "loadWaveform(" not in block and "_renderWaveform(" not in block
    print(f"Bug117 applyTheme no DB reload -> {ok}")
    return ok


def main():
    results = [
        ("helper", test_sync_helper_exists()),
        ("call", test_apply_theme_calls_sync()),
        ("no_reload", test_apply_theme_no_reload_waveform()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 117 checks passed.")


if __name__ == "__main__":
    main()
