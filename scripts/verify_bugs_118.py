"""Regression checks for bug 118 (_waveChart TDZ before applyTheme on load)."""
import os
import re

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_wave_chart_declared_before_apply_theme_call():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    wave_pos = src.find("let _waveChart = null")
    sync_pos = src.find("function _syncWaveformChartTheme")
    m = re.search(r"(?m)^applyTheme\(cTheme\);\s*$", src)
    apply_call = m.start() if m else -1
    ok = wave_pos != -1 and apply_call != -1 and wave_pos < sync_pos < apply_call
    print(f"Bug118 _waveChart before sync/applyTheme(cTheme) -> {ok}")
    return ok


def test_single_wave_chart_declaration():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    count = len(re.findall(r"let _waveChart\s*=\s*null", src))
    ok = count == 1
    print(f"Bug118 single _waveChart declaration -> {ok} (count={count})")
    return ok


def main():
    results = [
        ("order", test_wave_chart_declared_before_apply_theme_call()),
        ("once", test_single_wave_chart_declaration()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 118 checks passed.")


if __name__ == "__main__":
    main()
