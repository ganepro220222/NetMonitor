"""Regression checks for bug 116 (waveform chart theme via data-theme sync)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_apply_theme_sets_data_theme():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("function applyTheme(t)", 1)[1].split(
            "function setTheme", 1)[0]
    ok = (
        "setAttribute('data-theme'" in block
        and "dark?'dark':'light'" in block
    )
    print(f"Bug116 applyTheme syncs data-theme -> {ok}")
    return ok


def test_render_waveform_reads_data_theme():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("function _renderWaveform", 1)[1].split(
            "function ", 2)[0]
    ok = "getAttribute('data-theme')==='dark'" in block
    print(f"Bug116 _renderWaveform uses data-theme -> {ok}")
    return ok


def main():
    results = [
        ("applyTheme", test_apply_theme_sets_data_theme()),
        ("render", test_render_waveform_reads_data_theme()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 116 checks passed.")


if __name__ == "__main__":
    main()
