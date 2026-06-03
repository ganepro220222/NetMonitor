"""Regression checks for bug 72 (waveform window export keeps sub-second ts)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import fmt_ts_ms


def _waveform_export_timestamp(ts) -> str:
    return fmt_ts_ms(ts) if ts else ""


def _waveform_export_unix_ts(ts):
    return round(float(ts), 3) if ts else ""

WAVEFORM = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "waveform_window.py",
)


def test_export_formatters_distinguish_subsecond():
    base = 1780507000.0
    t1 = base + 0.10
    t2 = base + 0.70
    csv_ts = [_waveform_export_timestamp(t1), _waveform_export_timestamp(t2)]
    csv_unix = [_waveform_export_unix_ts(t1), _waveform_export_unix_ts(t2)]
    ok = (
        csv_ts[0] != csv_ts[1]
        and csv_unix[0] != csv_unix[1]
        and csv_ts[0] == fmt_ts_ms(t1)
        and csv_ts[1] == fmt_ts_ms(t2)
        and csv_unix == [1780507000.1, 1780507000.7]
    )
    print(f"Bug72 csv_ts={csv_ts} csv_unix={csv_unix} -> {ok}")
    return ok


def test_source_no_second_truncation_in_export_paths():
    with open(WAVEFORM, encoding="utf-8") as f:
        text = f.read()
    csv_block = text.split("def _export_csv", 1)[1].split(
        "def _export_png", 1)[0]
    xlsx_block = text.split("def _export_excel", 1)[1].split(
        "def _set_status", 1)[0]
    xlsx_data = xlsx_block.split("for p in pts:", 1)[-1]
    ok = (
        "_waveform_export_timestamp(ts)" in csv_block
        and "_waveform_export_unix_ts(ts)" in csv_block
        and 'timespec="seconds"' not in csv_block
        and "int(ts)" not in csv_block
        and "_waveform_export_timestamp(ts)" in xlsx_data
        and "_waveform_export_unix_ts(ts)" in xlsx_data
        and "int(ts)" not in xlsx_data
        and "def _waveform_export_timestamp" in text
        and "fmt_ts_ms" in text
        and "round(float(ts), 3)" in text
    )
    print(f"Bug72 source export helpers + no int(ts) -> {ok}")
    return ok


def main():
    results = [
        ("formatters", test_export_formatters_distinguish_subsecond()),
        ("source", test_source_no_second_truncation_in_export_paths()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 72 checks passed.")


if __name__ == "__main__":
    main()
