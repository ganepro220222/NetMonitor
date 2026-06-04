"""Regression checks for SLA P95 UX (rolling window, hints) and waveform Y-scale."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")


def _temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


def test_rolling_7d_covers_raw_for_p95():
    """Rolling 7d start should be inside default 8d raw retention."""
    now = int(time.time())
    start_rolling = now - 7 * 86400
    path = _temp_db()
    ds = DataStore(path, raw_retention_days=8)
    ds._schema_ready.wait(timeout=5)
    try:
        ok = ds._raw_covers_window_start(start_rolling)
        print(f"Bug98 rolling 7d start covered by raw retention -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_calendar_7d_midnight_often_uncovered():
    """Calendar 7d at 00:00 is ~1 day older than rolling — fails on 7d retention."""
    now = int(time.time())
    start_cal = now - 7 * 86400
    start_cal = start_cal - (start_cal % 86400)  # midnight boundary
    path = _temp_db()
    ds = DataStore(path, raw_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    try:
        ok = not ds._raw_covers_window_start(start_cal)
        print(f"Bug98 calendar midnight start outside 7d raw -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_sla_rolling_and_p95_ui():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    sla = text.split("function initSLATab", 1)[1].split("function exportSLAExcel", 1)[0]
    wave = text.split("let _waveYScale", 1)[1].split("function loadWaveform", 1)[0]
    checks = {
        "rolling": "_slaRollingDays" in sla and "getSLATimeRange" in sla,
        "rolling_ts": "_slaRollingDays" in sla and "86400" in sla,
        "msP95": "msP95" in sla,
        "api_flag": "p95_from_raw" in text,
        "copy": "P95" in text and "原始探测明细" in text,
        "wave_btn": "toggleWaveformScale" in text and "waveform-scale-btn" in text,
        "log_scale": "logarithmic" in text,
    }
    ok = all(checks.values())
    print(f"Bug98 source checks {checks} -> {ok}")
    return ok


def main():
    results = [
        ("rolling_covers", test_rolling_7d_covers_raw_for_p95()),
        ("calendar_gap", test_calendar_7d_midnight_often_uncovered()),
        ("source", test_source_sla_rolling_and_p95_ui()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 98 checks passed.")


if __name__ == "__main__":
    main()
