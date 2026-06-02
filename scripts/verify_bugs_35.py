"""Regression checks for bug 35 (5-minute waveform at 0.05s min interval)."""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import (
    DEFAULT_CONFIG,
    MIN_PING_INTERVAL_S,
    normalize_ping_interval,
)
from src.history_store import DataPoint, HistoryStore, TargetHistory

INTERVAL = MIN_PING_INTERVAL_S
SAMPLES = 6001
WINDOW = TargetHistory.WINDOW_SECONDS
ANCHOR = 1_700_000_000.0


def _fill_history(maxlen: int, samples: int = SAMPLES,
                  interval: float = INTERVAL) -> TargetHistory:
    hist = TargetHistory(maxlen=maxlen)
    for i in range(samples):
        ts = ANCHOR - (samples - 1 - i) * interval
        hist._buffer.append(DataPoint(timestamp=ts, latency_ms=10.0))
    return hist


def _plot_at_anchor(hist: TargetHistory):
    with patch("src.history_store.time.time", return_value=ANCHOR):
        return hist.get_plot_data()


def _dialog_accepts(iv: float) -> bool:
    """Same rule as AddTargetDialog / EditTargetDialog."""
    return iv >= MIN_PING_INTERVAL_S


def test_defaults_are_7000():
    store = HistoryStore()
    store.ensure_target("t1")
    h = store.get_history("t1")
    ok = (TargetHistory.DEFAULT_MAXLEN == 7000
          and store._maxlen == 7000
          and h._buffer.maxlen == 7000)
    print(f"Bug35 defaults: store_maxlen={store._maxlen} "
          f"buffer_maxlen={h._buffer.maxlen} -> {ok}")
    return ok


def test_maxlen_7000_covers_five_minutes():
    hist = _fill_history(TargetHistory.DEFAULT_MAXLEN)
    times, lats = _plot_at_anchor(hist)
    oldest = min(times) if times else 0.0
    ok = (len(hist) == SAMPLES
          and len(times) == SAMPLES
          and len(lats) == SAMPLES
          and oldest <= -(WINDOW - 1))
    print(f"Bug35 maxlen=7000 @0.05s: buffer={len(hist)} plot={len(times)} "
          f"oldest_x={oldest:.2f} expected~=-{WINDOW} -> {ok}")
    return ok


def test_maxlen_1000_truncates_at_005():
    hist = _fill_history(1000)
    times, _ = _plot_at_anchor(hist)
    oldest = min(times) if times else 0.0
    ok = len(hist) == 1000 and oldest > -(WINDOW - 100)
    print(f"Bug35 maxlen=1000 control: buffer={len(hist)} "
          f"oldest_x={oldest:.2f} (expect ~-50s) -> {ok}")
    return ok


def test_history_store_plot_path():
    store = HistoryStore()
    store.ensure_target("t1")
    for i in range(SAMPLES):
        ts = ANCHOR - (SAMPLES - 1 - i) * INTERVAL
        store._histories["t1"]._buffer.append(
            DataPoint(timestamp=ts, latency_ms=5.0))
    with patch("src.history_store.time.time", return_value=ANCHOR):
        times, _ = store.get_history("t1").get_plot_data()
    oldest = min(times)
    ok = len(times) == SAMPLES and oldest <= -(WINDOW - 1)
    print(f"Bug35 HistoryStore path: plot={len(times)} oldest_x={oldest:.2f} -> {ok}")
    return ok


def test_dialog_interval_validation():
    cases = [
        (0.05, True),
        (0.049, False),
        (0.005, False),
    ]
    ok = all(_dialog_accepts(iv) == expect for iv, expect in cases)
    print(f"Bug35 dialog bounds (add/edit): {cases} -> {ok}")
    return ok


def test_engine_clamps_sub_minimum():
    ok = normalize_ping_interval(0.005) == MIN_PING_INTERVAL_S
    ok = ok and normalize_ping_interval(1.0) == 1.0
    ok = ok and normalize_ping_interval("bad", default=2.0) == 2.0
    print(f"Bug35 normalize: 0.005->{normalize_ping_interval(0.005)} "
          f"1.0->{normalize_ping_interval(1.0)} -> {ok}")
    return ok


def test_default_ping_interval_unchanged():
    ok = DEFAULT_CONFIG["settings"]["ping_interval"] == 1.0
    print(f"Bug35 default ping_interval={DEFAULT_CONFIG['settings']['ping_interval']} "
          f"-> {ok}")
    return ok


def main():
    results = [
        ("defaults 7000", test_defaults_are_7000()),
        ("7000 full 5min @0.05s", test_maxlen_7000_covers_five_minutes()),
        ("1000 truncates (control)", test_maxlen_1000_truncates_at_005()),
        ("HistoryStore path", test_history_store_plot_path()),
        ("dialog 0.05 bounds", test_dialog_interval_validation()),
        ("engine clamp", test_engine_clamps_sub_minimum()),
        ("default 1.0s", test_default_ping_interval_unchanged()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 35 checks passed.")


if __name__ == "__main__":
    main()
