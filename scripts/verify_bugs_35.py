"""Regression checks for bug 35 (5-minute in-memory waveform buffer)."""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.history_store import DataPoint, HistoryStore, TargetHistory

INTERVAL = 0.5
SAMPLES = 601
WINDOW = TargetHistory.WINDOW_SECONDS
ANCHOR = 1_700_000_000.0


def _fill_history(maxlen: int) -> TargetHistory:
    hist = TargetHistory(maxlen=maxlen)
    for i in range(SAMPLES):
        ts = ANCHOR - (SAMPLES - 1 - i) * INTERVAL
        hist._buffer.append(DataPoint(timestamp=ts, latency_ms=10.0))
    return hist


def _plot_at_anchor(hist: TargetHistory):
    with patch("src.history_store.time.time", return_value=ANCHOR):
        return hist.get_plot_data()


def test_defaults_are_1000():
    store = HistoryStore()
    store.ensure_target("t1")
    h = store.get_history("t1")
    ok = (TargetHistory.DEFAULT_MAXLEN == 1000
          and store._maxlen == 1000
          and h._buffer.maxlen == 1000)
    print(f"Bug35 defaults: store_maxlen={store._maxlen} "
          f"buffer_maxlen={h._buffer.maxlen} -> {ok}")
    return ok


def test_old_maxlen_300_truncates():
    hist = _fill_history(300)
    times, _ = _plot_at_anchor(hist)
    oldest = min(times) if times else 0.0
    ok = len(hist) == 300 and oldest > -200
    print(f"Bug35 maxlen=300 (bad): buffer={len(hist)} plot={len(times)} "
          f"oldest_x={oldest:.1f} -> {ok}")
    return ok


def test_maxlen_1000_covers_five_minutes():
    hist = _fill_history(TargetHistory.DEFAULT_MAXLEN)
    times, lats = _plot_at_anchor(hist)
    oldest = min(times) if times else 0.0
    ok = (len(hist) == SAMPLES
          and len(times) == SAMPLES
          and len(lats) == SAMPLES
          and oldest <= -(WINDOW - 5))
    print(f"Bug35 maxlen=1000: buffer={len(hist)} plot={len(times)} "
          f"oldest_x={oldest:.1f} expected~=-{WINDOW} -> {ok}")
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
    ok = len(times) == SAMPLES and oldest <= -(WINDOW - 5)
    print(f"Bug35 HistoryStore path: plot={len(times)} oldest_x={oldest:.1f} -> {ok}")
    return ok


def main():
    results = [
        ("defaults 1000", test_defaults_are_1000()),
        ("300 truncates (control)", test_old_maxlen_300_truncates()),
        ("1000 full window", test_maxlen_1000_covers_five_minutes()),
        ("HistoryStore path", test_history_store_plot_path()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 35 checks passed.")


if __name__ == "__main__":
    main()
