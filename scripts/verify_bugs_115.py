"""Regression checks for bug 115 (stats_reset on wipe start clears browser stats)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_begin_wipe_broadcasts_stats_reset():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("def begin_target_history_wipe", 1)[1].split(
            "def _history_data_available", 1)[0]
    ok = (
        '_stats.pop(tid, None)' in block
        and '"type": "stats_reset"' in block
    )
    print(f"Bug115 begin_target_history_wipe clears + stats_reset -> {ok}")
    return ok


def test_stats_reset_rebuilds_bars_not_db():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    block = src.split("msg.type==='stats_reset'", 1)[1].split(
        "msg.type==='history_wiped'", 1)[0]
    ok = (
        "purgeDonutTarget(msg.tid)" in block
        and "buildBarCharts()" in block
        and "_refreshStatsCharts" not in block
        and "loadWaveform" not in block
    )
    print(f"Bug115 stats_reset UI-only refresh -> {ok}")
    return ok


def test_history_wiped_still_refreshes_db():
    with open(WEB, encoding="utf-8") as f:
        block = f.read().split("msg.type==='history_wiped'", 1)[1].split(
            "msg.type==='remove'", 1)[0]
    ok = "_refreshStatsCharts" in block and "loadWaveform" in block
    print(f"Bug115 history_wiped still DB refresh -> {ok}")
    return ok


def main():
    results = [
        ("begin", test_begin_wipe_broadcasts_stats_reset()),
        ("stats_reset", test_stats_reset_rebuilds_bars_not_db()),
        ("history_wiped", test_history_wiped_still_refreshes_db()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 115 checks passed.")


if __name__ == "__main__":
    main()
