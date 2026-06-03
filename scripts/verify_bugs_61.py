"""Regression checks for bug 61 (cleanup backfill uses earliest raw floor)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def _hourly_agg_block() -> str:
    with open(DATA_STORE, encoding="utf-8") as f:
        return f.read().split("def _hourly_agg(self, conn", 1)[1].split(
            "def get_sla_stats(", 1)[0]


def test_backfill_uses_earliest_raw_agg_floor_for_gap_scan():
    block = _hourly_agg_block()
    ok = (
        "agg_floor = (first_raw[0] // 3600) * 3600" in block
        and "(tid, agg_floor, current_hour" in block
        and "h = agg_floor" not in block
    )
    print(f"Bug61 backfill agg_floor for gap scan only -> {ok}")
    return ok


def test_gap_scan_uses_agg_floor_not_recompute_only():
    block = _hourly_agg_block()
    idx = block.find("if backfill_internal_gaps:")
    gap = block[idx:block.find("for hour_ts in sorted", idx)]
    ok = "(tid, agg_floor, current_hour" in gap
    print(f"Bug61 gap scan uses agg_floor -> {ok}")
    return ok


def test_routine_still_uses_recompute_floor():
    block = _hourly_agg_block()
    ok = (
        "hour_start = max(agg_floor," in block
        and "min(hour_start, recent_floor)" in block
    )
    print(f"Bug61 routine retention floor preserved -> {ok}")
    return ok


def main():
    results = [
        ("agg_floor", test_backfill_uses_earliest_raw_agg_floor_for_gap_scan()),
        ("gap_floor", test_gap_scan_uses_agg_floor_not_recompute_only()),
        ("routine", test_routine_still_uses_recompute_floor()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 61 checks passed.")


if __name__ == "__main__":
    main()
