"""Regression checks for bug 62 (backfill must not REPLACE old complete hourly)."""
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


def test_no_full_agg_floor_sweep_in_backfill():
    block = _hourly_agg_block()
    backfill = block.split("if backfill_internal_gaps:", 1)[1].split(
        "else:", 1)[0]
    ok = "h = agg_floor" not in backfill
    print(f"Bug62 no agg_floor full sweep -> {ok}")
    return ok


def test_old_rescue_uses_insert_or_ignore():
    block = _hourly_agg_block()
    ok = (
        "INSERT OR IGNORE INTO pings_hourly" in block
        and "hour_ts < recent_floor" in block
    )
    print(f"Bug62 INSERT OR IGNORE for old rescue -> {ok}")
    return ok


def test_gap_except_still_present():
    block = _hourly_agg_block()
    ok = "EXCEPT" in block and "agg_floor" in block
    print(f"Bug62 gap EXCEPT with agg_floor -> {ok}")
    return ok


def main():
    results = [
        ("no_sweep", test_no_full_agg_floor_sweep_in_backfill()),
        ("ignore", test_old_rescue_uses_insert_or_ignore()),
        ("gap", test_gap_except_still_present()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 62 checks passed.")


if __name__ == "__main__":
    main()
