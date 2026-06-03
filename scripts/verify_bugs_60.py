"""Regression checks for bug 60 (routine hourly limits target discovery window)."""
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


def test_routine_target_discovery_windowed():
    block = _hourly_agg_block()
    ok = (
        "if backfill_internal_gaps:" in block
        and "WHERE ts>=? AND ts<?" in block
        and "else:" in block
    )
    print(f"Bug60 routine windowed target discovery -> {ok}")
    return ok


def test_backfill_keeps_full_target_discovery():
    block = _hourly_agg_block()
    idx = block.find("if backfill_internal_gaps:")
    branch = block[idx:block.find("else:", idx)]
    ok = (
        "SELECT DISTINCT target_id FROM pings_raw" in branch
        and "WHERE ts>=" not in branch
    )
    print(f"Bug60 backfill full target discovery -> {ok}")
    return ok


def test_no_loose_index_scan_claim_for_routine():
    block = _hourly_agg_block()
    ok = "loose-index-scan" not in block
    print(f"Bug60 removed misleading loose-index comment -> {ok}")
    return ok


def main():
    results = [
        ("windowed", test_routine_target_discovery_windowed()),
        ("full_backfill", test_backfill_keeps_full_target_discovery()),
        ("comment", test_no_loose_index_scan_claim_for_routine()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 60 checks passed.")


if __name__ == "__main__":
    main()
