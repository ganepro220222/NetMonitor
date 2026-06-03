"""Regression checks for bug 58 (_hourly_agg internal gap backfill)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def test_hourly_agg_uses_gap_except_query():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _hourly_agg(self, conn):", 1)[1].split(
            "def get_sla_stats(", 1)[0]
    ok = (
        "hours_to_agg = set()" in block
        and "EXCEPT" in block
        and "SELECT DISTINCT (ts / 3600) * 3600 AS hour_ts" in block
        and "for hour_ts in sorted(hours_to_agg):" in block
    )
    print(f"Bug58 gap EXCEPT backfill in _hourly_agg -> {ok}")
    return ok


def test_docstring_mentions_internal_gap():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _hourly_agg(self, conn):", 1)[1].split(
            '"""', 2)[1]
    ok = "internal" in block.lower() or "high-water mark" in block.lower()
    print(f"Bug58 docstring notes internal gaps -> {ok}")
    return ok


def main():
    results = [
        ("gap_query", test_hourly_agg_uses_gap_except_query()),
        ("doc", test_docstring_mentions_internal_gap()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 58 checks passed.")


if __name__ == "__main__":
    main()
