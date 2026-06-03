"""Regression checks for bug 58 (_hourly_agg internal gap backfill)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def test_hourly_agg_uses_gap_except_query_when_enabled():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _hourly_agg(self, conn", 1)[1].split(
            "def get_sla_stats(", 1)[0]
    ok = (
        "backfill_internal_gaps" in block
        and "if backfill_internal_gaps:" in block
        and "EXCEPT" in block
        and "SELECT DISTINCT (ts / 3600) * 3600 AS hour_ts" in block
    )
    print(f"Bug58 gap EXCEPT when backfill_internal_gaps -> {ok}")
    return ok


def test_writer_cleanup_uses_gap_backfill():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    ok = "self._hourly_agg(conn, backfill_internal_gaps=True)" in text
    print(f"Bug59 cleanup path enables gap backfill -> {ok}")
    return ok


def test_writer_routine_hourly_skips_gap_backfill_flag():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    idx = text.find("if now - last_hourly >= self.HOURLY_AGG_INTERVAL:")
    block = text[idx:idx + 400] if idx >= 0 else ""
    ok = (
        "self._hourly_agg(conn)" in block
        and "backfill_internal_gaps=True" not in block
    )
    print(f"Bug59 routine hourly tick no gap flag -> {ok}")
    return ok


def test_docstring_mentions_internal_gap():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _hourly_agg(self, conn", 1)[1].split(
            '"""', 2)[1]
    ok = "internal" in block.lower() or "high-water mark" in block.lower()
    print(f"Bug58 docstring notes internal gaps -> {ok}")
    return ok


def main():
    results = [
        ("gap_query", test_hourly_agg_uses_gap_except_query_when_enabled()),
        ("cleanup", test_writer_cleanup_uses_gap_backfill()),
        ("routine", test_writer_routine_hourly_skips_gap_backfill_flag()),
        ("doc", test_docstring_mentions_internal_gap()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 58 checks passed.")


if __name__ == "__main__":
    main()
