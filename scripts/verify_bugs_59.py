"""Regression checks for bug 59 (gap scan not on routine hourly tick)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def test_signature_has_backfill_flag():
    with open(DATA_STORE, encoding="utf-8") as f:
        text = f.read()
    ok = "def _hourly_agg(self, conn, *, backfill_internal_gaps: bool = False):" in text
    print(f"Bug59 backfill_internal_gaps parameter -> {ok}")
    return ok


def test_gap_query_gated():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _hourly_agg(self, conn", 1)[1].split(
            "def get_sla_stats(", 1)[0]
    ok = "if backfill_internal_gaps:" in block
    print(f"Bug59 gap query gated -> {ok}")
    return ok


def main():
    results = [
        ("signature", test_signature_has_backfill_flag()),
        ("gated", test_gap_query_gated()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 59 checks passed.")


if __name__ == "__main__":
    main()
