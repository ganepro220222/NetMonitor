"""Regression checks for bug 100 (no P95 coverage tolerance past raw cutoff)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def test_start_before_cutoff_not_covered():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(path, raw_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    try:
        cutoff = ds._raw_retention_cutoff()
        start = cutoff - 60
        ok = not ds._raw_covers_window_start(start)
        print(f"Bug100 start 60s before cutoff covered=False -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_rollup_skips_p95_when_not_covered():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(path, raw_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    try:
        now = time.time()
        cutoff = ds._raw_retention_cutoff()
        start = cutoff - 60
        end = now
        conn = ds._read_conn()
        merged = ds._rollup_latency_for_window(
            conn, "T", [], start, end)
        ok = merged.get("lat_p95") is None
        print(f"Bug100 rollup lat_p95 None when uncovered -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_strict_cutoff():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _raw_covers_window_start", 1)[1].split(
            "def _global_lat_p95_sql", 1)[0]
    ok = (
        "_RAW_COVERS_TOLERANCE_S" not in block
        and "int(start_ts) >= self._raw_retention_cutoff()" in block
    )
    print(f"Bug100 source strict cutoff -> {ok}")
    return ok


def main():
    results = [
        ("not_covered", test_start_before_cutoff_not_covered()),
        ("rollup", test_rollup_skips_p95_when_not_covered()),
        ("source", test_source_strict_cutoff()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 100 checks passed.")


if __name__ == "__main__":
    main()
