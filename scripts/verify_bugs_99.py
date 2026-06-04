"""Regression checks for bug 99 (legacy 7d raw retention vs rolling SLA P95)."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import ConfigManager, DEFAULT_CONFIG
from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_MANAGER = os.path.join(ROOT, "src", "config_manager.py")
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def test_legacy_config_migrates_7_to_8():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "targets": [],
                "settings": {"db_raw_retention_days": 7, "ping_interval": 1.0},
            }, f)
        cm = ConfigManager(path)
        raw = cm.get_setting("db_raw_retention_days")
        mig = cm.get_setting("_config_migrations") or {}
        ok = raw == 8 and mig.get("raw_retention_7_to_8") is True
        with open(path, encoding="utf-8") as f:
            on_disk = json.load(f)["settings"]["db_raw_retention_days"]
        ok = ok and on_disk == 8
        print(f"Bug99 config migration 7->8: loaded={raw} disk={on_disk} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_7d_retention_strict_boundary_rejects_early_start():
    """7d retention: start even 1s before cutoff must not claim raw coverage."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(path, raw_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    try:
        cutoff = ds._raw_retention_cutoff()
        start = cutoff - 1
        ok = not ds._raw_covers_window_start(start)
        print(f"Bug99 7d strict: start=cutoff-1 covered=False -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_migrated_8d_covers_rolling_7d():
    now = int(time.time())
    start = now - 7 * 86400
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(path, raw_retention_days=8)
    ds._schema_ready.wait(timeout=5)
    try:
        ok = ds._raw_covers_window_start(start)
        print(f"Bug99 8d retention covers rolling 7d start -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_migration_no_p95_tolerance():
    with open(CONFIG_MANAGER, encoding="utf-8") as f:
        cm = f.read()
    with open(DATA_STORE, encoding="utf-8") as f:
        ds = f.read()
    block = ds.split("def _raw_covers_window_start", 1)[1].split(
        "def _global_lat_p95_sql", 1)[0]
    ok = (
        "_apply_config_migrations" in cm
        and "raw_retention_7_to_8" in cm
        and DEFAULT_CONFIG["settings"]["db_raw_retention_days"] == 8
        and "_RAW_COVERS_TOLERANCE_S" not in ds
        and "Bug100" in block or "no slack" in block.lower() or
        "int(start_ts) >= self._raw_retention_cutoff()" in block
    )
    print(f"Bug99 source migration, strict P95 cutoff -> {ok}")
    return ok


def main():
    results = [
        ("migrate", test_legacy_config_migrates_7_to_8()),
        ("7d_strict", test_7d_retention_strict_boundary_rejects_early_start()),
        ("eight_day", test_migrated_8d_covers_rolling_7d()),
        ("source", test_source_migration_no_p95_tolerance()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 99 checks passed.")


if __name__ == "__main__":
    main()
