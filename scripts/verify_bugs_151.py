"""Regression: bump DataStore generation before settings swap (Bug 151)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore
from src.ping_engine import PingEngine

PING_ENGINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ping_engine.py",
)
DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)

_CFG = {
    "window_size": 10,
    "ping_interval": 0.05,
    "timeout": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
    "http_success_codes": "2xx",
}


def _source_bump_before_settings_swap():
    with open(PING_ENGINE, encoding="utf-8") as f:
        text = f.read()
    for fn in ("def update_target_thresholds", "def update_global_settings"):
        block = text.split(fn, 1)[1].split("\n    def ", 1)[0]
        bump = block.find("bump_target_generation")
        lock = block.find("with m._commit_lock:")
        ok = bump != -1 and lock != -1 and bump < lock
        if not ok:
            print(f"Bug151 source {fn} bump-before-lock -> False")
            return False
    print("Bug151 source bump before settings swap -> True")
    return True


def _source_record_traceroute_producer_guard():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def record_traceroute", 1)[1].split(
            "def set_wipe_complete_callback", 1)[0]
    ok = (
        "current_target_generation(target_id) != captured_generation" in block
        and block.find("return") < block.find("_queue.put")
    )
    print(f"Bug151 source record_traceroute producer guard -> {ok}")
    return ok


def test_stale_traceroute_rejected_at_producer():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        ds.bump_target_generation("t1")
        accepted = []
        real_put = ds._queue.put

        def track_put(item):
            if item[0] == "traceroute":
                accepted.append(item)
            return real_put(item)

        ds._queue.put = track_put
        ds.record_traceroute(
            "t1", "GW", "10.0.0.1", time.time(), [{"hop": 1}],
            captured_generation=0)
        ds.shutdown()
        ok = len(accepted) == 0
        print(f"Bug151 stale traceroute not queued -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_global_semantic_bumps_before_settings_version():
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1")
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    order = []

    class _DS:
        def bump_target_generation(self, tid):
            order.append(("bump", mon._settings_version, mon.settings.get("timeout")))

    eng.set_data_store(_DS())
    eng.update_global_settings({"timeout": 5.0})
    eng.remove_target("t1", join_timeout=2.0)
    ok = (
        len(order) == 1
        and order[0][1] == 0
        and order[0][2] == 1.0
        and mon.settings.get("timeout") == 5.0
        and mon._settings_version == 1
    )
    print(f"Bug151 bump precedes settings/version swap -> {ok} order={order}")
    return ok


def main():
    results = [
        ("source_order", _source_bump_before_settings_swap()),
        ("source_tr", _source_record_traceroute_producer_guard()),
        ("producer", test_stale_traceroute_rejected_at_producer()),
        ("runtime_order", test_global_semantic_bumps_before_settings_version()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 151 checks passed.")


if __name__ == "__main__":
    main()
