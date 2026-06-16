"""Regression: global semantic settings bump _settings_version (Bug 149)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import PingEngine

PING_ENGINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ping_engine.py",
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


class _FakeDS:
    def __init__(self):
        self._gen = {}

    def current_target_generation(self, target_id: str) -> int:
        return self._gen.get(target_id, 0)

    def bump_target_generation(self, target_id: str) -> None:
        self._gen[target_id] = self.current_target_generation(target_id) + 1


def test_global_timeout_bumps_settings_version():
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1")
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    before = (mon._settings_version, mon.settings.get("timeout"))
    probe_v = mon._settings_version
    eng.update_global_settings({"timeout": 5.0})
    after = (mon._settings_version, mon.settings.get("timeout"))
    rejected = probe_v == mon._settings_version
    eng.remove_target("t1", join_timeout=2.0)
    ok = (
        before == (0, 1.0)
        and after == (1, 5.0)
        and not rejected
    )
    print(f"Bug149 global timeout bumps version -> {ok} before={before} after={after}")
    return ok


def test_global_timeout_override_skips_bump():
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1", custom_settings={"timeout": 8.0})
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    mon._override_keys = {"timeout"}
    probe_v = mon._settings_version
    eng.update_global_settings({"timeout": 5.0})
    ok = (
        mon._settings_version == probe_v
        and mon.settings.get("timeout") == 8.0
    )
    eng.remove_target("t1", join_timeout=2.0)
    print(f"Bug149 per-target timeout override preserved -> {ok}")
    return ok


def test_global_semantic_bumps_datastore_generation():
    ds = _FakeDS()
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.set_data_store(ds)
    eng.add_target("t1", "127.0.0.1")
    eng.update_global_settings({"timeout": 5.0})
    eng.remove_target("t1", join_timeout=2.0)
    ok = ds.current_target_generation("t1") == 1
    print(f"Bug149 DS gen bump on global semantic -> {ok}")
    return ok


def test_threshold_only_global_change_no_bump():
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1")
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    probe_v = mon._settings_version
    eng.update_global_settings({"consecutive_loss_red": 7})
    ok = mon._settings_version == probe_v
    eng.remove_target("t1", join_timeout=2.0)
    print(f"Bug149 threshold-only global change no bump -> {ok}")
    return ok


def test_source_update_global_settings_semantic_guard():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def update_global_settings", 1)[1].split(
            "def update_settings", 1)[0]
    ok = (
        "semantic_changed" in block
        and "bump_target_generation" in block
        and block.find("bump_target_generation")
        < block.find("with m._commit_lock:")
    )
    print(f"Bug149 source update_global_settings guard -> {ok}")
    return ok


def main():
    results = [
        ("version_bump", test_global_timeout_bumps_settings_version()),
        ("override", test_global_timeout_override_skips_bump()),
        ("ds_bump", test_global_semantic_bumps_datastore_generation()),
        ("threshold_only", test_threshold_only_global_change_no_bump()),
        ("source", test_source_update_global_settings_semantic_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 149 checks passed.")


if __name__ == "__main__":
    main()
