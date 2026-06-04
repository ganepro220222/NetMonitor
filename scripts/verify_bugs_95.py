"""Regression checks for bug 95 (settings/version split on semantic edit)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import PingEngine, PingResult, TargetMonitor

PING_ENGINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ping_engine.py",
)
MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)

_CFG = {
    "window_size": 10,
    "ping_interval": 0.05,
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


class _BlockingMonitor(TargetMonitor):
    def __init__(self, started: threading.Event, release: threading.Event, **kwargs):
        super().__init__(**kwargs)
        self._probe_started = started
        self._probe_release = release

    def _do_ping(self) -> PingResult:
        self._probe_started.set()
        self._probe_release.wait(timeout=5.0)
        return PingResult(success=True, latency_ms=1.0)


def _run_loop_commit_would_accept(mon, probe_settings_version: int) -> bool:
    with mon._commit_lock:
        return probe_settings_version == mon._settings_version


def test_old_prebump_allows_stale_commit():
    """Reproduce Bug95 shape: version bumped before settings swap."""
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1", custom_settings=dict(_CFG))
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    eng.invalidate_target_settings("t1")
    probe_v = mon._settings_version
    codes_at_capture = mon.settings.get("http_success_codes")
    would_commit = _run_loop_commit_would_accept(mon, probe_v)
    eng.update_target_thresholds("t1", {"http_success_codes": "500"})
    eng.remove_target("t1", join_timeout=2.0)
    ok = (
        would_commit
        and codes_at_capture == "2xx"
        and mon.settings.get("http_success_codes") == "500"
    )
    print(f"Bug95 old pre-bump stale commit path -> {ok}")
    return ok


def test_atomic_update_rejects_pre_swap_probe():
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.add_target("t1", "127.0.0.1", custom_settings=dict(_CFG))
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    probe_v = mon._settings_version
    eng.update_target_thresholds("t1", {"http_success_codes": "500"})
    rejected = not _run_loop_commit_would_accept(mon, probe_v)
    ok = (
        rejected
        and mon.settings.get("http_success_codes") == "500"
    )
    eng.remove_target("t1", join_timeout=2.0)
    print(f"Bug95 atomic swap rejects stale probe -> {ok}")
    return ok


def test_inflight_probe_dropped_on_semantic_edit():
    ds = _FakeDS()
    probe_started = threading.Event()
    probe_release = threading.Event()
    windows = []

    def on_change(state):
        windows.append(len(getattr(state, "loss_window", []) or []))

    mon = _BlockingMonitor(
        started=probe_started,
        release=probe_release,
        target_id="t2",
        ip="127.0.0.1",
        settings=dict(_CFG),
        on_state_change=on_change,
    )
    mon._data_store = ds
    mon.start()
    if not probe_started.wait(timeout=2.0):
        mon.stop()
        print("Bug95 inflight: probe did not start -> False")
        return False
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng._monitors = {"t2": mon}
    eng.set_data_store(ds)
    eng.update_target_thresholds("t2", {"http_success_codes": "500"})
    probe_release.set()
    time.sleep(0.4)
    mon.stop()
    mon.join(timeout=2.0)
    ok = len(windows) == 0 and mon.settings.get("http_success_codes") == "500"
    print(f"Bug95 inflight probe dropped windows={windows} -> {ok}")
    return ok


def test_semantic_edit_bumps_datastore_generation():
    ds = _FakeDS()
    eng = PingEngine(_CFG.copy(), lambda s: None)
    eng.set_data_store(ds)
    eng.add_target("t3", "127.0.0.1", custom_settings=dict(_CFG))
    eng.update_target_thresholds("t3", {"http_success_codes": "500"})
    eng.remove_target("t3", join_timeout=2.0)
    ok = ds.current_target_generation("t3") == 1
    print(f"Bug95 DS gen bump on semantic change -> {ok}")
    return ok


def test_source_no_prebump_in_on_edit():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split("def _on_edit(self, target_id):", 1)[1].split(
            "def _on_delete", 1)[0]
    first_apply = block.find("self.engine.update_target_thresholds")
    first_labels = block.find("self._target_labels[target_id]")
    ok = (
        "self.engine.invalidate_target_settings" not in block
        and "Bug95" in block
        and first_apply != -1
        and first_labels != -1
        and first_apply < first_labels
    )
    print(f"Bug95 source _on_edit early atomic swap -> {ok}")
    return ok


def test_source_update_bumps_ds_on_semantic():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def update_target_thresholds", 1)[1].split(
            "def pause_target", 1)[0]
    ok = (
        "semantic_changed" in block
        and "bump_target_generation" in block
    )
    print(f"Bug95 source update_target_thresholds DS bump -> {ok}")
    return ok


def main():
    results = [
        ("old_path", test_old_prebump_allows_stale_commit()),
        ("atomic", test_atomic_update_rejects_pre_swap_probe()),
        ("inflight", test_inflight_probe_dropped_on_semantic_edit()),
        ("ds_bump", test_semantic_edit_bumps_datastore_generation()),
        ("source_edit", test_source_no_prebump_in_on_edit()),
        ("source_engine", test_source_update_bumps_ds_on_semantic()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 95 checks passed.")


if __name__ == "__main__":
    main()
