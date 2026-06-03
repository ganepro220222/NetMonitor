"""Regression checks for bug 81 (probe-start DataStore generation snapshot)."""
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ping_engine import PingEngine, PingResult, TargetMonitor

PING_ENGINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ping_engine.py",
)


class _FakeDS:
    def __init__(self):
        self._gen = {}

    def current_target_generation(self, target_id: str) -> int:
        return self._gen.get(target_id, 0)

    def bump_target_generation(self, target_id: str) -> None:
        self._gen[target_id] = self.current_target_generation(target_id) + 1


class _FastMonitor(TargetMonitor):
    def _do_ping(self) -> PingResult:
        return PingResult(success=True, latency_ms=1.0)


class _BlockingMonitor(TargetMonitor):
    def __init__(self, started: threading.Event, release: threading.Event, **kwargs):
        super().__init__(**kwargs)
        self._probe_started = started
        self._probe_release = release

    def _do_ping(self) -> PingResult:
        self._probe_started.set()
        self._probe_release.wait(timeout=5.0)
        return PingResult(success=True, latency_ms=1.0)


def test_monitor_gets_data_store_from_engine():
    ds = _FakeDS()
    states = []
    eng = PingEngine({}, lambda s: states.append(s))
    eng.set_data_store(ds)
    eng.add_target("t1", "127.0.0.1", custom_settings={"ping_interval": 0.05})
    with eng._monitors_lock:
        mon = eng._monitors["t1"]
    ok_ref = getattr(mon, "_data_store", None) is ds
    time.sleep(0.35)
    eng.remove_target("t1", join_timeout=2.0)
    ok_gen = (
        ok_ref
        and len(states) >= 1
        and states[-1].probe_data_store_generation == 0
    )
    print(f"Bug81 monitor wired + gen in callback: ref={ok_ref} "
          f"gen={getattr(states[-1], 'probe_data_store_generation', None) if states else None} "
          f"-> {ok_gen}")
    return ok_gen


def test_generation_captured_before_blocking_ping():
    ds = _FakeDS()
    probe_started = threading.Event()
    probe_release = threading.Event()
    done = threading.Event()
    captured = []

    def on_change(state):
        captured.append(state.probe_data_store_generation)
        done.set()

    cfg = {
        "window_size": 10,
        "ping_interval": 0.05,
        "consecutive_loss_orange": 3,
        "consecutive_loss_red": 5,
        "latency_warn_ms": 1000,
        "consecutive_lat_orange": 3,
        "recovery_count": 5,
    }
    mon = _BlockingMonitor(
        started=probe_started,
        release=probe_release,
        target_id="t2",
        ip="127.0.0.1",
        settings=cfg,
        on_state_change=on_change,
    )
    mon._data_store = ds
    mon.start()
    if not probe_started.wait(timeout=2.0):
        mon.stop()
        print("Bug81 timing: probe did not start -> False")
        return False
    # Wipe during blocking probe: live gen becomes 1; snapshot must stay 0.
    ds.bump_target_generation("t2")
    probe_release.set()
    if not done.wait(timeout=2.0):
        mon.stop()
        print("Bug81 timing: callback timeout -> False")
        return False
    mon.stop()
    mon.join(timeout=2.0)
    ok = (
        captured
        and captured[-1] == 0
        and ds.current_target_generation("t2") == 1
    )
    print(f"Bug81 capture before wipe bump: captured={captured} "
          f"live_gen={ds.current_target_generation('t2')} -> {ok}")
    return ok


def test_source_capture_before_do_ping():
    with open(PING_ENGINE, encoding="utf-8") as f:
        block = f.read().split("def _run_loop(self):", 1)[1].split(
            "def _do_ping(self)", 1)[0]
    cap = block.find("probe_data_store_generation")
    ping = block.find("result = self._do_ping()")
    post_ping_cap = block.find(
        "current_target_generation(self.target_id)",
        ping,
    )
    with open(PING_ENGINE, encoding="utf-8") as f:
        src = f.read()
    add_ok = "monitor._data_store = self._data_store" in src
    set_ok = re.search(
        r"def set_data_store\(.*?\n(?:.*?\n)*?.*?for m in self\._monitors",
        src,
        re.DOTALL,
    ) is not None
    ok = (
        cap != -1 and ping != -1 and cap < ping
        and post_ping_cap == -1
        and add_ok and set_ok
    )
    print(f"Bug81 source probe-start capture + wiring -> {ok}")
    return ok


def main():
    results = [
        ("wiring", test_monitor_gets_data_store_from_engine()),
        ("timing", test_generation_captured_before_blocking_ping()),
        ("source", test_source_capture_before_do_ping()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 81 checks passed.")


if __name__ == "__main__":
    main()
