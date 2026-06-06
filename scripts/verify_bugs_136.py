"""Regression checks for desktop ACK button state (Bug 136).

The toolbar ACK button must reflect pending un-ACK'd red webhook incidents:
disabled when nothing to confirm, highlighted when reminders can be silenced.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.config_manager import DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def _alerter(**cfg_kw):
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_Cfg(**cfg_kw))
    return a


def test_pending_count_empty():
    a = _alerter()
    ok = a.count_pending_ack_incidents() == 0
    print(f"Bug136 pending count empty initially -> {ok}")
    return ok


def test_pending_count_after_red():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    ok = a.count_pending_ack_incidents() == 1
    print(f"Bug136 pending count after red -> {ok}")
    return ok


def test_pending_count_after_ack():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.acknowledge_all_incidents()
    ok = a.count_pending_ack_incidents() == 0
    print(f"Bug136 pending count after ACK -> {ok}")
    return ok


def test_pending_count_after_recovery():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "green")
    ok = a.count_pending_ack_incidents() == 0
    print(f"Bug136 pending count after recovery -> {ok}")
    return ok


def test_orange_not_pending():
    """Partial recovery (red→orange) stops reminders; button stays idle."""
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.on_status_change("t1", "GW", "10.0.0.1", "orange")
    ok = a.count_pending_ack_incidents() == 0
    print(f"Bug136 orange incident not pending -> {ok}")
    return ok


def test_multi_red_pending():
    a = _alerter()
    a.on_status_change("t1", "GW1", "10.0.0.1", "red")
    a.on_status_change("t2", "GW2", "10.0.0.2", "red")
    ok = a.count_pending_ack_incidents() == 2
    print(f"Bug136 multi red pending -> {ok}")
    return ok


def test_ack_still_red_disables_pending():
    a = _alerter()
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    a.acknowledge_all_incidents()
    ok = (
        a.count_pending_ack_incidents() == 0
        and a._webhook_incidents["t1"].current_status == "red"
        and a._webhook_incidents["t1"].acknowledged
    )
    print(f"Bug136 ACK while still red clears pending -> {ok}")
    return ok


def test_main_window_ack_btn_wired():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "self._ack_btn" in src
        and "def _update_ack_btn" in src
        and "count_pending_ack_incidents" in src
        and "self._update_ack_btn()" in src
        and 'state="disabled"' in src
    )
    print(f"Bug136 main_window ACK button wired -> {ok}")
    return ok


def main():
    results = [
        ("empty", test_pending_count_empty()),
        ("red", test_pending_count_after_red()),
        ("ack", test_pending_count_after_ack()),
        ("recovery", test_pending_count_after_recovery()),
        ("orange", test_orange_not_pending()),
        ("multi", test_multi_red_pending()),
        ("ack_red", test_ack_still_red_disables_pending()),
        ("ui_wire", test_main_window_ack_btn_wired()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 136 checks passed.")


if __name__ == "__main__":
    main()
