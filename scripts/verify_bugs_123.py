"""Regression checks for bug 123 (red-alarm loop exit race)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_MANAGER = os.path.join(ROOT, "src", "alert_manager.py")


def _loop_body():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"def _red_alarm_loop\(self\):.*?def _play_sync\(",
        src, re.DOTALL,
    )
    return m.group(0) if m else ""


def test_stop_check_under_lock_before_play():
    body = _loop_body()
    lock_pos = body.find("with self._alarm_lock:")
    stop_pos = body.find("if self._red_alarm_stop.is_set():")
    play_pos = body.find("self._play_sync")
    ok = (
        lock_pos != -1
        and stop_pos != -1
        and play_pos != -1
        and lock_pos < stop_pos < play_pos
        and "self._red_alarm_active = False" in body[lock_pos:play_pos]
    )
    print(f"Bug123 stop check under _alarm_lock before _play_sync -> {ok}")
    return ok


def test_no_finally_unconditional_reset():
    body = _loop_body()
    ok = "finally:" not in body
    print(f"Bug123 _red_alarm_loop has no finally reset -> {ok}")
    return ok


def test_exception_path_resets_active_under_lock():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"except Exception as e:.*?def _play_sync\(",
        src, re.DOTALL,
    )
    block = m.group(0) if m else ""
    ok = (
        "with self._alarm_lock:" in block
        and "self._red_alarm_active = False" in block
    )
    print(f"Bug123 exception path resets active under lock -> {ok}")
    return ok


def test_stop_red_alarm_does_not_clear_active():
    with open(ALERT_MANAGER, encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"def _stop_red_alarm\(self\):.*?def _red_alarm_loop\(",
        src, re.DOTALL,
    )
    block = m.group(0) if m else ""
    ok = (
        "_red_alarm_stop.set()" in block
        and re.search(
            r"self\._red_alarm_active\s*=\s*False",
            block,
        ) is None
    )
    print(f"Bug123 _stop_red_alarm signals stop only (no active=False) -> {ok}")
    return ok


def main():
    results = [
        ("lock_order", test_stop_check_under_lock_before_play()),
        ("no_finally", test_no_finally_unconditional_reset()),
        ("except_reset", test_exception_path_resets_active_under_lock()),
        ("stop_signal", test_stop_red_alarm_does_not_clear_active()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 123 checks passed.")


if __name__ == "__main__":
    main()
