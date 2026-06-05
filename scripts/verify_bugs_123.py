"""Regression checks for bug 123.

red-alarm loop exit race: the stop-check that decides to leave the loop
must be atomic with the _red_alarm_active reset (same _alarm_lock that
_ensure/_stop use), and must NOT rely on a `finally` (which would run
after a locked return and clobber a freshly-restarted thread's
active=True, spawning a second concurrent alarm loop).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT = os.path.join(ROOT, "src", "alert_manager.py")


def _loop_body() -> str:
    with open(ALERT, encoding="utf-8") as f:
        src = f.read()
    after = src.split("def _red_alarm_loop", 1)[1]
    return after.split("\n    def ", 1)[0]


def test_exit_decision_under_lock():
    body = _loop_body()
    li = body.find("with self._alarm_lock:")
    after = body[li:] if li != -1 else ""
    ok = (li != -1
          and "if self._red_alarm_stop.is_set():" in after
          and "self._red_alarm_active = False" in after
          and "return" in after)
    print(f"Bug123 exit decision under _alarm_lock -> {ok}")
    return ok


def test_no_finally_unconditional_reset():
    body = _loop_body()
    ok = "finally:" not in body
    print(f"Bug123 no finally unconditional reset -> {ok}")
    return ok


def test_except_path_resets_active():
    body = _loop_body()
    parts = body.split("except Exception", 1)
    ok = len(parts) == 2 and "self._red_alarm_active = False" in parts[1]
    print(f"Bug123 except path still resets active -> {ok}")
    return ok


def test_stop_check_precedes_play():
    body = _loop_body()
    i_lock = body.find("with self._alarm_lock:")
    i_play = body.find("self._play_sync(")
    ok = i_lock != -1 and i_play != -1 and i_lock < i_play
    print(f"Bug123 stop-check precedes play -> {ok}")
    return ok


def main():
    results = [
        ("exit_locked", test_exit_decision_under_lock()),
        ("no_finally", test_no_finally_unconditional_reset()),
        ("except_reset", test_except_path_resets_active()),
        ("order", test_stop_check_precedes_play()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 123 checks passed.")


if __name__ == "__main__":
    main()
