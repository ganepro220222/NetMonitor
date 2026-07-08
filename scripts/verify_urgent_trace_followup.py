"""Regression: ambiguous first trace schedules one follow-up while still red."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager, TRACE_FOLLOWUP_DELAY_SEC


def test_followup_scheduled_on_clean_trace_while_red():
    a = AlertManager(enabled=False)
    requested = []

    class _Cfg:
        def get_setting(self, key):
            defaults = {
                "webhook_url": "https://example.com/hook",
                "webhook_include_trace": True,
                "webhook_trace_update_enabled": True,
                "webhook_trace_change_only": True,
            }
            return defaults.get(key)

    class _DS:
        def enqueue_webhook_outbox(self, **kwargs):
            pass

        def current_target_generation(self, tid):
            return 0

    a._config = _Cfg()
    a._data_store = _DS()
    a.set_trace_request_callback(lambda tid: requested.append(tid))

    a.on_status_change(
        "tid1", "节点A", "www.example.com", "red",
        ping_type="icmp", failure_reason="timeout",
    )

    hops = [{"hop": i, "ip": f"10.0.0.{i}", "status": "ok"} for i in range(1, 6)]
    hops.append({"hop": 6, "ip": "203.0.113.1", "status": "ok"})

    a.on_traceroute_result({
        "tid": "tid1",
        "ip": "www.example.com",
        "resolve_ip": "203.0.113.1",
        "ts": time.time(),
        "hops": hops,
        "urgent": True,
        "spawn_ts": time.time() - 5,
    })

    ok_scheduled = len(requested) >= 1  # initial via on_status_change paths
    time.sleep(TRACE_FOLLOWUP_DELAY_SEC + 0.3)
    ok_followup = len(requested) >= 2
    print(f"followup requested={requested} scheduled={ok_scheduled} "
          f"followup={ok_followup} -> {ok_scheduled and ok_followup}")
    return ok_scheduled and ok_followup


def test_no_followup_when_break_found():
    a = AlertManager(enabled=False)
    requested = []
    a.set_trace_request_callback(lambda tid: requested.append(tid))

    class _Cfg:
        def get_setting(self, key):
            return {
                "webhook_url": "",
                "webhook_include_trace": True,
                "webhook_trace_update_enabled": True,
            }.get(key)

    a._config = _Cfg()
    a.on_status_change(
        "tid2", "节点B", "10.0.0.9", "red",
        ping_type="icmp", failure_reason="timeout",
    )
    before = len(requested)
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": None, "status": "break", "error": "timed out"},
    ]
    a.on_traceroute_result({
        "tid": "tid2",
        "ip": "10.0.0.9",
        "ts": time.time(),
        "hops": hops,
        "urgent": True,
    })
    time.sleep(TRACE_FOLLOWUP_DELAY_SEC + 0.2)
    ok = len(requested) == before
    print(f"no followup on break requested={requested} before={before} -> {ok}")
    return ok


def main():
    results = [
        ("followup", test_followup_scheduled_on_clean_trace_while_red()),
        ("no_break", test_no_followup_when_break_found()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All urgent trace followup checks passed.")


if __name__ == "__main__":
    main()
