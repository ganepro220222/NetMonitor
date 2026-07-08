"""Regression: alert_red compact backoff + shorter HTTP timeout (Batch 1)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import (
    ALERT_RED_BACKOFF_SECONDS,
    BACKOFF_SECONDS,
    WebhookOutboxDispatcher,
    compute_next_attempt_ts,
    webhook_http_timeout,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_alert_red_backoff_sequence():
    now = 1_000_000.0
    expected = list(ALERT_RED_BACKOFF_SECONDS)
    ok = True
    for attempt, exp in enumerate(expected, start=1):
        got = compute_next_attempt_ts(attempt, now, event="alert_red") - now
        if abs(got - exp) > 0.01:
            print(f"  FAIL attempt={attempt} got={got} expected={exp}")
            ok = False
    # Plateau beyond tuple length
    tail = compute_next_attempt_ts(99, now, event="alert_red") - now
    if tail != expected[-1]:
        print(f"  FAIL tail got={tail} expected={expected[-1]}")
        ok = False
    print(f"alert_red backoff sequence -> {ok}")
    return ok


def test_other_events_keep_default_backoff():
    now = 1_000_000.0
    # First failure: attempt=1 -> BACKOFF_SECONDS[1]=15
    got = compute_next_attempt_ts(1, now, event="recovery") - now
    ok = got == BACKOFF_SECONDS[1]
    print(f"recovery backoff first retry={got}s expected={BACKOFF_SECONDS[1]} -> {ok}")
    return ok


def test_http_timeout_helper():
    ok = (
        webhook_http_timeout("alert_red", 1) == 5
        and webhook_http_timeout("alert_red", 3) == 5
        and webhook_http_timeout("alert_red", 4) == 10
        and webhook_http_timeout("recovery", 1) == 10
    )
    print(f"webhook_http_timeout helper -> {ok}")
    return ok


def test_outbox_uses_alert_red_backoff_on_failure():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    class _Cfg:
        def get_setting(self, k):
            vals = {
                "webhook_url": "http://127.0.0.1:9/hook",
                "webhook_include_trace": False,
                "webhook_trace_update_enabled": False,
            }
            return vals.get(k)

        def get_targets(self):
            return [{"id": "t1", "label": "GW", "ip": "10.0.0.1"}]

    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_Cfg())
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)

    def _fail(*_a, **_k):
        raise OSError("connection refused")

    a._send_webhook = staticmethod(_fail)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")
    now = time.time()
    rows = ds.fetch_deliverable_webhook_outbox(now, limit=5)
    if not rows:
        print("outbox alert_red backoff on failure -> False (no row)")
        return False
    disp._deliver_one(rows[0], now)
    row = next(
        r for r in ds.get_webhook_deliveries(target_id="t1", limit=5)
        if r.get("event") == "alert_red"
    )
    delay = float(row["next_attempt_ts"]) - now
    ok = (
        row.get("delivery_state") == "pending"
        and abs(delay - ALERT_RED_BACKOFF_SECONDS[0]) < 2.0
    )
    print(
        f"outbox alert_red first retry delay={delay:.1f}s "
        f"state={row.get('delivery_state')} -> {ok}"
    )
    return ok


def main():
    results = [
        ("sequence", test_alert_red_backoff_sequence()),
        ("default", test_other_events_keep_default_backoff()),
        ("timeout", test_http_timeout_helper()),
        ("outbox", test_outbox_uses_alert_red_backoff_on_failure()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All alert_red backoff checks passed.")


if __name__ == "__main__":
    main()
