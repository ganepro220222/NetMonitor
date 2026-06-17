"""Regression: webhook outbox observability + defensive reseed."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter
from src.webhook_outbox import WebhookDeliveryAborted


def _row(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=50)
    row = next(r for r in rows if r["delivery_id"] == delivery_id)
    return row["delivery_state"], row.get("last_error", "")


def test_malformed_target_skipped_on_reseed():
    ds_path = None
    from src.data_store import DataStore
    import tempfile
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    a, _, _ = make_alerter(ds=ds)
    n = a.reseed_webhook_incidents(
        [{"label": "no-id"}, {"id": "good", "label": "OK", "ip": "1.2.3.4"}],
        set())
    ok = n == 0 and a._webhook_known_targets == {"good"}
    print(f"Bug175 malformed target skipped on reseed -> {ok} known={a._webhook_known_targets}")
    return ok


def test_abort_reason_preserved():
    a, disp, ds = make_alerter(
        targets=[{"id": "t", "label": "GW", "ip": "10.0.0.1"}])
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id="ABORT-1",
        target_id="t",
        incident_id="INC1",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload={
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "x", "extra": {},
            "gate": ["alert_red", "t", 1], "event_ts": now,
        },
        event_ts=now,
        max_attempts=0,
    )
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1
        a._webhook_known_targets.add("t")

    def _boom(*_a, **_k):
        raise WebhookDeliveryAborted("cancelled")

    a._send_webhook = _boom
    rows = ds.get_webhook_deliveries(limit=10)
    raw = next(r for r in rows if r["delivery_id"] == "ABORT-1")
    row = dict(raw)
    row["payload_json"] = json.dumps(row.pop("payload", {}), ensure_ascii=False)
    disp._deliver_one(row, now)
    state, err = _row(ds, "ABORT-1")
    ok = state == "dropped_stale" and err == "cancelled"
    print(f"Bug175 abort reason preserved -> {ok} state={state!r} err={err!r}")
    return ok


def main():
    results = [
        ("malformed_target", test_malformed_target_skipped_on_reseed()),
        ("abort_reason", test_abort_reason_preserved()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 175 checks passed.")


if __name__ == "__main__":
    main()
