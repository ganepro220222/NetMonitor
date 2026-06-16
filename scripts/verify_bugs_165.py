"""Regression: ACK/pause/remove must abort gated reminder before network send."""
import json
import os
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.webhook_test_util import make_alerter
from src.alert_manager import AlertManager


def _outbox_row(ds, delivery_id: str) -> dict:
    rows = ds.get_webhook_deliveries(limit=100)
    row = next(r for r in rows if r["delivery_id"] == delivery_id)
    row = dict(row)
    row["payload_json"] = json.dumps(row.pop("payload", {}), ensure_ascii=False)
    return row


def _enqueue_reminder(a, ds, *, delivery_id: str, target_id: str = "race"):
    a.on_status_change(target_id, "GW", "10.0.0.1", "red")
    inc = a._webhook_incidents[target_id]
    rem_gate = ("reminder", target_id, inc.push_seq)
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='delivered', "
            "delivered_ts=?, updated_at=? "
            "WHERE target_id=? AND event='alert_red'",
            (time.time(), time.time(), target_id))
        conn.commit()
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id=target_id,
        incident_id=inc.incident_id,
        incident_seq=inc.push_seq,
        event="alert_reminder",
        order_key=target_id,
        payload={
            "event": "alert_reminder",
            "target": "GW",
            "ip": "10.0.0.1",
            "status": "red",
            "message": "连接仍未恢复",
            "extra": a._build_reminder_extra(a._snapshot_incident(inc)),
            "gate": list(rem_gate),
            "event_ts": time.time(),
        },
        event_ts=time.time(),
        max_attempts=12,
    )
    return _outbox_row(ds, delivery_id), target_id


def _apply_action(a, action: str, target_id: str):
    if action == "ack":
        assert a.acknowledge_incident(target_id)
        return "acknowledged"
    if action == "pause":
        a.on_target_paused(target_id)
        return "target_paused"
    a.on_target_removed(target_id)
    return "target_removed"


def _race_scenario(*, action: str, delivery_id: str):
    """Mock _send_webhook blocks after entry; main thread ACK/pause/remove."""
    a, disp, ds = make_alerter()
    sent = []
    entered = threading.Event()
    release = threading.Event()
    target_id = "race"

    def _send(url, event, target, ip, status, message, ts_str,
              extra=None, *, event_ts=None, queued_ts=None, sent_ts=None,
              attempt=1, delivery_id="", gate=None):
        entered.set()
        release.wait(timeout=5)
        a.assert_outbox_webhook_send_allowed(delivery_id=delivery_id, gate=gate)
        sent.append((event, delivery_id))

    a._send_webhook = _send
    row, target_id = _enqueue_reminder(a, ds, delivery_id=delivery_id)

    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    t.start()
    assert entered.wait(timeout=5), "dispatcher did not reach _send_webhook"
    expected_error = _apply_action(a, action, target_id)
    release.set()
    t.join(timeout=5)

    rem = _outbox_row(ds, delivery_id)
    return {
        "action": action,
        "sent": sent,
        "rows": [(rem["delivery_id"], rem["delivery_state"], rem["last_error"])],
        "expected_error": expected_error,
    }


def _internal_send_race_scenario(*, action: str, delivery_id: str):
    """Real _send_webhook; block in _format_webhook_text before urlopen."""
    a, disp, ds = make_alerter()
    entered = threading.Event()
    release = threading.Event()
    urlopen_calls = []
    real_format = AlertManager._format_webhook_text
    target_id = "race"

    def _blocking_format(*args, **kwargs):
        entered.set()
        release.wait(timeout=5)
        return real_format(*args, **kwargs)

    row, target_id = _enqueue_reminder(a, ds, delivery_id=delivery_id)

    def _record_urlopen(req, timeout=10):
        urlopen_calls.append(getattr(req, "full_url", str(req)))
        return type("Resp", (), {"read": lambda self: b"", "__enter__": lambda s: s,
                                  "__exit__": lambda *a: None})()

    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    with patch.object(AlertManager, "_format_webhook_text",
                      staticmethod(_blocking_format)):
        with patch("urllib.request.urlopen", side_effect=_record_urlopen):
            t.start()
            assert entered.wait(timeout=5), "did not reach payload build block"
            expected_error = _apply_action(a, action, target_id)
            release.set()
            t.join(timeout=5)

    rem = _outbox_row(ds, delivery_id)
    return {
        "action": action,
        "sent": urlopen_calls,
        "rows": [(rem["delivery_id"], rem["delivery_state"], rem["last_error"])],
        "expected_error": expected_error,
    }


def _post_final_assert_race_scenario(*, action: str, delivery_id: str):
    """Real _send_webhook; race after final in-lock check, before urlopen()."""
    a, disp, ds = make_alerter()
    entered = threading.Event()
    release = threading.Event()
    urlopen_calls = []
    target_id = "t1"

    def _pre_http_hook(*, delivery_id="", gate=None):
        entered.set()
        release.wait(timeout=5)

    row, target_id = _enqueue_reminder(
        a, ds, delivery_id=delivery_id, target_id=target_id)

    def _record_urlopen(req, timeout=10):
        urlopen_calls.append(getattr(req, "full_url", str(req)))
        return type("Resp", (), {"read": lambda self: b"", "__enter__": lambda s: s,
                                  "__exit__": lambda *a: None})()

    a._webhook_pre_http_send_hook = _pre_http_hook
    t = threading.Thread(
        target=disp._deliver_one, args=(row, time.time()), daemon=True)
    with patch("urllib.request.urlopen", side_effect=_record_urlopen):
        t.start()
        assert entered.wait(timeout=5), "did not reach pre-http hook"
        expected_error = _apply_action(a, action, target_id)
        release.set()
        t.join(timeout=5)

    rem = _outbox_row(ds, delivery_id)
    return {
        "action": action,
        "sent": urlopen_calls,
        "rows": [(rem["delivery_id"], rem["delivery_state"], rem["last_error"])],
        "expected_error": expected_error,
    }


def _check_during_send(r):
    ok = (
        r["sent"] == []
        and r["rows"][0][1] == "dropped_stale"
        and r["rows"][0][2] == r["expected_error"]
    )
    print(f"Bug165 {r['action']} during _send_webhook -> {ok} {r}")
    return ok


def _check_no_urlopen(r):
    ok = (
        r["sent"] == []
        and r["rows"][0][1] == "dropped_stale"
        and r["rows"][0][2] == r["expected_error"]
    )
    print(f"Bug165 {r['action']} before urlopen -> {ok} {r}")
    return ok


def test_ack_during_send():
    return _check_during_send(
        _race_scenario(action="ack", delivery_id="ack-during_send"))


def test_pause_during_send():
    return _check_during_send(
        _race_scenario(action="pause", delivery_id="pause-during_send"))


def test_remove_during_send():
    return _check_during_send(
        _race_scenario(action="remove", delivery_id="remove-during_send"))


def test_ack_before_urlopen():
    return _check_no_urlopen(
        _internal_send_race_scenario(
            action="ack", delivery_id="ack-before_urlopen"))


def test_pause_before_urlopen():
    return _check_no_urlopen(
        _internal_send_race_scenario(
            action="pause", delivery_id="pause-before_urlopen"))


def test_remove_before_urlopen():
    return _check_no_urlopen(
        _internal_send_race_scenario(
            action="remove", delivery_id="remove-before_urlopen"))


def test_ack_after_final_assert():
    return _check_no_urlopen(
        _post_final_assert_race_scenario(
            action="ack", delivery_id="ack-after_final_assert"))


def test_pause_after_final_assert():
    return _check_no_urlopen(
        _post_final_assert_race_scenario(
            action="pause", delivery_id="pause-after_final_assert"))


def test_remove_after_final_assert():
    return _check_no_urlopen(
        _post_final_assert_race_scenario(
            action="remove", delivery_id="remove-after_final_assert"))


def main():
    results = [
        ("ack_during_send", test_ack_during_send()),
        ("pause_during_send", test_pause_during_send()),
        ("remove_during_send", test_remove_during_send()),
        ("ack_before_urlopen", test_ack_before_urlopen()),
        ("pause_before_urlopen", test_pause_before_urlopen()),
        ("remove_before_urlopen", test_remove_before_urlopen()),
        ("ack_after_final_assert", test_ack_after_final_assert()),
        ("pause_after_final_assert", test_pause_after_final_assert()),
        ("remove_after_final_assert", test_remove_after_final_assert()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 165 checks passed.")


if __name__ == "__main__":
    main()
