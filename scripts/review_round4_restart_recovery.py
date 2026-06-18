"""Round 4: Restart Recovery — pending/sending/orphan/stale-incident recovery review.

Verification targets:
  1. Pending rows survive restart → can be dispatched
  2. Sending rows → recovered_after_restart → dispatched
  3. Stale sending (lease >120s) → stale_sending_recovered → dispatched
  4. Orphan target (deleted) → target_orphan → dropped_stale
  5. Closed incident → gated rows dropped
  6. Delivered rows remain unchanged
  7. Recovery does not cause duplicate delivery
  8. Reconciled row count is accurate
"""

import json
import os
import sys
import threading
import time
import tempfile
import http.server
import socketserver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import (
    WebhookOutboxDispatcher, SENDING_LEASE_SEC,
    max_attempts_for_event, REMINDER_MAX_ATTEMPTS,
)

# ============================================================
# Simple mock HTTP server (always returns 200 OK)
# ============================================================

class RestartHandler(http.server.BaseHTTPRequestHandler):
    captured: list[dict] = []
    _lock = threading.Lock()

    @classmethod
    def reset(cls):
        with cls._lock:
            cls.captured.clear()

    @classmethod
    def snapshot(cls):
        with cls._lock:
            return list(cls.captured)

    def _capture(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {"_raw": body.decode("utf-8", errors="replace")}
        with self._lock:
            self.captured.append({"body": payload, "ts": time.time()})

    def do_POST(self):
        self._capture()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        data = b'{"ok":true}'
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


class RestartServer:
    def __init__(self, port: int = 48020):
        self._port = port
        self._httpd = None
        self._thread = None

    @property
    def base_url(self):
        p = self._httpd.socket.getsockname()[1] if self._httpd else self._port
        return f"http://127.0.0.1:{p}"

    def start(self):
        for _ in range(20):
            try:
                self._httpd = socketserver.TCPServer(
                    ("127.0.0.1", self._port), RestartHandler)
                break
            except OSError:
                self._port += 1
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


# ============================================================
# Test infrastructure
# ============================================================

_results = []

def record(name, ok, detail=""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")


def _create_cfg(webhook_url, target_ids=None):
    """Create a config class with known targets."""
    tids = target_ids or ["T1"]

    class _Cfg:
        def get_setting(self, k):
            if k == "webhook_url":
                return webhook_url
            return None

        def get_targets(self):
            return [{"id": t, "label": t, "ip": "10.0.0.1"} for t in tids]

    return _Cfg()


def _make_am(ds, cfg, skip_baselines=False):
    """Create AlertManager + Dispatcher for a given config."""
    assets = os.path.join(ROOT, "assets")
    a = AlertManager(enabled=False, assets_dir=assets)
    a.set_config(cfg)
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    if skip_baselines:
        a._webhook_outbox_baselines_restored = True
        a._webhook_known_targets_initialized = True
        a._webhook_known_targets = set(
            cfg.get_targets()[0].get("id") for _ in []  # empty
        ) or {"T1"}  # default
        # Actually compute from cfg
        a._webhook_known_targets = {t["id"] for t in cfg.get_targets()}
    return a, disp


def _enqueue_row(ds, delivery_id, target_id="T1", incident_id="INC-T1",
                 event="alert_red", order_key="T1", state="pending",
                 attempt_count=0, last_error="", next_attempt_ts=None,
                 last_attempt_ts=None, first_queued_ts=None,
                 max_attempts=0, incident_seq=1, delivered_ts=None):
    """Direct SQL insert to precisely control row state."""
    import json as _json
    now = time.time()
    payload = {
        "event": event, "target": target_id, "ip": "10.0.0.1",
        "status": "green", "message": f"test {event}",
        "extra": {}, "event_ts": now,
    }
    conn = ds._outbox_write_conn()
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, "
        " order_key, payload_json, event_ts, first_queued_ts, "
        " next_attempt_ts, last_attempt_ts, attempt_count, max_attempts, "
        " delivery_state, last_error, created_at, updated_at, delivered_ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (delivery_id, target_id, incident_id, incident_seq, event,
         order_key, _json.dumps(payload, ensure_ascii=False), now,
         first_queued_ts or now, next_attempt_ts or now,
         last_attempt_ts or now, attempt_count, max_attempts,
         state, last_error, now, now, delivered_ts))
    conn.commit()


def _get_row(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=1000)
    for r in rows:
        if r.get("delivery_id") == delivery_id:
            return r
    return {}


def _controlled_tick(disp, now):
    """Run one tick with controlled time."""
    am = disp._am
    ds = am._data_store
    if ds is None or not am._webhook_configured():
        return
    am.ensure_webhook_outbox_baselines()
    ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
    from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC
    ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
    for row in ds.fetch_deliverable_webhook_outbox(now, limit=50):
        disp._deliver_one(row, now)


# ============================================================
# TESTS
# ============================================================

def test_01_pending_survives_restart(server: RestartServer):
    """Pending row should survive process restart and be dispatchable."""
    print("\n-- 1. Pending survives restart --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    # Phase 1: Enqueue pending row
    _enqueue_row(ds, "WH-R4-PEND-01", state="pending")
    row1 = _get_row(ds, "WH-R4-PEND-01")
    record("01a phase1 state=pending", row1.get("delivery_state") == "pending",
           f"state={row1.get('delivery_state')}")

    # Simulate restart: create new AM with same DB
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=True)

    # Row should still be pending
    row2 = _get_row(ds, "WH-R4-PEND-01")
    record("01b after restart state=pending", row2.get("delivery_state") == "pending",
           f"state={row2.get('delivery_state')}")

    # Tick to deliver
    t0 = time.time()
    _controlled_tick(disp2, t0 + 10)
    row3 = _get_row(ds, "WH-R4-PEND-01")
    record("01c delivered after restart", row3.get("delivery_state") == "delivered",
           f"state={row3.get('delivery_state')}")

    # Verify exactly one POST
    captured = RestartHandler.snapshot()
    record("01d exactly 1 POST", len(captured) == 1,
           f"captured={len(captured)}")


def test_02_sending_recovered_after_restart(server: RestartServer):
    """Sending rows → recovered_after_restart → dispatched."""
    print("\n-- 2. Sending recovered after restart --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    # Phase 1: Queue row in 'sending' state (simulating in-flight at crash)
    _enqueue_row(ds, "WH-R4-SEND-01", state="sending",
                 last_attempt_ts=time.time() - 10)

    row1 = _get_row(ds, "WH-R4-SEND-01")
    record("02a phase1 state=sending", row1.get("delivery_state") == "sending",
           f"state={row1.get('delivery_state')}")

    # Phase 2: Simulate restart — call recover_orphaned_sending directly
    ds.recover_orphaned_sending_webhook_outbox(time.time())

    row2 = _get_row(ds, "WH-R4-SEND-01")
    record("02b recovered to pending", row2.get("delivery_state") == "pending",
           f"state={row2.get('delivery_state')}")
    record("02c error=recovered_after_restart",
           row2.get("last_error") == "recovered_after_restart",
           f"error={row2.get('last_error')!r}")

    # Tick to deliver
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=True)
    t0 = time.time()
    _controlled_tick(disp2, t0 + 10)

    row3 = _get_row(ds, "WH-R4-SEND-01")
    record("02d delivered", row3.get("delivery_state") == "delivered",
           f"state={row3.get('delivery_state')}")
    record("02e no duplicate POST", len(RestartHandler.snapshot()) == 1,
           f"captured={len(RestartHandler.snapshot())}")


def test_03_stale_sending_lease_recovery(server: RestartServer):
    """Sending rows with old last_attempt_ts → stale_sending_recovered."""
    print("\n-- 3. Stale sending lease recovery --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    now = time.time()
    # Queue in 'sending' with last_attempt_ts 200s ago (past 120s lease)
    _enqueue_row(ds, "WH-R4-STALE-01", state="sending",
                 last_attempt_ts=now - 200)

    row1 = _get_row(ds, "WH-R4-STALE-01")
    record("03a phase1 state=sending", row1.get("delivery_state") == "sending",
           f"state={row1.get('delivery_state')}")

    # Simulate tick: recover_stale_sending should reclaim it
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=True)

    # Manually invoke stale recovery to verify
    n = ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
    record("03b stale_sending recovered count", n >= 1,
           f"recovered={n} row(s)")

    row2 = _get_row(ds, "WH-R4-STALE-01")
    record("03c state=pending", row2.get("delivery_state") == "pending",
           f"state={row2.get('delivery_state')}")
    record("03d error=stale_sending_recovered",
           row2.get("last_error") == "stale_sending_recovered",
           f"error={row2.get('last_error')!r}")

    # Now deliver it
    _controlled_tick(disp2, now + 10)
    row3 = _get_row(ds, "WH-R4-STALE-01")
    record("03e delivered", row3.get("delivery_state") == "delivered",
           f"state={row3.get('delivery_state')}")
    record("03f one POST", len(RestartHandler.snapshot()) == 1,
           f"captured={len(RestartHandler.snapshot())}")


def test_04_stale_sending_within_lease_not_recovered(server: RestartServer):
    """Sending row within lease should NOT be recovered by stale check."""
    print("\n-- 4. Fresh sending (within lease) NOT recovered --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    now = time.time()
    _enqueue_row(ds, "WH-R4-FRESH-01", state="sending",
                 last_attempt_ts=now - 10)  # only 10s ago

    # Stale recovery should NOT touch it
    n = ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
    row = _get_row(ds, "WH-R4-FRESH-01")
    record("04a still sending (within lease)",
           row.get("delivery_state") == "sending",
           f"state={row.get('delivery_state')}")
    record("04b zero recovered by stale check", n == 0,
           f"recovered={n}")


def test_05_orphan_target_dropped(server: RestartServer):
    """Orphan target (not in config) → dropped_stale + target_orphan."""
    print("\n-- 5. Orphan target dropped --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    # Queue rows for a target NOT in the new config
    _enqueue_row(ds, "WH-R4-ORPH-01", target_id="TOld", order_key="TOld",
                 state="pending", incident_id="INC-OLD")
    _enqueue_row(ds, "WH-R4-ORPH-02", target_id="TOld", order_key="TOld",
                 state="sending", incident_id="INC-OLD")

    # New config only has T1 (not TOld) — do NOT skip baselines
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=False)

    # Trigger reconciliation
    a2._webhook_outbox_baselines_restored = False
    a2.ensure_webhook_outbox_baselines()

    row1 = _get_row(ds, "WH-R4-ORPH-01")
    row2 = _get_row(ds, "WH-R4-ORPH-02")
    record("05a pending orphan → dropped_stale",
           row1.get("delivery_state") == "dropped_stale",
           f"state={row1.get('delivery_state')}")
    record("05b pending orphan error=target_orphan",
           row1.get("last_error") == "target_orphan",
           f"error={row1.get('last_error')!r}")
    record("05c sending orphan → dropped_stale",
           row2.get("delivery_state") == "dropped_stale",
           f"state={row2.get('delivery_state')}")
    record("05d sending orphan error=target_orphan",
           row2.get("last_error") == "target_orphan",
           f"error={row2.get('last_error')!r}")


def test_06_closed_incident_gated_rows_dropped(server: RestartServer):
    """Gated rows for closed incidents → dropped_stale."""
    print("\n-- 6. Closed incident gated rows dropped --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    # Queue reminder for a closed incident
    _enqueue_row(ds, "WH-R4-CLSD-01", target_id="T1", order_key="T1",
                 event="alert_reminder", incident_id="INC-CLOSED",
                 state="pending", max_attempts=REMINDER_MAX_ATTEMPTS)
    _enqueue_row(ds, "WH-R4-CLSD-02", target_id="T1", order_key="T1",
                 event="diagnostic_update", incident_id="INC-CLOSED",
                 state="pending", max_attempts=8)

    # Config has T1 but INC-CLOSED is NOT an open incident
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=False)

    # Reconciliation: T1 is known, but INC-CLOSED is not in open_incidents
    # open_iid_map will NOT contain INC-CLOSED for T1
    # So drop_stale_webhook_outbox_for_closed_incidents should drop them
    a2._webhook_outbox_baselines_restored = False
    a2.ensure_webhook_outbox_baselines()

    row1 = _get_row(ds, "WH-R4-CLSD-01")
    row2 = _get_row(ds, "WH-R4-CLSD-02")
    record("06a reminder dropped_stale",
           row1.get("delivery_state") == "dropped_stale",
           f"state={row1.get('delivery_state')}")
    record("06b diagnostic dropped_stale",
           row2.get("delivery_state") == "dropped_stale",
           f"state={row2.get('delivery_state')}")


def test_07_delivered_rows_unchanged(server: RestartServer):
    """Delivered rows should remain delivered after restart."""
    print("\n-- 7. Delivered rows unchanged --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    now = time.time()
    _enqueue_row(ds, "WH-R4-DONE-01", state="delivered",
                 attempt_count=1, last_error="",
                 delivered_ts=now - 100)

    # Restart
    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=True)

    row = _get_row(ds, "WH-R4-DONE-01")
    record("07a still delivered", row.get("delivery_state") == "delivered",
           f"state={row.get('delivery_state')}")
    record("07b attempt_count preserved", row.get("attempt_count") == 1,
           f"attempt={row.get('attempt_count')}")
    record("07c no extra POST", len(RestartHandler.snapshot()) == 0,
           f"captured={len(RestartHandler.snapshot())}")


def test_08_no_duplicate_on_recovery(server: RestartServer):
    """Recovered sending row should produce exactly one delivery."""
    print("\n-- 8. No duplicate delivery on recovery --")
    RestartHandler.reset()

    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "restart_test.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    now = time.time()
    _enqueue_row(ds, "WH-R4-NODUP-01", state="sending",
                 last_attempt_ts=now - 200)

    # Recover sending → pending
    ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)

    cfg = _create_cfg(server.base_url, ["T1"])
    a2, disp2 = _make_am(ds, cfg, skip_baselines=True)

    # Multiple ticks should only deliver once
    for i in range(3):
        _controlled_tick(disp2, now + i + 10)

    row = _get_row(ds, "WH-R4-NODUP-01")
    captured = RestartHandler.snapshot()
    record("08a delivered", row.get("delivery_state") == "delivered",
           f"state={row.get('delivery_state')}")
    record("08b exactly 1 POST (no duplicates)", len(captured) == 1,
           f"captured={len(captured)} batches, events={[c['body'].get('event') for c in captured]}")


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 72)
    print("Round 4: Restart Recovery — pending/sending/orphan/stale review")
    print("=" * 72)

    server = RestartServer(48020)
    server.start()
    print(f"\nMock server: {server.base_url}")

    tests = [
        ("01 pending survives restart", test_01_pending_survives_restart),
        ("02 sending recovered", test_02_sending_recovered_after_restart),
        ("03 stale sending lease", test_03_stale_sending_lease_recovery),
        ("04 fresh sending untouched", test_04_stale_sending_within_lease_not_recovered),
        ("05 orphan target dropped", test_05_orphan_target_dropped),
        ("06 closed incident gated", test_06_closed_incident_gated_rows_dropped),
        ("07 delivered unchanged", test_07_delivered_rows_unchanged),
        ("08 no duplicate delivery", test_08_no_duplicate_on_recovery),
    ]

    for name, fn in tests:
        try:
            fn(server)
        except Exception as e:
            import traceback
            record(f"{name} UNHANDLED", False, str(e))
            traceback.print_exc()

    server.stop()

    passed = sum(1 for _, ok, _ in _results if ok)
    failed = sum(1 for _, ok, _ in _results if not ok)
    print(f"\n{'=' * 72}")
    print(f"SUMMARY: {passed}/{passed + failed} passed")

    if failed:
        print("FAILURES:")
        for name, ok, detail in _results:
            if not ok:
                print(f"  - {name}: {detail}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
