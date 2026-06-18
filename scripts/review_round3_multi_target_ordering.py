"""Round 3: Multi-target concurrency, red/recovery ordering, non-blocking, message storm prevention.

Verification targets:
  1. Same target red -> recovery  ordering (red sent first)
  2. Red backoff does NOT block due recovery (closed-summary unblock)
  3. Different targets don't block each other (A error, B delivered)
  4. Message storm: 100 reminders coalesced to 1 pending
  5. Multi-target fan-out: 10 targets, alternate error/ok
  6. Per-target ordering integrity across multiple event types
  7. Closed-summary unblock: red long backoff, recovery proceeds
"""

import json
import os
import sys
import threading
import time
import tempfile
import urllib.request
import http.server
import socketserver

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import (
    WebhookOutboxDispatcher, BACKOFF_SECONDS, CLOSED_SUMMARY_DELAY_SEC,
    max_attempts_for_event, REMINDER_MAX_ATTEMPTS, SENDING_LEASE_SEC,
)

# ============================================================
# Mock HTTP server with per-path behavior
# ============================================================

class MultiTargetHandler(http.server.BaseHTTPRequestHandler):
    """Routes: /ok, /500, /429, /delay/<secs>, /target/<N>/ok, /target/<N>/500"""
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
        rec = {
            "path": self.path,
            "method": self.command,
            "body": payload,
            "ts": time.time(),
        }
        with self._lock:
            self.captured.append(rec)

    def _respond(self, code: int, body: str = ""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        data = body.encode("utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self._capture()
        path = self.path.rstrip("/") or "/"

        # /delay/N
        if path.startswith("/delay/"):
            try:
                secs = float(path.split("/")[2])
            except Exception:
                secs = 0
            time.sleep(min(secs, 30))
            self._respond(200, json.dumps({"ok": True, "delayed": secs}))
            return

        # /target/N/ok or /target/N/500
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[0] == "target":
            if parts[2] == "500":
                self._respond(500, json.dumps({"error": "simulated 500"}))
                return
            elif parts[2] == "ok":
                self._respond(200, json.dumps({"ok": True}))
                return

        # Top-level routes
        if path == "/ok":
            self._respond(200, json.dumps({"ok": True}))
        elif path == "/500":
            self._respond(500, json.dumps({"error": "simulated 500"}))
        elif path == "/429":
            self._respond(429, json.dumps({"error": "rate limited"}))
        else:
            self._respond(404, json.dumps({"error": "not found"}))

    def log_message(self, fmt, *args):
        pass  # silence server logs


class MultiTargetServer:
    def __init__(self, port: int = 0):
        self._port = port or 48010
        self._httpd: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        p = self._httpd.socket.getsockname()[1] if self._httpd else self._port
        return f"http://127.0.0.1:{p}"

    def start(self):
        for attempt in range(20):
            try:
                self._httpd = socketserver.TCPServer(
                    ("127.0.0.1", self._port), MultiTargetHandler)
                break
            except OSError:
                self._port += 1
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


# ============================================================
# Test infrastructure
# ============================================================

_results: list[tuple[str, bool, str]] = []

def record(name: str, ok: bool, detail: str = ""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")


def make_fixture(server: MultiTargetServer, webhook_url: str,
                 event: str = "alert_red", target_id: str = "T1",
                 incident_id: str = "INC-TEST-001",
                 max_attempts: int = 0,
                 order_key: str = "") -> tuple:
    """Create AlertManager + DataStore + Dispatcher, enqueue one test row."""
    import uuid
    import os as _os

    td = tempfile.mkdtemp()
    db_path = _os.path.join(td, f"t-r3-{_os.urandom(4).hex()}.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)  # wait for schema init on write thread

    # Mutable URL container so tests can change the webhook URL mid-test
    url_box = [webhook_url]

    class _Cfg:
        def get_setting(self, k):
            if k == "webhook_url":
                return url_box[0]
            return None

        def get_targets(self):
            return []

    assets = _os.path.join(ROOT, "assets")
    a = AlertManager(enabled=False, assets_dir=assets)
    a.set_config(_Cfg())
    a.set_data_store(ds)

    # Set up incident state so gate passes
    with a._webhook_incident_lock:
        a._webhook_valid_seq[target_id] = 1

    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)

    # Skip baseline reconciliation (no real incidents exist)
    a._webhook_outbox_baselines_restored = True
    a._webhook_known_targets_initialized = True
    a._webhook_known_targets = {target_id}

    # Monkey-patch direct_enqueue_test_webhook (reuse from round 2)
    if not hasattr(AlertManager, "direct_enqueue_test_webhook"):
        def direct_enqueue_test_webhook(
                self, *, delivery_id, target_id, incident_id, incident_seq,
                event, order_key, target_label, ip,
                event_ts, max_attempts=0, gate=None):
            payload = {
                "event": event,
                "target": target_label,
                "ip": ip,
                "status": "red" if event == "alert_red" else "green",
                "message": f"test {event}",
                "extra": {},
                "gate": list(gate) if gate else None,
                "event_ts": event_ts,
            }
            self._data_store.enqueue_webhook_outbox(
                delivery_id=delivery_id,
                target_id=target_id,
                incident_id=incident_id,
                incident_seq=incident_seq,
                event=event,
                order_key=order_key,
                payload=payload,
                event_ts=event_ts,
                max_attempts=max_attempts,
            )
        AlertManager.direct_enqueue_test_webhook = direct_enqueue_test_webhook

    # Enqueue the initial test row
    a.direct_enqueue_test_webhook(
        delivery_id=f"WH-R3-{_os.urandom(4).hex().upper()}",
        target_id=target_id,
        incident_id=incident_id,
        incident_seq=1,
        event=event,
        order_key=order_key or target_id,
        target_label=target_id,
        ip="10.0.0.1",
        event_ts=time.time(),
        max_attempts=max_attempts,
    )

    return a, disp, ds, url_box


def get_row(ds, delivery_id):
    rows = ds.get_webhook_deliveries(limit=1000)
    for r in rows:
        if r.get("delivery_id") == delivery_id:
            return r
    return {}


def make_row_due(ds, delivery_id, now):
    """Force next_attempt_ts so fetch_deliverable picks this row."""
    conn = ds._outbox_write_conn()
    conn.execute(
        "UPDATE webhook_outbox SET next_attempt_ts=? WHERE delivery_id=?",
        (float(now), delivery_id))
    conn.commit()


def controlled_tick(disp, now: float):
    """Run one tick with controlled 'now' instead of time.time()."""
    am = disp._am
    ds = am._data_store
    if ds is None or not am._webhook_configured():
        return
    am.ensure_webhook_outbox_baselines()
    ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
    n_blocked = ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
    if n_blocked:
        print(f"         [closed-summary unblock: dropped {n_blocked} row(s)]")
    for row in ds.fetch_deliverable_webhook_outbox(now, limit=50):
        disp._deliver_one(row, now)


def enqueue_webhook(a: AlertManager, event: str, target_id: str,
                    incident_id: str = "", order_key: str = "",
                    max_attempts: int = 0, event_ts: float = 0.0):
    """Enqueue a webhook row via AlertManager's _push_webhook-like path."""
    import uuid
    ds = a._data_store
    if ds is None:
        return None
    delivery_id = str(uuid.uuid4())
    payload = {
        "event": event, "target": target_id, "ip": "10.0.0.1",
        "status": "red" if event == "alert_red" else "green",
        "message": f"test {event}",
        "extra": {}, "event_ts": event_ts or time.time(),
    }
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id, target_id=target_id,
        incident_id=incident_id or f"INC-{target_id}",
        incident_seq=1,
        event=event, order_key=order_key or target_id,
        payload=payload, event_ts=event_ts or time.time(),
        max_attempts=max_attempts,
    )
    return delivery_id


# ============================================================
# TESTS
# ============================================================

def test_01_red_before_recovery(server: MultiTargetServer):
    """Same target: red must be dispatched before recovery."""
    print("\n-- 1. Same target red -> recovery ordering --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_red",
        target_id="T1", incident_id="INC-T1", order_key="T1")
    t0 = time.time()

    # Enqueue recovery (should be behind red in order_key)
    did_rec = enqueue_webhook(
        a, "recovery", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=0, event_ts=t0 + 1)

    # Get red delivery_id
    rows = ds.get_webhook_deliveries(limit=10)
    red_row = [r for r in rows if r["event"] == "alert_red"][0]
    did_red = red_row["delivery_id"]

    # Tick both
    controlled_tick(disp, t0 + 2)
    controlled_tick(disp, t0 + 3)

    captured = MultiTargetHandler.snapshot()
    events_sent = [c["body"].get("event") for c in captured]

    record("01a red sent", "alert_red" in events_sent,
           f"events in order: {events_sent}")
    record("01b recovery sent", "recovery" in events_sent,
           f"events in order: {events_sent}")
    # Red must appear before recovery in capture order
    if "alert_red" in events_sent and "recovery" in events_sent:
        red_idx = events_sent.index("alert_red")
        rec_idx = events_sent.index("recovery")
        record("01c red before recovery", red_idx < rec_idx,
               f"red@{red_idx}, recovery@{rec_idx}")
    else:
        record("01c red before recovery", False, "one or both not found")

    # Both should be delivered
    red_state = get_row(ds, did_red).get("delivery_state", "")
    rec_state = get_row(ds, did_rec).get("delivery_state", "")
    record("01d red delivered", red_state == "delivered", f"state={red_state}")
    record("01e recovery delivered", rec_state == "delivered",
           f"state={rec_state}")


def test_02_different_targets_non_blocking(server: MultiTargetServer):
    """Target TA (error, long backoff) should not block Target TB (ok, deliverable)."""
    print("\n-- 2. Different targets: TA backoff, TB ok (non-blocking) --")
    MultiTargetHandler.reset()

    # Both targets share the same webhook URL
    url_500 = f"{server.base_url}/500"
    url_ok = f"{server.base_url}/ok"

    a, disp, ds, url_box = make_fixture(
        server, url_500, event="alert_red",
        target_id="TA", incident_id="INC-TA", order_key="TA")

    # Enqueue TB's red via direct enqueue
    with a._webhook_incident_lock:
        a._webhook_valid_seq["TB"] = 1
    a._webhook_known_targets.add("TB")
    a.direct_enqueue_test_webhook(
        delivery_id="WH-R3-TB-01",
        target_id="TB", incident_id="INC-TB", incident_seq=1,
        event="alert_red", order_key="TB",
        target_label="TB", ip="10.0.0.2",
        event_ts=time.time(), max_attempts=0,
    )

    t0 = time.time()

    # Tick 1: Both TA and TB should fail (URL=/500)
    controlled_tick(disp, t0)
    controlled_tick(disp, t0 + 0.1)  # second tick: TA dispatched first, TB second

    # Get both rows
    rows = ds.get_webhook_deliveries(limit=10)
    ta_rows = [r for r in rows if r["order_key"] == "TA"]
    tb_rows = [r for r in rows if r["order_key"] == "TB"]

    if ta_rows:
        record("02a TA attempt>=1 (failed)", ta_rows[0].get("attempt_count", 0) >= 1,
               f"attempt={ta_rows[0].get('attempt_count')}")
    if tb_rows:
        record("02b TB attempt>=1 (failed)", tb_rows[0].get("attempt_count", 0) >= 1,
               f"attempt={tb_rows[0].get('attempt_count')}")

    # Now: set TA to long backoff (next_attempt_ts = far future)
    # Set TB to due now
    # Change URL to /ok
    if ta_rows:
        ta_did = ta_rows[0]["delivery_id"]
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? WHERE delivery_id=?",
            (t0 + 9999, ta_did))
        conn.commit()

    if tb_rows:
        tb_did = tb_rows[0]["delivery_id"]
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=?, delivery_state='pending' WHERE delivery_id=?",
            (t0 - 1, tb_did))
        conn.commit()

    # Change config webhook URL to /ok
    url_box[0] = url_ok

    # Tick: TA should NOT be dispatched (long backoff), TB SHOULD deliver
    controlled_tick(disp, t0 + 10)

    if ta_rows:
        ta_did = ta_rows[0]["delivery_id"]
        ta_final = get_row(ds, ta_did)
        record("02c TA still pending (not unblocked)",
               ta_final.get("delivery_state") == "pending",
               f"state={ta_final.get('delivery_state')}")

    if tb_rows:
        tb_did = tb_rows[0]["delivery_id"]
        tb_final = get_row(ds, tb_did)
        record("02d TB delivered (not blocked by TA)",
               tb_final.get("delivery_state") == "delivered",
               f"state={tb_final.get('delivery_state')}")


def test_03_closed_summary_unblock(server: MultiTargetServer):
    """Red in long backoff; recovery due; closed-summary unblock drops red."""
    print("\n-- 3. Closed-summary unblock --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/500", event="alert_red",
        target_id="T1", incident_id="INC-T1", order_key="T1")

    # Get red delivery_id
    rows = ds.get_webhook_deliveries(limit=10)
    red_row = [r for r in rows if r["event"] == "alert_red"][0]
    did_red = red_row["delivery_id"]

    base = time.time()

    # Step 1: Fail red once to set attempt_count=1 and backoff
    controlled_tick(disp, base)
    red = get_row(ds, did_red)
    record("03a red failed once", red.get("attempt_count") == 1,
           f"attempt={red.get('attempt_count')}")

    # Step 2: Enqueue recovery (same order_key, same incident)
    did_rec = enqueue_webhook(
        a, "recovery", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=0, event_ts=base + 2)

    # Step 3: Make recovery due NOW, but red still in backoff (next_attempt_ts > now)
    # The closed-summary unblock should see: red head-of-line with next_ts > now,
    # recovery due, first_queued_ts age > 60s?
    # But the fixture's red first_queued_ts is recent. We need to simulate old red.

    # Artificially age the red first_queued_ts to > 60s ago
    conn = ds._outbox_write_conn()
    conn.execute(
        "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=? "
        "WHERE delivery_id=?",
        (base - 120, base + 300, did_red))  # red queued 120s ago, backoff 300s
    conn.execute(
        "UPDATE webhook_outbox SET next_attempt_ts=?, delivery_state='pending' WHERE delivery_id=?",
        (base - 10, did_rec))  # recovery due 10s ago, ensure pending
    conn.commit()

    # Change URL to /ok so recovery can deliver after unblock
    url_box[0] = f"{server.base_url}/ok"

    # Step 4: Tick should drop_stale red and deliver recovery
    controlled_tick(disp, base + 0.2)
    # controlled_tick handles drop_red_blocked_closed_summary internally

    red_final = get_row(ds, did_red)
    rec_final = get_row(ds, did_rec)

    record("03b red dropped_stale", red_final.get("delivery_state") == "dropped_stale",
           f"state={red_final.get('delivery_state')} "
           f"error={red_final.get('last_error','')}")
    record("03c recovery delivered", rec_final.get("delivery_state") == "delivered",
           f"state={rec_final.get('delivery_state')}")


def test_04_message_storm_coalescing(server: MultiTargetServer):
    """100 reminders for same target -> only 1 should be pending."""
    print("\n-- 4. Message storm: 100 reminders coalesced --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_reminder",
        target_id="T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS)

    t0 = time.time()

    # Enqueue 100 reminders for same target/incident
    dids = []
    for i in range(100):
        did = enqueue_webhook(
            a, "alert_reminder", "T1", incident_id="INC-T1", order_key="T1",
            max_attempts=REMINDER_MAX_ATTEMPTS, event_ts=t0 + i)
        dids.append(did)

    # Count pending reminders for this order_key
    all_rows = ds.get_webhook_deliveries(limit=200)
    pending_reminders = [
        r for r in all_rows
        if r["event"] == "alert_reminder"
        and r["order_key"] == "T1"
        and r["delivery_state"] == "pending"
    ]
    coalesced = [
        r for r in all_rows
        if r["event"] == "alert_reminder"
        and r["order_key"] == "T1"
        and r["last_error"] == "coalesced"
    ]

    record("04a only 1 pending reminder", len(pending_reminders) == 1,
           f"pending={len(pending_reminders)} (expected 1)")
    record("04b 99 coalesced", len(coalesced) >= 99,
           f"coalesced={len(coalesced)} (expected >=99)")
    record("04c no dropped rows", len(coalesced) + len(pending_reminders) >= 100,
           f"total preserved={len(coalesced) + len(pending_reminders)}")


def test_05_multi_target_fanout(server: MultiTargetServer):
    """10 targets all share same URL. Verify all order_keys are dispatched."""
    print("\n-- 5. Multi-target fan-out: 10 targets, all healthy --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_red",
        target_id="T0", incident_id="INC-T0", order_key="T0")

    t0 = time.time()

    # Enqueue red for 10 targets
    dids = []
    for i in range(1, 10):  # T0 already in fixture
        tid = f"T{i}"
        iid = f"INC-T{i}"
        with a._webhook_incident_lock:
            a._webhook_valid_seq[tid] = 1
        a._webhook_known_targets.add(tid)
        a.direct_enqueue_test_webhook(
            delivery_id=f"WH-R3-T{i}-01",
            target_id=tid, incident_id=iid, incident_seq=1,
            event="alert_red", order_key=tid,
            target_label=tid, ip=f"10.0.0.{i}",
            event_ts=t0 + i * 0.1, max_attempts=0,
        )
        dids.append(f"WH-R3-T{i}-01")

    # Run several ticks to process all 10 targets
    for i in range(15):
        controlled_tick(disp, t0 + float(i) + 5.0)

    # Check states: all should be delivered
    all_rows = ds.get_webhook_deliveries(limit=50)
    states = {}
    for r in all_rows:
        if r["event"] == "alert_red":
            states[r["order_key"]] = r.get("delivery_state", "?")

    delivered_count = sum(1 for s in states.values() if s == "delivered")
    record("05a all 10 targets delivered", delivered_count >= 10,
           f"delivered={delivered_count}/10 states={states}")

    captured = MultiTargetHandler.snapshot()
    record("05b 10 POSTs captured", len(captured) >= 10,
           f"captured={len(captured)}")


def test_06_red_backoff_then_recovery_unblock(server: MultiTargetServer):
    """Red long backoff -> recovery becomes due -> closed-summary delay passes -> unblock."""
    print("\n-- 6. Red backoff -> recovery unblock (full flow) --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_red",
        target_id="T1", incident_id="INC-T1", order_key="T1")

    rows = ds.get_webhook_deliveries(limit=10)
    red_row = [r for r in rows if r["event"] == "alert_red"][0]
    did_red = red_row["delivery_id"]

    base = time.time()

    # Make red fail once
    # We need /500 for the fail, so change URL temporarily
    am = a
    old_url = url_box[0]
    url_box[0] = f"{server.base_url}/500"
    controlled_tick(disp, base)
    url_box[0] = old_url  # restore

    red1 = get_row(ds, did_red)
    record("06a red failed", red1.get("attempt_count", 0) >= 1,
           f"attempt={red1.get('attempt_count')}")

    # Enqueue recovery
    did_rec = enqueue_webhook(
        a, "recovery", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=0, event_ts=base + 2)

    # Artificially age red: queued 120s ago, backoff 300s
    # Recovery due now
    conn = ds._outbox_write_conn()
    conn.execute(
        "UPDATE webhook_outbox SET first_queued_ts=?, next_attempt_ts=? "
        "WHERE delivery_id=?",
        (base - 120, base + 300, did_red))
    conn.execute(
        "UPDATE webhook_outbox SET next_attempt_ts=? WHERE delivery_id=?",
        (base - 10, did_rec))  # recovery due 10s ago
    conn.commit()

    # Tick at time when age > CLOSED_SUMMARY_DELAY_SEC
    controlled_tick(disp, base + 1)

    red_final = get_row(ds, did_red)
    rec_final = get_row(ds, did_rec)

    record("06b red unblocked (dropped_stale)",
           red_final.get("delivery_state") == "dropped_stale",
           f"state={red_final.get('delivery_state')} "
           f"error={red_final.get('last_error','')}")
    record("06c recovery delivered",
           rec_final.get("delivery_state") == "delivered",
           f"state={rec_final.get('delivery_state')}")


def test_07_per_target_ordering_integrity(server: MultiTargetServer):
    """Multiple event types per target: ordering preserved per order_key."""
    print("\n-- 7. Per-target ordering integrity --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_red",
        target_id="T1", incident_id="INC-T1", order_key="T1")

    t0 = time.time()

    # Enqueue sequence: red, reminder, diagnostic, recovery
    did_red = None
    for r in ds.get_webhook_deliveries(limit=10):
        if r["event"] == "alert_red":
            did_red = r["delivery_id"]

    did_rem = enqueue_webhook(
        a, "alert_reminder", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS, event_ts=t0 + 1)
    did_diag = enqueue_webhook(
        a, "diagnostic_update", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=8, event_ts=t0 + 2)
    did_rec = enqueue_webhook(
        a, "recovery", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=0, event_ts=t0 + 3)

    # Run ticks to dispatch all
    for i in range(10):
        controlled_tick(disp, t0 + float(i) + 10.0)

    # Verify all delivered
    states = {}
    for did, label in [(did_red, "red"), (did_rem, "rem"),
                        (did_diag, "diag"), (did_rec, "rec")]:
        if did:
            states[label] = get_row(ds, did).get("delivery_state", "?")

    record("07a all delivered",
           all(s == "delivered" for s in states.values()),
           f"states={states}")

    # Check capture order: red, reminder, diagnostic, recovery
    captured = MultiTargetHandler.snapshot()
    event_order = [c["body"].get("event") for c in captured if "body" in c]

    expected_order = ["alert_red", "alert_reminder", "diagnostic_update", "recovery"]
    ok_order = True
    for exp in expected_order:
        if exp not in event_order:
            ok_order = False
    # Verify relative ordering: red before reminder before diagnostic before recovery
    if all(e in event_order for e in expected_order):
        idxs = {e: event_order.index(e) for e in expected_order}
        ok_order = (idxs["alert_red"] < idxs["alert_reminder"]
                    < idxs["diagnostic_update"] < idxs["recovery"])
    record("07b event order preserved", ok_order,
           f"order={event_order}")


def test_08_reminder_coalesce_preserves_latest(server: MultiTargetServer):
    """Coalesce keeps latest reminder, drops old ones."""
    print("\n-- 8. Reminder coalesce preserves latest --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_reminder",
        target_id="T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS)

    t0 = time.time()

    # Enqueue reminder 1 (will be coalesced by #2 and #3)
    did1 = enqueue_webhook(
        a, "alert_reminder", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS, event_ts=t0)
    # Enqueue reminder 2 (coalesces #1, will be coalesced by #3)
    did2 = enqueue_webhook(
        a, "alert_reminder", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS, event_ts=t0 + 1)
    # Enqueue reminder 3 (coalesces #1 and #2)
    did3 = enqueue_webhook(
        a, "alert_reminder", "T1", incident_id="INC-T1", order_key="T1",
        max_attempts=REMINDER_MAX_ATTEMPTS, event_ts=t0 + 2)

    state1 = get_row(ds, did1).get("last_error", "")
    state2 = get_row(ds, did2).get("last_error", "")
    state3 = get_row(ds, did3).get("delivery_state", "")

    record("08a first reminder coalesced", state1 == "coalesced",
           f"error={state1}")
    record("08b second reminder coalesced", state2 == "coalesced",
           f"error={state2}")
    record("08c third reminder is pending (latest)", state3 == "pending",
           f"state={state3}")


def test_09_concurrent_delivery_across_targets(server: MultiTargetServer):
    """Multiple targets concurrently delivering: all reach delivered state."""
    print("\n-- 9. Concurrent delivery across 5 healthy targets --")
    MultiTargetHandler.reset()

    a, disp, ds, url_box = make_fixture(
        server, f"{server.base_url}/ok", event="alert_red",
        target_id="T0", incident_id="INC-T0", order_key="T0")

    t0 = time.time()
    dids = []
    for i in range(5):
        tid = f"T{i}"
        iid = f"INC-T{i}"
        with a._webhook_incident_lock:
            a._webhook_incidents[tid] = iid
            a._webhook_valid_seq[tid] = 1
        a._webhook_known_targets.add(tid)
        did = enqueue_webhook(
            a, "alert_red", tid, incident_id=iid, order_key=tid,
            max_attempts=0, event_ts=t0 + i)
        dids.append(did)

    # Run ticks
    for i in range(5):
        controlled_tick(disp, t0 + float(i) + 10.0)

    states = {}
    for did in dids:
        r = get_row(ds, did)
        states[r.get("order_key", "?")] = r.get("delivery_state", "?")

    all_delivered = all(s == "delivered" for s in states.values())
    record("09a all 5 targets delivered", all_delivered, f"states={states}")

    captured = MultiTargetHandler.snapshot()
    record("09b 5 POSTs captured", len(captured) >= 5,
           f"captured={len(captured)}")


# ============================================================
# Main
# ============================================================



def main():
    print("=" * 72)
    print("Round 3: Multi-target Concurrency, Ordering, Non-blocking")
    print("=" * 72)

    server = MultiTargetServer(48010)
    server.start()
    print(f"\nMock server: {server.base_url}")

    tests = [
        ("01 red-before-recovery", test_01_red_before_recovery),
        ("02 non-blocking targets", test_02_different_targets_non_blocking),
        ("03 closed-summary unblock", test_03_closed_summary_unblock),
        ("04 message storm coalesce", test_04_message_storm_coalescing),
        ("05 multi-target fanout", test_05_multi_target_fanout),
        ("06 red backoff unblock full", test_06_red_backoff_then_recovery_unblock),
        ("07 per-target ordering", test_07_per_target_ordering_integrity),
        ("08 reminder latest kept", test_08_reminder_coalesce_preserves_latest),
        ("09 5 concurrent deliveries", test_09_concurrent_delivery_across_targets),
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

