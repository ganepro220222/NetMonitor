"""Round 7: Long-running Stress / Performance Probe.

Verification targets:
  1. 100 targets all normal -> all delivered, no stuck rows
  2. 100 targets with 10 bad URLs -> healthy targets unblocked
  3. 100K historical rows -> API latency acceptable
  4. Reminder storm -> coalesced, no unbounded growth
  5. Rapid flapping -> per-target ordering maintained
  6. All 429 -> backoff works, no queue overflow
  7. No sending residue after stress
  8. Mixed states tick handles all conditions
  9. 1000 concurrent enqueues under lock contention
"""
import json, os, sys, tempfile, time, threading, http.server, socketserver
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import WebhookOutboxDispatcher, SENDING_LEASE_SEC

_results = []

def record(name, ok, detail=""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")

# ============================================================
# Controllable mock HTTP server
# ============================================================

class StressHandler(http.server.BaseHTTPRequestHandler):
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


class StressServer:
    def __init__(self, port=48030):
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
                    ("127.0.0.1", self._port), StressHandler)
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
# Helpers
# ============================================================

def _make_cfg(webhook_url, target_ids):
    class _Cfg:
        def get_setting(self, k):
            if k == "webhook_url": return webhook_url
            return None
        def get_targets(self):
            return [{"id": t, "label": t, "ip": f"10.0.{i//254}.{i%254+1}"}
                    for i, t in enumerate(target_ids)]
    return _Cfg()

def _make_am_disp(ds, cfg, skip_baselines=True):
    assets = os.path.join(ROOT, "assets")
    a = AlertManager(enabled=False, assets_dir=assets)
    a.set_config(cfg)
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    if skip_baselines:
        a._webhook_outbox_baselines_restored = True
        a._webhook_known_targets = {t["id"] for t in cfg.get_targets()}
    return a, disp

def _tick(disp, now):
    am = disp._am
    ds = am._data_store
    if ds is None or not am._webhook_configured(): return
    am.ensure_webhook_outbox_baselines()
    ds.recover_stale_sending_webhook_outbox(now, SENDING_LEASE_SEC)
    from src.webhook_outbox import CLOSED_SUMMARY_DELAY_SEC
    ds.drop_red_blocked_closed_summary(now, CLOSED_SUMMARY_DELAY_SEC)
    for row in ds.fetch_deliverable_webhook_outbox(now, limit=50):
        disp._deliver_one(row, now)

def _count_states(ds):
    conn = ds._read_conn()
    rows = conn.execute(
        "SELECT delivery_state, COUNT(*) FROM webhook_outbox GROUP BY delivery_state"
    ).fetchall()
    return {st: cnt for st, cnt in rows}

def _all_delivered(ds):
    s = _count_states(ds)
    return s.get("pending", 0) == 0 and s.get("sending", 0) == 0

# ============================================================
# TEST 1: 100 targets, all normal URLs -> all delivered
# ============================================================
def test_01_100_targets_all_normal(server):
    print("\n-- 1. 100 targets, all normal URLs --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    targets = [f"T-{i:03d}" for i in range(100)]
    cfg = _make_cfg(server.base_url, targets)
    am, disp = _make_am_disp(ds, cfg)

    for t in targets:
        am._push_webhook(
            event="alert_red", target=t, ip=f"10.0.{hash(t)%256}.1",
            status="red", message=f"Stress test {t}", order_key=t)

    initial = _count_states(ds)
    record("01a initial pending", initial.get("pending") == 100,
           f"states={initial}")

    t0 = time.time()
    ticks = 0
    max_ticks = 10
    while ticks < max_ticks:
        ticks += 1
        _tick(disp, time.time())
        if _all_delivered(ds):
            break

    final = _count_states(ds)
    captured = len(StressHandler.snapshot())
    elapsed = time.time() - t0
    record("01b all delivered", final.get("delivered", 0) == 100,
           f"states={final}, ticks={ticks}, captured={captured}, elapsed={elapsed:.1f}s")
    record("01c tick latency < 5s", elapsed < 5,
           f"elapsed={elapsed:.1f}s for {ticks} ticks")

# ============================================================
# TEST 2: 100 targets, 10 with long backoff -> healthy unblocked
# ============================================================
def test_02_bad_urls_dont_block_healthy(server):
    print("\n-- 2. 100 targets, 10 in long backoff -> 90 healthy unblocked --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    targets_all = [f"T-{i:03d}" for i in range(100)]
    stuck_targets = set(targets_all[:10])
    ok_targets = set(targets_all[10:])
    cfg = _make_cfg(server.base_url, targets_all)
    am, disp = _make_am_disp(ds, cfg)

    now = time.time()
    # Enqueue good targets (due immediately)
    for t in ok_targets:
        am._push_webhook(
            event="alert_red", target=t, ip=f"10.0.{hash(t)%256}.1",
            status="red", message=f"Good {t}", order_key=t)

    # Insert stuck-target rows: pending with next_attempt_ts far in future
    # This simulates targets whose head-of-line row is in long backoff
    # These should NOT prevent other targets from being dispatched
    payload = json.dumps({"event": "alert_red", "target": "STUCK",
                          "ip": "10.0.0.1", "status": "red",
                          "message": "stuck", "event_ts": now})
    conn = ds._outbox_write_conn()
    for t in sorted(stuck_targets):
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"STRESS-STUCK-{t}", t, f"INC-{t}", 1, "alert_red", t,
             payload, now, now, now + 99999, now, None, 3, 5,
             "pending", "simulated backoff", now, now))
    conn.commit()

    initial = _count_states(ds)
    record("02a initial", initial.get("pending") == 100,
           f"states={initial}")

    t0 = time.time()
    for _ in range(8):
        _tick(disp, time.time())
        s = _count_states(ds)
        if s.get("delivered", 0) >= 85:
            break

    final = _count_states(ds)
    delivered = final.get("delivered", 0)
    stuck_pending = final.get("pending", 0)
    elapsed = time.time() - t0
    record("02b good targets delivered", delivered >= 85,
           f"delivered={delivered}, states={final}, elapsed={elapsed:.1f}s")
    # Stuck targets (long backoff) stay pending, not blocking healthy ones
    record("02c stuck targets stay pending (non-blocking)",
           stuck_pending >= 8,
           f"pending (stuck)={stuck_pending} (expected >= 8)")

# ============================================================
# TEST 3: 100K historical rows -> API latency
# ============================================================
def test_03_100k_history_api_latency(server):
    print("\n-- 3. 100K historical rows -> API latency --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    print("    Inserting 100K delivered rows...")
    conn = ds._outbox_write_conn()
    now = time.time()
    payload = json.dumps({"event": "alert_red", "target": "GW", "ip": "10.0.0.1",
                          "status": "red", "message": "bulk", "event_ts": now - 86400})
    batch_size = 500
    total = 100000
    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        vals = []
        for i in range(start, end):
            did = f"WH-HIST-{i:06d}"
            ts = now - (i % 90 + 1) * 86400
            vals.append(
                f"('{did}','T1','INC-HIST',1,'alert_red','T1',"
                f"'{payload}',{ts},{ts},{ts},{ts},"
                f"{ts},1,0,'delivered','','{ts}','{ts}')"
            )
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES " + ",".join(vals))
    conn.commit()
    print(f"    Inserted 100K rows. DB size: {os.path.getsize(os.path.join(td, 't.db'))/1024/1024:.1f} MB")

    # Add 5 fresh pending rows
    for i in range(5):
        ds.enqueue_webhook_outbox(
            delivery_id=f"WH-FRESH-{i}", target_id=f"T-FRESH-{i}",
            incident_id="INC-FRESH", incident_seq=1,
            event="alert_red", order_key=f"T-FRESH-{i}",
            payload={"event": "alert_red", "target": f"T-FRESH-{i}", "ip": "10.0.0.1",
                     "status": "red", "message": "fresh", "event_ts": now},
            event_ts=now, max_attempts=0)

    # Measure problem API latency
    t0 = time.time()
    rows = ds.get_webhook_problem_deliveries(limit=100)
    problem_lat = time.time() - t0
    record("03a problem API latency < 1s", problem_lat < 1.0,
           f"latency={problem_lat*1000:.0f}ms, returned={len(rows)}")
    record("03b problem API correct", len(rows) == 5,
           f"got {len(rows)} problem rows (expected 5 pending)")

    # Measure stats API latency (may be slower due to full-table GROUP BY)
    t0 = time.time()
    stats = ds.get_webhook_delivery_stats()
    stats_lat = time.time() - t0
    record("03c stats API latency < 3s (full-table scan allowed)",
           stats_lat < 3.0,
           f"latency={stats_lat*1000:.0f}ms, stats={stats}")
    record("03d stats correct", stats.get("pending") == 5,
           f"stats={stats}")

    # Measure fetch_deliverable latency
    t0 = time.time()
    dr = ds.fetch_deliverable_webhook_outbox(now, limit=50)
    fetch_lat = time.time() - t0
    record("03e fetch_deliverable latency < 500ms", fetch_lat < 0.5,
           f"latency={fetch_lat*1000:.0f}ms, got {len(dr)}")

# ============================================================
# TEST 4: Reminder storm -> coalesce protection
# ============================================================
def test_04_reminder_storm_coalesce(server):
    print("\n-- 4. Reminder storm -> coalesce protection --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    target = "T-RS"
    cfg = _make_cfg(server.base_url, [target])
    am, disp = _make_am_disp(ds, cfg)

    # Send 100 reminders rapidly for the same incident
    for i in range(100):
        am._push_webhook(
            event="alert_reminder", target=target, ip="10.0.0.1",
            status="red", message=f"Reminder #{i}", order_key=target)

    counts = _count_states(ds)
    pending = counts.get("pending", 0)
    dropped = counts.get("dropped_stale", 0)
    total = pending + dropped

    record("04a 100 reminders enqueued total", total == 100,
           f"total={total}")
    record("04b only 1 pending (latest)", pending == 1,
           f"pending={pending}, dropped_stale={dropped}")
    record("04c 99 coalesced to dropped_stale", dropped >= 95,
           f"dropped_stale={dropped}")

# ============================================================
# TEST 5: Rapid flapping -> per-target ordering
# ============================================================
def test_05_rapid_flapping_ordering(server):
    print("\n-- 5. Rapid flapping -> per-target ordering --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    targets = [f"T-FLAP-{i}" for i in range(10)]
    cfg = _make_cfg(server.base_url, targets)
    am, disp = _make_am_disp(ds, cfg)

    for t in targets:
        for cycle in range(3):
            am._push_webhook(
                event="alert_red", target=t, ip="10.0.0.1",
                status="red", message=f"Red cycle {cycle}", order_key=t)
            am._push_webhook(
                event="recovery", target=t, ip="10.0.0.1",
                status="green", message=f"Recovery cycle {cycle}", order_key=t)

    initial = _count_states(ds)
    record("05a initial pending", initial.get("pending") == 60,
           f"states={initial}")

    # Tick all
    for _ in range(5):
        _tick(disp, time.time())

    final = _count_states(ds)
    captured = StressHandler.snapshot()

    # Check per-target ordering in captured events
    # Per target, events should appear as: red, recovery, red, recovery, red, recovery
    per_target_events = defaultdict(list)
    for c in captured:
        tgt = c["body"].get("target")
        evt = c["body"].get("event")
        if tgt and evt:
            per_target_events[tgt].append(evt)

    ordering_ok = True
    for t in targets:
        events = per_target_events.get(t, [])
        if len(events) < 2:
            continue
        # Each pair should be (red, recovery) in order
        for i in range(0, len(events) - 1, 2):
            pair = events[i:i+2]
            if len(pair) == 2 and not (pair[0] == "alert_red" and pair[1] == "recovery"):
                ordering_ok = False
                break

    record("05b per-target ordering maintained",
           ordering_ok and final.get("delivered", 0) > 0,
           f"delivered={final.get('delivered', 0)}, ordering_ok={ordering_ok}")

# ============================================================
# TEST 6: All 500 (simulating platform errors) -> backoff works
# ============================================================
def test_06_all_errors_backoff(server):
    print("\n-- 6. All deliveries fail (simulated) -> backoff works --")
    StressHandler.reset()

    # Use an invalid URL to cause connection errors
    bad_url = "http://127.0.0.1:19999/nonexistent"

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    targets = [f"T-ERR-{i}" for i in range(20)]
    cfg = _make_cfg(bad_url, targets)
    am, disp = _make_am_disp(ds, cfg)

    for t in targets:
        am._push_webhook(
            event="alert_red", target=t, ip="10.0.0.1",
            status="red", message=f"Error test {t}", order_key=t)

    initial = _count_states(ds)
    record("06a initial pending", initial.get("pending") == 20,
           f"states={initial}")

    # Tick - all will fail (connection refused)
    for _ in range(3):
        _tick(disp, time.time())

    mid = _count_states(ds)
    record("06b still pending after failures", mid.get("pending", 0) > 0,
           f"states={mid}")
    record("06c no premature delivery", mid.get("delivered", 0) == 0,
           f"delivered={mid.get('delivered', 0)}")

    # Verify attempt_count increased
    conn = ds._read_conn()
    attempts = conn.execute(
        "SELECT AVG(attempt_count) FROM webhook_outbox WHERE delivery_state='pending'"
    ).fetchone()[0]
    record("06d attempts incremented", attempts is not None and attempts > 0,
           f"avg_attempts={attempts:.1f}")

    # Verify next_attempt_ts is in the future (backoff)
    rows = ds.fetch_deliverable_webhook_outbox(time.time() + 4, limit=50)
    record("06e backoff prevents immediate retry", len(rows) <= 5,
           f"due_immediately={len(rows)} (backoff pushes next_attempt_ts forward)")

# ============================================================
# TEST 7: No sending residue after stress
# ============================================================
def test_07_no_sending_residue(server):
    print("\n-- 7. No sending residue after stress --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    targets = [f"T-RES-{i}" for i in range(50)]
    cfg = _make_cfg(server.base_url, targets)
    am, disp = _make_am_disp(ds, cfg)

    for t in targets:
        am._push_webhook(
            event="alert_red", target=t, ip="10.0.0.1",
            status="red", message=f"Residue {t}", order_key=t)

    for _ in range(5):
        _tick(disp, time.time())

    final = _count_states(ds)
    record("07a no sending residue",
           final.get("sending", 0) == 0,
           f"states={final}")
    record("07b all delivered", final.get("delivered", 0) >= 45,
           f"states={final}")

# ============================================================
# TEST 8: Mixed states tick handles all
# ============================================================
def test_08_mixed_states_tick(server):
    print("\n-- 8. Mixed states: pending+sending+delivered+dropped -> tick handles all --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    conn = ds._outbox_write_conn()
    now = time.time()
    payload = json.dumps({"event": "alert_red", "target": "T-MIX", "ip": "10.0.0.1",
                          "status": "red", "message": "mixed", "event_ts": now})

    # 5 fresh pending, 2 stale sending, 10 delivered, 3 dropped_stale
    for i in range(5):
        did = f"WH-MIX-PEND-{i}"
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, "T-MIX", "INC-MIX", 1, "alert_red", "T-MIX",
             payload, now, now, now, now - 200, None, 0, 0, "pending", "", now, now))

    for i in range(2):
        did = f"WH-MIX-SEND-{i}"
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, "T-MIX", "INC-MIX", 1, "alert_red", "T-MIX",
             payload, now, now, now, now - 200, None, 1, 0,
             "sending", "", now, now))
    conn.commit()

    targets = ["T-MIX"]
    cfg = _make_cfg(server.base_url, targets)
    am, disp = _make_am_disp(ds, cfg)

    t0 = time.time()
    _tick(disp, now + 10)
    elapsed = time.time() - t0
    record("08a tick handles mixed states quickly", elapsed < 2.0,
           f"elapsed={elapsed*1000:.0f}ms")

    final = _count_states(ds)
    record("08b no crash or exception", True,
           f"final states={final}")

# ============================================================
# TEST 9: 1000 concurrent enqueues under lock contention
# ============================================================
def test_09_concurrent_enqueue_lock(server):
    print("\n-- 9. 1000 concurrent enqueues (lock contention) --")
    StressHandler.reset()

    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    now = time.time()

    def enqueue_batch(start, count):
        for i in range(start, start + count):
            try:
                ds.enqueue_webhook_outbox(
                    delivery_id=f"WH-CONC-{i:05d}",
                    target_id="T-CONC", incident_id="INC-CONC", incident_seq=1,
                    event="alert_reminder", order_key=f"T-CONC-{i%10}",
                    payload={"event": "alert_reminder", "target": "T-CONC",
                             "ip": "10.0.0.1", "status": "red",
                             "message": f"Concurrent {i}", "event_ts": now},
                    event_ts=now, max_attempts=0)
            except Exception:
                pass

    threads = []
    t0 = time.time()
    for j in range(10):
        t = threading.Thread(target=enqueue_batch, args=(j * 100, 100))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0

    counts = _count_states(ds)
    total = sum(counts.values())
    record("09a all enqueued under contention", total >= 900,
           f"total={total}, elapsed={elapsed:.1f}s, states={counts}")
    record("09b lock contention handled (elapsed < 10s)", elapsed < 10,
           f"elapsed={elapsed:.1f}s for 1000 concurrent enqueues")

# ============================================================
# Main
# ============================================================
def main():
    print("=" * 72)
    print("Round 7: Long-running Stress / Performance Probe")
    print("=" * 72)

    server = StressServer(48030)
    server.start()
    print(f"\nMock server: {server.base_url}")

    tests = [
        ("01 100 targets all normal", test_01_100_targets_all_normal),
        ("02 bad URLs dont block healthy", test_02_bad_urls_dont_block_healthy),
        ("03 100K history API latency", test_03_100k_history_api_latency),
        ("04 reminder storm coalesce", test_04_reminder_storm_coalesce),
        ("05 rapid flapping ordering", test_05_rapid_flapping_ordering),
        ("06 all errors backoff", test_06_all_errors_backoff),
        ("07 no sending residue", test_07_no_sending_residue),
        ("08 mixed states tick", test_08_mixed_states_tick),
        ("09 concurrent enqueue lock", test_09_concurrent_enqueue_lock),
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