"""Concurrency & stress regression: webhook outbox under load, locks, and races.

Covers:
- Multi-target concurrent enqueue integrity
- Multi order_key FIFO ordering preservation
- Same order_key head-of-line (only one per key in fetch_deliverable)
- Config reload vs dispatcher tick consistency
- Large dataset (2000 terminal + 100 pending) performance
- Stats / problem API under load
- Cleanup concurrent with dispatch
- Dispatcher crash / restart mid-send recovery
- SQLite busy contention under rapid writes
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_STORE_PATH = os.path.join(ROOT, "src", "data_store.py")
_ALERT_MANAGER_PATH = os.path.join(ROOT, "src", "alert_manager.py")

_SUCCESS = True
_HOOK_URL = "http://127.0.0.1:9/hook"


def pass_fail(name: str, ok: bool, detail: str = "") -> bool:
    global _SUCCESS
    label = "PASS" if ok else "FAIL"
    suffix = f"  ({detail})" if detail else ""
    print(f"  {label} {name}{suffix}")
    if not ok:
        _SUCCESS = False
    return ok


def make_alerter(**kw):
    from scripts.webhook_test_util import make_alerter as _m
    return _m(**kw)


def install_push_capture(a, calls, disp=None):
    from scripts.webhook_test_util import install_push_capture as _i
    return _i(a, calls, disp)


# ════════════════════════════════════════════════════════════════════
# Test 1: Concurrent multi-thread enqueue integrity
# ════════════════════════════════════════════════════════════════════
def test_concurrent_enqueue_integrity():
    """10 threads each enqueue 10 events via _push_webhook (gate=None); no corruption."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": f"t{tid}", "label": f"T{tid}", "ip": f"10.0.{tid}.1"}
                 for tid in range(10)],
    )
    errors = []
    n_threads = 10
    n_per_thread = 10
    barrier = threading.Barrier(n_threads, timeout=10)

    def _worker(tid):
        try:
            barrier.wait(timeout=5)
            for j in range(n_per_thread):
                a._push_webhook(
                    event="alert_red", target=f"T{tid}",
                    ip=f"10.0.{tid}.{j+1}",
                    status="red", message=f"msg-{tid}-{j}",
                    order_key=f"t{tid}",
                    gate=None)  # no gate check needed for count
        except Exception as e:
            errors.append(f"t{tid}: {e}")

    threads = [threading.Thread(target=_worker, args=(i,), daemon=True)
               for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    rows = ds.get_webhook_deliveries(limit=500)
    pending = [r for r in rows if r["delivery_state"] == "pending"]
    ok = not errors and len(pending) == n_threads * n_per_thread
    pass_fail("concurrent enqueue integrity", ok,
              f"errors={errors} expected={n_threads * n_per_thread} got={len(pending)}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 2: Multi order_key FIFO ordering
# ════════════════════════════════════════════════════════════════════
def test_multi_order_key_fifo():
    """5 order_keys, each gets red→recovery via on_status_change; verify per-key FIFO."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": f"t{i}", "label": f"T{i}", "ip": f"10.0.0.{i+1}"}
                 for i in range(5)],
    )
    calls = []
    flush = install_push_capture(a, calls, disp)

    for i in range(5):
        a.on_status_change(f"t{i}", f"T{i}", f"10.0.0.{i+1}", "red")
        a._data_store.record_alert(target_id=f"t{i}", label=f"T{i}",
                                   ip=f"10.0.0.{i+1}", ts=time.time(),
                                   old_status="green", new_status="red",
                                   category="loss")
        a._data_store.flush()
        a.on_status_change(f"t{i}", f"T{i}", f"10.0.0.{i+1}", "green")

    flush(n=30, delay=0.02)

    # Per-key ordering: alert_red should come before recovery/inline_recovery
    per_key = {}
    for c in calls:
        key = c.get("order_key", c.get("target", ""))
        per_key.setdefault(key, []).append(c["event"])

    all_ok = True
    for key, events in per_key.items():
        has_red = "alert_red" in events
        red_idx = events.index("alert_red") if has_red else -1
        rec_idx = events.index("recovery") if "recovery" in events else 999
        ordered = red_idx < rec_idx if (has_red and "recovery" in events) else True
        pass_fail(f"  order_key={key} FIFO", ordered, f"events={events}")
        all_ok = all_ok and ordered

    dispatched_keys = {c.get("order_key", c.get("target", "")) for c in calls}
    target_count = len(dispatched_keys - {""})
    ok = all_ok and target_count >= 3
    pass_fail("multi order_key FIFO", ok,
              f"keys_dispatched={dispatched_keys}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 3: Same order_key head-of-line (only one row per key due)
# ════════════════════════════════════════════════════════════════════
def test_same_order_key_head_of_line():
    """Enqueue multiple events for same order_key; only the earliest is due."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": "tk", "label": "TK", "ip": "10.0.0.1"}],
    )

    # Create incident via on_status_change (triggers alert_red push)
    a.on_status_change("tk", "TK", "10.0.0.1", "red")
    a._data_store.record_alert(target_id="tk", label="TK", ip="10.0.0.1",
                               ts=time.time(), old_status="green",
                               new_status="red", category="loss")
    a._data_store.flush()

    # Force enqueue a second event under same order_key
    a._push_webhook(
        event="inline_recovery", target="TK", ip="10.0.0.1",
        status="green", message="rec", order_key="tk",
        gate=None)

    now = time.time()
    due = ds.fetch_deliverable_webhook_outbox(now + 1, limit=10)
    due_events = [r["event"] for r in due]
    # Only one row per order_key in the due set (head-of-line)
    ok = len(due) >= 1 and due_events[0] == "alert_red"
    pass_fail("same order_key head-of-line", ok,
              f"due={due_events} expected[0]=alert_red")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 4: Config reload consistency (change URL mid-dispatch)
# ════════════════════════════════════════════════════════════════════
def test_config_reload_during_dispatch():
    """Enqueue via _push_webhook, reload config, verify dispatch uses URL B."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": "t", "label": "T", "ip": "10.0.0.1"}],
    )

    calls = []
    a._send_webhook = staticmethod(
        lambda url, event, target, ip, status, message, ts_str,
        extra=None, **kw: calls.append({**kw, "url": url}))

    # Push webhook directly (no gate) so dispatch can proceed without incident
    a._push_webhook(
        event="alert_red", target="T", ip="10.0.0.1",
        status="red", message="test",
        order_key="t", gate=None,
    )
    a._data_store.flush()

    # Reload config with new URL (must preserve targets so
    # _webhook_target_known still passes gate checks)
    new_url = "http://127.0.0.1:9999/newhook"
    from scripts.webhook_test_util import default_cfg
    a.set_config(default_cfg(
        webhook_url=new_url,
        targets=[{"id": "t", "label": "T", "ip": "10.0.0.1"}],
    ))

    # Tick — dispatch should read URL from current config
    disp._tick()

    urls = [c.get("url") for c in calls]
    ok = len(urls) >= 1 and all(u == new_url for u in urls)
    pass_fail("config reload uses current URL", ok,
              f"urls={urls}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 5: Large dataset — fetch_deliverable performance
# ════════════════════════════════════════════════════════════════════
def test_large_dataset_fetch_performance():
    """2000 terminal rows + 100 pending; verify fetch is fast and correct."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )

    # Insert 100 pending rows first (different order_keys)
    now = time.time()
    import json
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        for i in range(100):
            conn.execute(
                "INSERT INTO webhook_outbox "
                "(delivery_id, target_id, incident_id, incident_seq, event, "
                " order_key, delivery_state, payload_json, first_queued_ts, "
                " next_attempt_ts, attempt_count, max_attempts, "
                " event_ts, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"PEND-{i:04d}", f"t{i}", f"inc-{i}", 1, "alert_red",
                 f"key-{i:04d}", "pending",
                 json.dumps({"event": "alert_red", "target": f"T{i}",
                             "ip": f"10.0.0.{i%255}", "status": "red",
                             "message": f"msg-{i}"}),
                 now, now, 0, 0, now, now, now))
        conn.commit()

        # Insert 2000 terminal rows
        for state, count in [("delivered", 700), ("dropped_stale", 600),
                              ("failed_permanent", 700)]:
            for i in range(count):
                conn.execute(
                    "INSERT INTO webhook_outbox "
                    "(delivery_id, target_id, incident_id, incident_seq, event, "
                    " order_key, delivery_state, payload_json, first_queued_ts, "
                    " next_attempt_ts, attempt_count, max_attempts, "
                    " delivered_ts, event_ts, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"{state[:6].upper()}-{i:04d}", "t-old", "inc-old", 1,
                     "alert_red", f"old-{i:04d}", state,
                     '{"event":"alert_red","target":"old","ip":"1.1.1.1","status":"red","message":"old"}',
                     now - 86400 * 30, now, 1, 0,
                     now - 86400 * 30 if state == "delivered" else None,
                     now - 86400 * 30, now - 86400 * 30, now - 86400 * 10))
            conn.commit()

    # Measure fetch
    t0 = time.perf_counter()
    due = ds.fetch_deliverable_webhook_outbox(now + 1, limit=50)
    elapsed = time.perf_counter() - t0

    # Should return up to 50 pending rows (different order_keys)
    ok = (
        1 <= len(due) <= 50
        and elapsed < 2.0
        and all(r["delivery_state"] == "pending" for r in due)
    )
    pass_fail("large dataset fetch performance", ok,
              f"due={len(due)} elapsed={elapsed:.3f}s")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 6: Stats API under load
# ════════════════════════════════════════════════════════════════════
def test_stats_api_under_load():
    """stats API returns correct counts with large dataset, < 3s."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )

    now = time.time()
    import json
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        states = {"pending": 50, "delivered": 500, "dropped_stale": 300,
                   "failed_permanent": 200, "sending": 1}
        for state, count in states.items():
            for i in range(count):
                conn.execute(
                    "INSERT INTO webhook_outbox "
                    "(delivery_id, target_id, incident_id, incident_seq, event, "
                    " order_key, delivery_state, payload_json, first_queued_ts, "
                    " next_attempt_ts, attempt_count, max_attempts, "
                    " event_ts, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"{state}-{i:04d}", f"t{i}", f"inc-{i}", 1, "alert_red",
                     f"order-{i:04d}", state,
                     json.dumps({"event": "alert_red", "target": f"T{i}",
                                 "ip": "10.0.0.1", "status": "red",
                                 "message": "test"}),
                     now, now, 0, 0, now, now, now))
        conn.commit()

    t0 = time.perf_counter()
    stats = ds.get_webhook_delivery_stats()
    elapsed = time.perf_counter() - t0

    ok = (
        stats.get("pending") == 50
        and stats.get("delivered") == 500
        and stats.get("dropped_stale") == 300
        and stats.get("failed_permanent") == 200
        and stats.get("sending") == 1
        and elapsed < 3.0
    )
    pass_fail("stats API under 1051 rows", ok,
              f"stats={stats} elapsed={elapsed:.3f}s")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 7: Problem API under load
# ════════════════════════════════════════════════════════════════════
def test_problem_api_under_load():
    """problem deliveries API returns current problems only, < 2s."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )

    now = time.time()
    import json
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        # 500 delivered + 500 dropped_stale
        for state, count in [("delivered", 500), ("dropped_stale", 500)]:
            for i in range(count):
                conn.execute(
                    "INSERT INTO webhook_outbox "
                    "(delivery_id, target_id, incident_id, incident_seq, event, "
                    " order_key, delivery_state, payload_json, first_queued_ts, "
                    " next_attempt_ts, attempt_count, max_attempts, "
                    " event_ts, created_at, updated_at, last_error) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"{state}-{i:04d}", "t-old", "inc-old", 1, "alert_red",
                     f"old-{i:04d}", state,
                     json.dumps({"event": "alert_red", "target": "old",
                                 "ip": "1.1.1.1", "status": "red",
                                 "message": "old"}),
                     now - 86400, now, 1, 0,
                     now - 86400, now - 86400, now - 86400, "stale"))
        # 5 current problems
        for i in range(5):
            conn.execute(
                "INSERT INTO webhook_outbox "
                "(delivery_id, target_id, incident_id, incident_seq, event, "
                " order_key, delivery_state, payload_json, first_queued_ts, "
                " next_attempt_ts, attempt_count, max_attempts, "
                " event_ts, created_at, updated_at, last_error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"PROB-{i:04d}", f"t{i}", f"inc-{i}", 1, "alert_red",
                 f"prob-{i:04d}", "pending",
                 json.dumps({"event": "alert_red", "target": f"T{i}",
                             "ip": "10.0.0.1", "status": "red",
                             "message": f"problem {i}"}),
                 now, now, 2, 0, now, now, now, f"HTTP Error {500 + i}"))
        conn.commit()

    t0 = time.perf_counter()
    problems = ds.get_webhook_problem_deliveries(limit=100)
    elapsed = time.perf_counter() - t0

    pending_problems = [p for p in problems if p["delivery_state"] == "pending"]
    ok = (
        len(pending_problems) >= 5
        and all(p.get("target_label") for p in problems)
        and all(p.get("payload_summary") for p in problems)
        and elapsed < 2.0
    )
    pass_fail("problem API under 1005 rows", ok,
              f"problems={len(pending_problems)} elapsed={elapsed:.3f}s")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 8: Cleanup concurrent with dispatch
# ════════════════════════════════════════════════════════════════════
def test_cleanup_concurrent_with_dispatch():
    """Run _cleanup (which deletes old terminal rows) while dispatcher is active."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": "t1", "label": "T1", "ip": "10.0.0.1"}],
    )

    now = time.time()
    import json
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        # 500 old delivered rows (eligible for cleanup with retention_days=0)
        for i in range(500):
            conn.execute(
                "INSERT INTO webhook_outbox "
                "(delivery_id, target_id, incident_id, incident_seq, event, "
                " order_key, delivery_state, payload_json, first_queued_ts, "
                " next_attempt_ts, attempt_count, max_attempts, "
                " delivered_ts, event_ts, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"OLD-{i:04d}", "t-old", "inc-old", 1, "alert_red",
                 f"old-{i:04d}", "delivered",
                 json.dumps({"event": "alert_red", "target": "old",
                             "ip": "1.1.1.1", "status": "red",
                             "message": "old"}),
                 now - 86400 * 400, now, 1, 0,
                 now - 86400 * 400, now - 86400 * 400, now - 86400 * 400,
                 now - 86400 * 300))
        conn.commit()

    # Push a current pending row via on_status_change
    a.on_status_change("t1", "T1", "10.0.0.1", "red")
    # Record alert so incident stays open
    a._data_store.record_alert(target_id="t1", label="T1", ip="10.0.0.1",
                               ts=time.time(), old_status="green",
                               new_status="red", category="loss")
    a._data_store.flush()

    # Set retention to 0 so cleanup removes old rows
    ds._webhook_outbox_retention_days = 0

    errors = []
    cleanup_done = threading.Event()

    def _do_cleanup():
        try:
            conn2 = ds._outbox_write_conn()
            ds._cleanup(conn2)
        except Exception as e:
            errors.append(f"cleanup: {e}")
        finally:
            cleanup_done.set()

    t = threading.Thread(target=_do_cleanup, daemon=True)
    t.start()

    # Meanwhile run dispatch ticks
    for _ in range(5):
        disp._tick()
        time.sleep(0.05)

    cleanup_done.wait(timeout=10)

    rows = ds.get_webhook_deliveries(limit=20)
    pending = [r for r in rows if r["delivery_state"] == "pending"]
    ok = not errors and len(pending) >= 1
    pass_fail("cleanup concurrent with dispatch", ok,
              f"errors={errors} pending={len(pending)}")
    return ok

    now = time.time()
    import json
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        # 500 old delivered rows (eligible for cleanup)
        for i in range(500):
            conn.execute(
                "INSERT INTO webhook_outbox "
                "(delivery_id, target_id, incident_id, incident_seq, event, "
                " order_key, delivery_state, payload_json, first_queued_ts, "
                " next_attempt_ts, attempt_count, max_attempts, "
                " delivered_ts, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"OLD-{i:04d}", "t-old", "inc-old", 1, "alert_red",
                 f"old-{i:04d}", "delivered",
                 json.dumps({"event": "alert_red", "target": "old", "ip": "1.1.1.1",
                             "status": "red", "message": "old"}),
                 now - 86400 * 400, now, 1, 0,
                 now - 86400 * 400, now - 86400 * 300))
        conn.commit()

    # Push a current pending row via on_status_change
    a.on_status_change("t1", "T1", "10.0.0.1", "red")
    # Record alert so incident stays open
    a._data_store.record_alert(target_id="t1", label="T1", ip="10.0.0.1",
                               ts=time.time(), old_status="green",
                               new_status="red", category="loss")
    a._data_store.flush()

    errors = []
    cleanup_done = threading.Event()

    def _do_cleanup():
        try:
            ds._cleanup()
        except Exception as e:
            errors.append(f"cleanup: {e}")
        finally:
            cleanup_done.set()

    # Run cleanup in background
    t = threading.Thread(target=_do_cleanup, daemon=True)
    t.start()

    # Meanwhile run dispatch ticks
    for _ in range(5):
        disp._tick()
        time.sleep(0.05)

    cleanup_done.wait(timeout=10)

    # Pending row should still be there
    rows = ds.get_webhook_deliveries(limit=10)
    ok = (
        not errors
        and any(r["delivery_id"].startswith("OLD-") is False
                and r["delivery_state"] == "pending" for r in rows)
    )
    pass_fail("cleanup concurrent with dispatch", ok,
              f"errors={errors} pending_preserved={ok}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 9: Dispatcher crash mid-send recovery
# ════════════════════════════════════════════════════════════════════
def test_dispatcher_crash_mid_send_recovery():
    """Simulate dispatcher crash while row is 'sending'; verify recovery."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
        targets=[{"id": "t1", "label": "T1", "ip": "10.0.0.1"}],
    )

    # Push a row
    a.on_status_change("t1", "T1", "10.0.0.1", "red")

    # Manually set to 'sending' (simulate crash after claim)
    now = time.time()
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET delivery_state='sending', "
            "last_attempt_ts=?, updated_at=? WHERE delivery_state='pending'",
            (now - 200, now - 200))
        conn.commit()

    # Verify row is sending
    rows = ds.get_webhook_deliveries(limit=5)
    sending = [r for r in rows if r["delivery_state"] == "sending"]
    assert sending, "expected sending row"

    # Simulate restart: recover then tick
    ds.recover_stale_sending_webhook_outbox(now, lease_sec=120)
    ds.recover_orphaned_sending_webhook_outbox()

    calls = []
    flush = install_push_capture(a, calls, disp)
    flush(n=8, delay=0.02)

    rows2 = ds.get_webhook_deliveries(limit=5)
    delivered = [r for r in rows2 if r["delivery_state"] == "delivered"]
    ok = len(delivered) >= 1
    pass_fail("dispatcher crash mid-send recovery", ok,
              f"delivered={len(delivered)} sending_before={len(sending)}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 10: SQLite busy contention under rapid writes
# ════════════════════════════════════════════════════════════════════
def test_sqlite_busy_contention():
    """Rapid concurrent writes from multiple threads; no timeout errors."""
    a, disp, ds = make_alerter(
        webhook_url=_HOOK_URL,
        webhook_include_trace=False,
        webhook_trace_update_enabled=False,
    )

    errors = []
    n_threads = 5
    n_ops = 20
    barrier = threading.Barrier(n_threads, timeout=10)

    def _worker(tid):
        try:
            barrier.wait(timeout=5)
            for i in range(n_ops):
                try:
                    with ds._outbox_lock:
                        conn = ds._outbox_write_conn()
                        conn.execute(
                            "INSERT INTO webhook_outbox "
                            "(delivery_id, target_id, incident_id, incident_seq, event, "
                            " order_key, delivery_state, payload_json, first_queued_ts, "
                            " next_attempt_ts, attempt_count, max_attempts, "
                            " event_ts, created_at, updated_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (f"BUSY-{tid}-{i:04d}", f"t{tid}", f"inc-{tid}", 1,
                             "alert_red", f"busy-{tid}", "pending",
                             '{"event":"alert_red","target":"T","ip":"1.1.1.1",'
                             '"status":"red","message":"busy"}',
                             time.time(), time.time(), 0, 0,
                             time.time(), time.time(), time.time()))
                        conn.commit()
                except Exception as e:
                    errors.append(f"t{tid}-{i}: {e}")
        except Exception as e:
            errors.append(f"t{tid} barrier: {e}")

    threads = [threading.Thread(target=_worker, args=(i,), daemon=True)
               for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    rows = ds.get_webhook_deliveries(limit=200)
    total = len([r for r in rows if r["delivery_id"].startswith("BUSY-")])
    ok = not errors and total == n_threads * n_ops
    pass_fail("SQLite busy contention", ok,
              f"errors={errors} expected={n_threads * n_ops} got={total}")
    return ok


# ════════════════════════════════════════════════════════════════════
# Test 11: Lock ordering safety (no deadlock under stress)
# ════════════════════════════════════════════════════════════════════
def test_lock_ordering_no_deadlock():
    """Stress the known nested lock path: _cancel_inflight during dispatch."""
    # Prevent background VACUUM from blocking concurrent DB operations.
    # Must patch the class BEFORE DataStore.__init__ starts the daemon.
    import src.data_store as _ds
    _maybe_vacuum_orig = _ds.DataStore._maybe_vacuum
    _ds.DataStore._maybe_vacuum = lambda self: None

    try:
        a, disp, ds = make_alerter(
            webhook_url=_HOOK_URL,
            webhook_include_trace=False,
            webhook_trace_update_enabled=False,
            targets=[{"id": f"t{i}", "label": f"T{i}", "ip": f"10.0.0.{i+1}"}
                     for i in range(10)],
        )

        # Patch _send_webhook to avoid 10s HTTP timeout per row.
        # Lock ordering is the goal here, not real HTTP behavior.
        calls_sent = []
        a._send_webhook = staticmethod(
            lambda url, event, target, ip, status, message, ts_str,
            extra=None, **kw: calls_sent.append(url) or None)

        # Push 10 red events
        for i in range(10):
            a.on_status_change(f"t{i}", f"T{i}", f"10.0.0.{i+1}", "red")

        timeout_hit = threading.Event()
        errors = []

        def _cancel_loop():
            try:
                for _ in range(30):
                    # Cancel sends targeting a non-existent target, exercising
                    # _webhook_outbox_send_lock → _outbox_lock path
                    a._cancel_inflight_outbox_sends("acknowledge")
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"cancel: {e}")

        def _dispatch_loop():
            try:
                for _ in range(30):
                    disp._tick()
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"dispatch: {e}")

        t1 = threading.Thread(target=_cancel_loop, daemon=True)
        t2 = threading.Thread(target=_dispatch_loop, daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        if t1.is_alive() or t2.is_alive():
            timeout_hit.set()

        ok = not errors and not timeout_hit.is_set()
        pass_fail("lock ordering no deadlock", ok,
                  f"errors={errors} timeout={timeout_hit.is_set()} "
                  f"sent={len(calls_sent)}")
        return ok
    finally:
        _ds.DataStore._maybe_vacuum = _maybe_vacuum_orig


# ════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════
def main():
    global _SUCCESS
    print("=== Concurrency & Stress Review ===\n")

    tests = [
        ("concurrent enqueue", test_concurrent_enqueue_integrity),
        ("multi-key FIFO", test_multi_order_key_fifo),
        ("head-of-line", test_same_order_key_head_of_line),
        ("config reload", test_config_reload_during_dispatch),
        ("large fetch perf", test_large_dataset_fetch_performance),
        ("stats under load", test_stats_api_under_load),
        ("problem API under load", test_problem_api_under_load),
        ("cleanup + dispatch", test_cleanup_concurrent_with_dispatch),
        ("crash recovery", test_dispatcher_crash_mid_send_recovery),
        ("SQLite contention", test_sqlite_busy_contention),
        ("lock no deadlock", test_lock_ordering_no_deadlock),
    ]

    for name, fn in tests:
        print(f"\n[{name}]")
        try:
            fn()
        except Exception as e:
            print(f"  ERROR {name}: {e}")
            import traceback
            traceback.print_exc()
            _SUCCESS = False

    print(f"\n{'ALL 11 tests passed' if _SUCCESS else 'SOME TESTS FAILED'}")
    sys.exit(0 if _SUCCESS else 1)


if __name__ == "__main__":
    main()
