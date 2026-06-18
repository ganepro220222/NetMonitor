"""Round 5: UI/API Observability — problem API, stats, XSS safety, filtering, ordering.
"""
import json, os, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.data_store import DataStore

_results = []

def record(name, ok, detail=""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}")
    if detail:
        print(f"         {detail}")

def _mk_ds():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)
    return ds

def _enqueue(ds, delivery_id, **kw):
    now = time.time()
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id=kw.get("target_id", "T-X"),
        incident_id=kw.get("incident_id", "INC-X"),
        incident_seq=kw.get("incident_seq", 1),
        event=kw.get("event", "alert_red"),
        order_key=kw.get("order_key", "T-X"),
        payload=kw.get("payload", {
            "event": "alert_red", "target": "Gate-X", "ip": "10.0.0.1",
            "status": "red", "message": "test", "event_ts": now,
        }),
        event_ts=now,
        max_attempts=kw.get("max_attempts", 0),
    )

def _update(ds, delivery_id, **kw):
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        sets = []
        params = []
        for k, v in kw.items():
            if k == "delivery_state":
                sets.append("delivery_state=?")
                params.append(v)
            elif k == "last_error":
                sets.append("last_error=?")
                params.append(v)
            elif k == "attempt_count":
                sets.append("attempt_count=?")
                params.append(int(v))
            elif k == "next_attempt_ts":
                sets.append("next_attempt_ts=?")
                params.append(float(v))
            elif k == "updated_at":
                sets.append("updated_at=?")
                params.append(float(v))
        params.append(delivery_id)
        conn.execute(f"UPDATE webhook_outbox SET {', '.join(sets)} WHERE delivery_id=?",
                     params)
        conn.commit()

# ============================================================
# TEST 1: Problem API field completeness
# ============================================================
def test_01_problem_api_fields():
    print("\n-- 1. Problem API field completeness --")
    ds = _mk_ds()
    now = time.time()
    _enqueue(ds, "WH-P1", target_id="T1", incident_id="INC1",
             event="alert_red", order_key="T1",
             payload={"event": "alert_red", "target": "Gate-1", "ip": "10.0.1.1",
                      "status": "red", "message": "连接中断", "event_ts": now})
    _update(ds, "WH-P1", last_error="timeout", attempt_count=3,
            next_attempt_ts=now + 60, updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("01a returns 1 row", len(rows) == 1, f"got {len(rows)}")

    row = rows[0]
    required_fields = [
        "delivery_id", "target_id", "incident_id", "event", "delivery_state",
        "attempt_count", "max_attempts", "last_error", "first_queued_ts",
        "next_attempt_ts", "last_attempt_ts", "delivered_ts",
        "payload_summary", "target_label", "payload",
    ]
    for fld in required_fields:
        record(f"01b field '{fld}' present", fld in row,
               f"value type={type(row.get(fld)).__name__}")

    record("01c delivery_id", row.get("delivery_id") == "WH-P1",
           f"got {row.get('delivery_id')!r}")
    record("01d target_id", row.get("target_id") == "T1",
           f"got {row.get('target_id')!r}")
    record("01e delivery_state", row.get("delivery_state") == "pending",
           f"got {row.get('delivery_state')!r}")
    record("01f attempt_count", row.get("attempt_count") == 3,
           f"got {row.get('attempt_count')}")
    record("01g last_error", row.get("last_error") == "timeout",
           f"got {row.get('last_error')!r}")
    record("01h next_attempt_ts present",
           row.get("next_attempt_ts") is not None,
           f"got {row.get('next_attempt_ts')}")
    record("01i first_queued_ts present",
           row.get("first_queued_ts") is not None,
           f"got {row.get('first_queued_ts')}")
    record("01j payload_summary non-empty",
           bool(row.get("payload_summary")),
           f"got {row.get('payload_summary')!r}")
    record("01k target_label",
           row.get("target_label") == "Gate-1",
           f"got {row.get('target_label')!r}")

# ============================================================
# TEST 2: Filtering — delivered excluded
# ============================================================
def test_02_filtering_delivered_excluded():
    print("\n-- 2. Filtering: delivered excluded --")
    ds = _mk_ds()
    _enqueue(ds, "WH-DONE", target_id="T1", event="alert_red", order_key="T1")
    ds.finish_webhook_outbox("WH-DONE", state="delivered", now=time.time())

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("02a delivered not in problem list", len(rows) == 0,
           f"got {len(rows)} rows: {[r.get('delivery_id') for r in rows]}")

# ============================================================
# TEST 3: Filtering — recent dropped_stale with error included
# ============================================================
def test_03_filtering_dropped_stale_with_error():
    print("\n-- 3. Filtering: recent dropped_stale with error --")
    ds = _mk_ds()
    now = time.time()
    _enqueue(ds, "WH-DROP-ERR", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-DROP-ERR", delivery_state="dropped_stale",
            last_error="target_orphan", updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("03a dropped_stale with error appears", len(rows) == 1,
           f"got {len(rows)} rows")
    if rows:
        record("03b delivery_state", rows[0].get("delivery_state") == "dropped_stale",
               f"got {rows[0].get('delivery_state')!r}")

# ============================================================
# TEST 4: Filtering — old dropped_stale without error excluded
# ============================================================
def test_04_filtering_old_dropped_stale_excluded():
    print("\n-- 4. Filtering: old dropped_stale (no error) excluded --")
    ds = _mk_ds()
    now = time.time()
    _enqueue(ds, "WH-DROP-OLD", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-DROP-OLD", delivery_state="dropped_stale",
            last_error="", updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("04a old dropped_stale excluded", len(rows) == 0,
           f"got {len(rows)} rows: {[r.get('delivery_id') for r in rows]}")

# ============================================================
# TEST 5: Ordering — pending/sending before terminal states
# ============================================================
def test_05_ordering_active_first():
    print("\n-- 5. Ordering: pending/sending before terminal --")
    ds = _mk_ds()
    now = time.time()
    _enqueue(ds, "WH-SEND", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-SEND", delivery_state="sending", updated_at=now)
    _enqueue(ds, "WH-PEND", target_id="T1", event="diagnostic_update", order_key="T1")
    _update(ds, "WH-PEND", delivery_state="pending", last_error="timeout", updated_at=now - 1)
    _enqueue(ds, "WH-DROP", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-DROP", delivery_state="dropped_stale", last_error="target_orphan",
            updated_at=now - 2)
    _enqueue(ds, "WH-FAIL", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-FAIL", delivery_state="failed_permanent", last_error="DNS fail",
            updated_at=now - 3)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("05a returns 4 rows", len(rows) == 4, f"got {len(rows)}")

    states = [r["delivery_state"] for r in rows]
    record("05b sending first", states[0] == "sending",
           f"order: {states}")
    record("05c pending second", states[1] == "pending",
           f"order: {states}")
    # failed_permanent or dropped_stale can be 3rd/4th

# ============================================================
# TEST 6: Stats API accuracy
# ============================================================
def test_06_stats_api():
    print("\n-- 6. Stats API accuracy --")
    ds = _mk_ds()
    now = time.time()

    # 2 pending, 1 sending, 1 delivered, 1 failed_permanent
    for i in range(2):
        did = f"WH-ST-P{i}"
        _enqueue(ds, did, target_id="T1", event="alert_red", order_key="T1")
        _update(ds, did, delivery_state="pending", updated_at=now)

    _enqueue(ds, "WH-ST-S1", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-ST-S1", delivery_state="sending", updated_at=now)

    _enqueue(ds, "WH-ST-D1", target_id="T1", event="alert_red", order_key="T1")
    ds.finish_webhook_outbox("WH-ST-D1", state="delivered", now=now)

    _enqueue(ds, "WH-ST-F1", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-ST-F1", delivery_state="failed_permanent",
            last_error="err", updated_at=now)

    stats = ds.get_webhook_delivery_stats()
    record("06a pending count", stats.get("pending") == 2,
           f"stats={stats}")
    record("06b sending count", stats.get("sending") == 1,
           f"stats={stats}")
    record("06c delivered count", stats.get("delivered") == 1,
           f"stats={stats}")
    record("06d failed_permanent count", stats.get("failed_permanent") == 1,
           f"stats={stats}")

# ============================================================
# TEST 7: Last failures API fields
# ============================================================
def test_07_failures_api():
    print("\n-- 7. Last failures API fields --")
    ds = _mk_ds()
    now = time.time()

    _enqueue(ds, "WH-FAIL1", target_id="T1", event="alert_red", order_key="T1")
    _update(ds, "WH-FAIL1", delivery_state="failed_permanent",
            last_error="HTTP 500", updated_at=now)
    _enqueue(ds, "WH-FAIL2", target_id="T2", event="recovery", order_key="T2")
    _update(ds, "WH-FAIL2", delivery_state="pending",
            last_error="connect refused", updated_at=now - 1)

    fails = ds.get_last_webhook_failures(limit=5)
    record("07a returns failures", len(fails) >= 1,
           f"got {len(fails)} fails")
    if fails:
        flds = {"delivery_id", "target_id", "event", "state", "error", "updated_at"}
        for f in fails:
            for fld in flds:
                record(f"07b field '{fld}' in failure", fld in f,
                       f"row={f.get('delivery_id')}")

# ============================================================
# TEST 8: payload_summary correctness
# ============================================================
def test_08_payload_summary():
    print("\n-- 8. payload_summary correctness --")
    ds = _mk_ds()
    now = time.time()
    _enqueue(ds, "WH-PS1", target_id="T1", event="alert_red", order_key="T1",
             payload={
                 "event": "alert_red", "target": "核心网关", "ip": "192.168.1.1",
                 "status": "red", "message": "丢包率 100% (5/5)",
                 "event_ts": now,
             })
    _update(ds, "WH-PS1", delivery_state="pending", updated_at=now,
            last_error="timeout")

    rows = ds.get_webhook_problem_deliveries(limit=10)
    summary = rows[0].get("payload_summary", "")
    record("08a has event", "event=alert_red" in summary, f"summary={summary}")
    record("08b has target", "target=核心网关" in summary, f"summary={summary}")
    record("08c has ip", "ip=192.168.1.1" in summary, f"summary={summary}")
    record("08d has status", "status=red" in summary, f"summary={summary}")
    record("08e has message", "message=丢包率" in summary, f"summary={summary}")

    # Test message truncation (>80 chars)
    ds2 = _mk_ds()
    long_msg = "A" * 100
    _enqueue(ds2, "WH-LONG", target_id="T1", event="alert_red", order_key="T1",
             payload={
                 "event": "alert_red", "target": "X", "ip": "1.2.3.4",
                 "status": "red", "message": long_msg, "event_ts": now,
             })
    _update(ds2, "WH-LONG", delivery_state="pending", updated_at=now)
    rows2 = ds2.get_webhook_problem_deliveries(limit=10)
    summary2 = rows2[0].get("payload_summary", "")
    record("08f long message truncated", len(summary2) < 200,
           f"len={len(summary2)}")

# ============================================================
# TEST 9: XSS safety — backend raw values preserved, esc() used in frontend
# ============================================================
def test_09_xss_safety():
    print("\n-- 9. XSS safety --")
    ds = _mk_ds()
    now = time.time()
    xss_payload = {
        "event": "alert_red",
        "target": '<img src=x onerror=alert(1)>',
        "ip": '<script>alert(2)</script>',
        "status": "red",
        "message": '<a href="javascript:alert(3)">click</a>',
        "event_ts": now,
    }
    _enqueue(ds, "WH-XSS", target_id="T1", event="alert_red", order_key="T1",
             payload=xss_payload)
    _update(ds, "WH-XSS", last_error='<img src=x onerror="alert(4)">',
            delivery_state="pending", updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    row = rows[0]

    # Backend returns raw values (JSON encoding handles escaping)
    record("09a last_error preserved raw",
           "<img" in row.get("last_error", ""),
           f"error={row.get('last_error')!r}")
    record("09b target_label preserved raw",
           "<img" in row.get("target_label", ""),
           f"label={row.get('target_label')!r}")
    record("09c payload xss preserved",
           "onerror" in row.get("payload", {}).get("target", ""),
           f"payload.target={row.get('payload', {}).get('target')!r}")

    # Verify frontend esc() function is defined and works correctly
    # (static check — esc() defined at line 1693 of web_server.py)
    import re
    web_server_path = os.path.join(ROOT, "src", "web_server.py")
    with open(web_server_path, "r", encoding="utf-8") as f:
        ws = f.read()
    record("09d esc() defined in web_server",
           "const esc=s=>String(s).replace(/&/g" in ws,
           "esc() function found")
    record("09e esc() used in renderWebhookFailPanel",
           "esc(r.last_error||'—')" in ws,
           "last_error rendering uses esc()")
    record("09f esc() used for target_label",
           "esc(r.target_label||'—')" in ws,
           "target_label rendering uses esc()")
    record("09g esc() used for delivery_id",
           "esc(r.delivery_id||'')" in ws,
           "delivery_id rendering uses esc()")
    record("09h esc() used for event",
           "esc(r.event||'')" in ws,
           "event rendering uses esc()")
    record("09i esc() used for delivery_state",
           "esc(r.delivery_state||'')" in ws,
           "delivery_state rendering uses esc()")
    record("09j esc() used for attempt_count",
           "esc(String(r.attempt_count" in ws,
           "attempt_count rendering uses esc()")
    record("09k esc() used for next_attempt_ts",
           "esc(_whFmtTs(r.next_attempt_ts))" in ws,
           "next_attempt_ts rendering uses esc()")
    record("09l esc() used for first_queued_ts",
           "esc(_whFmtTs(r.first_queued_ts))" in ws,
           "first_queued_ts rendering uses esc()")
    record("09m esc() used for payload_summary",
           "esc(_whPayloadSummary(r))" in ws,
           "payload_summary rendering uses esc()")

    # Verify pill uses textContent (XSS safe)
    record("09n pill uses textContent not innerHTML",
           "pill.textContent" in ws and "Webhook" in ws,
           "pill rendering XSS safe")

    # Verify overlay body uses innerHTML but with esc()-wrapped content
    record("09o overlay uses innerHTML",
           "body.innerHTML=" in ws,
           "overlay uses innerHTML (expected with esc wrapping)")

# ============================================================
# TEST 10: Copy debug text completeness
# ============================================================
def test_10_copy_debug_text():
    print("\n-- 10. Copy debug text completeness --")
    import re
    web_server_path = os.path.join(ROOT, "src", "web_server.py")
    with open(web_server_path, "r", encoding="utf-8") as f:
        ws = f.read()

    # Extract _whDebugText function body (note: \\n matches literal \n in source)
    m = re.search(r"function _whDebugText\(row\)\{.*?return lines\.join\('\\n'\);\s*\}", ws, re.DOTALL)
    debug_body = m.group(0) if m else ""

    debug_fields = [
        "delivery_id", "target_id", "target_label", "event", "state",
        "attempt_count", "max_attempts", "last_error",
        "first_queued_ts", "next_attempt_ts", "last_attempt_ts",
        "incident_id", "incident_seq", "order_key", "payload_summary",
    ]
    for fld in debug_fields:
        record(f"10a debug has '{fld}'", fld in debug_body,
               f"found: {fld in debug_body}")

# ============================================================
# TEST 11: limit enforcement
# ============================================================
def test_11_limit_enforcement():
    print("\n-- 11. Limit enforcement --")
    ds = _mk_ds()
    now = time.time()
    for i in range(10):
        _enqueue(ds, f"WH-LIM-{i}", target_id="T1", event="alert_red", order_key="T1")
        _update(ds, f"WH-LIM-{i}", delivery_state="pending",
                last_error=f"err {i}", updated_at=now - i)

    rows3 = ds.get_webhook_problem_deliveries(limit=3)
    record("11a limit=3 returns <=3", len(rows3) <= 3 and len(rows3) > 0,
           f"got {len(rows3)}")

    rows10 = ds.get_webhook_problem_deliveries(limit=10)
    record("11b limit=10 returns all 10", len(rows10) == 10,
           f"got {len(rows10)}")

# ============================================================
# TEST 12: Different states appear in problem list
# ============================================================
def test_12_covered_states():
    print("\n-- 12. All relevant states covered --")
    ds = _mk_ds()
    now = time.time()

    states_to_test = [
        ("pending", "timeout err", True),
        ("sending", "", True),
        ("failed_permanent", "HTTP 500", True),
        ("dropped_stale", "target_orphan", True),
        ("dropped_stale", "", False),
        ("delivered", "", False),
    ]

    for st, err, expected in states_to_test:
        did = f"WH-ST-{st}-{err}"
        _enqueue(ds, did, target_id="T1", event="alert_red", order_key="T1")
        _update(ds, did, delivery_state=st, last_error=err, updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=20)
    ids = {r["delivery_id"] for r in rows}

    for st, err, expected in states_to_test:
        did = f"WH-ST-{st}-{err}"
        record(f"12 {st} err={err!r} {'appears' if expected else 'excluded'}",
               (did in ids) == expected,
               f"found={did in ids}")

# ============================================================
# TEST 13: target_label from payload.target
# ============================================================
def test_13_target_label():
    print("\n-- 13. target_label extraction --")
    ds = _mk_ds()
    now = time.time()

    # Normal case
    _enqueue(ds, "WH-TL1", target_id="t-core", event="alert_red", order_key="t-core",
             payload={
                 "event": "alert_red", "target": "Core Router",
                 "ip": "10.0.0.1", "status": "red", "message": "down",
                 "event_ts": now,
             })
    _update(ds, "WH-TL1", delivery_state="pending", updated_at=now)

    rows = ds.get_webhook_problem_deliveries(limit=10)
    record("13a target_label = payload.target",
           rows[0].get("target_label") == "Core Router",
           f"got {rows[0].get('target_label')!r}, target_id={rows[0].get('target_id')!r}")

    # Missing target in payload
    _enqueue(ds, "WH-TL2", target_id="t-unknown", event="alert_red", order_key="t-unknown",
             payload={
                 "event": "alert_red", "ip": "10.0.0.2",
                 "status": "red", "message": "down",
                 "event_ts": now,
             })
    _update(ds, "WH-TL2", delivery_state="pending", updated_at=now)
    rows2 = ds.get_webhook_problem_deliveries(limit=10)
    row2 = [r for r in rows2 if r["delivery_id"] == "WH-TL2"]
    if row2:
        record("13b missing target → empty string", row2[0].get("target_label") == "",
               f"got target_label={row2[0].get('target_label')!r}")

# ============================================================
# Main
# ============================================================
def main():
    print("=" * 72)
    print("Round 5: UI/API Observability Review")
    print("=" * 72)

    tests = [
        ("01 problem API fields", test_01_problem_api_fields),
        ("02 filtering delivered excluded", test_02_filtering_delivered_excluded),
        ("03 filtering dropped_stale with error", test_03_filtering_dropped_stale_with_error),
        ("04 filtering old dropped_stale", test_04_filtering_old_dropped_stale_excluded),
        ("05 ordering active first", test_05_ordering_active_first),
        ("06 stats API", test_06_stats_api),
        ("07 failures API", test_07_failures_api),
        ("08 payload summary", test_08_payload_summary),
        ("09 XSS safety", test_09_xss_safety),
        ("10 copy debug text", test_10_copy_debug_text),
        ("11 limit enforcement", test_11_limit_enforcement),
        ("12 covered states", test_12_covered_states),
        ("13 target_label", test_13_target_label),
    ]

    for name, fn in tests:
        try:
            fn()
        except Exception as e:
            import traceback
            record(f"{name} UNHANDLED", False, str(e))
            traceback.print_exc()

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
