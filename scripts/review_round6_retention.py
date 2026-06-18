"""Round 6: webhook_outbox Retention / Cleanup Strategy Probe.

Verification targets:
  1. _cleanup_webhook_outbox() deletes terminal rows beyond retention cutoff
  2. pending / sending are NEVER deleted by cleanup
  3. delivered rows use COALESCE(delivered_ts, updated_at) for cutoff
  4. dropped_stale / failed_permanent use updated_at for cutoff
  5. Retention config: db_webhook_outbox_retention_days (7-3650, default 90)
  6. Ops view (_webhook_ops_recent_cutoff) caps at max 7 days
  7. Stats API only counts terminal rows within 7-day ops window
  8. Retention is live-updatable via update_retention()
  9. Large-scale bulk cleanup works (1000+ rows per state)
 10. Default 90-day retention is enforced
"""
import json, os, sys, tempfile, time, threading

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

def _count_rows(ds, state=None):
    conn = ds._read_conn()
    if state:
        r = conn.execute("SELECT COUNT(*) FROM webhook_outbox WHERE delivery_state=?",
                         (state,)).fetchone()
    else:
        r = conn.execute("SELECT COUNT(*) FROM webhook_outbox").fetchone()
    return r[0] if r else 0

def _count_all(ds):
    conn = ds._read_conn()
    rows = conn.execute(
        "SELECT delivery_state, COUNT(*) FROM webhook_outbox GROUP BY delivery_state"
    ).fetchall()
    return {st: cnt for st, cnt in rows}

def _bulk_insert(ds, state, count, age_days, base_did):
    """Insert `count` rows of a given state with specified age."""
    conn = ds._outbox_write_conn()
    now = time.time()
    ago = now - age_days * 86400
    ts = ago  # first_queued / updated_at / delivered_ts = days old

    payload = json.dumps({
        "event": f"test_{state}", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": f"bulk {state} row",
        "event_ts": ts,
    }, ensure_ascii=False)

    rows_sql = []
    for i in range(count):
        did = f"{base_did}-{i}"
        d_ts = ts if state == "delivered" else None
        rows_sql.append(
            f"('{did}','T1','INC-BULK',1,'alert_red','T1',"
            f"'{payload}',{ts},{ts},{ts},{ts},"
            f"{d_ts if d_ts else 'NULL'},1,0,'{state}',"
            f"'','{ts}','{ts}')"
        )

    # Batch insert in chunks of 200
    chunk = 200
    for j in range(0, len(rows_sql), chunk):
        batch = rows_sql[j:j+chunk]
        sql = (
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES "
            + ",".join(batch)
        )
        conn.execute(sql)
    conn.commit()

# ============================================================
# TEST 1: pending/sending NEVER deleted by cleanup
# ============================================================
def test_01_pending_sending_protected():
    print("\n-- 1. pending/sending NEVER deleted by cleanup --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    _bulk_insert(ds, "pending", 10, 30, "WH-PROT-PEND")   # 30 days old
    _bulk_insert(ds, "sending", 10, 30, "WH-PROT-SEND")    # 30 days old

    record("01a before", _count_rows(ds, "pending") == 10,
           f"pending={_count_rows(ds, 'pending')}")
    record("01b before", _count_rows(ds, "sending") == 10,
           f"sending={_count_rows(ds, 'sending')}")

    # Run cleanup (retention=7 days, rows are 30 days old)
    conn = ds._outbox_write_conn()
    with conn:
        ds._cleanup_webhook_outbox(conn, now)

    record("01c pending survived", _count_rows(ds, "pending") == 10,
           f"pending after cleanup={_count_rows(ds, 'pending')}")
    record("01d sending survived", _count_rows(ds, "sending") == 10,
           f"sending after cleanup={_count_rows(ds, 'sending')}")

# ============================================================
# TEST 2: Old delivered rows ARE deleted
# ============================================================
def test_02_old_delivered_deleted():
    print("\n-- 2. Old delivered rows deleted by cleanup --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    # 10 old (30 days), 5 recent (1 day)
    _bulk_insert(ds, "delivered", 10, 30, "WH-OLD-DEL")
    _bulk_insert(ds, "delivered", 5, 1, "WH-NEW-DEL")

    record("02a before", _count_rows(ds, "delivered") == 15,
           f"total delivered={_count_rows(ds, 'delivered')}")

    conn = ds._outbox_write_conn()
    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    record("02b old deleted", deleted >= 10,
           f"deleted={deleted}")
    record("02c recent survived", _count_rows(ds, "delivered") == 5,
           f"remaining delivered={_count_rows(ds, 'delivered')}")

# ============================================================
# TEST 3: Old dropped_stale rows deleted
# ============================================================
def test_03_old_dropped_stale_deleted():
    print("\n-- 3. Old dropped_stale rows deleted --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    _bulk_insert(ds, "dropped_stale", 10, 30, "WH-OLD-DROP")
    _bulk_insert(ds, "dropped_stale", 3, 1, "WH-NEW-DROP")

    record("03a before", _count_rows(ds, "dropped_stale") == 13,
           f"total dropped_stale={_count_rows(ds, 'dropped_stale')}")

    conn = ds._outbox_write_conn()
    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    record("03b old deleted", _count_rows(ds, "dropped_stale") == 3,
           f"remaining dropped_stale={_count_rows(ds, 'dropped_stale')}")

# ============================================================
# TEST 4: Old failed_permanent rows deleted
# ============================================================
def test_04_old_failed_permanent_deleted():
    print("\n-- 4. Old failed_permanent rows deleted --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    _bulk_insert(ds, "failed_permanent", 10, 30, "WH-OLD-FAIL")
    _bulk_insert(ds, "failed_permanent", 3, 1, "WH-NEW-FAIL")

    record("04a before", _count_rows(ds, "failed_permanent") == 13,
           f"total failed_permanent={_count_rows(ds, 'failed_permanent')}")

    conn = ds._outbox_write_conn()
    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    record("04b old deleted", _count_rows(ds, "failed_permanent") == 3,
           f"remaining failed_permanent={_count_rows(ds, 'failed_permanent')}")

# ============================================================
# TEST 5: delivered uses delivered_ts, fallback updated_at
# ============================================================
def test_05_delivered_uses_delivered_ts():
    print("\n-- 5. delivered COALESCE(delivered_ts, updated_at) --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    # Insert a row with old delivered_ts but recent updated_at
    # This simulates a row delivered 30 days ago but updated recently
    conn = ds._outbox_write_conn()
    ts_old = now - 30 * 86400
    ts_recent = now - 1 * 86400
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "edge case", "event_ts": ts_old,
    }, ensure_ascii=False)
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("WH-DTS-EDGE", "T1", "INC-EDGE", 1, "alert_red", "T1",
         payload, ts_old, ts_old, ts_old, ts_old,
         ts_old, 1, 0, "delivered", "", ts_old, ts_recent))
    conn.commit()

    record("05a before", _count_rows(ds, "delivered") == 1,
           f"delivered={_count_rows(ds, 'delivered')}")

    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    # delivered_ts is 30 days old (beyond 7-day retention), so it SHOULD be deleted
    record("05b deleted (uses delivered_ts not updated_at)",
           deleted >= 1 and _count_rows(ds, "delivered") == 0,
           f"deleted={deleted}, remaining={_count_rows(ds, 'delivered')}")

# ============================================================
# TEST 6: Config default 90 days, range 7-3650
# ============================================================
def test_06_config_settings():
    print("\n-- 6. Config settings --")
    import re
    config_path = os.path.join(ROOT, "src", "config_manager.py")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = f.read()

    record("06a default 90 days",
           '"db_webhook_outbox_retention_days": 90' in cfg,
           "default value found")
    record("06b range (7, 3650)",
           '"db_webhook_outbox_retention_days": (7, 3650)' in cfg,
           "range constraint found")

    # Verify DataStore constructor default
    ds_path = os.path.join(ROOT, "src", "data_store.py")
    with open(ds_path, "r", encoding="utf-8") as f:
        ds_code = f.read()
    record("06c DataStore default=90",
           "webhook_outbox_retention_days: int = 90" in ds_code or
           "webhook_outbox_retention_days: int=90" in ds_code,
           "constructor default found")

# ============================================================
# TEST 7: Retention is live-updatable
# ============================================================
def test_07_live_update_retention():
    print("\n-- 7. Live-update retention --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=90)
    ds._schema_ready.wait(timeout=5)

    record("07a initial=90", ds._webhook_outbox_retention_days == 90,
           f"got {ds._webhook_outbox_retention_days}")

    ds.update_retention(webhook_outbox=30)
    record("07b updated to 30", ds._webhook_outbox_retention_days == 30,
           f"got {ds._webhook_outbox_retention_days}")

    ds.update_retention(webhook_outbox=365)
    record("07c updated to 365", ds._webhook_outbox_retention_days == 365,
           f"got {ds._webhook_outbox_retention_days}")

# ============================================================
# TEST 8: Ops view caps at 7 days max
# ============================================================
def test_08_ops_window_cap():
    print("\n-- 8. Ops view caps at 7 days --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=90)
    ds._schema_ready.wait(timeout=5)

    # Even with 90-day retention, ops view window = min(7, 90) = 7
    now = time.time()
    cutoff = ds._webhook_ops_recent_cutoff(now)
    window_days = (now - cutoff) / 86400
    record("08a ops window capped at 7", 6.5 <= window_days <= 7.5,
           f"window={window_days:.1f} days")

    # With 3-day retention, window = min(7, 3) = 3
    ds2 = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                    webhook_outbox_retention_days=3)
    ds2._schema_ready.wait(timeout=5)
    cutoff2 = ds2._webhook_ops_recent_cutoff(now)
    window2 = (now - cutoff2) / 86400
    record("08b ops window follows retention", 2.5 <= window2 <= 3.5,
           f"window={window2:.1f} days (retention=3)")

# ============================================================
# TEST 9: Bulk-scale cleanup (1000 rows per state)
# ============================================================
def test_09_bulk_cleanup():
    print("\n-- 9. Bulk-scale cleanup (1000 rows per state) --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    # Insert 1000 old rows per terminal state
    _bulk_insert(ds, "delivered", 1000, 30, "WH-BULK-D")
    _bulk_insert(ds, "dropped_stale", 1000, 30, "WH-BULK-DS")
    _bulk_insert(ds, "failed_permanent", 1000, 30, "WH-BULK-F")
    # Insert 50 recent
    _bulk_insert(ds, "delivered", 50, 1, "WH-BULK-RECENT")

    before = _count_all(ds)
    record("09a before", sum(before.values()) == 3050,
           f"counts={before}")

    conn = ds._outbox_write_conn()
    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    after = _count_all(ds)
    record("09b after", after.get("delivered", 0) == 50,
           f"counts={after}")
    record("09c deleted count", deleted == 3000,
           f"deleted={deleted}")

# ============================================================
# TEST 10: Stats API only counts recent terminal rows
# ============================================================
def test_10_stats_api_window():
    print("\n-- 10. Stats API respects ops window --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = time.time()

    # Insert old delivered (30 days) and fresh pending
    _bulk_insert(ds, "delivered", 50, 30, "WH-STAT-OLD")
    # Fresh pending
    for i in range(5):
        did = f"WH-STAT-PEND-{i}"
        conn = ds._outbox_write_conn()
        payload = json.dumps({
            "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
            "status": "red", "message": "test", "event_ts": now,
        }, ensure_ascii=False)
        conn.execute(
            "INSERT INTO webhook_outbox "
            "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
            " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
            " delivered_ts, attempt_count, max_attempts, delivery_state, "
            " last_error, created_at, updated_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, "T1", "INC-PEND", 1, "alert_red", "T1",
             payload, now, now, now, now,
             None, 0, 0, "pending", "", now, now))
        conn.commit()

    stats = ds.get_webhook_delivery_stats()

    # pending should be 5 (all fresh)
    record("10a pending=5", stats.get("pending") == 5,
           f"stats={stats}")

    # Old delivered (30 days) should NOT appear in stats
    # because ops cutoff = max 7 days
    record("10b old delivered excluded from stats",
           stats.get("delivered", 0) == 0,
           f"stats={stats}")

# ============================================================
# TEST 11: Delivered with NULL delivered_ts uses updated_at
# ============================================================
def test_11_null_delivered_ts_fallback():
    print("\n-- 11. NULL delivered_ts falls back to updated_at --")
    ds = DataStore(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   webhook_outbox_retention_days=7)
    ds._schema_ready.wait(timeout=5)
    now = int(time.time())

    conn = ds._outbox_write_conn()
    ts_recent = now - 1 * 86400
    ts_old = now - 30 * 86400
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "null_dts", "event_ts": ts_old,
    }, ensure_ascii=False)

    # Row with NULL delivered_ts, old updated_at
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("WH-NULL-DTS-OLD", "T1", "INC-NULL", 1, "alert_red", "T1",
         payload, ts_old, ts_old, ts_old, ts_old,
         None, 1, 0, "delivered", "", ts_old, ts_old))
    # Row with NULL delivered_ts, recent updated_at
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("WH-NULL-DTS-NEW", "T1", "INC-NULL", 1, "alert_red", "T1",
         payload, ts_recent, ts_recent, ts_recent, ts_recent,
         None, 1, 0, "delivered", "", ts_recent, ts_recent))
    conn.commit()

    record("11a before", _count_rows(ds, "delivered") == 2,
           f"delivered={_count_rows(ds, 'delivered')}")

    with conn:
        deleted = ds._cleanup_webhook_outbox(conn, now)

    # Old row (updated_at=30 days ago) deleted; recent row survives
    record("11b old deleted", _count_rows(ds, "delivered") == 1,
           f"remaining delivered={_count_rows(ds, 'delivered')}")

# ============================================================
# Main
# ============================================================
def main():
    print("=" * 72)
    print("Round 6: webhook_outbox Retention / Cleanup Strategy Probe")
    print("=" * 72)

    tests = [
        ("01 pending/sending protected", test_01_pending_sending_protected),
        ("02 old delivered deleted", test_02_old_delivered_deleted),
        ("03 old dropped_stale deleted", test_03_old_dropped_stale_deleted),
        ("04 old failed_permanent deleted", test_04_old_failed_permanent_deleted),
        ("05 delivered uses delivered_ts", test_05_delivered_uses_delivered_ts),
        ("06 config settings", test_06_config_settings),
        ("07 live update retention", test_07_live_update_retention),
        ("08 ops window cap", test_08_ops_window_cap),
        ("09 bulk cleanup", test_09_bulk_cleanup),
        ("10 stats API window", test_10_stats_api_window),
        ("11 null delivered_ts fallback", test_11_null_delivered_ts_fallback),
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
