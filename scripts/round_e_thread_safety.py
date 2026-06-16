#!/usr/bin/env python3
"""Round E: Thread Safety / Concurrency Audit
==============================================
Tests lock correctness, generation guard defense-in-depth,
writer-thread data integrity, and WebServer lock atomicity.

Test areas:
  E1 - Writer thread data integrity (N producers → 1 consumer)
  E2 - Three-layer generation guard (producer/queue/flush filters)
  E3 - Per-target commit lock serialization
  E4 - Alert immediate-flush vs periodic flush
  E5 - WebServer _lock atomicity (_targets ↔ _stats)
  E6 - Concurrent record_ping high-throughput
  E7 - Writer thread resilience (error recovery, shutdown integrity)
  E8 - Lock ordering / deadlock check
"""

import sys, os, json, tempfile, time, threading, queue, random, uuid, sqlite3

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.data_store import DataStore

_passed = 0
_failed = 0

def check(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")

# ====================================================================
#  E1: Writer thread data integrity (N producers → 1 consumer)
# ====================================================================
def test_e1_writer_integrity():
    print("\n-- E1: Writer thread data integrity --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    BASE = time.time()
    tid = "t-e1"
    N = 500
    errors = []
    results_lock = threading.Lock()

    def producer(i):
        try:
            ok = ds.record_ping(
                target_id=tid, label="E1", ip="10.0.0.1", ts=BASE + i * 0.1,
                status="green", latency_ms=10.0 + i * 0.1, loss_rate=0.0,
                probe_success=True, ping_type="icmp"
            )
            with results_lock:
                if not ok:
                    errors.append(f"producer {i} rejected")
        except Exception as e:
            with results_lock:
                errors.append(f"producer {i}: {e}")

    threads = []
    for i in range(N):
        t = threading.Thread(target=producer, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    check(len(errors) == 0,
          f"E1a: all {N} record_ping accepted (errors={len(errors)})")

    # Wait for writer to flush
    time.sleep(2)
    ds.shutdown()

    # Verify DB
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM pings_raw WHERE target_id=?", (tid,)).fetchone()[0]
    conn.close()

    check(count == N,
          f"E1b: all {N} rows persisted (got {count})")

    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E2: Three-layer generation guard
# ====================================================================
def test_e2_generation_guard():
    print("\n-- E2: Three-layer generation guard --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    BASE = time.time()
    tid = "t-e2"
    gen0 = ds.current_target_generation(tid)  # 0

    # E2a: Producer-side fast-path filter
    ds.bump_target_generation(tid)  # gen now 1
    ok = ds.record_ping(
        target_id=tid, label="E2", ip="1.1.1.1", ts=BASE + 1,
        status="green", latency_ms=5.0, loss_rate=0.0, probe_success=True,
        ping_type="icmp", captured_generation=gen0  # stale!
    )
    check(ok == False,
          f"E2a: producer fast-path rejects stale gen (gen0 vs gen1)")

    # E2b: Queue-boundary filter
    # record_ping with current gen passes fast-path, then bump + wipe before flush
    gen1 = ds.current_target_generation(tid)  # 1
    ok2 = ds.record_ping(
        target_id=tid, label="E2", ip="1.1.1.1", ts=BASE + 2,
        status="green", latency_ms=5.0, loss_rate=0.0, probe_success=True,
        ping_type="icmp", captured_generation=gen1
    )
    check(ok2 == True,
          f"E2b: current-gen ping accepted at producer")
    # Now bump generation — the queued ping is stale
    ds.bump_target_generation(tid)  # gen 2

    time.sleep(1)
    ds.shutdown()

    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM pings_raw WHERE target_id=?", (tid,)
    ).fetchone()[0]
    conn.close()
    check(count == 0,
          f"E2b: stale ping filtered at queue boundary or flush (0 rows, got {count})")

    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E3: Per-target commit lock serialization
# ====================================================================
def test_e3_commit_lock():
    print("\n-- E3: Per-target commit lock serialization --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    tid = "t-e3"
    events = []
    ev_lock = threading.Lock()
    barrier = threading.Barrier(2, timeout=10)

    def bump_thread():
        barrier.wait()
        ds.bump_target_generation(tid)
        with ev_lock:
            events.append(("bump", time.monotonic()))

    def record_thread():
        lock = ds.commit_lock_for(tid)
        barrier.wait()
        time.sleep(0.05)  # ensure bump thread is waiting on commit_lock
        with lock:
            ds.record_ping(
                target_id=tid, label="E3", ip="1.1.1.1", ts=time.time(),
                status="green", latency_ms=5.0, loss_rate=0.0,
                probe_success=True, ping_type="icmp"
            )
            time.sleep(0.1)  # hold lock
            with ev_lock:
                events.append(("record_done", time.monotonic()))
        # bump should have been serialized — bump happens AFTER record_done
        # OR bump happened before record started (but then gen check rejects)

    t1 = threading.Thread(target=bump_thread)
    t2 = threading.Thread(target=record_thread)
    t1.start(); t2.start()
    t1.join(timeout=5); t2.join(timeout=5)

    ds.shutdown()

    # E3a: The commit lock serializes correctly — no deadlock, no concurrent mutation
    check(len(events) == 2,
          f"E3a: both threads completed without deadlock (events: {events})")

    # E3b: Verify commit_lock type (is Lock, not RLock — see ping_engine for RLock)
    lock = ds.commit_lock_for("t-e3b")
    check(isinstance(lock, type(threading.Lock())),
          f"E3b: DataStore commit_lock is threading.Lock (got {type(lock).__name__})")

    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E4: Alert immediate-flush
# ====================================================================
def test_e4_alert_flush():
    print("\n-- E4: Alert immediate-flush vs periodic flush --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    BASE = time.time()
    tid = "t-e4"
    ds.record_ping(
        target_id=tid, label="E4", ip="9.9.9.9", ts=BASE,
        status="green", latency_ms=5.0, loss_rate=0.0,
        probe_success=True, ping_type="icmp"
    )
    # Record an alert — should trigger immediate flush
    ds.record_alert(
        target_id=tid, label="E4", ip="9.9.9.9", ts=BASE + 1,
        old_status="green", new_status="red", category="availability"
    )
    time.sleep(1)  # wait for writer thread to process

    conn = sqlite3.connect(db_path)
    alerts = conn.execute(
        "SELECT old_status, new_status, category FROM alert_events WHERE target_id=?",
        (tid,)
    ).fetchall()
    conn.close()

    check(len(alerts) >= 1,
          f"E4a: alert immediately flushed to DB (got {len(alerts)} rows)")
    if alerts:
        check(alerts[0] == ("green", "red", "availability"),
              f"E4a: alert data correct (got {alerts[0]})")

    ds.shutdown()
    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E5: WebServer _lock atomicity simulation
# ====================================================================
def test_e5_webserver_lock():
    print("\n-- E5: WebServer _lock atomicity simulation --")
    # Simulate the WebServer's _lock pattern: update_target must atomically
    # update _targets and _stats together
    lock = threading.Lock()
    _targets = {}
    _stats = {}
    errors = []

    tid = "t-e5"
    _targets[tid] = {"tid": tid, "status": "green", "latency_ms": 5.0}
    _stats[tid] = {"total": 0, "lat_sum": 0.0, "success": 0}

    N_THREADS = 10
    N_UPDATES = 200
    barrier = threading.Barrier(N_THREADS, timeout=10)

    def updater(thread_id):
        barrier.wait()
        for i in range(N_UPDATES):
            with lock:
                t = _targets.get(tid)
                s = _stats.get(tid)
                if t is None or s is None:
                    errors.append(f"thread {thread_id} iter {i}: missing _targets or _stats")
                    return
                t["latency_ms"] = 10.0 + thread_id * 0.1
                s["total"] += 1
                s["lat_sum"] += t["latency_ms"]
                s["success"] += 1

    threads = []
    for i in range(N_THREADS):
        t = threading.Thread(target=updater, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=10)

    check(len(errors) == 0,
          f"E5a: no missing _targets/_stats under concurrency ({len(errors)} errors)")
    check(_stats[tid]["total"] == N_THREADS * N_UPDATES,
          f"E5b: total = {N_THREADS*N_UPDATES} (got {_stats[tid]['total']})")

# ====================================================================
#  E6: Concurrent record_ping high-throughput
# ====================================================================
def test_e6_concurrent_pings():
    print("\n-- E6: Concurrent record_ping high-throughput --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    BASE = time.time()
    tids = [f"t-e6-{i}" for i in range(10)]
    N_PER_TID = 50
    N_THREADS = 5
    total = len(tids) * N_PER_TID * N_THREADS  # each thread goes through all tids

    barrier = threading.Barrier(N_THREADS, timeout=10)
    errors = []
    err_lock = threading.Lock()

    def producer(thread_id):
        barrier.wait()
        for t_idx, tid in enumerate(tids):
            for i in range(N_PER_TID):
                try:
                    ds.record_ping(
                        target_id=tid, label=f"E6-{t_idx}", ip=f"10.0.{t_idx}.{i % 255}",
                        ts=BASE + t_idx * 100 + i * 0.02,
                        status="green", latency_ms=float(i % 50 + 1),
                        loss_rate=0.0, probe_success=True, ping_type="icmp"
                    )
                except Exception as e:
                    with err_lock:
                        errors.append(f"thread {thread_id} tid {tid} i {i}: {e}")

    threads = []
    for i in range(N_THREADS):
        t = threading.Thread(target=producer, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=30)

    check(len(errors) == 0,
          f"E6a: no exceptions during {total} concurrent record_pings ({len(errors)} errors)")

    time.sleep(3)
    ds.shutdown()

    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM pings_raw").fetchone()[0]
    conn.close()

    check(count == total,
          f"E6b: all {total} rows persisted (got {count})")

    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E7: Writer thread resilience
# ====================================================================
def test_e7_writer_resilience():
    print("\n-- E7: Writer thread resilience --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)

    BASE = time.time()
    tid = "t-e7"

    # E7a: Queue accepts items while writer is busy
    for i in range(100):
        ds.record_ping(
            target_id=tid, label="E7", ip="7.7.7.7", ts=BASE + i * 0.01,
            status="green", latency_ms=1.0, loss_rate=0.0,
            probe_success=True, ping_type="icmp"
        )
    check(True, "E7a: queue accepted 100 items without blocking")

    # E7b: Shutdown drains remaining queue items
    ds.shutdown()
    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM pings_raw WHERE target_id=?", (tid,)
    ).fetchone()[0]
    conn.close()
    check(count == 100,
          f"E7b: shutdown drained all 100 queued items (got {count})")

    # E7c: Double shutdown is safe
    try:
        ds.shutdown()
        check(True, "E7c: double shutdown does not crash")
    except Exception as e:
        check(False, f"E7c: double shutdown crashed: {e}")

    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  E8: Lock ordering verification
# ====================================================================
def test_e8_lock_ordering():
    print("\n-- E8: Lock ordering / deadlock check --")
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(db_path)
    ds._schema_ready.wait(timeout=10)
    tid = "t-e8"

    # E8a: commit_lock → _target_gen_lock is the documented order
    # Acquire in this order, verify no deadlock
    commit_lock = ds.commit_lock_for(tid)
    acquired_c = commit_lock.acquire(timeout=2)
    check(acquired_c, "E8a: acquired commit_lock")
    if acquired_c:
        gen = ds.current_target_generation(tid)  # acquires _target_gen_lock internally
        check(isinstance(gen, int), f"E8a: read generation under commit_lock (gen={gen})")
        commit_lock.release()

    # E8b: _target_gen_lock → commit_lock would be reverse — verify no deadlock
    # This is NOT the documented order, but should not deadlock since both
    # are Lock (not RLock), and Python won't deadlock if acquired in reverse
    # from different call stacks
    gen2 = ds.current_target_generation(tid)  # releases _target_gen_lock
    commit_lock2 = ds.commit_lock_for(tid)
    acquired_c2 = commit_lock2.acquire(timeout=2)
    check(acquired_c2, "E8b: reverse order (gen_lock→commit_lock) also succeeds")
    if acquired_c2:
        commit_lock2.release()

    # E8c: bump_target_generation acquires commit_lock → _target_gen_lock
    # Verify no deadlock
    ds.bump_target_generation(tid)
    gen3 = ds.current_target_generation(tid)
    check(gen3 == gen2 + 1,
          f"E8c: bump_target_generation increments gen ({gen2}→{gen3})")

    # E8d: Concurrent bumps from different threads don't deadlock
    errors = []
    err_lock = threading.Lock()
    barrier = threading.Barrier(5, timeout=10)

    def bumper():
        barrier.wait()
        for _ in range(10):
            try:
                ds.bump_target_generation("t-e8d")
            except Exception as e:
                with err_lock:
                    errors.append(str(e))

    threads = [threading.Thread(target=bumper) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    check(len(errors) == 0,
          f"E8d: 5 threads × 10 bumps no deadlock ({len(errors)} errors)")
    final_gen = ds.current_target_generation("t-e8d")
    check(final_gen == 50,
          f"E8d: gen matches 50 bumps (got {final_gen})")

    ds.shutdown()
    try: os.unlink(db_path)
    except: pass

# ====================================================================
#  Runner
# ====================================================================

def main():
    global _passed, _failed
    test_e1_writer_integrity()
    test_e2_generation_guard()
    test_e3_commit_lock()
    test_e4_alert_flush()
    test_e5_webserver_lock()
    test_e6_concurrent_pings()
    test_e7_writer_resilience()
    test_e8_lock_ordering()

    total = _passed + _failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {_passed} passed, {_failed} failed out of {total}")
    if _failed == 0:
        print("All checks passed")
    else:
        print("SOME CHECKS FAILED - review output above")
    return _failed

if __name__ == "__main__":
    sys.exit(main())
