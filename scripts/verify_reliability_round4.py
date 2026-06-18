"""Round-4 reliability: concurrent outbox enqueue + dispatcher (no sqlite cross-thread)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_dispatch_loop(disp, stop: threading.Event, errors: list, interval=0.02):
    while not stop.is_set():
        try:
            disp._tick()
        except Exception as e:
            errors.append(str(e))
        stop.wait(interval)


def test_main_enqueue_background_dispatch():
    """Equivalent to /tmp/repro_outbox_thread_conn.py expectations."""
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter(
        targets=[{"id": "t1", "label": "GW", "ip": "10.0.0.1"}])
    calls = []
    errors = []
    a._send_webhook = staticmethod(lambda *_a, **_k: calls.append(1))

    a.on_status_change("t1", "GW", "10.0.0.1", "red")

    done = threading.Event()

    def _tick():
        try:
            disp._tick()
        except Exception as e:
            errors.append(str(e))
        finally:
            done.set()

    threading.Thread(target=_tick, daemon=True).start()
    done.wait(timeout=5)

    rows = ds.get_webhook_deliveries(target_id="t1", limit=5)
    ok = (
        not errors
        and calls
        and any(r["delivery_state"] == "delivered" for r in rows)
        and not any("same thread" in e for e in errors)
    )
    print(f"Round4 repro cross-thread dispatch -> {ok} "
          f"calls={len(calls)} errors={errors}")
    return ok


def test_concurrent_enqueue_while_dispatching():
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter(targets=[
        {"id": f"{p}{i}", "label": f"N{p}{i}", "ip": f"10.0.0.{i+1}"}
        for p in ("A", "B", "C") for i in range(4)])
    calls = []
    errors = []
    lock = threading.Lock()
    stop = threading.Event()

    def _send(*_a, **_k):
        with lock:
            calls.append(1)

    a._send_webhook = staticmethod(_send)
    dt = threading.Thread(
        target=_run_dispatch_loop, args=(disp, stop, errors), daemon=True)
    dt.start()

    def _producer(prefix: str, n: int):
        for i in range(n):
            tid = f"{prefix}{i}"
            try:
                a.on_status_change(tid, f"N{tid}", f"10.0.0.{i+1}", "red")
            except Exception as e:
                errors.append(str(e))
            time.sleep(0.005)

    threads = [
        threading.Thread(target=_producer, args=("A", 4), daemon=True),
        threading.Thread(target=_producer, args=("B", 4), daemon=True),
        threading.Thread(target=_producer, args=("C", 4), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    deadline = time.time() + 8
    while time.time() < deadline:
        stats = ds.get_webhook_delivery_stats()
        delivered = stats.get("delivered", 0)
        pending = stats.get("pending", 0) + stats.get("sending", 0)
        if delivered >= 10 and pending == 0:
            break
        time.sleep(0.05)

    stop.set()
    dt.join(timeout=2)

    stats = ds.get_webhook_delivery_stats()
    ok = (
        not any("same thread" in e for e in errors)
        and stats.get("delivered", 0) >= 10
        and len(calls) >= 10
    )
    print(f"Round4 concurrent enqueue+dispatch -> {ok} "
          f"stats={stats} calls={len(calls)} errors={len(errors)}")
    return ok


def test_failed_send_retries_without_sqlite_error():
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter(
        targets=[{"id": "t1", "label": "GW", "ip": "10.0.0.1"}])
    errors = []
    fail_once = {"n": 0}

    def _send(*_a, **_k):
        fail_once["n"] += 1
        if fail_once["n"] == 1:
            raise OSError("connection refused")

    a._send_webhook = staticmethod(_send)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")

    disp._tick()
    row = ds.get_webhook_deliveries(target_id="t1", limit=1)[0]
    ok_retry_pending = (
        row["delivery_state"] == "pending"
        and int(row.get("attempt_count") or 0) >= 1
    )

    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        conn.execute(
            "UPDATE webhook_outbox SET next_attempt_ts=? WHERE target_id='t1'",
            (time.time(),))
        conn.commit()

    try:
        disp._tick()
    except Exception as e:
        errors.append(str(e))

    row2 = ds.get_webhook_deliveries(target_id="t1", limit=1)[0]
    ok = (
        ok_retry_pending
        and row2["delivery_state"] == "delivered"
        and not any("same thread" in e for e in errors)
    )
    print(f"Round4 fail then retry delivered -> {ok} "
          f"after={row2['delivery_state']} attempts={row2.get('attempt_count')}")
    return ok


def test_read_conn_parallel_with_outbox_writes():
    """Read path (_read_conn TLS) while dispatcher writes outbox."""
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter()
    errors = []
    stop = threading.Event()
    dt = threading.Thread(
        target=_run_dispatch_loop, args=(disp, stop, errors), daemon=True)
    dt.start()

    a._send_webhook = staticmethod(lambda *_a, **_k: None)

    def _read_loop():
        for _ in range(50):
            try:
                ds.get_webhook_delivery_stats()
                ds.fetch_deliverable_webhook_outbox(time.time(), limit=10)
            except Exception as e:
                errors.append(str(e))
            time.sleep(0.01)

    rt = threading.Thread(target=_read_loop, daemon=True)
    rt.start()
    for i in range(8):
        a.on_status_change(f"t{i}", f"N{i}", f"10.0.0.{i+1}", "red")
        time.sleep(0.01)

    rt.join(timeout=5)
    stop.set()
    dt.join(timeout=2)

    ok = not any("same thread" in e for e in errors)
    print(f"Round4 parallel read+outbox write -> {ok} errors={len(errors)}")
    return ok


def main():
    results = [
        ("repro", test_main_enqueue_background_dispatch()),
        ("concurrent", test_concurrent_enqueue_while_dispatching()),
        ("retry", test_failed_send_retries_without_sqlite_error()),
        ("read_parallel", test_read_conn_parallel_with_outbox_writes()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All round-4 reliability checks passed.")


if __name__ == "__main__":
    main()
