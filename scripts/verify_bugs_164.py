"""Regression: outbox dispatcher uses per-thread sqlite write conn (Bug 164)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")


def test_enqueue_main_thread_dispatch_background():
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter()
    calls = []
    errors = []

    def _send(*_a, **_k):
        calls.append(1)

    a._send_webhook = staticmethod(_send)
    a.on_status_change("t1", "GW", "10.0.0.1", "red")

    tick_done = threading.Event()

    def _run_tick():
        try:
            disp._tick()
        except Exception as e:
            errors.append(str(e))
        finally:
            tick_done.set()

    t = threading.Thread(target=_run_tick, daemon=True)
    t.start()
    tick_done.wait(timeout=5)

    rows = ds.get_webhook_deliveries(target_id="t1", limit=5)
    states = [
        (r["event"], r["delivery_state"], r.get("attempt_count"), r.get("last_error"))
        for r in rows
    ]
    ok = (
        not errors
        and calls
        and any(r["delivery_state"] == "delivered" for r in rows)
    )
    print(
        f"Bug164 cross-thread outbox dispatch -> {ok} "
        f"errors={errors} calls={len(calls)} states={states}"
    )
    return ok


def test_outbox_conn_is_thread_local():
    from scripts.webhook_test_util import make_alerter

    a, disp, ds = make_alerter()
    main_conn = None
    bg_conn = None
    done = threading.Event()

    def _bg():
        nonlocal bg_conn
        with ds._outbox_lock:
            bg_conn = ds._outbox_write_conn()
        done.set()

    with ds._outbox_lock:
        main_conn = ds._outbox_write_conn()
    t = threading.Thread(target=_bg, daemon=True)
    t.start()
    done.wait(timeout=5)
    ok = main_conn is not None and bg_conn is not None and main_conn is not bg_conn
    print(f"Bug164 per-thread outbox conn -> {ok}")
    return ok


def test_source_thread_local_outbox_conn():
    with open(DATA_STORE, encoding="utf-8") as f:
        src = f.read()
    fn = src.split("def _outbox_write_conn", 1)[1].split(
        "def enqueue_webhook_outbox", 1)[0]
    ok = (
        "_outbox_tls" in src
        and "check_same_thread=False" in fn
        and "_outbox_conn = None" not in src
    )
    print(f"Bug164 source thread-local outbox conn -> {ok}")
    return ok


def main():
    results = [
        ("dispatch", test_enqueue_main_thread_dispatch_background()),
        ("thread_local", test_outbox_conn_is_thread_local()),
        ("source", test_source_thread_local_outbox_conn()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 164 checks passed.")


if __name__ == "__main__":
    main()
