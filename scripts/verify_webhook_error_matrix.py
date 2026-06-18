"""Regression: webhook error matrix — 500, 429, refused, truncated response.

Verifies that every external error path:
  - does NOT lose the message
  - increments attempt_count
  - records last_error (when retrying)
  - sets next_attempt_ts via backoff (when retrying)
  - does NOT misreport as delivered (except known Windows http.client quirk)
"""
import json
import os
import sys
import tempfile
import threading
import time
import http.server
import socketserver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore
from src.alert_manager import AlertManager
from src.webhook_outbox import WebhookOutboxDispatcher

# ── controllable mock server ──────────────────────────────────────

class ErrorHandler(http.server.BaseHTTPRequestHandler):
    """Returns the status code encoded in the URL path, e.g. /500 -> 500."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        _body = self.rfile.read(length)
        if self.path.startswith("/close"):
            # Content-Length mismatch then socket close — IncompleteRead on Unix.
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 100000\r\n"
                b"\r\n"
                b"truncated-body"
            )
            self.wfile.flush()
            self.connection.close()
            return
        code = 200
        try:
            parts = self.path.lstrip("/").split("/")
            code = int(parts[0])
        except (ValueError, IndexError):
            pass
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        data = b'{"ok":true}' if code < 400 else b'{"error":"simulated"}'
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


class MockServer:
    def __init__(self):
        self._httpd = None
        self._thread = None

    @property
    def url(self):
        p = self._httpd.socket.getsockname()[1] if self._httpd else 0
        return f"http://127.0.0.1:{p}"

    def start(self):
        for _ in range(20):
            try:
                self._httpd = socketserver.TCPServer(("127.0.0.1", 0), ErrorHandler)
                break
            except OSError:
                pass
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


# ── helpers ────────────────────────────────────────────────────────

def _make_fixture(webhook_url):
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    class _Cfg:
        def get_setting(self, k):
            if k == "webhook_url":
                return webhook_url
            return None
        def get_targets(self):
            return [{"id": "t", "label": "t", "ip": "10.0.0.1"}]

    assets = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(assets, "assets")
    a = AlertManager(enabled=False, assets_dir=assets)
    a.set_config(_Cfg())
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    return a, disp, ds


def _enqueue_one(ds, delivery_id, now=None):
    now = now or time.time()
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "test", "event_ts": now,
    })
    conn = ds._outbox_write_conn()
    conn.execute(
        "INSERT INTO webhook_outbox "
        "(delivery_id, target_id, incident_id, incident_seq, event, order_key, "
        " payload_json, event_ts, first_queued_ts, next_attempt_ts, last_attempt_ts, "
        " delivered_ts, attempt_count, max_attempts, delivery_state, "
        " last_error, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (delivery_id, "t", "INC", 1, "alert_red", "t",
         payload, now, now, now, now, None, 0, 0, "pending", "", now, now))
    conn.commit()


def _deliver_one(disp, delivery_id, now):
    """Simulate one delivery attempt for a specific row."""
    ds = disp._am._data_store
    conn = ds._read_conn()
    row = conn.execute(
        "SELECT * FROM webhook_outbox WHERE delivery_id=?", (delivery_id,)
    ).fetchone()
    if not row:
        return
    disp._deliver_one(ds._outbox_row_to_dict(row), now)


def _row_state(ds, delivery_id):
    conn = ds._read_conn()
    row = conn.execute(
        "SELECT delivery_state, attempt_count, last_error, next_attempt_ts "
        "FROM webhook_outbox WHERE delivery_id=?",
        (delivery_id,)).fetchone()
    return {"delivery_state": row[0], "attempt_count": row[1],
            "last_error": row[2], "next_attempt_ts": row[3]} if row else None


# ── tests ──────────────────────────────────────────────────────────

def test_500():
    srv = MockServer()
    srv.start()
    _a, disp, ds = _make_fixture(srv.url + "/500")
    now = time.time()
    _enqueue_one(ds, "D500", now)
    _deliver_one(disp, "D500", now)
    st = _row_state(ds, "D500")
    srv.stop()
    ok = (st["delivery_state"] == "pending"
          and st["attempt_count"] > 0
          and st["last_error"] != ""
          and st["next_attempt_ts"] > now)
    print(f"  HTTP 500 -> pending+backoff: {ok}  state={st}")
    return ok


def test_429():
    srv = MockServer()
    srv.start()
    _a, disp, ds = _make_fixture(srv.url + "/429")
    now = time.time()
    _enqueue_one(ds, "D429", now)
    _deliver_one(disp, "D429", now)
    st = _row_state(ds, "D429")
    srv.stop()
    ok = (st["delivery_state"] == "pending"
          and st["attempt_count"] > 0
          and st["last_error"] != ""
          and st["next_attempt_ts"] > now)
    print(f"  HTTP 429 -> pending+backoff: {ok}  state={st}")
    return ok


def test_refused():
    """Connect to a closed port -> connection refused."""
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    class _Cfg:
        def get_setting(self, k):
            if k == "webhook_url":
                return "http://127.0.0.1:19999/nonexistent"
            return None
        def get_targets(self):
            return [{"id": "t", "label": "t", "ip": "10.0.0.1"}]

    assets = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assets = os.path.join(assets, "assets")
    a = AlertManager(enabled=False, assets_dir=assets)
    a.set_config(_Cfg())
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    now = time.time()
    _enqueue_one(ds, "DREFUSED", now)
    _deliver_one(disp, "DREFUSED", now)
    st = _row_state(ds, "DREFUSED")
    ok = (st["delivery_state"] == "pending"
          and st["attempt_count"] > 0
          and st["last_error"] != "")
    print(f"  connection refused -> pending+error: {ok}  state={st}")
    return ok


def test_truncated_response():
    """Truncated HTTP body must retry as pending, not delivered."""
    srv = MockServer()
    srv.start()
    _a, disp, ds = _make_fixture(srv.url + "/close")
    now = time.time()
    _enqueue_one(ds, "DCLOSE", now)
    _deliver_one(disp, "DCLOSE", now)
    st = _row_state(ds, "DCLOSE")
    srv.stop()

    err = (st["last_error"] or "").lower()
    ok = (
        st["delivery_state"] == "pending"
        and st["attempt_count"] > 0
        and st["next_attempt_ts"] > now
        and any(kw in err for kw in (
            "incomplete", "close", "reset", "shutdown",
            "connection", "eof", "remote", "truncat", "disconnected",
        ))
    )
    print(f"  truncated response -> pending+error: {ok}  state={st}")
    return ok


def main():
    results = [
        ("500", test_500()),
        ("429", test_429()),
        ("refused", test_refused()),
        ("truncated_response", test_truncated_response()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook error matrix checks passed.")


if __name__ == "__main__":
    main()
