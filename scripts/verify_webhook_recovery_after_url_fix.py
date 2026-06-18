"""Regression: webhook recovery after URL fix.

When a webhook URL is broken and then corrected:
  - first delivery attempt fails with error recorded
  - second attempt with corrected URL succeeds
  - attempt_count increments correctly
  - delivered_ts is written
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
from scripts.webhook_test_util import patch_connection_refused


class OKHandler(http.server.BaseHTTPRequestHandler):
    """Always returns 200 and captures request body."""
    captured = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        try:
            self.captured.append(json.loads(body))
        except Exception:
            self.captured.append({"_raw": body.decode("utf-8", "replace")})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        data = b'{"ok":true}'
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
        OKHandler.captured.clear()
        for _ in range(20):
            try:
                self._httpd = socketserver.TCPServer(("127.0.0.1", 0), OKHandler)
                break
            except OSError:
                pass
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def _enqueue_one(ds, delivery_id, now):
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "recovery test", "event_ts": now,
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
        "SELECT delivery_state, attempt_count, last_error, delivered_ts "
        "FROM webhook_outbox WHERE delivery_id=?",
        (delivery_id,)).fetchone()
    return {"delivery_state": row[0], "attempt_count": row[1],
            "last_error": row[2], "delivered_ts": row[3]} if row else None


def _make_disp(ds, webhook_url):
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
    return a, disp


def test_recover_after_url_fix():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    # Step 1: bad URL (simulated connection refused, not a fixed local port)
    bad_url = "http://127.0.0.1:1/nonexistent"
    a1, disp1 = _make_disp(ds, bad_url)
    now = time.time()
    _enqueue_one(ds, "DREC", now)
    with patch_connection_refused():
        _deliver_one(disp1, "DREC", now)
    st1 = _row_state(ds, "DREC")
    step1_ok = (st1["delivery_state"] == "pending"
                and st1["attempt_count"] == 1
                and st1["last_error"] != "")
    print(f"  step1 fail with bad URL: {step1_ok}  state={st1}")

    # Step 2: fix URL
    srv = MockServer()
    srv.start()
    a2, disp2 = _make_disp(ds, srv.url)
    # Advance next_attempt_ts so row is due now
    conn = ds._outbox_write_conn()
    conn.execute(
        "UPDATE webhook_outbox SET next_attempt_ts=? WHERE delivery_id=?",
        (time.time(), "DREC"))
    conn.commit()
    _deliver_one(disp2, "DREC", time.time())
    st2 = _row_state(ds, "DREC")
    step2_ok = (st2["delivery_state"] == "delivered"
                and st2["attempt_count"] == 2
                and st2["delivered_ts"] is not None)
    print(f"  step2 deliver with fixed URL: {step2_ok}  state={st2}")

    # Verify delivery_id was included in platform payload
    found_delivery_id = any(
        c.get("delivery_id") == "DREC" or "DREC" in str(c)
        for c in OKHandler.captured
    )
    srv.stop()
    print(f"  delivery_id in captured payload: {found_delivery_id}")
    return step1_ok and step2_ok and found_delivery_id


def main():
    results = [
        ("recover_after_url_fix", test_recover_after_url_fix()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook recovery checks passed.")


if __name__ == "__main__":
    main()
