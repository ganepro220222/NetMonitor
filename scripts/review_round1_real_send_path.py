"""Round 1: Real Send Path & Platform Compatibility Review

Verification targets:
  1. Generic webhook payload — delivery_id, attempt, timestamp fields present
  2. Lark/Feishu payload — msg_type="text", content.text contains delivery_id
  3. WeCom/DingTalk payload — msgtype="text", text.content contains delivery_id
  4. Full outbox lifecycle: pending → sending → delivered on 2xx
  5. 4xx / 5xx → retry (NOT delivered), backoff increments attempt_count
  6. Hostname boundary — path/query/userinfo platform tokens are NOT misdetected
  7. Platform 2xx → delivered state in DB; 4xx/5xx → pending (retry)

Uses a local HTTP server (http.server) as a mock platform endpoint.
"""

import json
import os
import sys
import threading
import time
import urllib.request
import http.server
import socketserver
import tempfile
import uuid

# Ensure project root is on path.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.alert_manager import AlertManager
from src.data_store import DataStore
from src.webhook_outbox import WebhookOutboxDispatcher

# ──────────────────────────────────────────────────────────
#  Local HTTP mock server
# ──────────────────────────────────────────────────────────

class CaptureHandler(http.server.BaseHTTPRequestHandler):
    """Capture every POST body + headers, return controlled status codes."""

    captured: list[dict] = []
    _status_code: int = 200
    _response_body: bytes = b'{"errcode":0,"errmsg":"ok"}'
    _lock = threading.Lock()
    _response_delay: float = 0.0  # simulate latency

    @classmethod
    def configure(cls, status_code: int = 200,
                  response_body: bytes = b'{"errcode":0,"errmsg":"ok"}',
                  delay: float = 0.0):
        with cls._lock:
            cls._status_code = status_code
            cls._response_body = response_body
            cls._response_delay = delay

    @classmethod
    def reset_captured(cls):
        with cls._lock:
            cls.captured.clear()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        with self._lock:
            self.captured.append({
                "path": self.path,
                "headers": dict(self.headers),
                "body_raw": raw_body,
            })
            delay = self._response_delay
            status = self._status_code
            resp_body = self._response_body
        if delay > 0:
            time.sleep(delay)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass  # suppress stderr noise


class MockServer:
    """Manage a local HTTP server lifecycle for webhook tests."""

    def __init__(self):
        self._port = 0
        self._httpd: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def captured(self) -> list[dict]:
        return CaptureHandler.captured

    def configure(self, status_code=200, body=None, delay=0.0):
        resp = (body or json.dumps({"errcode": 0, "errmsg": "ok"})).encode()
        CaptureHandler.configure(status_code=status_code, response_body=resp,
                                 delay=delay)

    def start(self) -> None:
        CaptureHandler.reset_captured()
        # Find a free port
        for port in range(48000, 49000):
            try:
                self._httpd = socketserver.TCPServer(
                    ("127.0.0.1", port), CaptureHandler)
                self._port = port
                break
            except OSError:
                continue
        if self._httpd is None:
            raise RuntimeError("Cannot bind mock server port")
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._thread = None

    def reset_captured(self) -> None:
        CaptureHandler.reset_captured()


# ──────────────────────────────────────────────────────────
#  Payload validators
# ──────────────────────────────────────────────────────────

def _hostname_from_url(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url.strip()).hostname or "").lower()
    except Exception:
        return ""


def check_generic_payload(capture: dict) -> tuple[bool, str]:
    """Validate generic JSON payload has all required fields."""
    try:
        body = json.loads(capture["body_raw"].decode())
    except Exception as e:
        return False, f"JSON parse error: {e}"

    checks = [
        ("event" in body, "missing 'event' field"),
        (body.get("event") in ("alert_red", "recovery",
         "alert_reminder", "alert_reminder_aggregate",
         "diagnostic_update", "incident_closed_summary"),
         f"unknown event: {body.get('event')}"),
        ("target" in body, "missing 'target' field"),
        ("ip" in body, "missing 'ip' field"),
        ("status" in body, "missing 'status' field"),
        ("message" in body, "missing 'message' field"),
        ("timestamp" in body, "missing 'timestamp' field"),
        ("delivery_id" in body, "missing 'delivery_id' field"),
        (body.get("delivery_id", "").startswith("WH-"),
         f"delivery_id format wrong: {body.get('delivery_id')}"),
        ("attempt" in body, "missing 'attempt' field"),
        (isinstance(body.get("attempt"), int) and body["attempt"] >= 1,
         f"attempt should be int >= 1, got {body.get('attempt')}"),
        ("msg_type" not in body, "generic should NOT have msg_type"),
        ("msgtype" not in body, "generic should NOT have msgtype"),
        (body.get("target") != "",
         "target should not be empty"),
    ]
    for ok, reason in checks:
        if not ok:
            return False, reason
    return True, "ok"


def check_lark_payload(capture: dict) -> tuple[bool, str]:
    """Validate Lark/Feishu payload structure."""
    try:
        body = json.loads(capture["body_raw"].decode())
    except Exception as e:
        return False, f"JSON parse error: {e}"

    if body.get("msg_type") != "text":
        return False, f"Lark msg_type should be 'text', got {body.get('msg_type')}"
    content = body.get("content")
    if not isinstance(content, dict):
        return False, f"Lark content should be dict, got {type(content)}"
    text = content.get("text", "")
    if not isinstance(text, str) or len(text) == 0:
        return False, "Lark content.text missing or empty"
    if "投递ID：" not in text:
        return False, f"Lark text missing delivery_id: {text[:80]}..."
    if "event" in body:
        return False, "Lark payload should NOT have top-level 'event'"
    if "delivery_id" in body:
        return False, "Lark payload should NOT have top-level 'delivery_id' (in text only)"
    return True, "ok"


def check_wecom_payload(capture: dict) -> tuple[bool, str]:
    """Validate WeCom/DingTalk payload structure."""
    try:
        body = json.loads(capture["body_raw"].decode())
    except Exception as e:
        return False, f"JSON parse error: {e}"

    if body.get("msgtype") != "text":
        return False, f"WeCom msgtype should be 'text', got {body.get('msgtype')}"
    text_block = body.get("text")
    if not isinstance(text_block, dict):
        return False, f"WeCom text should be dict, got {type(text_block)}"
    content = text_block.get("content", "")
    if not isinstance(content, str) or len(content) == 0:
        return False, "WeCom text.content missing or empty"
    if "投递ID：" not in content:
        return False, f"WeCom text missing delivery_id: {content[:80]}..."
    if "event" in body:
        return False, "WeCom payload should NOT have top-level 'event'"
    if "delivery_id" in body:
        return False, "WeCom payload should NOT have top-level 'delivery_id' (in text only)"
    return True, "ok"


def check_text_timing_fields(text: str) -> tuple[bool, str]:
    """Verify timing fields are present in platform text."""
    checks = [
        ("消息生成：" in text, "missing '消息生成'"),
        ("入队时间：" in text, "missing '入队时间'"),
        ("发送时间：" in text, "missing '发送时间'"),
    ]
    for ok, reason in checks:
        if not ok:
            return False, reason
    return True, "ok"


# ──────────────────────────────────────────────────────────
#  Test helpers
# ──────────────────────────────────────────────────────────

def make_test_alerter(mock_url: str):
    """Create AlertManager + DataStore + dispatcher wired to mock server."""
    td = tempfile.mkdtemp()
    db_path = os.path.join(td, f"t-{uuid.uuid4().hex[:8]}.db")
    ds = DataStore(db_path=db_path)
    ds._schema_ready.wait(timeout=10)

    class _Cfg:
        def get_setting(self, k):
            return {"webhook_url": mock_url}.get(k)

        def get_targets(self):
            return [{"id": "t", "label": "GW", "ip": "10.0.0.1"}]

    assets_dir = os.path.join(ROOT, "assets")
    a = AlertManager(enabled=False, assets_dir=assets_dir)
    a.set_config(_Cfg())
    a.set_data_store(ds)
    disp = WebhookOutboxDispatcher(a)
    a.set_outbox_dispatcher(disp)
    return a, disp, ds


def get_outbox_row(ds, delivery_id: str) -> dict:
    rows = ds.get_webhook_deliveries(limit=50)
    return next((r for r in rows if r["delivery_id"] == delivery_id), {})


# ──────────────────────────────────────────────────────────
#  Test cases
# ──────────────────────────────────────────────────────────

_results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = ""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}{' — ' + detail if detail else ''}")


# ── 1. Generic payload direct send ────────────────────────

def test_01_generic_payload_direct_send(server: MockServer):
    """Direct _send_webhook to a generic URL → capture JSON payload."""
    print("\n── 1. Generic payload (direct send) ──")
    server.configure(status_code=200)
    server.reset_captured()

    a, _, _ = make_test_alerter(server.base_url)
    # Monkey-patch the HTTP commit to capture but allow realistic flow
    captured_raw = []

    def _fake_commit(req, *, delivery_id="", gate=None, timeout=10):
        try:
            data = req.data
            captured_raw.append(json.loads(data.decode()))
        except Exception:
            pass
        # Actually send to mock server (to verify HTTP path works)
        with urllib.request.urlopen(req, timeout=10):
            pass

    a._commit_outbox_webhook_http = _fake_commit
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    a._send_webhook(
        server.base_url, "alert_red", "测试网关", "10.0.0.1", "red",
        "连接中断测试", "2026-06-18 10:00:00",
        extra={"incident": {"started_at": "2026-06-18 09:55:00"}},
        event_ts=time.time(), queued_ts=time.time() - 10,
        sent_ts=time.time(), attempt=1,
        delivery_id="WH-TEST0000000001", gate=None,
    )

    # Check HTTP was received
    if not server.captured:
        record("01a HTTP received", False, "no request captured")
        return

    # Check generic payload
    ok, reason = check_generic_payload(server.captured[0])
    record("01a generic payload schema", ok, reason)

    body = json.loads(server.captured[0]["body_raw"].decode())
    record("01b delivery_id in generic JSON", body.get("delivery_id") == "WH-TEST0000000001")
    record("01c attempt in generic JSON", body.get("attempt") == 1)
    record("01d target field", body.get("target") == "测试网关")
    record("01e status field", body.get("status") == "red")
    record("01f extra incident propagated", "incident" in body)

    # Check capture worked
    if captured_raw:
        record("01g capture hook worked", "delivery_id" in captured_raw[0])


# ── 2. Lark/Feishu payload ────────────────────────────────

def _install_mock_hostname_detection(a, lark=False, wecom=False):
    """Mock _is_lark_feishu_webhook_url / _is_wecom_dingtalk_webhook_url
    so we can use 127.0.0.1 URLs but test platform payload construction."""
    orig_lark = a._is_lark_feishu_webhook_url
    orig_wecom = a._is_wecom_dingtalk_webhook_url

    def mock_lark(url):
        return lark

    def mock_wecom(url):
        return wecom

    a._is_lark_feishu_webhook_url = staticmethod(mock_lark)
    a._is_wecom_dingtalk_webhook_url = staticmethod(mock_wecom)
    return orig_lark, orig_wecom


def _restore_hostname_detection(a, orig_lark, orig_wecom):
    a._is_lark_feishu_webhook_url = staticmethod(orig_lark)
    a._is_wecom_dingtalk_webhook_url = staticmethod(orig_wecom)


def test_02_lark_payload(server: MockServer):
    """_send_webhook with Lark detection → verify msg_type=text, content.text."""
    print("\n── 2. Lark/Feishu payload ──")
    server.configure(status_code=200)
    server.reset_captured()

    a, _, _ = make_test_alerter(server.base_url)
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    def _fake_commit(req, *, delivery_id="", gate=None, timeout=10):
        with urllib.request.urlopen(req, timeout=10):
            pass
    a._commit_outbox_webhook_http = _fake_commit

    orig_lark, orig_wecom = _install_mock_hostname_detection(a, lark=True, wecom=False)

    # Use 127.0.0.1 but tell the platform detector it's Lark
    url = f"{server.base_url}/hook"
    server.reset_captured()
    a._send_webhook(
        url, "alert_red", "GW", "10.0.0.1", "red",
        "连接中断", "ts",
        extra={},
        event_ts=time.time(), queued_ts=time.time() - 5,
        sent_ts=time.time(), attempt=1,
        delivery_id="WH-LARK-TEST-001", gate=None,
    )

    _restore_hostname_detection(a, orig_lark, orig_wecom)

    if not server.captured:
        record("02a Lark received", False, "no request captured")
        return
    ok, reason = check_lark_payload(server.captured[0])
    record("02a Lark payload schema", ok, reason)
    body = json.loads(server.captured[0]["body_raw"].decode())
    text = body.get("content", {}).get("text", "")
    tok, trea = check_text_timing_fields(text)
    record("02b Lark timing fields", tok, trea)
    record("02c delivery_id in Lark text",
           "投递ID：WH-LARK-TEST-001" in text)

    # Also verify attempt > 1 shows in text
    server.reset_captured()
    _install_mock_hostname_detection(a, lark=True, wecom=False)
    a._send_webhook(
        url, "alert_red", "GW", "10.0.0.1", "red",
        "重试测试", "ts",
        extra={},
        event_ts=time.time(), queued_ts=time.time() - 30,
        sent_ts=time.time(), attempt=3,
        delivery_id="WH-LARK-RETRY-001", gate=None,
    )
    _restore_hostname_detection(a, orig_lark, orig_wecom)
    body2 = json.loads(server.captured[0]["body_raw"].decode())
    txt2 = body2.get("content", {}).get("text", "")
    record("02d attempt>1 reflected in Lark text",
           "第 3 次尝试" in txt2 or "第3次尝试" in txt2,
           f"text snippet: {txt2[-120:]}")


# ── 3. WeCom/DingTalk payload ─────────────────────────────

def test_03_wecom_payload(server: MockServer):
    """_send_webhook with WeCom detection → verify msgtype=text."""
    print("\n── 3. WeCom/DingTalk payload ──")
    server.configure(status_code=200)
    server.reset_captured()

    a, _, _ = make_test_alerter(server.base_url)
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    def _fake_commit(req, *, delivery_id="", gate=None, timeout=10):
        with urllib.request.urlopen(req, timeout=10):
            pass
    a._commit_outbox_webhook_http = _fake_commit

    orig_lark, orig_wecom = _install_mock_hostname_detection(a, lark=False, wecom=True)

    url = f"{server.base_url}/hook"
    server.reset_captured()
    a._send_webhook(
        url, "alert_red", "GW", "10.0.0.1", "red",
        "连接中断", "ts",
        extra={},
        event_ts=time.time(), queued_ts=time.time() - 5,
        sent_ts=time.time(), attempt=1,
        delivery_id="WH-WECOM-TEST-001", gate=None,
    )

    _restore_hostname_detection(a, orig_lark, orig_wecom)

    if not server.captured:
        record("03a WeCom received", False, "no request captured")
        return
    ok, reason = check_wecom_payload(server.captured[0])
    record("03a WeCom payload schema", ok, reason)
    body = json.loads(server.captured[0]["body_raw"].decode())
    text = body.get("text", {}).get("content", "")
    tok, trea = check_text_timing_fields(text)
    record("03b WeCom timing fields", tok, trea)
    record("03c delivery_id in WeCom text",
           "投递ID：WH-WECOM-TEST-001" in text)


# ── 4. Hostname boundary (negative tests) ─────────────────

def test_04_hostname_boundary(server: MockServer):
    """Ensure path/query/userinfo tokens are NOT misdetected as platform."""
    print("\n── 4. Hostname boundary (negative) ──")
    server.configure(status_code=200)

    a, _, _ = make_test_alerter(server.base_url)
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    def _fake_commit(req, *, delivery_id="", gate=None, timeout=10):
        with urllib.request.urlopen(req, timeout=10):
            pass
    a._commit_outbox_webhook_http = _fake_commit

    # Ensure allowlists are set to real values (not overridden by previous tests)
    a._LARK_FEISHU_WEBHOOK_HOSTS = AlertManager._LARK_FEISHU_WEBHOOK_HOSTS
    a._WECOM_DINGTALK_WEBHOOK_HOSTS = AlertManager._WECOM_DINGTALK_WEBHOOK_HOSTS

    negative_cases = [
        ("path-larksuite", f"http://127.0.0.1:{server._port}/open.larksuite.com/hook"),
        ("path-feishu", f"http://127.0.0.1:{server._port}/feishu/status"),
        ("path-dingtalk", f"http://127.0.0.1:{server._port}/dingtalk/status"),
        ("query-feishu", f"http://127.0.0.1:{server._port}/hook?feishu=1"),
        ("query-oapi", f"http://127.0.0.1:{server._port}/hook?oapi=dingtalk"),
    ]
    for name, url in negative_cases:
        server.reset_captured()
        try:
            a._send_webhook(
                url, "alert_red", "GW", "10.0.0.1", "red",
                "test", "ts", {},
                event_ts=1, queued_ts=2, sent_ts=3, attempt=1,
                delivery_id=f"WH-BOUND-{name[:4].upper()}", gate=None,
            )
        except Exception as e:
            record(f"04a {name}", False, f"unexpected error: {e}")
            continue
        if not server.captured:
            record(f"04a {name}", False, "no request")
            continue
        kind = _payload_kind_from_capture(server.captured[0])
        ok = kind == "generic"
        record(f"04a {name}", ok, f"expected=generic got={kind}")


def _payload_kind_from_capture(capture: dict) -> str:
    try:
        body = json.loads(capture["body_raw"].decode())
    except Exception:
        return "parse_error"
    if body.get("msg_type") == "text":
        return "lark"
    if body.get("msgtype") == "text":
        return "wecom"
    if body.get("event") and body.get("delivery_id"):
        return "generic"
    return "unknown"


# ── 5. Full outbox lifecycle: 2xx success ─────────────────

def test_05_outbox_lifecycle_2xx(server: MockServer):
    """Full outbox flow: enqueue → claim → send → delivered on 2xx."""
    print("\n── 5. Outbox lifecycle (2xx → delivered) ──")
    server.configure(status_code=200, body='{"errcode":0,"errmsg":"ok"}')
    server.reset_captured()

    a, disp, ds = make_test_alerter(server.base_url)

    # Set up incident state so gate passes
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    now = time.time()
    a.direct_enqueue_test_webhook(
        delivery_id="WH-OUTBOX-2XX-01", target_id="t", incident_id="INC",
        incident_seq=1, event="alert_red", order_key="t",
        target_label="GW", ip="10.0.0.1",
        event_ts=now, gate=("alert_red", "t", 1),
    )

    # Run the dispatcher tick
    disp._tick()

    # Check outbox state
    row = get_outbox_row(ds, "WH-OUTBOX-2XX-01")
    state = row.get("delivery_state", "")
    last_error = row.get("last_error", "")
    attempt = row.get("attempt_count", 0)

    record("05a state=delivered", state == "delivered",
           f"got state={state} error={last_error!r}")
    record("05b attempt_count=1", attempt == 1, f"got attempt={attempt}")
    record("05c no last_error", last_error in ("", None),
           f"got error={last_error!r}")
    record("05d delivered_ts set", row.get("delivered_ts") is not None)
    record("05e HTTP request received", len(server.captured) == 1,
           f"got {len(server.captured)} requests")

    # Verify the sent payload
    if server.captured:
        body = json.loads(server.captured[0]["body_raw"].decode())
        record("05f payload has delivery_id",
               body.get("delivery_id") == "WH-OUTBOX-2XX-01")


# ── 6. Outbox lifecycle: 4xx → retry ──────────────────────

def test_06_outbox_lifecycle_4xx(server: MockServer):
    """Outbox with 4xx response → should retry (NOT delivered)."""
    print("\n── 6. Outbox lifecycle (4xx → retry) ──")
    server.configure(status_code=400, body='{"errcode":400,"errmsg":"bad"}')
    server.reset_captured()

    a, disp, ds = make_test_alerter(server.base_url)
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    now = time.time()
    a.direct_enqueue_test_webhook(
        delivery_id="WH-OUTBOX-4XX-01", target_id="t", incident_id="INC4",
        incident_seq=1, event="alert_red", order_key="t",
        target_label="GW", ip="10.0.0.1",
        event_ts=now, gate=("alert_red", "t", 1),
    )

    disp._tick()

    row = get_outbox_row(ds, "WH-OUTBOX-4XX-01")
    state = row.get("delivery_state", "")
    last_error = row.get("last_error", "")
    attempt = row.get("attempt_count", 0)

    record("06a state != delivered", state != "delivered",
           f"got state={state}")
    record("06b state is pending (retry)", state == "pending",
           f"got state={state}")
    record("06c attempt_count incremented", attempt > 0,
           f"got attempt={attempt}")
    record("06d has last_error", bool(last_error),
           f"error={last_error[:60] if last_error else 'N/A'}")
    record("06e next_attempt_ts set", row.get("next_attempt_ts") is not None)
    record("06f HTTP request was sent", len(server.captured) >= 1,
           f"got {len(server.captured)}")


# ── 7. Outbox lifecycle: 5xx → retry ──────────────────────

def test_07_outbox_lifecycle_5xx(server: MockServer):
    """Outbox with 5xx response → should retry (NOT delivered)."""
    print("\n── 7. Outbox lifecycle (5xx → retry) ──")
    server.configure(status_code=500, body='{"errcode":500}')
    server.reset_captured()

    a, disp, ds = make_test_alerter(server.base_url)
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    now = time.time()
    a.direct_enqueue_test_webhook(
        delivery_id="WH-OUTBOX-5XX-01", target_id="t", incident_id="INC5",
        incident_seq=1, event="alert_red", order_key="t",
        target_label="GW", ip="10.0.0.1",
        event_ts=now, gate=("alert_red", "t", 1),
    )

    disp._tick()

    row = get_outbox_row(ds, "WH-OUTBOX-5XX-01")
    state = row.get("delivery_state", "")

    record("07a state != delivered", state != "delivered",
           f"got state={state}")
    record("07b state is pending (retry)", state == "pending",
           f"got state={state}")
    record("07c HTTP request sent", len(server.captured) >= 1)


# ── 8. Platform 200 but errcode != 0 (product policy) ─────

def test_08_platform_200_but_errcode_nonzero(server: MockServer):
    """Platform returns HTTP 200 but errcode != 0 — current code treats as success."""
    print("\n── 8. Platform HTTP 200 with errcode!=0 (product policy note) ──")
    server.configure(status_code=200,
                     body='{"errcode":93000,"errmsg":"invalid token"}')
    server.reset_captured()

    a, disp, ds = make_test_alerter(server.base_url)
    with a._webhook_incident_lock:
        a._webhook_valid_seq["t"] = 1

    now = time.time()
    a.direct_enqueue_test_webhook(
        delivery_id="WH-POLICY-200-01", target_id="t", incident_id="INCP",
        incident_seq=1, event="alert_red", order_key="t",
        target_label="GW", ip="10.0.0.1",
        event_ts=now, gate=("alert_red", "t", 1),
    )

    disp._tick()

    row = get_outbox_row(ds, "WH-POLICY-200-01")
    state = row.get("delivery_state", "")

    # Current behavior: HTTP 200 → delivered (does not inspect body)
    record("08a HTTP 200 → delivered (current behavior)",
           state == "delivered",
           f"state={state} — NOTE: code treats HTTP 200 as success "
           f"regardless of body errcode")


# ── 9. Multiple event types ───────────────────────────────

def test_09_all_event_types_generic(server: MockServer):
    """Verify all 6 event types produce correct generic payloads."""
    print("\n── 9. All event types (generic payload) ──")
    server.configure(status_code=200)

    a, _, _ = make_test_alerter(server.base_url)
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    def _fake_commit(req, *, delivery_id="", gate=None, timeout=10):
        with urllib.request.urlopen(req, timeout=10):
            pass
    a._commit_outbox_webhook_http = _fake_commit

    events = [
        ("alert_red", "red", "连接中断"),
        ("recovery", "green", "已恢复"),
        ("alert_reminder", "red", "仍未恢复"),
        ("alert_reminder_aggregate", "red", "汇总"),
        ("diagnostic_update", "orange", "诊断更新"),
        ("incident_closed_summary", "green", "闭环总结"),
    ]
    for evt, st, msg in events:
        server.reset_captured()
        a._send_webhook(
            server.base_url, evt, "GW", "10.0.0.1", st, msg,
            "2026-06-18 10:00:00",
            extra={"incident": {"started_at": "2026-06-18 09:00:00"}},
            event_ts=time.time(), queued_ts=time.time() - 5,
            sent_ts=time.time(), attempt=1,
            delivery_id=f"WH-EVT-{evt[:8].upper()}", gate=None,
        )
        ok, reason = check_generic_payload(server.captured[0])
        record(f"09a {evt}", ok, reason)


# ──────────────────────────────────────────────────────────
#  Helper: direct enqueue bypass (avoids full incident setup)
# ──────────────────────────────────────────────────────────

def _add_direct_enqueue(AlertManager):
    """Monkey-patch a helper method for direct outbox enqueue tests."""
    def direct_enqueue_test_webhook(
            self, *, delivery_id, target_id, incident_id, incident_seq,
            event, order_key, target_label, ip,
            event_ts, gate=None):
        payload = {
            "event": event,
            "target": target_label,
            "ip": ip,
            "status": "red" if event == "alert_red" else "green",
            "message": "test message",
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
            max_attempts=0,
        )
    AlertManager.direct_enqueue_test_webhook = direct_enqueue_test_webhook


# ──────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("Round 1: Real Send Path & Platform Compatibility Review")
    print("=" * 64)

    _add_direct_enqueue(AlertManager)

    server = MockServer()
    server.start()
    print(f"Mock server started on {server.base_url}")

    try:
        test_01_generic_payload_direct_send(server)
        test_02_lark_payload(server)
        test_03_wecom_payload(server)
        test_04_hostname_boundary(server)
        test_05_outbox_lifecycle_2xx(server)
        test_06_outbox_lifecycle_4xx(server)
        test_07_outbox_lifecycle_5xx(server)
        test_08_platform_200_but_errcode_nonzero(server)
        test_09_all_event_types_generic(server)
    finally:
        server.stop()

    # ── Summary ──
    total = len(_results)
    passed = sum(1 for _, ok, _ in _results if ok)
    failed_records = [(n, d) for n, ok, d in _results if not ok]

    print(f"\n{'=' * 64}")
    print(f"SUMMARY: {passed}/{total} passed")
    if failed_records:
        print("FAILURES:")
        for name, detail in failed_records:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
