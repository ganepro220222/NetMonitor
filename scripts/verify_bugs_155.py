"""Regression: /api/alerts/ack rejects non-object JSON with 400, not 500 (Bug 155)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")


def _ack_client():
    from src.web_server import WebServer, FLASK_AVAILABLE

    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not available")
    ws = WebServer(port=0)
    ws.set_alert_ack_callback(lambda tid: True)
    return ws._app.test_client()


def _post_ack(client, payload):
    if isinstance(payload, str):
        data = payload
        content_type = "application/json"
    else:
        data = json.dumps(payload)
        content_type = "application/json"
    return client.post(
        "/api/alerts/ack",
        data=data,
        content_type=content_type,
    )


def test_non_object_json_returns_400_not_500():
    client = _ack_client()
    cases = [
        ["not-object"],
        123,
        "x",
        True,
    ]
    ok = True
    for payload in cases:
        r = _post_ack(client, payload)
        body = json.loads(r.get_data())
        if r.status_code != 400 or body.get("error") != "tid_required":
            ok = False
            print(f"Bug155 payload={payload!r} -> {r.status_code} {body}")
    print(f"Bug155 non-object JSON -> 400 tid_required -> {ok}")
    return ok


def test_valid_tid_still_acknowledges():
    client = _ack_client()
    r = _post_ack(client, {"tid": "t1"})
    body = json.loads(r.get_data())
    ok = r.status_code == 200 and body.get("ok") is True
    print(f"Bug155 valid object ack -> {ok}")
    return ok


def test_not_configured_returns_503():
    from src.web_server import WebServer, FLASK_AVAILABLE

    if not FLASK_AVAILABLE:
        return True
    ws = WebServer(port=0)
    with ws._app.test_client() as client:
        r = client.post(
            "/api/alerts/ack",
            data=json.dumps({"tid": "t1"}),
            content_type="application/json",
        )
    body = json.loads(r.get_data())
    ok = r.status_code == 503 and body.get("error") == "not_configured"
    print(f"Bug155 not configured -> 503 -> {ok}")
    return ok


def test_source_isinstance_guard():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("def api_alerts_ack", 1)[1].split(
            "@app.route", 1)[0]
    ok = "if not isinstance(body, dict):" in block
    print(f"Bug155 source isinstance guard -> {ok}")
    return ok


def main():
    results = [
        ("non_object", test_non_object_json_returns_400_not_500()),
        ("valid", test_valid_tid_still_acknowledges()),
        ("not_cfg", test_not_configured_returns_503()),
        ("source", test_source_isinstance_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 155 checks passed.")


if __name__ == "__main__":
    main()
