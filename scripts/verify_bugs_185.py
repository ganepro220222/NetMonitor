"""Regression: Lark international webhook URLs use Feishu/Lark text payload."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _capture_send(a):
    bodies = []
    a.assert_outbox_webhook_send_allowed = lambda **kw: None

    def _commit(req, *, delivery_id="", gate=None, timeout=10):
        bodies.append(json.loads(req.data.decode()))

    a._commit_outbox_webhook_http = _commit
    return bodies


def _send(a, url):
    a._send_webhook(
        url,
        "alert_red",
        "GW",
        "10.0.0.1",
        "red",
        "msg",
        "ts",
        {},
        event_ts=1,
        queued_ts=2,
        sent_ts=3,
        attempt=1,
        delivery_id="DID",
        gate=None,
    )


def test_feishu_url():
    from scripts.webhook_test_util import make_alerter
    a, _, _ = make_alerter()
    bodies = _capture_send(a)
    _send(a, "https://open.feishu.cn/open-apis/bot/v2/hook/x")
    ok = (
        len(bodies) == 1
        and bodies[0].get("msg_type") == "text"
        and isinstance(bodies[0].get("content"), dict)
        and "text" in bodies[0]["content"]
    )
    print(f"Bug185 feishu url -> {ok} payload_keys={list(bodies[0].keys()) if bodies else []}")
    return ok


def test_larksuite_url():
    from scripts.webhook_test_util import make_alerter
    a, _, _ = make_alerter()
    bodies = _capture_send(a)
    _send(a, "https://open.larksuite.com/open-apis/bot/v2/hook/TEST")
    ok = (
        len(bodies) == 1
        and bodies[0].get("msg_type") == "text"
        and isinstance(bodies[0].get("content"), dict)
        and "text" in bodies[0]["content"]
        and "event" not in bodies[0]
    )
    print(
        f"Bug185 larksuite url -> {ok} "
        f"payload_keys={list(bodies[0].keys()) if bodies else []}")
    return ok


def test_generic_url():
    from scripts.webhook_test_util import make_alerter
    a, _, _ = make_alerter()
    bodies = _capture_send(a)
    _send(a, "https://example.com/hook")
    ok = (
        len(bodies) == 1
        and bodies[0].get("event") == "alert_red"
        and bodies[0].get("delivery_id") == "DID"
        and "msg_type" not in bodies[0]
    )
    print(f"Bug185 generic url -> {ok} payload_keys={list(bodies[0].keys()) if bodies else []}")
    return ok


def main():
    results = [
        ("feishu", test_feishu_url()),
        ("larksuite", test_larksuite_url()),
        ("generic", test_generic_url()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 185 checks passed.")


if __name__ == "__main__":
    main()
