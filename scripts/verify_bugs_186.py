"""Regression: platform webhook URL detection must match hostname only (Bug186)."""
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


def _is_generic(body):
    return (
        body.get("event") == "alert_red"
        and body.get("delivery_id") == "DID"
        and body.get("attempt") == 1
        and "msg_type" not in body
        and "msgtype" not in body
    )


def test_unrelated_false_positives():
    from scripts.webhook_test_util import make_alerter
    cases = [
        ("larksuite path",
         "https://example.com/open.larksuite.com/open-apis/bot/v2/hook/TEST"),
        ("feishu path", "https://example.com/feishu/status"),
        ("dingtalk path", "https://example.com/dingtalk/status"),
        ("oapi host", "https://not-oapi-example.invalid/hook"),
        ("query feishu", "https://example.com/hook?feishu=1&larksuite=2"),
    ]
    ok = True
    for name, url in cases:
        a, _, _ = make_alerter()
        bodies = _capture_send(a)
        _send(a, url)
        case_ok = len(bodies) == 1 and _is_generic(bodies[0])
        ok = ok and case_ok
        print(
            f"  unrelated {name} -> {case_ok} "
            f"payload_keys={list(bodies[0].keys()) if bodies else []}")
    print(f"Bug186 unrelated false positives -> {ok}")
    return ok


def test_real_platform_hosts():
    from scripts.webhook_test_util import make_alerter
    cases = [
        ("feishu", "https://open.feishu.cn/open-apis/bot/v2/hook/x", "lark"),
        ("larksuite", "https://open.larksuite.com/open-apis/bot/v2/hook/x", "lark"),
        ("wecom", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?k=1", "wecom"),
        ("dingtalk", "https://oapi.dingtalk.com/robot/send?access_token=x", "wecom"),
        ("feishu upper host",
         "https://OPEN.FEISHU.CN/open-apis/bot/v2/hook/x", "lark"),
    ]
    ok = True
    for name, url, kind in cases:
        a, _, _ = make_alerter()
        bodies = _capture_send(a)
        _send(a, url)
        if kind == "lark":
            case_ok = bodies and bodies[0].get("msg_type") == "text"
        else:
            case_ok = bodies and bodies[0].get("msgtype") == "text"
        ok = ok and case_ok
        print(f"  real host {name} -> {case_ok}")
    print(f"Bug186 real platform hosts -> {ok}")
    return ok


def main():
    results = [
        ("false_positives", test_unrelated_false_positives()),
        ("real_hosts", test_real_platform_hosts()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 186 checks passed.")


if __name__ == "__main__":
    main()
