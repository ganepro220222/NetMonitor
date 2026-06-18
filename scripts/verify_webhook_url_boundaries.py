"""Regression: webhook platform URL hostname allowlist boundary cases.

Uses urlparse(hostname) exact allowlist matching — do not revert to full-URL
substring or broad suffix rules when adding platform domains.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager

# When adding a hostname to the allowlists below, also extend these templates.
_LARK_FEISHU_ALLOWED_HOSTS = tuple(AlertManager._LARK_FEISHU_WEBHOOK_HOSTS)
_WECOM_DINGTALK_ALLOWED_HOSTS = tuple(AlertManager._WECOM_DINGTALK_WEBHOOK_HOSTS)


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


def _payload_kind(body: dict) -> str:
    if body.get("msg_type") == "text":
        return "lark"
    if body.get("msgtype") == "text":
        return "wecom"
    if body.get("event") == "alert_red" and body.get("delivery_id") == "DID":
        return "generic"
    return "unknown"


def _check_url(name, url, expected):
    from scripts.webhook_test_util import make_alerter
    a, _, _ = make_alerter()
    bodies = _capture_send(a)
    _send(a, url)
    got = _payload_kind(bodies[0]) if bodies else "missing"
    host = AlertManager._webhook_url_hostname(url)
    ok = got == expected
    print(f"  {name} host={host!r} expected={expected} got={got} -> {ok}")
    return ok


def test_positive_hostname_boundaries():
    cases = [
        ("uppercase host",
         "https://OPEN.FEISHU.CN/open-apis/bot/v2/hook/x", "lark"),
        ("explicit port",
         "https://open.feishu.cn:443/open-apis/bot/v2/hook/x", "lark"),
        ("userinfo on allowed host",
         "https://bot:token@open.larksuite.com/open-apis/bot/v2/hook/x", "lark"),
        ("path and query tokens",
         "https://open.larksuite.com/open-apis/bot/v2/hook/x"
         "?dingtalk=1&oapi=1&feishu=path-token", "lark"),
        ("wecom port and query",
         "https://qyapi.weixin.qq.com:443/cgi-bin/webhook/send?k=1&feishu=q", "wecom"),
        ("dingtalk path depth",
         "https://oapi.dingtalk.com/robot/send/with/extra/path?access_token=x", "wecom"),
    ]
    ok = all(_check_url(n, u, e) for n, u, e in cases)
    print(f"url_boundaries positive -> {ok}")
    return ok


def test_negative_hostname_boundaries():
    cases = [
        ("path contains larksuite",
         "https://example.com/open.larksuite.com/open-apis/bot/v2/hook/TEST",
         "generic"),
        ("path contains feishu",
         "https://example.com/feishu/status", "generic"),
        ("path contains dingtalk",
         "https://example.com/dingtalk/status", "generic"),
        ("query platform tokens",
         "https://example.com/hook?feishu=1&larksuite=2&oapi=3", "generic"),
        ("host suffix evil",
         "https://open.feishu.cn.evil.com/hook", "generic"),
        ("host prefix evil",
         "https://evil-open.feishu.cn/hook", "generic"),
        ("host missing open prefix",
         "https://feishu.cn/open-apis/bot/v2/hook/x", "generic"),
        ("host extra suffix label",
         "https://open.feishu.cn.com/hook", "generic"),
        ("oapi token in unrelated host",
         "https://not-oapi-example.invalid/hook", "generic"),
        ("userinfo mimics platform host",
         "https://open.feishu.cn@example.com/hook", "generic"),
        ("userinfo feishu on generic host",
         "https://feishu:token@example.com/hook", "generic"),
        ("port on generic host with path token",
         "https://example.com:8443/dingtalk/status", "generic"),
        ("larkoffice evil prefix host",
         "https://not.open.larkoffice.com/hook", "generic"),
    ]
    ok = all(_check_url(n, u, e) for n, u, e in cases)
    print(f"url_boundaries negative -> {ok}")
    return ok


def _evil_host_cases_for_allowed(allowed_host: str, label: str):
    """Template negatives for each exact allowlist hostname."""
    return [
        (f"{label} suffix evil",
         f"https://{allowed_host}.evil.com/hook", "generic"),
        (f"{label} prefix evil",
         f"https://evil{allowed_host}/hook", "generic"),
        (f"{label} not-prefix host",
         f"https://not.{allowed_host}/hook", "generic"),
        (f"{label} userinfo@allowed",
         f"https://{allowed_host}@example.com/hook", "generic"),
    ]


def test_allowlist_evil_host_templates():
    cases = []
    for host in _LARK_FEISHU_ALLOWED_HOSTS:
        cases.extend(_evil_host_cases_for_allowed(host, f"lark {host}"))
    for host in _WECOM_DINGTALK_ALLOWED_HOSTS:
        cases.extend(_evil_host_cases_for_allowed(host, f"wecom {host}"))
    cases.extend([
        ("generic path platform token",
         "https://example.com/open.feishu.cn/open-apis/bot/v2/hook/x", "generic"),
        ("generic query platform token",
         "https://example.com/hook?open.larksuite.com=1&qyapi.weixin.qq.com=2",
         "generic"),
    ])
    ok = all(_check_url(n, u, e) for n, u, e in cases)
    print(f"url_boundaries allowlist evil templates -> {ok}")
    return ok


def test_platform_text_includes_delivery_id():
    from scripts.webhook_test_util import make_alerter
    cases = [
        ("feishu",
         "https://open.feishu.cn/open-apis/bot/v2/hook/x",
         lambda b: b["content"]["text"]),
        ("larksuite",
         "https://open.larksuite.com/open-apis/bot/v2/hook/x",
         lambda b: b["content"]["text"]),
        ("wecom",
         "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?k=1",
         lambda b: b["text"]["content"]),
        ("dingtalk",
         "https://oapi.dingtalk.com/robot/send?access_token=x",
         lambda b: b["text"]["content"]),
    ]
    ok = True
    for name, url, get_text in cases:
        a, _, _ = make_alerter()
        bodies = _capture_send(a)
        _send(a, url)
        text = get_text(bodies[0]) if bodies else ""
        case_ok = "投递ID：DID" in text
        ok = ok and case_ok
        print(f"  platform text delivery_id {name} -> {case_ok}")
    print(f"url_boundaries platform delivery_id -> {ok}")
    return ok


def test_allowlist_helpers_match_send():
    """Hostname helpers stay consistent with _send_webhook payload branch."""
    pairs = [
        ("https://open.feishu.cn/hook", True, False),
        ("https://OPEN.LARKSUITE.COM/hook", True, False),
        ("https://qyapi.weixin.qq.com/hook", False, True),
        ("https://example.com/feishu", False, False),
        ("https://open.feishu.cn.evil.com/hook", False, False),
    ]
    ok = True
    for url, lark, wecom in pairs:
        got_lark = AlertManager._is_lark_feishu_webhook_url(url)
        got_wecom = AlertManager._is_wecom_dingtalk_webhook_url(url)
        case_ok = got_lark == lark and got_wecom == wecom
        ok = ok and case_ok
        print(
            f"  helper {AlertManager._webhook_url_hostname(url)!r} "
            f"lark={got_lark} wecom={got_wecom} -> {case_ok}")
    print(f"url_boundaries helpers -> {ok}")
    return ok


def main():
    results = [
        ("positive", test_positive_hostname_boundaries()),
        ("negative", test_negative_hostname_boundaries()),
        ("evil_templates", test_allowlist_evil_host_templates()),
        ("platform_delivery_id", test_platform_text_includes_delivery_id()),
        ("helpers", test_allowlist_helpers_match_send()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook URL boundary checks passed.")


if __name__ == "__main__":
    main()
