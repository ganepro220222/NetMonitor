"""Traceroute request / summary policy by probe type and failure reason.

Probes measure different layers (ICMP echo, TCP connect, HTTP, DNS UDP).
Auto-traceroute only helps for suspected *network-path* failures.  Application-
or endpoint-layer reds (port closed, HTTP 5xx, DNS hijack, etc.) must not
trigger path traces or push misleading hop break summaries.
"""

from __future__ import annotations

from src.traceroute_summary import summarize_break, trace_signature

# ── failure layer classification ─────────────────────────────────────

_TCP_ENDPOINT = frozenset({
    "tcp_timeout", "connection_refused", "invalid_port",
})

_HTTP_ENDPOINT_EXACT = frozenset({
    "http_timeout", "too_many_redirects", "invalid_url",
    "keyword_not_found", "keyword_found", "connection_refused",
    "tcp_timeout", "bad_response", "body_incomplete", "body_recv_timeout",
    "chunked_premature_eof", "header_incomplete", "recv_closed",
    "recv_timeout", "tcp_failed", "tls_timeout",
})

PING_TYPE_LABELS = {
    "icmp": "ICMP",
    "tcp": "TCP",
    "http": "HTTP",
    "https": "HTTPS",
    "dns": "DNS",
}

_DNS_ENDPOINT_EXACT = frozenset({
    "dns_timeout", "dns_bad_response", "dns_no_a_record", "dns_no_domain",
    "nxdomain",
})


def failure_layer(ping_type: str | None,
                  failure_reason: str | None) -> str:
    """Return ``network`` | ``endpoint`` | ``config``.

    *network*  — path / reachability diagnosis may help (ICMP loss, etc.)
    *endpoint* — service/port/app/DNS semantics; tracert is misleading
    *config*    — operator misconfiguration; tracert irrelevant
    """
    pt = (ping_type or "icmp").strip().lower()
    fr = (failure_reason or "").strip()

    # Reason-first: unambiguous codes regardless of stored ping_type.
    if fr in ("no_reply", "timeout"):
        return "network"
    if fr.startswith("error:"):
        return "network"

    if fr == "invalid_port":
        return "config"
    if fr in _TCP_ENDPOINT:
        return "endpoint"
    if fr.startswith("tcp_failed:"):
        return "endpoint"

    if fr in _HTTP_ENDPOINT_EXACT:
        return "endpoint"
    for prefix in ("dns_failed:", "tls_failed:", "url_parse:", "status_",
                   "ssl_error"):
        if fr.startswith(prefix):
            return "endpoint"

    if fr in _DNS_ENDPOINT_EXACT:
        return "endpoint"
    for prefix in ("dns_hijack:", "dns_rcode_", "dns_error:"):
        if fr.startswith(prefix):
            return "endpoint"

    if pt == "icmp":
        return "network"

    if pt == "tcp":
        if fr.startswith("dns_failed:"):
            return "endpoint"
        return "endpoint"

    if pt in ("http", "https"):
        return "endpoint"

    if pt == "dns":
        return "endpoint"

    return "endpoint"


def should_request_traceroute(ping_type: str | None,
                              failure_reason: str | None) -> bool:
    """Whether an urgent / refresh traceroute may help this outage."""
    return failure_layer(ping_type, failure_reason) == "network"


def trace_skip_summary(ping_type: str | None,
                       failure_reason: str | None) -> dict:
    """Placeholder summary when tracert is skipped or not applicable."""
    pt = (ping_type or "icmp").strip().lower()
    fr = (failure_reason or "").strip()
    layer = failure_layer(pt, fr)

    if layer == "config":
        detail = _describe_failure(fr) or "配置错误"
        text = f"未执行路径追踪（{detail}，与路由无关）"
    elif pt in ("http", "https"):
        detail = _describe_failure(fr) or "应用层故障"
        text = f"未执行路径追踪（{detail}，HTTP 监测与 ICMP 路径无直接对应）"
    elif pt == "dns":
        detail = _describe_failure(fr) or "DNS 查询失败"
        text = f"未执行路径追踪（{detail}，与 traceroute 无直接对应）"
    elif pt == "tcp":
        detail = _describe_failure(fr) or "端口不可达"
        text = f"未执行路径追踪（{detail}，多为端口/服务问题而非路径断点）"
    else:
        detail = _describe_failure(fr) or "探测失败"
        text = f"未执行路径追踪（{detail}）"

    return {
        "reached": None,
        "last_ok": None,
        "break_at": None,
        "total_hops": 0,
        "text": text,
        "skipped": True,
    }


def describe_failure(fr: str | None) -> str:
    """Translate machine failure codes into short Chinese labels."""
    if not fr:
        return ""
    mapping = {
        "no_reply": "ICMP 无响应",
        "timeout": "ICMP 超时",
        "tcp_timeout": "TCP 连接超时",
        "connection_refused": "TCP 连接被拒绝",
        "tcp_failed": "TCP 连接失败",
        "http_timeout": "HTTP 请求超时",
        "too_many_redirects": "HTTP 重定向过多",
        "invalid_url": "URL 无效",
        "bad_response": "HTTP 响应异常",
        "body_incomplete": "HTTP 响应体不完整",
        "body_recv_timeout": "HTTP 响应体接收超时",
        "chunked_premature_eof": "分块传输提前结束",
        "header_incomplete": "HTTP 响应头不完整",
        "recv_timeout": "接收超时",
        "recv_closed": "连接被对端关闭",
        "tls_timeout": "TLS 握手超时",
        "dns_timeout": "DNS 查询超时",
        "dns_bad_response": "DNS 响应异常",
        "nxdomain": "域名不存在 (NXDOMAIN)",
        "dns_no_a_record": "DNS 无 A 记录",
        "dns_no_domain": "未配置查询域名",
        "invalid_port": "端口配置无效",
        "keyword_not_found": "页面关键词缺失",
        "keyword_found": "页面含禁止关键词",
    }
    if fr in mapping:
        return mapping[fr]
    if fr.startswith("status_"):
        return f"HTTP 状态 {fr[7:]}"
    if fr.startswith("dns_hijack:"):
        return "DNS 解析与预期不符"
    if fr.startswith("tls_failed:"):
        return "TLS 握手失败"
    if fr.startswith("dns_failed:"):
        return "DNS 解析失败"
    if fr.startswith("tcp_failed:"):
        return "TCP 连接失败"
    if fr.startswith("dns_rcode_"):
        return f"DNS 错误码 {fr[10:]}"
    if fr.startswith("dns_error:"):
        return "DNS 查询错误"
    if fr.startswith("url_parse:"):
        return "URL 解析失败"
    if fr.startswith("send_failed:"):
        return "HTTP 发送失败"
    if fr.startswith("unexpected:"):
        return "HTTP 请求异常"
    if fr.startswith("error:"):
        return f"探测错误 ({fr[6:]})"
    return fr.split(":", 1)[0]


def ping_type_label(ping_type: str | None) -> str:
    pt = (ping_type or "icmp").strip().lower()
    return PING_TYPE_LABELS.get(pt, pt.upper() or "ICMP")


# Back-compat alias for existing imports / tests
_describe_failure = describe_failure


def _hops_have_break(hops: list) -> bool:
    return any(h.get("status") in ("break", "after") for h in (hops or []))


def _tcp_checks_ok(tcp_checks: list | None) -> bool:
    if not tcp_checks:
        return False
    return any(c.get("success") for c in tcp_checks)


def _open_tcp_ports(tcp_checks: list | None) -> list[int]:
    out: list[int] = []
    for c in tcp_checks or []:
        if c.get("success") and c.get("port") is not None:
            out.append(int(c["port"]))
    return out


def _probe_indicates_ok(*, probe_success: bool | None,
                        status: str | None) -> bool:
    if probe_success is not None:
        return bool(probe_success)
    return (status or "").strip().lower() == "green"


def classify_path_break(hops: list | None, *,
                        tcp_checks: list | None = None,
                        ping_type: str | None = None,
                        probe_success: bool | None = None,
                        status: str | None = None,
                        failure_reason: str | None = None) -> dict:
    """Classify ICMP-traceroute darkness vs the target's own probe semantics.

    Shared by ``summarize_for_display`` (big screen) and ``summarize_for_alert``
    (webhook).  Returns ``break_kind``:

    * ``none``          — no hop break/after in the path
    * ``icmp_filtered`` — path goes dark but service probe / aux TCP says OK
    * ``real``          — path dark and probes also failing (network outage)
    * ``endpoint``      — HTTP/DNS app-layer failure; hop mark is reference only
    """
    hops = hops or []
    has_break = _hops_have_break(hops)
    probe_ok = _probe_indicates_ok(probe_success=probe_success, status=status)
    if not has_break:
        return {
            "break_kind": "none",
            "icmp_filtered": False,
            "service_ok": probe_ok,
        }

    pt = (ping_type or "icmp").strip().lower() or "icmp"
    tcp_ok = _tcp_checks_ok(tcp_checks)
    layer = failure_layer(pt, failure_reason or "")

    # Live probe green → ICMP blind spot regardless of node type (fixes DNS).
    if probe_ok:
        return {
            "break_kind": "icmp_filtered",
            "icmp_filtered": True,
            "service_ok": True,
            "hint": pt,
        }

    # HTTP/DNS red with endpoint-layer failure — do not treat as network break.
    if pt in ("http", "https", "dns") and layer == "endpoint":
        return {
            "break_kind": "endpoint",
            "icmp_filtered": False,
            "service_ok": False,
            "failure_detail": describe_failure(failure_reason),
        }

    # ICMP/TCP nodes, or network-layer timeout on any type: aux TCP is tie-breaker.
    if tcp_ok:
        return {
            "break_kind": "icmp_filtered",
            "icmp_filtered": True,
            "service_ok": False,
            "hint": "tcp_aux",
        }

    return {
        "break_kind": "real",
        "icmp_filtered": False,
        "service_ok": False,
    }


def _path_ok_hop_suffix(base: dict) -> str:
    """Compact hop tail for path-complete summaries, e.g. （共6跳→221.13.0.217）."""
    total = int(base.get("total_hops") or 0)
    last_ok = base.get("last_ok") or {}
    ip = last_ok.get("ip")
    if total and ip:
        return f"（共{total}跳→{ip}）"
    if total:
        return f"（共{total}跳）"
    return ""


def format_path_ok_while_probe_fails(
        base: dict,
        *,
        ping_type: str | None,
        failure_reason: str | None,
) -> str:
    """Webhook / screen copy when traceroute is clean but the probe is still red."""
    detail = describe_failure(failure_reason)
    if not detail:
        detail = f"{ping_type_label(ping_type)}探测失败"
    pt = (ping_type or "icmp").strip().lower()
    if pt == "icmp":
        hint = "疑禁 ping 或 ICMP 策略"
    elif pt == "tcp":
        hint = "疑端口/服务问题，非路由断点"
    else:
        hint = "疑探测层与路由层不一致"
    suffix = _path_ok_hop_suffix(base)
    return (
        f"监测仍失败（{detail}）；路由可达、无中间断点{suffix}。{hint}"
    )


def _service_hint(cls: dict, ping_type: str | None,
                  tcp_checks: list | None) -> str:
    hint = cls.get("hint")
    if cls.get("service_ok"):
        if hint == "dns":
            return "（DNS 查询正常）"
        if hint in ("http", "https"):
            return "（HTTP 监测正常）"
        if hint == "icmp":
            return "（ICMP 监测正常）"
    ports = _open_tcp_ports(tcp_checks)
    if ports:
        return f"（{'/'.join(str(p) for p in ports[:4])} 端口通）"
    if hint == "tcp_aux":
        return "（辅助端口检测仍通）"
    if cls.get("service_ok"):
        return "（监测仍通）"
    return "（辅助端口检测仍通）"


def summarize_for_display(hops: list, *,
                          tcp_checks: list | None = None,
                          status: str | None = None,
                          ping_type: str | None = None,
                          probe_success: bool | None = None,
                          failure_reason: str | None = None) -> dict:
    """Topology / big-screen summary: keep hop location, classify break kind."""
    base = summarize_break(hops or [])
    cls = classify_path_break(
        hops,
        tcp_checks=tcp_checks,
        ping_type=ping_type,
        probe_success=probe_success,
        status=status,
        failure_reason=failure_reason,
    )
    kind = cls["break_kind"]
    base["break_kind"] = kind
    base["icmp_filtered"] = cls.get("icmp_filtered", False)
    base["service_ok"] = cls.get("service_ok")

    if kind == "none":
        if (status or "").strip().lower() == "red" and not cls.get("service_ok"):
            base["text"] = format_path_ok_while_probe_fails(
                base,
                ping_type=ping_type,
                failure_reason=failure_reason,
            )
        return base

    break_at = base.get("break_at")
    hop_n = (break_at or {}).get("hop", "?")

    if kind == "icmp_filtered":
        hint = _service_hint(cls, ping_type, tcp_checks)
        base["text"] = (
            f"traceroute 在第{hop_n}跳后不可见，目标可能过滤 ICMP{hint}；"
            f"不等于路径故障"
        )
    elif kind == "endpoint":
        detail = cls.get("failure_detail") or "应用层异常"
        base["text"] = (
            f"{detail}；traceroute 在第{hop_n}跳后 ICMP 不可见，"
            f"路径信息仅供参考"
        )
    elif kind == "real" and base.get("text"):
        base["text"] = (
            f"{base['text']}（辅助端口检测也不通，疑似真实路径问题）"
        )

    return base


def summarize_for_alert(hops: list, *,
                        ping_type: str | None,
                        failure_reason: str | None,
                        tcp_checks: list | None = None) -> dict:
    """Build webhook / report trace summary with layer-aware context."""
    if not should_request_traceroute(ping_type, failure_reason):
        return trace_skip_summary(ping_type, failure_reason)

    base = summarize_break(hops or [])
    cls = classify_path_break(
        hops,
        tcp_checks=tcp_checks,
        ping_type=ping_type,
        probe_success=False,
        status="red",
        failure_reason=failure_reason,
    )

    if cls["break_kind"] == "icmp_filtered":
        hint = _service_hint(cls, ping_type, tcp_checks)
        text = (
            f"监测仍失败（{describe_failure(failure_reason) or '探测失败'}）；"
            f"traceroute 某跳后 ICMP 不可见{hint}，不等于路径故障"
        )
        return {
            **base,
            "text": text,
            "icmp_filtered": True,
            "break_at": None,
        }

    if cls["break_kind"] == "none":
        base["text"] = format_path_ok_while_probe_fails(
            base,
            ping_type=ping_type,
            failure_reason=failure_reason,
        )

    elif cls["break_kind"] == "real" and base.get("text"):
        base["text"] = (
            f"{base['text']}（辅助端口检测也不通，疑似真实路径问题）"
        )

    return base


def trace_signature_from_summary(summary: dict) -> tuple:
    if summary.get("skipped"):
        return ("skipped", summary.get("text"))
    return trace_signature(summary)
