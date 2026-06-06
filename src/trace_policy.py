"""Traceroute request / summary policy by probe type and failure reason.

Probes measure different layers (ICMP echo, TCP connect, HTTP, DNS UDP).
Auto-traceroute only helps for suspected *network-path* failures.  Application-
or endpoint-layer reds (port closed, HTTP 5xx, DNS hijack, etc.) must not
trigger path traces or push misleading hop break summaries.
"""

from __future__ import annotations

from src.traceroute_summary import summarize_break, trace_signature

# ── failure layer classification ─────────────────────────────────────

_ICMP_NETWORK = frozenset()  # any non-empty ICMP fail is network-layer

_TCP_ENDPOINT = frozenset({
    "tcp_timeout", "connection_refused", "invalid_port",
})

_HTTP_ENDPOINT_EXACT = frozenset({
    "http_timeout", "too_many_redirects", "invalid_url",
    "keyword_not_found", "keyword_found", "connection_refused",
    "tcp_timeout",
})

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
        return "network" if fr else "network"

    if pt == "tcp":
        if fr.startswith("dns_failed:"):
            return "endpoint"
        return "endpoint" if fr else "endpoint"

    if pt in ("http", "https"):
        return "endpoint"

    if pt == "dns":
        return "endpoint"

    return "network" if pt == "icmp" else "endpoint"


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


def _describe_failure(fr: str) -> str:
    if not fr:
        return ""
    mapping = {
        "no_reply": "ICMP 无响应",
        "timeout": "ICMP 超时",
        "tcp_timeout": "TCP 连接超时",
        "connection_refused": "TCP 连接被拒绝",
        "http_timeout": "HTTP 请求超时",
        "dns_timeout": "DNS 查询超时",
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
    return fr.split(":", 1)[0]


def _hops_have_break(hops: list) -> bool:
    return any(h.get("status") in ("break", "after") for h in (hops or []))


def _tcp_checks_ok(tcp_checks: list | None) -> bool:
    if not tcp_checks:
        return False
    return any(c.get("success") for c in tcp_checks)


def summarize_for_alert(hops: list, *,
                        ping_type: str | None,
                        failure_reason: str | None,
                        tcp_checks: list | None = None) -> dict:
    """Build webhook / report trace summary with layer-aware context."""
    if not should_request_traceroute(ping_type, failure_reason):
        return trace_skip_summary(ping_type, failure_reason)

    base = summarize_break(hops or [])

    if _hops_have_break(hops) and _tcp_checks_ok(tcp_checks):
        text = (
            "目标可能过滤 ICMP，traceroute 显示的断点不一定代表服务中断"
            "（辅助端口检测仍通）。"
        )
        if base.get("text"):
            text = f"{text} 原始：{base['text']}"
        return {
            **base,
            "text": text,
            "icmp_filtered": True,
            "break_at": None,
        }

    return base


def trace_signature_from_summary(summary: dict) -> tuple:
    if summary.get("skipped"):
        return ("skipped", summary.get("text"))
    return trace_signature(summary)
