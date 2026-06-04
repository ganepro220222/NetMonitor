"""Host / IP validation shared by UI dialogs and regression scripts."""
from __future__ import annotations

import ipaddress
import re

_LABEL_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
_ZONE_ID_RE = re.compile(r"^[\w.-]+$")


def _is_valid_ip_literal(host: str) -> bool:
    """Strict IPv4/IPv6 literal check; optional %zone_id on IPv6."""
    addr = host
    if "%" in host:
        addr, _, zone = host.partition("%")
        if not zone or not _ZONE_ID_RE.match(zone):
            return False
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def normalize_dns_expected_ipv4(raw: str) -> tuple[str | None, str | None]:
    """Parse comma-separated IPv4 list for DNS expected IPs. Returns (csv, err)."""
    if any(sep in raw for sep in ("，", ";", "；")):
        return None, "预期解析 IP 请使用英文逗号分隔，例如：1.1.1.1,8.8.8.8"
    items = [x.strip() for x in raw.split(",") if x.strip()]
    if not items:
        return None, "预期解析 IP 格式错误"
    out = []
    for item in items:
        try:
            ip = ipaddress.ip_address(item)
        except ValueError:
            return None, f"无效的预期解析 IP：{item}"
        if ip.version != 4:
            return None, "当前 DNS 监控只校验 A 记录，请填写 IPv4 地址"
        out.append(str(ip))
    return ",".join(out), None


_HTTP_SUCCESS_CLASSES = frozenset({"2xx", "3xx", "4xx", "5xx"})


def normalize_http_success_codes(raw: str) -> tuple[str | None, str | None]:
    """Parse HTTP success status rule. Returns (canonical_csv, err).

    Supports class tokens 2xx/3xx/4xx/5xx and exact codes 100-599, comma-separated.
    Empty input normalizes to the default ``2xx,3xx``.
    """
    text = (raw or "").strip()
    if not text:
        return "2xx,3xx", None
    if any(sep in text for sep in ("，", ";", "；")):
        return None, "成功状态码请使用英文逗号分隔，例如：2xx,3xx 或 200,201"
    if "-" in text:
        return None, "成功状态码不支持范围写法，请使用 2xx 或精确状态码，例如：200,201"
    parts_raw = [p.strip().lower().replace(" ", "") for p in text.split(",")]
    if not parts_raw or any(not p for p in parts_raw):
        return None, "成功状态码格式错误，不能包含空项"
    seen: set[str] = set()
    out: list[str] = []
    for part in parts_raw:
        if part in _HTTP_SUCCESS_CLASSES:
            if part not in seen:
                seen.add(part)
                out.append(part)
            continue
        try:
            code = int(part)
        except ValueError:
            return None, f"无法识别的成功状态码规则：{part}"
        if not (100 <= code <= 599):
            return None, f"状态码必须在 100–599 之间：{code}"
        token = str(code)
        if token not in seen:
            seen.add(token)
            out.append(token)
    if not out:
        return None, "成功状态码格式错误"
    return ",".join(out), None


def effective_latency_warn_ms_hint(
    ping_type: str, global_settings: dict | None = None,
) -> str:
    """Placeholder for per-target latency_warn_ms when field is left empty."""
    from src.ping_engine import HTTPMonitor
    if (ping_type or "icmp").lower() in ("http", "https"):
        return str(HTTPMonitor.DEFAULT_WARN_LAT)
    g = global_settings or {}
    return str(g.get("latency_warn_ms", 150))


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host:
        return _is_valid_ip_literal(host)
    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)
