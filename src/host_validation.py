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


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host:
        return _is_valid_ip_literal(host)
    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)
