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


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host:
        return _is_valid_ip_literal(host)
    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)
