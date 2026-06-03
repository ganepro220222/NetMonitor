"""Host / IP validation shared by UI dialogs and regression scripts."""
from __future__ import annotations

import re

_LABEL_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    ipv4 = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4, host):
        return all(0 <= int(p) <= 255 for p in host.split("."))
    if ":" in host:
        return bool(re.match(r"^[0-9a-fA-F:]+(%\w+)?$", host))
    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(_LABEL_RE.match(label) for label in labels)
