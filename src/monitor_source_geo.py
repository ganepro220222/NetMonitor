"""Auto-detect monitor source location for /screen geo arcs.

The monitor source is where probes originate (this host).  Resolution order:

  1. Manual ``settings.monitor_geo`` (UI / config.json) — always wins.
  2. Local route IPv4 via UDP connect — when the host has a direct public IP.
  3. Public egress IPv4 via a short HTTP lookup — for NAT / intranet hosts.

Target IP geolocation remains offline (ip2region) except for the optional
egress-IP fetch above, which only runs when manual geo is unset and the
local interface is not a usable public address.
"""
from __future__ import annotations

import re
import socket
import threading
import urllib.error
import urllib.request
from typing import Any

from src.geo_resolver import GeoResolver, is_public_ip, parse_manual_geo

_EGRESS_CACHE_LOCK = threading.Lock()
_EGRESS_CACHE: dict[str, Any] = {"ip": None, "ts": 0.0, "fail_ts": 0.0,
                                 "inflight": False}
_EGRESS_TTL_OK = 3600.0
_EGRESS_TTL_FAIL = 300.0
_EGRESS_ENDPOINTS = (
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def detect_route_local_ipv4() -> str | None:
    """Return the IPv4 this host would use to reach the public Internet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        ip = (ip or "").strip()
        return ip if _IPV4_RE.fullmatch(ip) else None
    except OSError:
        return None


def fetch_public_egress_ipv4(timeout: float = 2.5) -> str | None:
    """Best-effort public egress IPv4; cached to limit outbound requests."""
    import time
    now = time.time()
    with _EGRESS_CACHE_LOCK:
        cached = _EGRESS_CACHE.get("ip")
        ts = float(_EGRESS_CACHE.get("ts") or 0)
        fail_ts = float(_EGRESS_CACHE.get("fail_ts") or 0)
        if cached and now - ts < _EGRESS_TTL_OK:
            return cached
        if not cached and fail_ts and now - fail_ts < _EGRESS_TTL_FAIL:
            return None

    ip = _fetch_public_egress_uncached(timeout=timeout)
    with _EGRESS_CACHE_LOCK:
        if ip:
            _EGRESS_CACHE["ip"] = ip
            _EGRESS_CACHE["ts"] = time.time()
            _EGRESS_CACHE["fail_ts"] = 0.0
        else:
            _EGRESS_CACHE["fail_ts"] = time.time()
    return ip


def _egress_cached_ipv4() -> str | None:
    """Return a fresh cached public egress IPv4 without any network I/O."""
    import time
    with _EGRESS_CACHE_LOCK:
        cached = _EGRESS_CACHE.get("ip")
        ts = float(_EGRESS_CACHE.get("ts") or 0)
    if cached and time.time() - ts < _EGRESS_TTL_OK:
        return cached
    return None


def prewarm_egress_async() -> None:
    """Populate the egress-IP cache on a background thread so the read-only
    /screen geo request path never blocks on the outbound HTTP probe. No-op
    when a fetch is unnecessary (fresh cache), backed off (recent failure), or
    already in flight."""
    import time
    with _EGRESS_CACHE_LOCK:
        if _EGRESS_CACHE.get("inflight"):
            return
        now = time.time()
        cached = _EGRESS_CACHE.get("ip")
        ts = float(_EGRESS_CACHE.get("ts") or 0)
        fail_ts = float(_EGRESS_CACHE.get("fail_ts") or 0)
        if cached and now - ts < _EGRESS_TTL_OK:
            return
        if fail_ts and now - fail_ts < _EGRESS_TTL_FAIL:
            return
        _EGRESS_CACHE["inflight"] = True

    def _run():
        try:
            fetch_public_egress_ipv4()
        finally:
            with _EGRESS_CACHE_LOCK:
                _EGRESS_CACHE["inflight"] = False

    threading.Thread(target=_run, name="egress-prewarm", daemon=True).start()


def _fetch_public_egress_uncached(timeout: float = 2.5) -> str | None:
    headers = {"User-Agent": "NetMonitor/1.0 (monitor-source-geo)"}
    for url in _EGRESS_ENDPOINTS:
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(64).decode("ascii", errors="ignore").strip()
            if _IPV4_RE.fullmatch(body) and is_public_ip(body):
                return body
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            continue
    return None


def _format_monitor_source(geo: dict, probe_ip: str, loc_source: str) -> dict:
    out = dict(geo)
    city = out.get("city") or out.get("region") or ""
    base = out.get("label") or "监控主机"
    if city and city not in base:
        out["label"] = f"{base} · {city}"
    else:
        out.setdefault("label", base)
    out["loc_source"] = loc_source
    out["probe_ip"] = probe_ip
    return out


def resolve_monitor_source(
        resolver: GeoResolver,
        manual_geo: dict | None = None,
        *,
        allow_egress_fetch: bool = True,
) -> dict | None:
    """Resolve monitor-source geo for /screen arcs."""
    manual = parse_manual_geo(manual_geo)
    if manual:
        out = dict(manual)
        out.setdefault("label", out.get("label") or out.get("city") or "监控主机")
        out["loc_source"] = "manual"
        if manual_geo and isinstance(manual_geo, dict):
            probe = manual_geo.get("probe_ip")
            if isinstance(probe, str) and probe.strip():
                out["probe_ip"] = probe.strip()
        return out

    local_ip = detect_route_local_ipv4()
    if local_ip and is_public_ip(local_ip):
        geo = resolver.lookup_public_ip(local_ip)
        if geo:
            return _format_monitor_source(geo, local_ip, "local_ip")

    # Prefer the cached egress IP (no network I/O). Only fetch synchronously
    # when explicitly allowed -- the read-only /screen path passes
    # allow_egress_fetch=False and relies on prewarm_monitor_source().
    egress = _egress_cached_ipv4()
    if egress is None and allow_egress_fetch:
        egress = fetch_public_egress_ipv4()
    if egress and is_public_ip(egress):
        geo = resolver.lookup_public_ip(egress)
        if geo:
            return _format_monitor_source(geo, egress, "egress_ip")

    return None


def prewarm_monitor_source(manual_geo: dict | None = None) -> None:
    """Kick a background egress lookup for auto monitor-source detection so the
    /screen geo request path never blocks. No-op when manual geo is configured
    or the local route IP is already public."""
    if parse_manual_geo(manual_geo):
        return
    local_ip = detect_route_local_ipv4()
    if local_ip and is_public_ip(local_ip):
        return
    prewarm_egress_async()
