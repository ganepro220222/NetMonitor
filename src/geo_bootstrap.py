"""Bootstrap offline geo: ensure ip2region xdb exists before /screen lookups."""
from __future__ import annotations

import os
import threading
import urllib.error
import urllib.request

from src.geo_resolver import GeoResolver, MIN_XDB_BYTES, is_valid_xdb_file
XDB_URLS = (
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb",
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
)

_XDB_DOWNLOAD_LOCK = threading.Lock()
_XDB_DOWNLOAD_INFLIGHT = False


def xdb_dest_for_base(base_dir: str) -> str:
    return os.path.join(os.path.abspath(base_dir), "assets", "ip2region_v4.xdb")


def download_ip2region_xdb(dest: str, *, timeout: float = 120.0) -> bool:
    """Download ip2region_v4.xdb to *dest*. Return True on success."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    headers = {"User-Agent": "NetMonitor-ip2region-downloader/1.0"}
    for url in XDB_URLS:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if len(data) < MIN_XDB_BYTES:
                print(f"[ip2region] skip {url}: too small ({len(data)} bytes)")
                continue
            tmp = dest + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, dest)
            print(f"[ip2region] OK {len(data):,} bytes -> {dest}")
            return True
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            print(f"[ip2region] fail {url}: {exc}")
    return False


def ensure_ip2region_xdb(
        base_dir: str | None = None,
        *,
        allow_download: bool = True,
        force: bool = False,
) -> str | None:
    """Return path to ip2region xdb, downloading into assets/ when missing."""
    if not base_dir:
        return GeoResolver.resolve_xdb_path(None)

    dest = xdb_dest_for_base(base_dir)
    legacy = os.path.join(os.path.abspath(base_dir), "assets", "ip2region.xdb")

    if not force:
        if is_valid_xdb_file(dest):
            return dest
        if is_valid_xdb_file(legacy):
            return legacy
        # Only accept alternate locations when the primary dest file is absent —
        # a corrupt dest must be repaired, not masked by another valid copy.
        if not os.path.isfile(dest):
            elsewhere = GeoResolver.resolve_xdb_path(base_dir)
            if elsewhere and elsewhere not in (dest, legacy):
                return elsewhere

    if not allow_download:
        return GeoResolver.resolve_xdb_path(base_dir)

    if force or not is_valid_xdb_file(dest):
        if download_ip2region_xdb(dest):
            return dest

    if is_valid_xdb_file(legacy):
        print(f"[ip2region] download failed; using legacy {legacy}")
        return legacy

    print("[ip2region] not available — public-IP auto geo disabled until xdb exists:")
    print(f"  {dest}")
    print("  Run: python scripts/download_ip2region.py")
    return GeoResolver.resolve_xdb_path(base_dir)


def prewarm_ip2region_download_async(base_dir: str | None) -> None:
    """Download ip2region xdb on a background thread when missing (non-blocking)."""
    global _XDB_DOWNLOAD_INFLIGHT
    if not base_dir:
        return
    if GeoResolver.resolve_xdb_path(base_dir):
        return
    with _XDB_DOWNLOAD_LOCK:
        if _XDB_DOWNLOAD_INFLIGHT:
            return
        if GeoResolver.resolve_xdb_path(base_dir):
            return
        _XDB_DOWNLOAD_INFLIGHT = True

    def _run():
        global _XDB_DOWNLOAD_INFLIGHT
        try:
            ensure_ip2region_xdb(base_dir, allow_download=True)
        finally:
            with _XDB_DOWNLOAD_LOCK:
                _XDB_DOWNLOAD_INFLIGHT = False

    threading.Thread(
        target=_run,
        name="ip2region-download",
        daemon=True,
    ).start()
