"""Bootstrap offline geo: ensure ip2region xdb exists before /screen lookups."""
from __future__ import annotations

import os
import urllib.error
import urllib.request

from src.geo_resolver import GeoResolver

MIN_XDB_BYTES = 1_000_000
XDB_URLS = (
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb",
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
)


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
    existing = GeoResolver.resolve_xdb_path(base_dir)
    if existing and os.path.isfile(existing) and not force:
        return existing

    if not allow_download or not base_dir:
        return existing if existing and os.path.isfile(existing) else None

    dest = xdb_dest_for_base(base_dir)
    if os.path.isfile(dest) and not force:
        return dest
    if download_ip2region_xdb(dest):
        return dest

    legacy = os.path.join(os.path.abspath(base_dir), "assets", "ip2region.xdb")
    if os.path.isfile(legacy):
        print(f"[ip2region] download failed; using legacy {legacy}")
        return legacy

    print("[ip2region] not available — public-IP auto geo disabled until xdb exists:")
    print(f"  {dest}")
    print("  Run: python scripts/download_ip2region.py")
    return GeoResolver.resolve_xdb_path(base_dir)
