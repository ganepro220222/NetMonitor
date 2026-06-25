"""Download ip2region_v4.xdb into assets/ for offline public-IP geolocation.

Official repo renamed ip2region.xdb -> data/ip2region_v4.xdb (IPv4) around v3/v4.
This script is the only network step; runtime lookups are 100% local.

Usage:
  python scripts/download_ip2region.py          # skip if already present
  python scripts/download_ip2region.py --force  # re-download

Exit 0 when the file exists (downloaded or already there); non-zero on failure.
"""
from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "assets", "ip2region_v4.xdb")
MIN_BYTES = 1_000_000

# Current official filenames (2024+); legacy ip2region.xdb URLs are 404.
URLS = (
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
    "https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb",
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb",
)


def download(dest: str) -> bool:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    headers = {"User-Agent": "NetMonitor-ip2region-downloader/1.0"}
    for url in URLS:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            if len(data) < MIN_BYTES:
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    args = ap.parse_args()
    if os.path.isfile(DEST) and not args.force:
        print(f"[ip2region] already present ({os.path.getsize(DEST):,} bytes)")
        return 0
    if download(DEST):
        return 0
    legacy = os.path.join(ROOT, "assets", "ip2region.xdb")
    if os.path.isfile(legacy):
        print(f"[ip2region] download failed; using legacy {legacy}")
        return 0
    print("[ip2region] not available — public-IP auto geo disabled until xdb is placed:")
    print(f"  {DEST}")
    print("  Manual: https://github.com/lionsoul2014/ip2region/tree/master/data")
    return 1


if __name__ == "__main__":
    sys.exit(main())
