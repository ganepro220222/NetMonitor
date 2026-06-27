"""Download ip2region_v4.xdb into assets/ for offline public-IP geolocation.

Usage:
  python scripts/download_ip2region.py          # skip if already present
  python scripts/download_ip2region.py --force  # re-download

Exit 0 when the file exists (downloaded or already there); non-zero on failure.
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.geo_bootstrap import ensure_ip2region_xdb, xdb_dest_for_base
from src.geo_resolver import is_valid_xdb_file, probe_xdb_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    ap.add_argument("--quiet", action="store_true", help="no output when already present")
    args = ap.parse_args()
    dest = xdb_dest_for_base(ROOT)
    if probe_xdb_file(dest) and not args.force:
        if not args.quiet:
            print(f"[ip2region] already present ({os.path.getsize(dest):,} bytes)")
        return 0
    path = ensure_ip2region_xdb(ROOT, allow_download=True, force=args.force)
    return 0 if probe_xdb_file(path) else 1


if __name__ == "__main__":
    sys.exit(main())
