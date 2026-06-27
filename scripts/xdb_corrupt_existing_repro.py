#!/usr/bin/env python3
"""Reproduce: corrupt existing ip2region_v4.xdb must trigger re-download, not skip."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import src.geo_bootstrap as gb
from src.geo_bootstrap import ensure_ip2region_xdb, xdb_dest_for_base
from src.geo_resolver import GeoResolver, is_valid_xdb_file


def main() -> int:
    td = tempfile.mkdtemp()
    assets = os.path.join(td, "assets")
    os.makedirs(assets)
    dest = xdb_dest_for_base(td)
    with open(dest, "wb") as fh:
        fh.write(b"bad")

    calls = {"n": 0}
    real = gb.download_ip2region_xdb

    def counting_download(path, **kw):
        calls["n"] += 1
        return real(path, **kw)

    gb.download_ip2region_xdb = counting_download  # type: ignore
    try:
        ensure_path = ensure_ip2region_xdb(td, allow_download=True)
        res = GeoResolver(ensure_path) if ensure_path else GeoResolver(xdb_path=dest)
        print(f"ensure_path {ensure_path}")
        print(f"download_calls {calls['n']}")
        sz = os.path.getsize(dest) if os.path.isfile(dest) else 0
        print(f"file_size {sz} xdb_loaded {res.is_xdb_loaded()}")
        if (
            calls["n"] == 0
            and not is_valid_xdb_file(dest)
            and sz > 0
        ):
            print("BUG: corrupt existing xdb is treated as ready; setup/start will not repair it")
            return 1
        if is_valid_xdb_file(dest) or calls["n"] > 0:
            print("OK: corrupt xdb triggers repair attempt")
            return 0
        print("WARN: no download and dest still invalid (network may be unavailable)")
        return 0
    finally:
        gb.download_ip2region_xdb = real  # type: ignore


if __name__ == "__main__":
    raise SystemExit(main())
