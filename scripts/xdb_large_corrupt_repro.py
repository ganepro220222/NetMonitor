"""Repro: 1MB all-zero ip2region xdb passes size gate but is unusable."""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import src.geo_bootstrap as gb
from src.geo_bootstrap import ensure_ip2region_xdb, xdb_dest_for_base
from src.geo_resolver import GeoResolver, MIN_XDB_BYTES, is_valid_xdb_file


def main() -> int:
    td = tempfile.mkdtemp()
    dest = xdb_dest_for_base(td)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(b"\x00" * MIN_XDB_BYTES)

    calls = {"n": 0}
    real = gb.download_ip2region_xdb

    def fake_download(path, **kw):
        calls["n"] += 1
        return False

    gb.download_ip2region_xdb = fake_download  # type: ignore
    try:
        path = ensure_ip2region_xdb(td, allow_download=True)
        rx = GeoResolver(path)
        lookup = rx.lookup_public_ip("9.9.9.9")
        print(f"is_valid_xdb_file {is_valid_xdb_file(dest)} size {os.path.getsize(dest)}")
        print(f"ensure_path {path}")
        print(f"download_calls {calls['n']}")
        print(f"xdb_loaded {rx.is_xdb_loaded()} lookup_9.9.9.9 {lookup}")
        bug = (
            is_valid_xdb_file(dest)
            and calls["n"] == 0
            and rx.is_xdb_loaded()
        )
        if bug:
            print(
                "BUG: large corrupt xdb passes size gate, is reported loaded, "
                "and bootstrap will not repair it"
            )
            return 1
        print("OK: large corrupt xdb rejected or triggers repair")
        return 0
    finally:
        gb.download_ip2region_xdb = real  # type: ignore


if __name__ == "__main__":
    sys.exit(main())
