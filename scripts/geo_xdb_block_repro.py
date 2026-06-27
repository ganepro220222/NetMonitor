#!/usr/bin/env python3
"""Reproduce: build_geo must not block on xdb lazy-load on the request path."""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import src.geo_resolver as gr
import src.screen_service as ss
from src.web_server import WebServer


def main() -> int:
    with tempfile.NamedTemporaryFile(suffix=".xdb", delete=False) as fh:
        fh.write(b"x" * 512)
        fake_path = fh.name

    real_init = gr._XdbMemorySearcher.__init__

    def slow_init(self, db_path: str):
        time.sleep(0.55)
        raise ValueError("slow xdb read")

    gr._XdbMemorySearcher.__init__ = slow_init  # type: ignore[method-assign]
    orig_resolve = gr.GeoResolver.resolve_xdb_path
    try:
        missing = os.path.join(tempfile.gettempdir(), "geo_xdb_block_repro_missing.xdb")
        res = gr.GeoResolver(xdb_path=missing)
        assert res.is_xdb_loaded() is False

        gr.GeoResolver.resolve_xdb_path = staticmethod(lambda base_dir=None: fake_path)  # type: ignore

        w = WebServer(port=0)
        w._running = True
        w._geo_resolver = res

        t0 = time.time()
        payload = ss.build_geo(w, resolver=res)
        elapsed = time.time() - t0

        print(f"elapsed {elapsed:.2f} geo_db_ready {payload.get('geo_db_ready')}")
        if elapsed >= 0.35:
            print("BUG: build_geo request path synchronously blocked on xdb load")
            return 1
        if payload.get("geo_db_ready") is not False:
            print("BUG: geo_db_ready should be False before background prewarm completes")
            return 1
        print("OK: build_geo returned quickly without synchronous xdb IO")
        return 0
    finally:
        gr._XdbMemorySearcher.__init__ = real_init  # type: ignore[method-assign]
        gr.GeoResolver.resolve_xdb_path = orig_resolve
        try:
            os.unlink(fake_path)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
