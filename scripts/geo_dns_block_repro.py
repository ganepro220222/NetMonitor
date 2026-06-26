"""Regression: build_geo must NOT block on uncached hostname DNS (cache miss).

Before fix: elapsed ~0.65s when getaddrinfo is monkeypatched to sleep 0.65s.
After fix: request path returns unlocated in <50ms; DNS runs in background prewarm.
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import src.geo_resolver as gr
import src.screen_service as ss
from src.web_server import WebServer


def main():
    with gr._DNS_CACHE_LOCK:
        gr._DNS_CACHE.clear()

    real = gr.socket.getaddrinfo

    def slow(host, *a, **k):
        time.sleep(0.65)
        return [(2, 1, 6, "", ("8.8.8.8", 0))]

    gr.socket.getaddrinfo = slow
    try:
        w = WebServer(port=0)
        w._running = True
        w.update_target(
            tid="dns1",
            label="Slow DNS",
            ip="slow-host.example.com",
            status="green",
            latency_ms=5.0,
            jitter_ms=1.0,
            loss_rate=0.0,
            is_probe_result=True,
            ping_type="icmp",
        )
        ss.invalidate_screen_cache()
        t0 = time.time()
        payload = ss.build_geo(w)
        dt = time.time() - t0
        row = payload["targets"][0] if payload.get("targets") else {}
        print(
            f"elapsed {dt:.3f} kind={row.get('kind')} "
            f"geo={row.get('geo') is not None} geo_val={row.get('geo')}"
        )
        blocked = dt >= 0.6
        return not blocked
    finally:
        gr.socket.getaddrinfo = real
        with gr._DNS_CACHE_LOCK:
            gr._DNS_CACHE.clear()


if __name__ == "__main__":
    ok = main()
    print("PASS non-blocking geo path" if ok else "FAIL still blocks on DNS cache miss")
    sys.exit(0 if ok else 1)
