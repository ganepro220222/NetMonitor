"""Regression: Web ACK reconnect + pause/resume stale ACK cache (post-159)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import WebServer, FLASK_AVAILABLE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_SERVER = os.path.join(ROOT, "src", "web_server.py")


class _CaptureBroadcaster:
    def __init__(self):
        self.messages = []

    def push(self, msg):
        self.messages.append(msg)


def test_pause_resume_refresh_ack_cache():
    if not FLASK_AVAILABLE:
        print("Bug160 pause/resume ack -> skipped (no Flask)")
        return True

    ws = WebServer(port=0)
    ws._running = True
    ws.set_incident_ack_status_fn(lambda tid: tid == "t1")
    ws.update_target(
        tid="t1", label="GW", ip="10.0.0.1", status="red",
        latency_ms=None, jitter_ms=None, loss_rate=1.0,
    )
    ok_before = (
        ws._targets["t1"]["status"] == "red"
        and ws._targets["t1"]["incident_acknowledged"] is True
    )

    bc = _CaptureBroadcaster()
    ws._broadcaster = bc
    ws.pause_target("t1")
    paused_cache = ws._targets["t1"]["incident_acknowledged"]
    pause_push = json.loads(bc.messages[-1]) if bc.messages else {}
    pause_ack = pause_push.get("target", {}).get("incident_acknowledged")
    api_rows = ws._targets_for_client()
    api_ack = next(r["incident_acknowledged"] for r in api_rows if r["tid"] == "t1")

    ws.resume_target("t1")
    resume_cache = ws._targets["t1"]["incident_acknowledged"]
    resume_push = json.loads(bc.messages[-1]) if bc.messages else {}
    resume_ack = resume_push.get("target", {}).get("incident_acknowledged")

    ok = (
        ok_before
        and paused_cache is False
        and pause_ack is False
        and api_ack is False
        and resume_cache is False
        and resume_ack is False
    )
    print(
        f"Bug160 pause/resume ack refresh -> {ok} "
        f"pause_cache={paused_cache} pause_sse={pause_ack} "
        f"resume_cache={resume_cache} resume_sse={resume_ack}"
    )
    return ok


def test_source_init_clears_ack_set_and_pause_refreshes():
    with open(WEB_SERVER, encoding="utf-8") as f:
        ws = f.read()
    init_block = ws.split("if(msg.type==='init')", 1)[1].split(
        "if(msg.type==='update')", 1)[0]
    pause_block = ws.split("def pause_target", 1)[1].split(
        "def resume_target", 1)[0]
    resume_block = ws.split("def resume_target", 1)[1].split(
        "def update_target", 1)[0]
    ok = (
        "acknowledgedTids.clear()" in init_block
        and "t.incident_acknowledged" in init_block
        and "_live_incident_acknowledged" in pause_block
        and "_live_incident_acknowledged" in resume_block
    )
    print(f"Bug160 source init ack reset + pause/resume -> {ok}")
    return ok


def main():
    results = [
        ("pause_resume", test_pause_resume_refresh_ack_cache()),
        ("source", test_source_init_clears_ack_set_and_pause_refreshes()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 160 checks passed.")


if __name__ == "__main__":
    main()
