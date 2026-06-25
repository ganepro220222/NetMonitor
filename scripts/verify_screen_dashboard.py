"""Regression: /screen situational dashboard routes and screen_service aggregators."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.screen_service import (
    build_events,
    build_overview,
    build_paths,
    build_topn,
    compute_health_score,
    compute_risk_score,
    demo_overview,
    parse_window,
)
from src.traceroute_summary import summarize_break
from src.web_server import WebServer


def test_parse_window():
    start, end, label = parse_window("today", now=1_700_000_000.0)
    ok = end > start and "今" in label
    start7, end7, _ = parse_window("7d", now=1_700_000_000.0)
    ok = ok and (end7 - start7) >= 7 * 86400 - 1
    print(f"parse_window -> {ok}")
    return ok


def test_score_helpers():
    risk = compute_risk_score(red=1, orange=0, open_incidents=1, webhook_failures=0)
    health = compute_health_score(green=7, total=8, red=1, orange=0, avg_uptime=99.9)
    ok = risk["score"] > 0 and 0 <= health["score"] <= 10
    print(f"score helpers risk={risk} health={health} -> {ok}")
    return ok


def test_summarize_break_wording():
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": "202.1.1.1", "status": "break", "error": "timeout"},
    ]
    s = summarize_break(hops)
    ok = (
        s.get("break_at")
        and "故障" not in s.get("text", "")
        and "中断" in s.get("text", "")
    )
    print(f"summarize_break cautious text -> {ok} text={s.get('text')!r}")
    return ok


def test_build_overview_paths():
    w = WebServer(port=0)
    w._running = True
    w.update_target(
        tid="T1", label="NodeA", ip="10.0.0.1", status="green",
        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0, is_probe_result=True)
    w.update_target(
        tid="T2", label="NodeB", ip="10.0.0.2", status="red",
        latency_ms=None, jitter_ms=0.0, loss_rate=1.0,
        probe_success=False, is_probe_result=True)
    ov = build_overview(w, window="today")
    paths = build_paths(w, window="today")
    top = build_topn(w, window="today")
    ev = build_events(w, limit=10)
    ok = (
        ov["counts"]["targets"] == 2
        and ov["counts"]["red"] == 1
        and isinstance(paths.get("paths"), list)
        and len(paths["paths"]) >= 1
        and "lowest_sla" in top
        and isinstance(ev, list)
    )
    print(f"build overview/paths/top/events -> {ok}")
    return ok


def test_http_routes():
    w = WebServer(port=0)
    if not getattr(w, "_app", None):
        print("HTTP routes -> SKIP (Flask unavailable)")
        return True
    with w._app.test_client() as c:
        r_screen = c.get("/screen")
        r_demo = c.get("/api/screen/overview?demo=1")
        r_paths = c.get("/api/screen/paths?demo=1")
        r_ev = c.get("/api/screen/events?demo=1")
    body_ev = json.loads(r_ev.data)
    ok = (
        r_screen.status_code == 200
        and b"id=\"stage\"" in r_screen.data
        and r_demo.status_code == 200
        and json.loads(r_demo.data).get("demo") is True
        and r_paths.status_code == 200
        and bool(json.loads(r_paths.data).get("paths"))
        and r_ev.status_code == 200
        and isinstance(body_ev.get("events"), list)
    )
    print(f"HTTP /screen + demo APIs -> {ok}")
    return ok


def test_topo_layout_covers_all_hops():
    """Mirror layoutSerpentine node count: source + N hops + target."""
    hop_count = 17
    node_count = hop_count + 2
    cols = min(14, max(6, int((node_count * 2.2) ** 0.5 + 0.999)))
    rows = (node_count + cols - 1) // cols
    ok = rows >= 2 and node_count <= cols * rows
    print(f"topo layout 17 hops -> {node_count} nodes, {rows} rows -> {ok}")
    return ok


def test_source_guards():
    svc_path = os.path.join(ROOT, "src", "screen_service.py")
    ws_path = os.path.join(ROOT, "src", "web_server.py")
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    with open(svc_path, encoding="utf-8") as f:
        svc = f.read()
    with open(ws_path, encoding="utf-8") as f:
        ws = f.read()
    ok = (
        os.path.isfile(html_path)
        and "request_now" not in svc
        and "force=1" not in svc
        and 'route("/screen")' in ws.replace(" ", "")
        and "/api/screen/overview" in ws
        and "window.open('/screen'" in ws
        and "layoutSerpentine" in open(html_path, encoding="utf-8").read()
    )
    print(f"source guards + wiring -> {ok}")
    return ok


def test_demo_payload_shape():
    d = demo_overview()
    ok = "risk" in d and "health" in d and isinstance(d.get("counts"), dict)
    print(f"demo overview shape -> {ok}")
    return ok


def main():
    tests = [
        ("parse_window", test_parse_window()),
        ("scores", test_score_helpers()),
        ("summarize_break", test_summarize_break_wording()),
        ("builders", test_build_overview_paths()),
        ("topo_layout", test_topo_layout_covers_all_hops()),
        ("http", test_http_routes()),
        ("source", test_source_guards()),
        ("demo", test_demo_payload_shape()),
    ]
    failed = [n for n, ok in tests if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("PASS verify_screen_dashboard")


if __name__ == "__main__":
    main()
