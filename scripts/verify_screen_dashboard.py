"""Regression: /screen situational dashboard routes and screen_service aggregators."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.screen_service import (
    build_events,
    build_merged_graph,
    build_overview,
    build_paths,
    build_route_diff,
    build_topn,
    compute_health_score,
    compute_risk_score,
    demo_events,
    demo_overview,
    invalidate_screen_cache,
    parse_window,
    should_merge_target_hop,
    _path_graph,
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


def test_break_kind_display():
    from src.trace_policy import classify_path_break, summarize_for_display
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": "202.1.1.1", "status": "break"},
    ]
    icmp = summarize_for_display(
        hops, tcp_checks=[{"port": 443, "success": True}],
        ping_type="icmp", probe_success=False, status="red")
    real = summarize_for_display(
        hops, tcp_checks=[{"port": 443, "success": False}],
        ping_type="icmp", probe_success=False, status="red")
    dns_ok = summarize_for_display(
        hops, tcp_checks=[{"port": 443, "success": False}],
        ping_type="dns", probe_success=True, status="green")
    http_ep = summarize_for_display(
        hops, tcp_checks=[{"port": 443, "success": True}],
        ping_type="http", probe_success=False, status="red",
        failure_reason="status_500")
    ok = (
        icmp.get("break_kind") == "icmp_filtered"
        and real.get("break_kind") == "real"
        and dns_ok.get("break_kind") == "icmp_filtered"
        and dns_ok.get("service_ok") is True
        and http_ep.get("break_kind") == "endpoint"
        and classify_path_break(
            hops, ping_type="http", probe_success=False,
            failure_reason="status_500")["break_kind"] == "endpoint"
    )
    print(f"break_kind icmp/real/dns/http -> {ok}")
    return ok


def test_merged_graph():
    paths = [
        {"tid": "A", "label": "A", "status": "green", "hops": [
            {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
            {"hop": 2, "ip": "10.0.0.2", "status": "ok"},
        ]},
        {"tid": "B", "label": "B", "status": "red", "hops": [
            {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
            {"hop": 2, "ip": "10.0.0.9", "status": "break"},
        ]},
    ]
    mg = build_merged_graph(paths)
    ok = (
        mg.get("path_count") == 2
        and mg.get("shared_hops") == 1
        and any(n.get("id") == "hop:10.0.0.1" for n in mg.get("nodes", []))
    )
    print(f"build_merged_graph shared hop -> {ok}")
    return ok


def test_target_merge_scheme_c():
    reached_hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 20, "ip": "47.108.166.19", "status": "ok"},
    ]
    broken_hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 6, "ip": "219.1.1.1", "status": "break"},
    ]
    ok_merge = should_merge_target_hop(reached_hops, "47.108.166.19")
    ok_split = not should_merge_target_hop(broken_hops, "202.98.198.167")
    g = _path_graph(
        reached_hops, "T", "台网", "green",
        {"reached": True, "break_kind": "none"},
        target_ip="47.108.166.19")
    ok_graph = (
        g.get("target_merged") is True
        and not any(n.get("type") == "target" for n in g.get("nodes", []))
        and any(n.get("is_target") for n in g.get("nodes", []))
    )
    ok = ok_merge and ok_split and ok_graph
    print(f"target merge scheme C -> {ok} merge={ok_merge} split={ok_split} graph={ok_graph}")
    return ok


def test_route_diff():
    old = [{"hop": 1, "ip": "10.0.0.1"}, {"hop": 2, "ip": "1.1.1.1"}]
    new = [{"hop": 1, "ip": "10.0.0.1"}, {"hop": 2, "ip": "8.8.8.8"}]
    diff = build_route_diff(old, new)
    ok = (
        diff is not None
        and diff["old_ips"] == ["10.0.0.1", "1.1.1.1"]
        and diff["new_ips"] == ["10.0.0.1", "8.8.8.8"]
        and 1 in diff["changed_hops"]
        and "1.1.1.1" in diff["text"]
    )
    print(f"build_route_diff -> {ok} text={diff.get('text') if diff else None!r}")
    return ok


def test_demo_events_shape():
    rows = demo_events()
    types = {r.get("type") for r in rows}
    ok = (
        "open_incident" in types
        and "route_changed" in types
        and "recovery" in types
        and any(r.get("route_diff") for r in rows if r.get("type") == "route_changed")
    )
    print(f"demo_events phase3 types -> {ok} types={types}")
    return ok


def test_build_events_db():
    import tempfile
    import time
    from src.data_store import DataStore

    td = tempfile.mkdtemp()
    db = os.path.join(td, "screen_ev.db")
    ds = DataStore(db_path=db)
    ds._schema_ready.wait(timeout=5)
    w = WebServer(port=0)
    w._running = True
    w._data_store = ds
    w.update_target(
        tid="T1", label="NodeA", ip="10.0.0.1", status="green",
        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0, is_probe_result=True)
    ts = time.time() - 120
    ds.record_alert(
        target_id="T1", label="NodeA", ip="10.0.0.1",
        ts=ts, old_status="green", new_status="red", category="loss",
        failure_reason="timeout")
    ds.flush()
    time.sleep(0.25)
    w.update_target(
        tid="T1", label="NodeA", ip="10.0.0.1", status="red",
        latency_ms=None, jitter_ms=0.0, loss_rate=1.0,
        probe_success=False, is_probe_result=True)
    ev = build_events(w, window="today", limit=20)
    ok = (
        isinstance(ev, list)
        and len(ev) >= 1
        and any(e.get("type") in ("incident_open", "open_incident") for e in ev)
    )
    print(f"build_events db-backed -> {ok} types={[e.get('type') for e in ev]}")
    return ok


def test_invalidate_cache():
    invalidate_screen_cache()
    print("invalidate_screen_cache -> True")
    return True


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
        and isinstance(paths.get("merged"), dict)
        and paths["merged"].get("path_count", 0) >= 1
        and "lowest_sla" in top
        and "most_outages" in top
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
        and bool(json.loads(r_paths.data).get("merged"))
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
    tp_path = os.path.join(ROOT, "src", "trace_policy.py")
    ws_path = os.path.join(ROOT, "src", "web_server.py")
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    with open(svc_path, encoding="utf-8") as f:
        svc = f.read()
    with open(tp_path, encoding="utf-8") as f:
        tp = f.read()
    with open(ws_path, encoding="utf-8") as f:
        ws = f.read()
    html = open(html_path, encoding="utf-8").read()
    ok = (
        os.path.isfile(html_path)
        and "request_now" not in svc
        and "force=1" not in svc
        and 'route("/screen")' in ws.replace(" ", "")
        and "/api/screen/overview" in ws
        and "window.open('/screen'" in ws
        and "layoutSerpentine" in html
        and "syncAutoRotate" in html
        and "break-ripple" in html
        and "trace_break" in ws
        and "trace_heal" in ws
        and "route_changed" in ws
        and "build_merged_graph" in svc
        and "summarize_for_display" in svc
        and "classify_path_break" in tp
        and "endpoint-node" in html
        and "invalidate_screen_cache" in svc
        and "topOutages" in html
        and "route-compare" in html
        and "build_route_diff" in svc
        and "should_merge_target_hop" in svc
        and "open_incident" in svc
        and "onRouteChangedSSE" in html
    )
    print(f"source guards + wiring -> {ok}")
    return ok


def test_demo_payload_shape():
    d = demo_overview()
    ok = (
        "risk" in d and "health" in d
        and isinstance(d.get("counts"), dict)
        and "score_meta" in d
    )
    print(f"demo overview shape -> {ok}")
    return ok


def main():
    tests = [
        ("parse_window", test_parse_window()),
        ("scores", test_score_helpers()),
        ("summarize_break", test_summarize_break_wording()),
        ("break_kind", test_break_kind_display()),
        ("target_merge", test_target_merge_scheme_c()),
        ("route_diff", test_route_diff()),
        ("demo_events", test_demo_events_shape()),
        ("merged_graph", test_merged_graph()),
        ("invalidate_cache", test_invalidate_cache()),
        ("builders", test_build_overview_paths()),
        ("events_db", test_build_events_db()),
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
