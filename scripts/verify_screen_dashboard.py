"""Regression: /screen situational dashboard routes and screen_service aggregators."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.screen_service import (
    build_events,
    build_geo,
    build_merged_graph,
    build_overview,
    build_paths,
    build_route_diff,
    build_topn,
    compute_health_score,
    compute_risk_score,
    demo_events,
    demo_geo,
    demo_overview,
    invalidate_screen_cache,
    parse_window,
    should_merge_target_hop,
    _path_graph,
)
from src.geo_resolver import GeoResolver, is_private_ip, is_public_ip, parse_manual_geo, region_string_to_coords
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


def test_merged_unknown_hops_not_shared():
    """Unrelated timeout hops must not merge across targets (Bug 1)."""
    paths = [
        {"tid": "A", "label": "A", "status": "red", "hops": [
            {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
            {"hop": 2, "ip": "*", "status": "break"},
        ]},
        {"tid": "B", "label": "B", "status": "red", "hops": [
            {"hop": 1, "ip": "10.0.0.2", "status": "ok"},
            {"hop": 2, "ip": "*", "status": "break"},
        ]},
    ]
    mg = build_merged_graph(paths)
    unk = [n for n in mg.get("nodes", []) if str(n.get("id", "")).startswith("hop:unk:")]
    shared_unk = [n for n in unk if len(n.get("target_tids") or []) > 1]
    ok = (
        len(unk) == 2
        and not shared_unk
        and mg.get("shared_hops") == 0
    )
    print(f"merged unknown hops isolated -> {ok} unk={len(unk)} shared_hops={mg.get('shared_hops')}")
    return ok


def test_path_graph_distinct_timeout_hops():
    """Repeated timeout hops must not collapse to hop:* self-loop (Bug 2)."""
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": "*", "status": "after"},
        {"hop": 3, "ip": "*", "status": "after"},
    ]
    g = _path_graph(
        hops, "T", "目标", "red",
        {"reached": False, "break_kind": "real"},
        target_ip="203.0.113.9")
    ids = {n["id"] for n in g.get("nodes", [])}
    self_loops = [e for e in g.get("edges", []) if e.get("from") == e.get("to")]
    ok = (
        "hop:*" not in ids
        and "hop:unk:T:2" in ids
        and "hop:unk:T:3" in ids
        and not self_loops
    )
    print(f"path graph timeout hops distinct -> {ok} self_loops={len(self_loops)}")
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


def test_overseas_coords():
    hit = region_string_to_coords("United States|California|0|Google LLC|US")
    ok_hit = hit is not None and hit[2] in ("region", "country", "city")
    xdb = GeoResolver.resolve_xdb_path(ROOT)
    ok_ip = True
    ok_cf = True
    if xdb and os.path.isfile(xdb):
        rx = GeoResolver(xdb)
        g = rx.lookup_public_ip("8.8.8.8")
        ok_ip = bool(g is not None and g.get("lat") is not None and g.get("country"))
        print(f"overseas 8.8.8.8 -> {g}")
    rx2 = GeoResolver(xdb if xdb and os.path.isfile(xdb) else None)
    cf = rx2.lookup_public_ip("1.1.1.1")
    ok_cf = (
        cf is not None
        and cf.get("source") == "wellknown"
        and cf.get("lon", 0) < 0
    )
    print(f"anycast 1.1.1.1 -> {cf}")
    ok = ok_hit and ok_ip and ok_cf
    print(f"overseas coords fallback -> {ok}")
    return ok


def test_geo_resolver():
    res = GeoResolver()
    manual = parse_manual_geo({"lat": 31.2, "lon": 121.5, "city": "上海"})
    ok_manual = manual and manual["lat"] == 31.2
    priv = res.resolve_target(ip="10.0.0.1", resolve_ip="10.0.0.1", manual_geo=None)
    pub = res.resolve_target(
        ip="202.98.198.167", resolve_ip="202.98.198.167",
        manual_geo={"lat": 30.5, "lon": 104.0})
    ok = (
        ok_manual
        and is_private_ip("10.0.0.1")
        and is_public_ip("202.98.198.167")
        and priv["kind"] == "private"
        and pub["kind"] == "manual"
    )
    xdb = GeoResolver.resolve_xdb_path(ROOT)
    if xdb and os.path.isfile(xdb):
        rx = GeoResolver(xdb)
        baidu = rx.lookup_public_ip("220.181.38.148")
        ok = ok and baidu is not None and baidu.get("lat") is not None
        print(f"geo_resolver xdb={os.path.basename(xdb)} baidu={baidu}")
    print(f"geo_resolver -> {ok}")
    return ok


def test_demo_geo_shape():
    d = demo_geo()
    ok = (
        d.get("demo") is True
        and isinstance(d.get("targets"), list)
        and len(d["targets"]) >= 2
        and isinstance(d.get("inset"), list)
        and "stats" in d
        and any(t.get("break_geo") for t in d["targets"])
    )
    print(f"demo_geo shape -> {ok}")
    return ok


def test_build_geo():
    w = WebServer(port=0)
    w._running = True
    w.set_screen_geo(
        monitor_geo={"lat": 31.23, "lon": 121.47, "label": "监控主机"},
        target_geos={"T1": {"lat": 39.9, "lon": 116.4, "city": "北京"}},
        resolver=GeoResolver(),
    )
    w.update_target(
        tid="T1", label="Beijing", ip="220.181.38.148", status="green",
        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0, is_probe_result=True)
    w.update_target(
        tid="T2", label="LAN", ip="10.0.0.8", status="orange",
        latency_ms=10.0, jitter_ms=1.0, loss_rate=0.1, is_probe_result=True)
    payload = build_geo(w)
    kinds = {r["tid"]: r["kind"] for r in payload.get("targets", [])}
    ok = (
        payload.get("source") is not None
        and kinds.get("T1") == "manual"
        and kinds.get("T2") == "private"
        and len(payload.get("inset", [])) >= 1
        and payload.get("stats", {}).get("private") == 1
    )
    print(f"build_geo -> {ok} kinds={kinds}")
    return ok


def test_build_geo_stats_private_vs_unlocated():
    """stats.private must not count unlocated public/hostname inset rows."""
    w = WebServer(port=0)
    w._running = True
    w.set_screen_geo(resolver=GeoResolver())
    w.update_target(
        tid="priv", label="Private", ip="10.0.0.1", status="green",
        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0, is_probe_result=True)
    w.update_target(
        tid="host", label="HostNoResolve", ip="example.invalid", status="green",
        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0, is_probe_result=True)
    payload = build_geo(w)
    stats = payload.get("stats") or {}
    inset_kinds = {i["tid"]: i.get("inset_kind") for i in payload.get("inset", [])}
    ok = (
        inset_kinds.get("priv") == "private"
        and inset_kinds.get("host") == "unlocated"
        and stats.get("total") == 2
        and stats.get("private") == 1
        and stats.get("unlocated") == 1
        and stats.get("on_map") == 0
    )
    print(f"build_geo stats private/unlocated -> {ok} stats={stats}")
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
        r_geo = c.get("/api/screen/geo?demo=1")
        r_world = c.get("/vendor/world.json")
        r_ev = c.get("/api/screen/events?demo=1")
        r_vendor = c.get("/vendor/echarts.min.js")
    body_ev = json.loads(r_ev.data)
    body_geo = json.loads(r_geo.data)
    ok = (
        r_screen.status_code == 200
        and b"id=\"stage\"" in r_screen.data
        and b"btnTopoGeo" in r_screen.data
        and b"btnMapWorld" in r_screen.data
        and b"geoChart" in r_screen.data
        and r_demo.status_code == 200
        and json.loads(r_demo.data).get("demo") is True
        and r_paths.status_code == 200
        and bool(json.loads(r_paths.data).get("paths"))
        and bool(json.loads(r_paths.data).get("merged"))
        and r_geo.status_code == 200
        and body_geo.get("demo") is True
        and isinstance(body_geo.get("targets"), list)
        and r_world.status_code == 200
        and len(r_world.data) > 10000
        and r_vendor.status_code == 200
        and len(r_vendor.data) > 1000
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
        and "build_geo" in svc
        and "demo_geo" in svc
        and "open_incident" in svc
        and "onRouteChangedSSE" in html
        and "drillToSinglePath" in html
        and "setGeoMapMode" in html
        and "screen-window-btn" in html
        and "rotatePoolKeyInfo" in html
        and "ensureGeoMaps" in html
        and os.path.isfile(os.path.join(ROOT, "src", "web", "vendor", "world.json"))
        and os.path.getsize(os.path.join(ROOT, "src", "web", "vendor", "world.json")) > 10000
        and "geo-mode" in html
        and "/api/screen/geo" in ws
        and 'route("/vendor/' in ws.replace(" ", "")
        and "src/web/vendor" in open(os.path.join(ROOT, "build_exe.spec"), encoding="utf-8").read()
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
        ("overseas_coords", test_overseas_coords()),
        ("geo_resolver", test_geo_resolver()),
        ("demo_geo", test_demo_geo_shape()),
        ("build_geo", test_build_geo()),
        ("build_geo_stats", test_build_geo_stats_private_vs_unlocated()),
        ("route_diff", test_route_diff()),
        ("demo_events", test_demo_events_shape()),
        ("merged_graph", test_merged_graph()),
        ("merged_unk_isolated", test_merged_unknown_hops_not_shared()),
        ("path_graph_timeouts", test_path_graph_distinct_timeout_hops()),
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
