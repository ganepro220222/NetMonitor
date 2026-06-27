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
from src.geo_resolver import GeoResolver, is_private_ip, is_public_ip, parse_manual_geo, region_string_to_coords, build_manual_geo_from_fields, resolve_probe_ipv4, resolve_hostname_ipv4
from src.monitor_source_geo import detect_route_local_ipv4, resolve_monitor_source
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


def test_screen_cache_per_web_instance():
    """overview/topn TTL cache must not bleed across WebServer instances."""
    invalidate_screen_cache()
    w1 = WebServer(port=0)
    w1._running = True
    w1.update_target(
        tid="A", label="A", ip="1.1.1.1", status="red",
        latency_ms=1.0, jitter_ms=0.0, loss_rate=1.0, is_probe_result=True)
    w2 = WebServer(port=0)
    w2._running = True
    w2.update_target(
        tid="B", label="B", ip="8.8.8.8", status="green",
        latency_ms=1.0, jitter_ms=0.0, loss_rate=0.0, is_probe_result=True)
    ov1 = build_overview(w1, window="today")
    ov2 = build_overview(w2, window="today")
    top1 = build_topn(w1, window="today", n=5)
    top2 = build_topn(w2, window="today", n=5)
    ok = (
        ov1["counts"]["red"] == 1
        and ov2["counts"]["green"] == 1
        and ov2["counts"]["red"] == 0
        and all(r.get("tid") != "A" for r in top2.get("lowest_sla", []))
        and all(r.get("tid") != "B" for r in top1.get("lowest_sla", []))
    )
    print(f"screen cache per web instance -> {ok} w2={ov2['counts']}")
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
        and isinstance(paths.get("merged"), dict)
        and paths["merged"].get("path_count", 0) >= 1
        and "lowest_sla" in top
        and "most_outages" in top
        and isinstance(ev, list)
    )
    print(f"build overview/paths/top/events -> {ok}")
    return ok


def test_china_city_suffix_coords():
    """ip2region v4 city/province names carry 市/省 suffix — must not fall back to CN center."""
    cn_lat, cn_lon = 35.8617, 104.1954
    cases = [
        ("中国|甘肃省|兰州市|电信|CN", (36.0611, 103.8343)),
        ("中国|湖南省|长沙市|中国联通|CN", (28.228, 112.9388)),
        ("中国|贵州省|贵阳市|移动|CN", (26.647, 106.6302)),
        ("中国|北京|北京市|电信|CN", (39.9042, 116.4074)),
    ]
    ok = True
    for raw, (want_lat, want_lon) in cases:
        hit = region_string_to_coords(raw)
        if not hit:
            ok = False
            print(f"china suffix coords miss -> {raw}")
            continue
        lat, lon, _prec = hit
        if abs(lat - cn_lat) < 0.05 and abs(lon - cn_lon) < 0.05:
            ok = False
            print(f"china suffix fell back to country center -> {raw} {hit}")
        if abs(lat - want_lat) > 0.2 or abs(lon - want_lon) > 0.2:
            ok = False
            print(f"china suffix wrong coords -> {raw} got {hit} want ~({want_lat},{want_lon})")
    xdb = GeoResolver.resolve_xdb_path(ROOT)
    if xdb and os.path.isfile(xdb):
        rx = GeoResolver(xdb)
        for ip, (want_lat, want_lon) in (
            ("222.85.130.16", (26.647, 106.6302)),
            ("116.162.6.102", (28.228, 112.9388)),
        ):
            g = rx.lookup_public_ip(ip)
            if not g or abs(g["lat"] - cn_lat) < 0.05:
                ok = False
                print(f"china suffix xdb lookup -> {ip} {g}")
            elif abs(g["lat"] - want_lat) > 0.2 or abs(g["lon"] - want_lon) > 0.2:
                ok = False
                print(f"china suffix xdb coords -> {ip} {g} want ~({want_lat},{want_lon})")
    print(f"china city/province suffix coords -> {ok}")
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
        and "allow_egress_fetch=False" in svc
        and "prewarm_monitor_source" in svc
        and "geo_db_ready" in svc
        and "ensure_ip2region_xdb" in open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
        and "layoutSerpentine" in html
        and "syncAutoRotate" in html
        and "break-ripple" in html
        and "trace_break" in ws
        and "trace_heal" in ws
        and "route_changed" in ws
        and "build_merged_graph" in svc
        and "summarize_for_display" in svc
        and "classify_path_break" in tp
        and "resetGeoViewport" in html
        and "chinaOverviewViewport" in html
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
        and "clearTopoPending" in html
        and "ensureGeoMaps" in html
        and "dataErrorBanner" in html
        and "noteDataError" in html
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


def test_window_validation_normalizes():
    """paths/topn/geo must coerce an unknown ?window to 'today'. Otherwise
    build_topn caches by the raw window string -> unbounded _CACHE growth."""
    import src.screen_service as ss
    w = WebServer(port=0)
    if not getattr(w, "_app", None):
        print("window validation -> SKIP (Flask unavailable)")
        return True
    ss.invalidate_screen_cache()
    with w._app.test_client() as c:
        wins = [json.loads(c.get(f"/api/screen/{r}?window=junk-x").data).get("window")
                for r in ("paths", "topn", "geo")]
    # Layout-independent: the junk token must never reach any cache key
    # (cache keys may carry extra components such as id(web)).
    bad_keys = [k for k in ss._CACHE if any("junk" in str(x) for x in k)]
    ok = wins == ["today", "today", "today"] and not bad_keys
    print(f"window validation normalizes junk -> {ok} wins={wins} bad_keys={bad_keys}")
    return ok


def test_error_fallback_no_demo():
    """On a real backend failure overview/geo must degrade to an empty
    skeleton carrying ``error`` -- never demo data (which would paint fake
    healthy nodes onto the live screen)."""
    import src.screen_service as ss
    w = WebServer(port=0)
    if not getattr(w, "_app", None):
        print("error fallback -> SKIP (Flask unavailable)")
        return True

    def _boom(*a, **k):
        raise RuntimeError("boom")

    orig_ov, orig_geo = ss.build_overview, ss.build_geo
    ss.build_overview = _boom
    ss.build_geo = _boom
    try:
        with w._app.test_client() as c:
            ov = json.loads(c.get("/api/screen/overview").data)
            geo = json.loads(c.get("/api/screen/geo").data)
    finally:
        ss.build_overview, ss.build_geo = orig_ov, orig_geo
    ok = (
        bool(ov.get("error")) and ov.get("demo") is not True
        and (ov.get("counts") or {}).get("targets") == 0
        and (ov.get("risk") or {}).get("score") is None
        and bool(geo.get("error")) and geo.get("demo") is not True
        and geo.get("targets") == []
        and (geo.get("stats") or {}).get("on_map") == 0
    )
    print(f"error fallback empty-skeleton not demo -> {ok}")
    return ok


def test_monitor_source_geo():
    """Monitor source: manual wins; auto uses local or egress path."""
    rx = GeoResolver(GeoResolver.resolve_xdb_path(ROOT))
    manual = resolve_monitor_source(
        rx, {"lat": 31.2, "lon": 121.5, "city": "上海", "label": "办公室"})
    ok_manual = (
        manual is not None
        and manual.get("loc_source") == "manual"
        and manual.get("lat") == 31.2
    )
    auto = resolve_monitor_source(rx, None, allow_egress_fetch=False)
    route_ip = detect_route_local_ipv4()
    ok_auto = auto is None or auto.get("loc_source") in ("local_ip", "egress_ip")
    if route_ip and is_public_ip(route_ip):
        ok_auto = ok_auto and auto is not None and auto.get("loc_source") == "local_ip"
    print(f"monitor_source manual={ok_manual} auto={auto} route={route_ip} -> {ok_auto}")
    return ok_manual and ok_auto


def test_resolve_probe_ipv4():
    """Targets: literals resolve; private stays unplaced; domains when DNS works."""
    priv = resolve_probe_ipv4("10.0.0.1")
    ok_priv = priv is None
    ok_literal = resolve_probe_ipv4("8.8.8.8") == "8.8.8.8"
    rx = GeoResolver(GeoResolver.resolve_xdb_path(ROOT))
    placed = rx.resolve_target(ip="8.8.8.8", resolve_ip=None, manual_geo=None)
    ok_placed = placed.get("kind") == "public" and bool(placed.get("geo"))
    host_ip = resolve_hostname_ipv4("www.baidu.com")
    ok_domain = True
    if host_ip:
        pd = rx.resolve_target(ip="www.baidu.com", resolve_ip=None, manual_geo=None)
        ok_domain = pd.get("kind") == "public"
    print(
        f"resolve_probe_ipv4 priv={ok_priv} literal={ok_literal} "
        f"8.8.8.8={ok_placed} baidu_dns={host_ip} baidu_geo={ok_domain}")
    return ok_priv and ok_literal and ok_placed and ok_domain


def test_build_manual_geo_from_fields():
    """UI geo parser: city lookup, lat/lon pair, empty clears."""
    empty = build_manual_geo_from_fields()
    assert empty is None
    by_city = build_manual_geo_from_fields(city="贵阳")
    assert by_city and by_city.get("lat") and by_city.get("city") == "贵阳"
    by_coords = build_manual_geo_from_fields(lat="31.2", lon="121.5", label="上海")
    assert by_coords == parse_manual_geo({"lat": 31.2, "lon": 121.5, "label": "上海"})
    try:
        build_manual_geo_from_fields(lat="31.2")
        assert False, "partial lat/lon should fail"
    except ValueError:
        pass
    print("build_manual_geo_from_fields -> OK")
    return True


def test_dns_resolution_cached():
    """resolve_hostname_ipv4 must TTL-cache so the read-only geo path does not
    re-run a blocking getaddrinfo for the same hostname on every poll."""
    import src.geo_resolver as gr
    with gr._DNS_CACHE_LOCK:
        gr._DNS_CACHE.clear()
    calls = {"n": 0}
    real = gr.socket.getaddrinfo
    gr.socket.getaddrinfo = lambda host, *a, **k: (
        calls.__setitem__("n", calls["n"] + 1)
        or [(2, 1, 6, "", ("8.8.8.8", 0))])  # a genuinely public IP
    try:
        a = gr.resolve_hostname_ipv4("host.example.com")
        b = gr.resolve_hostname_ipv4("host.example.com")
    finally:
        gr.socket.getaddrinfo = real
        with gr._DNS_CACHE_LOCK:
            gr._DNS_CACHE.clear()
    ok = a == "8.8.8.8" and b == "8.8.8.8" and calls["n"] == 1
    print(f"dns resolution cached -> {ok} getaddrinfo_calls={calls['n']}")
    return ok


def test_geo_dns_off_request_path():
    """build_geo must not block on uncached hostname DNS; cache miss stays
    unlocated and prewarms lookup on a background thread."""
    import threading
    import time
    import src.geo_resolver as gr
    import src.screen_service as ss

    with gr._DNS_CACHE_LOCK:
        gr._DNS_CACHE.clear()
        gr._DNS_INFLIGHT.clear()
    done = threading.Event()
    real = gr.socket.getaddrinfo

    def slow(host, *a, **k):
        time.sleep(0.8)
        done.set()
        return [(2, 1, 6, "", ("8.8.8.8", 0))]

    gr.socket.getaddrinfo = slow
    try:
        w = WebServer(port=0)
        w._running = True
        w.update_target(
            tid="h1",
            label="Hostname",
            ip="uncached-host.example.com",
            status="green",
            latency_ms=5.0,
            jitter_ms=1.0,
            loss_rate=0.0,
            is_probe_result=True,
        )
        ss.invalidate_screen_cache()
        t0 = time.time()
        payload = ss.build_geo(w)
        dt = time.time() - t0
        row = payload["targets"][0] if payload.get("targets") else {}
        fast = dt < 0.35
        bg_ran = done.wait(2.0)
        unlocated = row.get("kind") == "public" and not row.get("geo")
    finally:
        gr.socket.getaddrinfo = real
        with gr._DNS_CACHE_LOCK:
            gr._DNS_CACHE.clear()
            gr._DNS_INFLIGHT.clear()
    ok = fast and bg_ran and unlocated
    print(f"geo dns off request path -> {ok} build_geo={dt:.2f}s unlocated={unlocated}")
    return ok


def test_geo_source_egress_off_request_path():
    """build_geo must not block on the egress HTTP probe; it reads the cache
    and prewarms the lookup on a background thread instead."""
    import threading
    import time
    import src.monitor_source_geo as msg
    import src.screen_service as ss
    orig_detect = msg.detect_route_local_ipv4
    orig_fetch = msg._fetch_public_egress_uncached
    done = threading.Event()
    hits = {"n": 0}

    def slow_fetch(timeout=2.5):
        hits["n"] += 1
        time.sleep(0.8)        # simulate a slow/timing-out egress probe
        done.set()
        return None

    msg.detect_route_local_ipv4 = lambda: "192.168.1.50"  # force NAT path
    msg._fetch_public_egress_uncached = slow_fetch
    with msg._EGRESS_CACHE_LOCK:
        msg._EGRESS_CACHE.update(
            {"ip": None, "ts": 0.0, "fail_ts": 0.0, "inflight": False})
    try:
        w = WebServer(port=0)
        w._running = True
        w.set_screen_geo(resolver=GeoResolver())  # monitor_geo unset -> auto
        w.update_target(tid="x", label="X", ip="8.8.8.8", status="green",
                        latency_ms=5.0, jitter_ms=1.0, loss_rate=0.0,
                        is_probe_result=True)
        ss.invalidate_screen_cache()
        t0 = time.time()
        payload = ss.build_geo(w)
        dt = time.time() - t0
        fast = dt < 0.4                # did NOT block on the 0.8s fetch
        bg_ran = done.wait(2.0)        # prewarm ran the fetch in background
    finally:
        msg.detect_route_local_ipv4 = orig_detect
        msg._fetch_public_egress_uncached = orig_fetch
        with msg._EGRESS_CACHE_LOCK:
            msg._EGRESS_CACHE.update(
                {"ip": None, "ts": 0.0, "fail_ts": 0.0, "inflight": False})
    ok = fast and bg_ran and payload.get("source") is None
    print(f"geo egress off request path -> {ok} build_geo={dt:.2f}s bg_fetch={hits['n']}")
    return ok


def test_maphint_db_warning_order():
    """geo_db_ready hint must append after overseas branches, not before."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    anchor = "let mapHint=mapMode==='china'"
    start = html.find(anchor)
    assert start >= 0, "mapHint block missing"
    block = html[start:start + 900]
    db_pos = block.find("geo_db_ready===false")
    china_pos = block.find("hiddenOverseas.length")
    world_pos = block.find("overseas.length")
    ok = db_pos > china_pos > 0 and db_pos > world_pos > 0
    print(f"maphint db warning order -> {ok}")
    return ok


def test_mark_scrollable_includes_root():
    """markScrollable(root) must tag root when root is .topo-detail (querySelectorAll skips self)."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    ok = (
        "base.matches" in html
        and "base.matches('.pbody,.tline,.topo-detail')" in html
        and "markScrollable(document.getElementById('topoDetail'))" in html
    )
    print(f"markScrollable root self -> {ok}")
    return ok


def test_render_geo_marks_topo_detail():
    """renderGeo async path must markScrollable after topoDetail innerHTML updates."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    start = html.find("function renderGeo(")
    assert start >= 0, "renderGeo missing"
    block = html[start:start + 12000]
    topo_pos = block.find("getElementById('topoDetail').innerHTML")
    mark_pos = block.find("markScrollable(document.getElementById('topoDetail'))", topo_pos)
    ok = topo_pos > 0 and mark_pos > topo_pos
    print(f"renderGeo marks topoDetail -> {ok}")
    return ok


def test_geo_chart_zero_size_guard():
    """Map controls must not render ECharts while #geoChart is hidden (0×0)."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    ok = (
        "function isGeoChartReady()" in html
        and "function disposeGeoChart()" in html
        and "if(!isGeoChartReady()) return;" in html
        and "if(topoMode!=='geo'||!geoData) return;" in html
        and "if(topoMode==='geo'&&geoData) renderGeo(geoData,false);" in html
        and "if(isGeoChartReady()) geoChart.resize()" in html
        and "#centerPanel:not(.geo-mode) #btnMapChina" in html
    )
    print(f"geo zero-size guard -> {ok}")
    return ok


def main():
    tests = [
        ("parse_window", test_parse_window()),
        ("scores", test_score_helpers()),
        ("summarize_break", test_summarize_break_wording()),
        ("break_kind", test_break_kind_display()),
        ("target_merge", test_target_merge_scheme_c()),
        ("overseas_coords", test_overseas_coords()),
        ("china_suffix_coords", test_china_city_suffix_coords()),
        ("geo_resolver", test_geo_resolver()),
        ("geo_ui_fields", test_build_manual_geo_from_fields()),
        ("monitor_source", test_monitor_source_geo()),
        ("resolve_probe", test_resolve_probe_ipv4()),
        ("demo_geo", test_demo_geo_shape()),
        ("build_geo", test_build_geo()),
        ("build_geo_stats", test_build_geo_stats_private_vs_unlocated()),
        ("route_diff", test_route_diff()),
        ("demo_events", test_demo_events_shape()),
        ("merged_graph", test_merged_graph()),
        ("merged_unk_isolated", test_merged_unknown_hops_not_shared()),
        ("path_graph_timeouts", test_path_graph_distinct_timeout_hops()),
        ("invalidate_cache", test_invalidate_cache()),
        ("cache_web_instance", test_screen_cache_per_web_instance()),
        ("builders", test_build_overview_paths()),
        ("events_db", test_build_events_db()),
        ("topo_layout", test_topo_layout_covers_all_hops()),
        ("http", test_http_routes()),
        ("window_valid", test_window_validation_normalizes()),
        ("error_fallback", test_error_fallback_no_demo()),
        ("dns_cached", test_dns_resolution_cached()),
        ("dns_off_path", test_geo_dns_off_request_path()),
        ("maphint_db", test_maphint_db_warning_order()),
        ("markscroll_root", test_mark_scrollable_includes_root()),
        ("render_geo_markscroll", test_render_geo_marks_topo_detail()),
        ("geo_zero_guard", test_geo_chart_zero_size_guard()),
        ("egress_off_path", test_geo_source_egress_off_request_path()),
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
