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


def test_alert_path_ok_while_probe_fails():
    """Red probe + clean traceroute must not read like the outage is false."""
    from src.trace_policy import summarize_for_alert, summarize_for_display

    hops = [
        {"hop": i, "ip": f"10.0.0.{i}", "status": "ok"}
        for i in range(1, 7)
    ]
    hops[-1]["ip"] = "221.13.0.217"
    alert = summarize_for_alert(
        hops, ping_type="icmp", failure_reason="no_reply",
        target_ip="221.13.0.217")
    display = summarize_for_display(
        hops, ping_type="icmp", failure_reason="no_reply",
        status="red", probe_success=False, target_ip="221.13.0.217")
    text = alert.get("text") or ""
    ok = (
        "监测仍失败" in text
        and "ICMP 无响应" in text
        and "可达目标" in text
        and "Echo 仍无响应" in text
        and "221.13.0.217" in text
        and "路由可达" not in text
        and "路径完整" not in text
        and alert.get("reached") is True
        and display.get("text") == text
    )
    print(f"alert path ok while probe fails -> {ok} text={text!r}")
    return ok


def test_alert_trace_not_reached_target():
    """Clean trace with last hop != target must not claim route reached target."""
    from src.trace_policy import summarize_for_alert

    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok"},
        {"hop": 2, "ip": "20.0.0.1", "status": "ok"},
    ]
    alert = summarize_for_alert(
        hops, ping_type="icmp", failure_reason="no_reply",
        target_ip="221.13.0.217")
    text = alert.get("text") or ""
    ok = (
        "未确认到达目标" in text
        and "221.13.0.217" in text
        and "20.0.0.1" in text
        and "路由可达" not in text
        and "禁 ping" not in text
        and alert.get("reached") is False
    )
    print(f"alert trace not reached target -> {ok} text={text!r}")
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


def test_monitor_geo_persists_reload():
    """settings.monitor_geo must survive ConfigManager reload (_sanitize_settings)."""
    import json
    import tempfile
    from src.config_manager import ConfigManager

    td = tempfile.mkdtemp()
    path = os.path.join(td, "config.json")
    geo = {"lat": 39.9042, "lon": 116.4074, "label": "Office", "city": "北京"}
    cm = ConfigManager(path)
    cm.set_monitor_geo(geo)
    with open(path, encoding="utf-8") as fh:
        saved = json.load(fh)["settings"].get("monitor_geo")
    cm2 = ConfigManager(path)
    mg, _ = cm2.get_screen_geo_bundle()
    ok = (
        saved
        and saved.get("lat") == geo["lat"]
        and mg is not None
        and mg.get("lat") == geo["lat"]
        and mg.get("lon") == geo["lon"]
    )
    cm2.set_monitor_geo(None)
    cm3 = ConfigManager(path)
    mg3, _ = cm3.get_screen_geo_bundle()
    ok = ok and mg3 is None
    print(f"monitor_geo persists reload -> {ok}")
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
        and "prewarm_ip2region_download_async" in open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
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
        and "screen.html" in open(os.path.join(ROOT, "build_exe.spec"), encoding="utf-8").read()
        # 3D globe (globe.gl) — twin of the 2D map; assets vendored + bundled
        and "renderGlobe" in html
        and "toggleGlobe" in html
        and "btnGlobe" in html
        and "hasWebGL" in html
        and "globe.gl.min.js" in html
        and "jpg|jpeg|png|webp" in ws  # /vendor route serves Earth textures
        and os.path.isfile(os.path.join(ROOT, "src", "web", "vendor", "globe.gl.min.js"))
        and os.path.getsize(os.path.join(ROOT, "src", "web", "vendor", "globe.gl.min.js")) > 100000
        and os.path.isfile(os.path.join(ROOT, "src", "web", "vendor", "earth-blue-marble.jpg"))
        # globe Phase-2: graticule, click-to-fly, interaction-aware auto-rotate
        and "globePauseRotate" in html
        and "onPointClick" in html
        # globe style switch (写实 ⇄ 城市灯光) + click-linked detail + label declutter
        and "applyGlobeStyle" in html
        and "setGlobeStyle" in html
        and "showGlobeNodeDetail" in html
        and "drillGlobeDetail" in html
        and "globeZoomIn" in html
        and os.path.isfile(os.path.join(ROOT, "src", "web", "vendor", "earth-night.jpg"))
        # globe country hover: highlight + name + pause auto-rotate (Natural Earth polys)
        and "onGlobePolyHover" in html
        and "polygonsData" in html
        and "polygonLabel" in html
        and os.path.isfile(os.path.join(ROOT, "src", "web", "vendor", "ne_countries.json"))
        and os.path.getsize(os.path.join(ROOT, "src", "web", "vendor", "ne_countries.json")) > 400000
        and os.path.isfile(os.path.join(ROOT, "scripts", "build_globe_countries.py"))
        and "applyGlobePolygonStyle" in html
        and "GLOBE_HOVER_ROTATE_DELAY_MS" in html
        and "globeClearPolyHover" in html
        and "logarithmicDepthBuffer" in html
        # Chinese country names on both the 2D world map (nameMap) and the 3D globe
        and "CN_COUNTRY" in html
        and "cnCountry" in html
        and "nameMap" in html
        and '"中国"' in html
        # globe perf: cap render resolution on extreme DPI + pause when hidden
        and "setPixelRatio" in html
        and "visibilitychange" in html
        and "webglcontextlost" in html
        # globe search/jump: locate a node or country and fly the camera there;
        # node labels double as large click targets (dots are hard to hit on a sphere)
        and "globeSearchInput" in html
        and "globeJumpToNode" in html
        and "globeJumpToCountry" in html
        and "globeFeatureCentroid" in html
        and "setupGlobeSearch" in html
        and "glb-clickable" in html
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


def test_geo_xdb_foolproof_bootstrap():
    """First-run: setup.bat + start.bat ensure xdb; main kicks async download."""
    main_py = open(os.path.join(ROOT, "main.py"), encoding="utf-8").read()
    bootstrap = open(os.path.join(ROOT, "src", "geo_bootstrap.py"), encoding="utf-8").read()
    resolver = open(os.path.join(ROOT, "src", "geo_resolver.py"), encoding="utf-8").read()
    dl = open(os.path.join(ROOT, "scripts", "download_ip2region.py"), encoding="utf-8").read()
    start_bat = open(os.path.join(ROOT, "start.bat"), encoding="utf-8").read()
    setup_bat = open(os.path.join(ROOT, "setup.bat"), encoding="utf-8").read()
    ok = (
        "def is_valid_xdb_file" in resolver
        and "def probe_xdb_file" in resolver
        and "is_valid_xdb_file(p)" in resolver
        and "is_valid_xdb_file(dest)" in bootstrap
        and "is_valid_xdb_file(dest)" in dl
        and "def prewarm_ip2region_download_async" in bootstrap
        and "resolve_xdb_path(BASE_DIR)" in main_py
        and "prewarm_ip2region_download_async(BASE_DIR)" in main_py
        and "download_ip2region.py" in start_bat
        and "download_ip2region.py" in setup_bat
        and "--quiet" in start_bat
    )
    print(f"geo xdb foolproof bootstrap -> {ok}")
    return ok


def test_xdb_corrupt_triggers_redownload():
    """A tiny corrupt ip2region_v4.xdb must not skip download/repair."""
    import shutil
    import tempfile
    import src.geo_bootstrap as gb
    from src.geo_bootstrap import ensure_ip2region_xdb, xdb_dest_for_base
    from src.geo_resolver import is_valid_xdb_file

    td = tempfile.mkdtemp()
    dest = xdb_dest_for_base(td)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(b"xxx")
    assert not is_valid_xdb_file(dest)

    real_xdb = os.path.join(ROOT, "assets", "ip2region_v4.xdb")
    calls = {"n": 0}
    real = gb.download_ip2region_xdb

    def fake_download(path, **kw):
        calls["n"] += 1
        if os.path.isfile(real_xdb):
            shutil.copy2(real_xdb, path)
        else:
            with open(path, "wb") as fh:
                fh.write(b"x" * gb.MIN_XDB_BYTES)
        return True

    gb.download_ip2region_xdb = fake_download  # type: ignore
    try:
        path = ensure_ip2region_xdb(td, allow_download=True)
        ok = calls["n"] == 1 and is_valid_xdb_file(path)
    finally:
        gb.download_ip2region_xdb = real  # type: ignore
    print(f"xdb corrupt triggers redownload -> {ok}")
    return ok


def test_xdb_large_corrupt_triggers_redownload():
    """A 1MB corrupt ip2region_v4.xdb must not skip download/repair."""
    import shutil
    import tempfile
    import src.geo_bootstrap as gb
    from src.geo_bootstrap import ensure_ip2region_xdb, xdb_dest_for_base
    from src.geo_resolver import GeoResolver, MIN_XDB_BYTES, is_valid_xdb_file, probe_xdb_file

    td = tempfile.mkdtemp()
    dest = xdb_dest_for_base(td)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(b"\x00" * MIN_XDB_BYTES)
    assert not probe_xdb_file(dest)
    assert not is_valid_xdb_file(dest)

    real_xdb = os.path.join(ROOT, "assets", "ip2region_v4.xdb")
    calls = {"n": 0}
    real = gb.download_ip2region_xdb

    def fake_download(path, **kw):
        calls["n"] += 1
        if os.path.isfile(real_xdb):
            shutil.copy2(real_xdb, path)
            return True
        with open(path, "wb") as fh:
            fh.write(b"\x00" * MIN_XDB_BYTES)
        return True

    gb.download_ip2region_xdb = fake_download  # type: ignore
    try:
        path = ensure_ip2region_xdb(td, allow_download=True)
        rx = GeoResolver(path)
        ok = (
            calls["n"] == 1
            and probe_xdb_file(path)
            and rx.is_xdb_loaded()
            and rx.lookup_public_ip("220.181.38.148") is not None
        )
    finally:
        gb.download_ip2region_xdb = real  # type: ignore
    print(f"xdb large corrupt triggers redownload -> {ok}")
    return ok


def test_geo_xdb_off_request_path():
    """build_geo must not synchronously load ip2region xdb on /api/screen/geo."""
    import tempfile
    import time
    import src.geo_resolver as gr
    import src.screen_service as ss

    with tempfile.NamedTemporaryFile(suffix=".xdb", delete=False) as fh:
        fh.write(b"x" * 512)
        fake_path = fh.name

    real_init = gr._XdbMemorySearcher.__init__

    def slow_init(self, db_path: str):
        time.sleep(0.55)
        raise ValueError("slow xdb read")

    orig_resolve = gr.GeoResolver.resolve_xdb_path
    gr._XdbMemorySearcher.__init__ = slow_init  # type: ignore[method-assign]
    payload = {}
    dt = 999.0
    try:
        missing = os.path.join(tempfile.gettempdir(), "verify_xdb_off_missing.xdb")
        res = gr.GeoResolver(xdb_path=missing)
        gr.GeoResolver.resolve_xdb_path = staticmethod(lambda base_dir=None: fake_path)  # type: ignore
        w = WebServer(port=0)
        w._running = True
        w._geo_resolver = res
        t0 = time.time()
        payload = ss.build_geo(w, resolver=res)
        dt = time.time() - t0
        ok = dt < 0.35 and payload.get("geo_db_ready") is False
    finally:
        gr._XdbMemorySearcher.__init__ = real_init  # type: ignore[method-assign]
        gr.GeoResolver.resolve_xdb_path = orig_resolve
        try:
            os.unlink(fake_path)
        except OSError:
            pass
    print(f"geo xdb off request path -> {ok} build_geo={dt:.2f}s geo_db_ready={payload.get('geo_db_ready')}")
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


def test_geo_viewport_setoption_merge():
    """Viewport changes must merge setOption; notMerge caused wrong geo scale on map switch."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    start = html.find("function renderGeo(")
    assert start >= 0, "renderGeo missing"
    block = html[start:start + 32000]
    set_pos = block.rfind("chart.setOption({")
    assert set_pos >= 0, "renderGeo setOption missing"
    tail = block[set_pos:set_pos + 8000]
    ok = (
        "}, false);" in tail
        and "viewportChanged&&!geoUserRoam);" not in tail
        and "if(viewportChanged&&!geoUserRoam)" in tail
    )
    print(f"geo viewport setOption merge -> {ok}")
    return ok


def test_counts_hint_includes_orange():
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    ok = "警告 ${c.orange||0}" in html or "警告 ${c.orange" in html
    print(f"counts hint includes orange -> {ok}")
    return ok


def test_overview_fresh_refresh():
    """Live panel refresh must bypass overview TTL and fetch with geo/paths."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    svc = open(os.path.join(ROOT, "src", "screen_service.py"), encoding="utf-8").read()
    ws = open(os.path.join(ROOT, "src", "web_server.py"), encoding="utf-8").read()
    ok = (
        "async function refreshLivePanels" in html
        and "api('overview',{fresh:true})" in html
        and "fresh: bool = False" in svc
        and 'request.args.get("fresh")' in ws
    )
    print(f"overview fresh refresh -> {ok}")
    return ok


def test_world_geo_hover_country_label():
    """2D world map must show Chinese country name on region hover."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    block = html[html.find("function renderGeo("):html.find("/* ───────── 3D globe", html.find("function renderGeo("))]
    ok = (
        "mapMode==='world'?{" in block
        and "show:true" in block
        and "formatter: p=>cnCountry(p.name)" in block
        and "return esc(cnCountry(p.name)" in block
    )
    print(f"world geo hover country label -> {ok}")
    return ok


def test_globe_countries_vendor_names():
    """Vendored ne_countries.json must carry real country names (not all Unknown)."""
    import json
    import re

    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    m = re.search(r"const CN_COUNTRY=(\{[^;]+\});", html)
    cn_map = json.loads(m.group(1)) if m else {}

    path = os.path.join(ROOT, "src", "web", "vendor", "ne_countries.json")
    data = json.load(open(path, encoding="utf-8"))
    names = [(f.get("properties") or {}).get("name") for f in data.get("features") or []]
    missing = sorted({n for n in names if n and n not in cn_map})
    ok = (
        len(names) >= 200
        and sum(1 for n in names if n and n != "Unknown") >= 200
        and "China" in names
        and "United States of America" in names
        and cn_map.get("Aruba") == "阿鲁巴"
        and not missing
    )
    if missing:
        print(f"  missing CN_COUNTRY keys ({len(missing)}): " + ", ".join(repr(n) for n in missing[:8]))
    print(f"globe countries vendor names -> {ok}")
    return ok


def test_globe_hover_rotate_delay():
    """Country hover must delay auto-rotate resume (not instant on mouse-out)."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    hover = html[html.find("function onGlobePolyHover("):html.find("function onGlobePointClick", html.find("function onGlobePolyHover("))]
    ok = (
        "GLOBE_HOVER_ROTATE_DELAY_MS" in html
        and "globePauseRotate(GLOBE_HOVER_ROTATE_DELAY_MS)" in hover
        and "autoRotate=!globeHoverPoly" not in hover
        and "clearTimeout(globe.__rotTimer)" in hover
        and "globeClearPolyHover()" in html
    )
    print(f"globe hover rotate delay -> {ok}")
    return ok


def test_globe_dynamic_data_guard():
    """3D globe must skip points/arcs refresh when poll data is unchanged."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    block = html[html.find("function renderGlobe("):html.find("function syncGlobeVisibility", html.find("function renderGlobe("))]
    sig_block = html[html.find("function globeDynamicSig("):html.find("function colorForStatus", html.find("function globeDynamicSig("))]
    ok = (
        "function globeDynamicSig" in html
        and "g.__dynSig!==dynSig" in block
        and "g.__dynSig=dynSig" in block
        and block.count("pointsData(pts)") == 1
        and "resumeAnimation" not in block
        and "x.tid,x.name,x.r" in sig_block
    )
    print(f"globe dynamic data guard -> {ok}")
    return ok


def test_globe_dynamic_sig_target_label():
    """Target rename must change globeDynamicSig so 3D labels refresh."""
    import json

    def globe_dynamic_sig(pts, label_pts, arcs, rings):
        return json.dumps(
            {
                "p": [[x["lat"], x["lng"], x["color"], x.get("tid"), x.get("name"), x["r"], x["alt"]] for x in pts],
                "l": [x.get("tid") or x.get("name") for x in label_pts],
                "a": [[x["a"], x["b"], x["c"], x["d"], x.get("color") and x["color"][1]] for x in arcs],
                "r": [[x["lat"], x["lng"]] for x in rings],
            },
            sort_keys=True,
        )

    pt_old = {"lat": 1, "lng": 2, "color": "#f00", "tid": "T1", "name": "Old Name", "r": 0.4, "alt": 0.03}
    pt_new = dict(pt_old, name="New Name")
    sig_old = globe_dynamic_sig([pt_old], [pt_old], [], [])
    sig_new = globe_dynamic_sig([pt_new], [pt_new], [], [])
    ok = sig_old != sig_new
    print(f"globe dynamic sig target label -> {ok}")
    return ok


def test_globe_stale_detail_sync():
    """3D globe must clear stale detail/selection when a target disappears."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    globe_block = html[html.find("function renderGlobe("):html.find("function syncGlobeVisibility", html.find("function renderGlobe("))]
    rotate_block = html[html.find("function refreshRotateState("):html.find("function syncAutoRotate", html.find("function refreshRotateState("))]
    static_ok = (
        "function ensureSelectedTidValid" in html
        and "function syncGlobeDetailState" in html
        and "function renderGlobeMapSummary" in html
        and "ensureSelectedTidValid();" in rotate_block
        and rotate_block.find("ensureSelectedTidValid();") < rotate_block.find("poolInfo.pool.length<ROTATE.minPaths")
        and "syncGlobeDetailState(data)" in globe_block
        and "targets.some(t=>t.tid===tid)" in html[html.find("function drillGlobeDetail("):html.find("function globeCameraFor", html.find("function drillGlobeDetail("))]
    )

    def ensure_selected_tid_valid(topo_mode, selected_tid, geo_targets, paths):
        if topo_mode == "geo":
            if not geo_targets:
                return None
            if not selected_tid or not any(t["tid"] == selected_tid for t in geo_targets):
                mappable = [t for t in geo_targets if t.get("geo")]
                return (mappable[0] if mappable else geo_targets[0])["tid"]
            return selected_tid
        if topo_mode == "single":
            if not paths:
                return None
            if not selected_tid or not any(p["tid"] == selected_tid for p in paths):
                return paths[0]["tid"]
            return selected_tid
        return selected_tid

    def sync_globe_detail_state(globe_detail_tid, targets):
        if not globe_detail_tid:
            return None, False
        if any(t["tid"] == globe_detail_tid for t in targets):
            return globe_detail_tid, False
        return None, True

    geo_targets = [{"tid": "T1", "geo": {"lat": 1, "lon": 2}}]
    selected = ensure_selected_tid_valid("geo", "T2", geo_targets, [])
    detail_tid, cleared = sync_globe_detail_state("T2", geo_targets)
    logic_ok = selected == "T1" and detail_tid is None and cleared
    ok = static_ok and logic_ok
    print(f"globe stale detail sync -> {ok}")
    return ok


def test_globe_stage_scale_compensation():
    """3D globe must compensate #stage CSS scale for pointer/raycast alignment."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    measure = html[
        html.find("function measureStageScale(") : html.find(
            "function clearGlobeScaleCompensation(", html.find("function measureStageScale(")
        )
    ]
    comp = html[
        html.find("function syncGlobeScaleCompensation(") : html.find(
            "function renderGlobe(", html.find("function syncGlobeScaleCompensation(")
        )
    ]
    render = html[
        html.find("function renderGlobe(") : html.find(
            "function syncGlobeVisibility", html.find("function renderGlobe(")
        )
    ]
    vis = html[
        html.find("function syncGlobeVisibility(") : html.find(
            "document.addEventListener('visibilitychange'", html.find("function syncGlobeVisibility(")
        )
    ]
    resize_block = html[
        html.find("addEventListener('resize'") : html.find("fitStage();", html.find("addEventListener('resize'")) + 120
    ]
    ok = (
        "function measureStageScale(" in html
        and "function syncGlobeScaleCompensation(" in html
        and "function syncGlobeRenderSize(" in html
        and "getBoundingClientRect()" in measure
        and "sr.width/stage.clientWidth" in measure
        and "clearGlobeScaleCompensation" in html
        and "Math.abs(s-1)<0.001" in comp
        and "__globeScaleSig" in comp
        and "parent.clientWidth" in comp
        and "(1/s)" in comp
        and "syncGlobeRenderSize(el, g)" in render
        and "syncGlobeScaleCompensation()" not in render
        and "syncGlobeScaleCompensation();" in vis
        and "syncGlobeScaleCompensation();" in resize_block
    )
    print(f"globe stage scale compensation -> {ok}")
    return ok


def test_geo_place_label_cn():
    """Monitor geo labels translate city/region/country and avoid mixed CN/EN."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    block = html[html.find("function geoPlaceLabel("):html.find("function geoScatterLabelPos", html.find("function geoPlaceLabel("))]
    static_ok = (
        "const CN_PLACE=" in html
        and "function cnPlace" in html
        and "cnPlace(g.city)" in block
        and "cnPlace(g.region)" in block
        and "cnPlace(g.country)" in block
    )

    cn_country = {"United States": "美国", "China": "中国"}
    cn_place = {"California": "加利福尼亚", "North Carolina": "北卡罗来纳"}

    def cn_place_fn(name):
        if name is None:
            return ""
        s = str(name).strip()
        if not s or s == "0":
            return ""
        if s in cn_country:
            return cn_country[s]
        if s in cn_place:
            return cn_place[s]
        if any("\u4e00" <= ch <= "\u9fff" for ch in s):
            return s
        return ""

    def geo_place_label(g):
        if not g:
            return ""
        city = cn_place_fn(g.get("city"))
        region = cn_place_fn(g.get("region"))
        country = cn_place_fn(g.get("country"))
        parts = []
        if city:
            parts.append(city)
        if region and region != city:
            parts.append(region)
        if country and country != city and country != region:
            parts.append(country)
        if parts:
            return " · ".join(parts)
        raw = [x for x in (g.get("city"), g.get("region"), g.get("country")) if x and str(x).strip() and str(x).strip() != "0"]
        return " · ".join(raw) if raw else ""

    logic_ok = (
        geo_place_label({"city": "山景城", "region": "加利福尼亚", "country": "United States"})
        == "山景城 · 加利福尼亚 · 美国"
        and geo_place_label({"city": "北京", "region": "北京", "country": "中国"}) == "北京 · 中国"
        and geo_place_label({"city": "Unknownville", "region": "California", "country": "United States"})
        == "加利福尼亚 · 美国"
        and "United States" not in geo_place_label(
            {"city": "山景城", "region": "加利福尼亚", "country": "United States"}
        )
    )
    ok = static_ok and logic_ok
    print(f"geo place label cn -> {ok}")
    return ok


def test_monitor_source_label_cn():
    """Monitor-source pins reuse geoPlaceLabel; auto path must not show raw English."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    static_ok = (
        "function monitorSourceLabel" in html
        and html.count("monitorSourceLabel(src)") >= 3
    )

    cn_country = {"United States": "美国"}
    cn_place = {"California": "加利福尼亚", "Los Angeles": "洛杉矶"}

    def cn_place_fn(name):
        if name is None:
            return ""
        s = str(name).strip()
        if not s or s == "0":
            return ""
        if s in cn_country:
            return cn_country[s]
        if s in cn_place:
            return cn_place[s]
        if any("\u4e00" <= ch <= "\u9fff" for ch in s):
            return s
        return ""

    def geo_place_label(g):
        if not g:
            return ""
        city = cn_place_fn(g.get("city"))
        region = cn_place_fn(g.get("region"))
        country = cn_place_fn(g.get("country"))
        parts = []
        if city:
            parts.append(city)
        if region and region != city:
            parts.append(region)
        if country and country != city and country != region:
            parts.append(country)
        if parts:
            return " · ".join(parts)
        raw = [x for x in (g.get("city"), g.get("region"), g.get("country")) if x and str(x).strip() and str(x).strip() != "0"]
        return " · ".join(raw) if raw else ""

    def monitor_source_label(src):
        if not src:
            return "监控主机"
        if src.get("loc_source") == "manual":
            custom = str(src.get("label") or "").strip()
            if custom:
                return custom
        place = geo_place_label(src)
        return ("监控主机 · " + place) if place else "监控主机"

    auto_src = {
        "label": "监控主机 · Los Angeles",
        "loc_source": "egress_ip",
        "city": "Los Angeles",
        "region": "California",
        "country": "United States",
    }
    manual_src = {
        "label": "上海办公室",
        "loc_source": "manual",
        "city": "上海",
        "region": "上海",
        "country": "中国",
    }
    auto_label = monitor_source_label(auto_src)
    manual_label = monitor_source_label(manual_src)
    logic_ok = (
        "Los Angeles" not in auto_label
        and "California" not in auto_label
        and "United States" not in auto_label
        and "洛杉矶" in auto_label
        and manual_label == "上海办公室"
    )
    ok = static_ok and logic_ok
    print(f"monitor source label cn -> {ok}")
    return ok


def test_screen_data_seq_guard():
    """loadAll/refreshLivePanels must ignore stale API responses when requests overlap."""
    html_path = os.path.join(ROOT, "src", "web", "screen.html")
    html = open(html_path, encoding="utf-8").read()
    load_start = html.find("async function loadAll(")
    refresh_start = html.find("async function refreshLivePanels(")
    assert load_start >= 0 and refresh_start >= 0
    load_block = html[load_start:html.find("function syncCenterPanelMode", load_start)]
    refresh_block = html[refresh_start:html.find("async function refreshPaths", refresh_start)]
    ok = (
        "let screenDataSeq=0" in html
        and "const seq=++screenDataSeq" in load_block
        and load_block.count("if(seq!==screenDataSeq) return") >= 2
        and "const seq=++screenDataSeq" in refresh_block
        and "if(seq!==screenDataSeq) return" in refresh_block
    )
    print(f"screen data seq guard -> {ok}")
    return ok


def test_overseas_focus_viewport_points():
    """Overseas focus must not include monitor source in bbox (avoids Africa center)."""
    html = open(os.path.join(ROOT, "src", "web", "screen.html"), encoding="utf-8").read()
    fn = html[html.find("function collectGeoFocusPoints("):html.find("function buildGraticule(", html.find("function collectGeoFocusPoints("))]
    ok = (
        "if(!isOverseasGeo(g)&&src&&src.lon!=null&&src.lat!=null)" in fn
        and "}else if(src&&src.lon!=null&&src.lat!=null){" in fn
    )
    print(f"overseas focus viewport points -> {ok}")
    return ok


def main():
    tests = [
        ("parse_window", test_parse_window()),
        ("scores", test_score_helpers()),
        ("summarize_break", test_summarize_break_wording()),
        ("break_kind", test_break_kind_display()),
        ("alert_path_ok", test_alert_path_ok_while_probe_fails()),
        ("alert_not_reached", test_alert_trace_not_reached_target()),
        ("target_merge", test_target_merge_scheme_c()),
        ("overseas_coords", test_overseas_coords()),
        ("china_suffix_coords", test_china_city_suffix_coords()),
        ("geo_resolver", test_geo_resolver()),
        ("monitor_geo_reload", test_monitor_geo_persists_reload()),
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
        ("xdb_off_path", test_geo_xdb_off_request_path()),
        ("xdb_foolproof", test_geo_xdb_foolproof_bootstrap()),
        ("xdb_corrupt", test_xdb_corrupt_triggers_redownload()),
        ("xdb_large_corrupt", test_xdb_large_corrupt_triggers_redownload()),
        ("maphint_db", test_maphint_db_warning_order()),
        ("markscroll_root", test_mark_scrollable_includes_root()),
        ("render_geo_markscroll", test_render_geo_marks_topo_detail()),
        ("geo_zero_guard", test_geo_chart_zero_size_guard()),
        ("geo_viewport_merge", test_geo_viewport_setoption_merge()),
        ("overseas_focus_pts", test_overseas_focus_viewport_points()),
        ("screen_data_seq", test_screen_data_seq_guard()),
        ("counts_hint_orange", test_counts_hint_includes_orange()),
        ("overview_fresh", test_overview_fresh_refresh()),
        ("world_geo_label", test_world_geo_hover_country_label()),
        ("globe_countries_names", test_globe_countries_vendor_names()),
        ("globe_hover_rotate_delay", test_globe_hover_rotate_delay()),
        ("globe_dyn_guard", test_globe_dynamic_data_guard()),
        ("globe_dyn_sig_label", test_globe_dynamic_sig_target_label()),
        ("globe_stale_detail", test_globe_stale_detail_sync()),
        ("globe_scale_comp", test_globe_stage_scale_compensation()),
        ("geo_place_label", test_geo_place_label_cn()),
        ("monitor_source_label", test_monitor_source_label_cn()),
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
