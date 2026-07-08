"""Read-only aggregators for the /screen situational dashboard.

All builders are side-effect free: they never schedule traceroute, mutate
targets, or touch alert/outbox state.
"""
from __future__ import annotations

import datetime
import threading
import time
from typing import Any, Callable, Optional

from src.trace_policy import (
    describe_failure,
    should_request_traceroute,
    summarize_for_display,
    trace_skip_summary,
)
from src.webhook_error_labels import enrich_webhook_failure

try:
    from src.geo_resolver import GeoResolver, parse_manual_geo
    from src.monitor_source_geo import (
        resolve_monitor_source, prewarm_monitor_source)
except ImportError:
    GeoResolver = None  # type: ignore
    parse_manual_geo = None  # type: ignore
    resolve_monitor_source = None  # type: ignore
    prewarm_monitor_source = None  # type: ignore

_CACHE_LOCK = threading.Lock()
_CACHE: dict[tuple, tuple[float, Any]] = {}

# Long-window SLA is expensive; cache screen TOP/overview aggregates briefly.
_CACHE_TTL = {"1h": 15.0, "today": 30.0, "7d": 300.0}

SCORE_META = {
    "risk": {
        "formula": "min(100, red×25 + orange×8 + open_incidents×5 + webhook_failures×3)",
        "inputs": ["当前 red 节点数", "当前 orange 节点数",
                   "未恢复 incident 数", "近期 Webhook 失败条数"],
        "grades": {"高": ">=60", "中": ">=30", "低": ">=10", "很低": "<10"},
    },
    "health": {
        "formula": "10×(0.55×green_ratio + 0.45×uptime_part) − penalty×10",
        "uptime_part": "窗口 SLA 平均连通率/100；无 SLA 数据时用 green_ratio",
        "penalty": "(red×0.08 + orange×0.03) / 节点总数",
        "grades": {"优": ">=9.0", "良": ">=7.5", "中": ">=5.0", "差": "<5.0"},
    },
}


def invalidate_screen_cache() -> None:
    """Drop overview/topn TTL cache after live state changes."""
    with _CACHE_LOCK:
        _CACHE.clear()


def parse_window(window: str, now: float | None = None) -> tuple[float, float, str]:
    """Return (start_ts, end_ts, label) for supported window tokens."""
    now = float(now if now is not None else time.time())
    w = (window or "today").strip().lower()
    if w == "1h":
        return now - 3600, now, "近 1 小时"
    if w == "7d":
        return now - 7 * 86400, now, "近 7 天"
    lt = datetime.datetime.fromtimestamp(now)
    start = datetime.datetime(lt.year, lt.month, lt.day).timestamp()
    return start, now, "今日"


def _cache_get(key: tuple, ttl: float):
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    return None


def _cache_set(key: tuple, value: Any):
    with _CACHE_LOCK:
        _CACHE[key] = (time.time(), value)


def compute_risk_score(*, red: int, orange: int, open_incidents: int,
                       webhook_failures: int) -> dict:
    raw = red * 25 + orange * 8 + open_incidents * 5 + webhook_failures * 3
    score = min(100.0, float(raw))
    if score >= 60:
        grade = "高"
    elif score >= 30:
        grade = "中"
    elif score >= 10:
        grade = "低"
    else:
        grade = "很低"
    return {"score": round(score, 1), "grade": grade}


_NO_SCORE = {"score": None, "grade": "--"}


def compute_health_score(*, green: int, total: int, red: int, orange: int,
                         avg_uptime: float | None) -> dict:
    if total <= 0:
        return dict(_NO_SCORE)
    ratio = green / total
    uptime_part = (avg_uptime / 100.0) if avg_uptime is not None else ratio
    penalty = (red * 0.08 + orange * 0.03) / max(total, 1)
    score = max(0.0, min(10.0, 10.0 * (0.55 * ratio + 0.45 * uptime_part) - penalty * 10))
    if score >= 9.0:
        grade = "优"
    elif score >= 7.5:
        grade = "良"
    elif score >= 5.0:
        grade = "中"
    else:
        grade = "差"
    return {"score": round(score, 2), "grade": grade}


def _status_counts(targets: list[dict]) -> dict[str, int]:
    counts = {"targets": len(targets), "green": 0, "orange": 0,
              "red": 0, "paused": 0, "gray": 0}
    for t in targets:
        st = t.get("status") or "gray"
        if st in counts:
            counts[st] += 1
        else:
            counts["gray"] += 1
    counts["online"] = counts["green"] + counts["orange"] + counts["red"]
    return counts


def _read_traceroute(web, tid: str, ip: str,
                     open_inc: dict | None) -> tuple[dict | None, str]:
    """Return (payload, source_tag). Never schedules traceroute."""
    with web._tracer_lock:
        cached = web._tracer_cache.get(tid)
        if cached is not None and cached.get("ip") == ip:
            return dict(cached), "cache"
    ds = web._data_store
    if ds and open_inc:
        snap = ds.get_incident_traceroute(
            tid,
            float(open_inc.get("started_at") or time.time()),
            incident_id=open_inc.get("incident_id") or "",
        )
        if snap:
            return snap, "incident"
    return None, "none"


def _norm_ip(ip: str | None) -> str:
    return (ip or "").strip().lower()


def _last_hop_with_ip(hops: list | None) -> dict | None:
    for h in reversed(hops or []):
        ip = _norm_ip(h.get("ip"))
        if ip and ip != "*":
            return h
    return None


def should_merge_target_hop(hops: list | None, target_ip: str,
                            summary: dict | None = None) -> bool:
    """Scheme C: merge last hop with target when IPs match; else keep separate."""
    _ = summary  # reserved for future heuristics; IP match is the primary rule
    target = _norm_ip(target_ip)
    if not target:
        return False
    last = _last_hop_with_ip(hops)
    if not last:
        return False
    return _norm_ip(last.get("ip")) == target


def _path_graph(hops: list, tid: str, label: str, status: str,
                summary: dict, *, target_ip: str = "") -> dict:
    nodes = [{"id": "source", "type": "source", "label": "监控主机"}]
    edges = []
    prev = "source"
    last_nid_with_ip = None
    for h in hops or []:
        hip = (h.get("ip") or "").strip()
        if hip and hip != "*":
            nid = f"hop:{hip}"
        else:
            nid = f"hop:unk:{tid}:{h.get('hop', '?')}"
        if not any(n["id"] == nid for n in nodes):
            nodes.append({
                "id": nid,
                "type": "hop",
                "label": f"Hop {h.get('hop', '?')}",
                "ip": hip or "*",
                "status": h.get("status") or "ok",
                "rtt_ms": h.get("rtt_ms"),
            })
        st = h.get("status") or "ok"
        edge_status = "red" if st in ("break", "after") else status
        edges.append({"from": prev, "to": nid, "status": edge_status})
        prev = nid
        if hip and hip != "*":
            last_nid_with_ip = nid
    merge = should_merge_target_hop(hops, target_ip, summary)
    if merge and last_nid_with_ip:
        for n in nodes:
            if n["id"] == last_nid_with_ip:
                n["is_target"] = True
                n["target_label"] = label
                n["tid"] = tid
                n["target_status"] = status
                break
    else:
        tgt = f"target:{tid}"
        nodes.append({
            "id": tgt,
            "type": "target",
            "tid": tid,
            "label": label,
            "status": status,
        })
        edges.append({"from": prev, "to": tgt, "status": status})
    return {"nodes": nodes, "edges": edges, "summary": summary,
            "target_merged": merge}


def _hop_node_id(h: dict, tid: str | None = None) -> str:
    hip = (h.get("ip") or "").strip()
    if hip and hip != "*":
        return f"hop:{hip}"
    hop_no = h.get("hop", "?")
    if tid:
        return f"hop:unk:{tid}:{hop_no}"
    return f"hop:unk:{hop_no}"


def build_merged_graph(paths: list[dict]) -> dict:
    """Merge per-target paths — shared hop IPs become one node."""
    nodes: dict[str, dict] = {
        "source": {
            "id": "source", "type": "source", "label": "监控主机",
            "target_tids": [], "status": "ok",
        },
    }
    edges: dict[tuple, dict] = {}
    order: list[str] = ["source"]

    def _add_node(nid: str, **meta):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "target_tids": [], **meta}
            order.append(nid)
        ent = nodes[nid]
        ent["target_tids"] = list(set(ent.get("target_tids", []))
                                   | set(meta.pop("target_tids", [])))
        for k, v in meta.items():
            if k == "status" and v in ("break", "after", "red"):
                ent["status"] = v
            elif k not in ent or ent[k] in (None, "ok", "green"):
                ent[k] = v

    def _add_edge(frm: str, to: str, tid: str, status: str):
        key = (frm, to)
        st = "red" if status in ("break", "after", "red") else status
        if key not in edges:
            edges[key] = {"from": frm, "to": to, "status": st,
                          "weight": 0, "target_tids": []}
        e = edges[key]
        e["weight"] += 1
        e["target_tids"] = list(set(e["target_tids"]) | {tid})
        if st in ("break", "after", "red"):
            e["status"] = st

    ranked = sorted(
        paths,
        key=lambda p: (0 if p.get("status") == "red" else
                       1 if p.get("status") == "orange" else 2,
                       p.get("label") or ""))

    for p in ranked:
        tid = p.get("tid") or ""
        if not tid:
            continue
        nodes["source"]["target_tids"] = list(
            set(nodes["source"]["target_tids"]) | {tid})
        prev = "source"
        for h in p.get("hops") or []:
            nid = _hop_node_id(h, tid)
            st = h.get("status") or "ok"
            _add_node(
                nid,
                type="hop",
                label=f"Hop {h.get('hop', '?')}",
                ip=h.get("ip") or "*",
                status=st,
                rtt_ms=h.get("rtt_ms"),
                target_tids=[tid],
            )
            edge_st = st if st in ("break", "after", "filtered") else "ok"
            _add_edge(prev, nid, tid, edge_st)
            prev = nid
        resolve_ip = p.get("resolve_ip") or p.get("ip") or ""
        summary = p.get("summary") or {}
        if should_merge_target_hop(p.get("hops"), resolve_ip, summary):
            last = _last_hop_with_ip(p.get("hops"))
            if last:
                nid = _hop_node_id(last)
                if nid in nodes:
                    ent = nodes[nid]
                    ent["is_target"] = True
                    ent["target_label"] = p.get("label") or tid
                    ent["tid"] = tid
                    ent["target_status"] = p.get("status") or "gray"
        else:
            tgt = f"target:{tid}"
            _add_node(
                tgt,
                type="target",
                tid=tid,
                label=p.get("label") or tid,
                status=p.get("status") or "gray",
                target_tids=[tid],
            )
            _add_edge(prev, tgt, tid, p.get("status") or "gray")

    return {
        "node_order": order,
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "path_count": len(paths),
        "shared_hops": sum(
            1 for n in nodes.values()
            if n.get("type") == "hop" and len(n.get("target_tids") or []) > 1),
    }


def build_paths(web, *, window: str = "today", limit: int = 12) -> dict:
    with web._lock:
        targets = []
        for tid, t in web._targets.items():
            d = dict(t)
            d.setdefault("tid", tid)
            targets.append(d)
    open_map: dict[str, dict] = {}
    ds = web._data_store
    tids = [t["tid"] for t in targets if t.get("tid")]
    if ds and tids:
        try:
            open_map = ds.get_open_incidents(tids)
        except Exception:
            open_map = {}

    def _prio(t):
        st = t.get("status") or "gray"
        rank = {"red": 0, "orange": 1, "gray": 2, "green": 3, "paused": 4}
        return (rank.get(st, 5), t.get("label") or t.get("tid") or "")

    ordered = sorted(targets, key=_prio)[: max(1, min(limit, 50))]
    paths = []
    for t in ordered:
        tid = t.get("tid") or ""
        if not tid:
            continue
        if not web._history_data_available(tid):
            continue
        ip = t.get("ip") or ""
        status = t.get("status") or "gray"
        open_inc = open_map.get(tid)
        trace, source = _read_traceroute(web, tid, ip, open_inc)
        hops = (trace or {}).get("hops") or []
        tcp_checks = (trace or {}).get("tcp_checks")
        ping_type = t.get("ping_type")
        failure_reason = t.get("failure_reason")
        trace_applicable = should_request_traceroute(ping_type, failure_reason)
        if trace:
            summary = summarize_for_display(
                hops,
                tcp_checks=tcp_checks,
                status=status,
                ping_type=ping_type,
                probe_success=t.get("probe_success"),
                failure_reason=failure_reason,
                target_ip=(trace or {}).get("resolve_ip") or ip,
            )
            trace_status = "completed"
        elif status in ("red", "orange") and not trace_applicable:
            summary = trace_skip_summary(ping_type, failure_reason)
            trace_status = "skipped"
        else:
            summary = summarize_for_display(
                hops,
                tcp_checks=tcp_checks,
                status=status,
                ping_type=ping_type,
                probe_success=t.get("probe_success"),
                failure_reason=failure_reason,
                target_ip=ip,
            )
            trace_status = "none"
            if status in ("red", "orange"):
                with web._tracer_lock:
                    pending = web._tracer_cache.get(tid) is None
                trace_status = "pending" if pending and source == "none" else "none"
        graph = _path_graph(
            hops, tid, t.get("label") or tid, status, summary,
            target_ip=(trace or {}).get("resolve_ip") or ip)
        route_changed = bool((trace or {}).get("route_changed"))
        route_diff = None
        prev_hops: list = []
        if route_changed and ds:
            try:
                hist = ds.get_traceroute_history(tid, limit=3)
                if len(hist) >= 2:
                    prev_hops = hist[1].get("hops") or []
                    route_diff = build_route_diff(prev_hops, hops)
            except Exception:
                route_diff = None
        paths.append({
            "tid": tid,
            "label": t.get("label") or tid,
            "ip": ip,
            "resolve_ip": (trace or {}).get("resolve_ip") or ip,
            "target_merged": graph.get("target_merged", False),
            "status": status,
            "incident_id": (open_inc or {}).get("incident_id"),
            "trace_status": trace_status,
            "trace_source": source,
            "route_changed": route_changed,
            "route_diff": route_diff,
            "prev_hops": prev_hops,
            "updated_at": (trace or {}).get("updated_at") or (trace or {}).get("ts"),
            "hops": hops,
            "tcp_checks": tcp_checks,
            "ping_type": t.get("ping_type"),
            "probe_success": t.get("probe_success"),
            "failure_reason": t.get("failure_reason"),
            "summary": summary,
            "graph": graph,
        })
    merged = build_merged_graph(paths)
    return {
        "window": window,
        "origin": {"id": "source", "label": "监控主机", "type": "source"},
        "paths": paths,
        "merged": merged,
    }


def build_overview(web, *, window: str = "today",
                   uptime_days: float | None = None,
                   fresh: bool = False) -> dict:
    cache_key = ("overview", id(web), window)
    ttl = _CACHE_TTL.get(window, 30.0)
    if not fresh:
        cached = _cache_get(cache_key, ttl)
        if cached is not None:
            return cached

    with web._lock:
        targets = list(web._live_targets_snapshot())
    counts = _status_counts(targets)
    tids = [t["tid"] for t in targets if t.get("tid")]
    query_tids = web._tids_for_history_query(tids)

    open_map: dict[str, dict] = {}
    webhook_failures = 0
    avg_uptime = None
    ds = web._data_store
    if ds and query_tids:
        try:
            open_map = ds.get_open_incidents(query_tids)
        except Exception:
            open_map = {}
        try:
            fails = ds.get_last_webhook_failures(5)
            webhook_failures = len(fails or [])
        except Exception:
            webhook_failures = 0
        start, end, _ = parse_window(window)
        try:
            batch = ds.get_sla_stats_batch(query_tids, start, end)
            ups = [s.get("uptime_pct") for s in batch.values()
                   if s.get("uptime_pct") is not None]
            if ups:
                avg_uptime = sum(ups) / len(ups)
        except Exception:
            avg_uptime = None

    if counts["targets"] <= 0:
        risk = dict(_NO_SCORE)
        health = dict(_NO_SCORE)
    else:
        risk = compute_risk_score(
            red=counts["red"],
            orange=counts["orange"],
            open_incidents=len(open_map),
            webhook_failures=webhook_failures,
        )
        health = compute_health_score(
            green=counts["green"],
            total=counts["targets"],
            red=counts["red"],
            orange=counts["orange"],
            avg_uptime=avg_uptime,
        )
    out = {
        "updated_at": int(time.time()),
        "window": window,
        "uptime_days": uptime_days,
        "counts": counts,
        "open_incidents": len(open_map),
        "webhook_failures": webhook_failures,
        "risk": risk,
        "health": health,
        "avg_uptime_pct": round(avg_uptime, 3) if avg_uptime is not None else None,
        "score_meta": SCORE_META,
        "score_inputs": {
            "red": counts["red"],
            "orange": counts["orange"],
            "open_incidents": len(open_map),
            "webhook_failures": webhook_failures,
            "green_ratio": (round(counts["green"] / counts["targets"], 4)
                            if counts["targets"] else None),
            "avg_uptime_pct": round(avg_uptime, 3) if avg_uptime is not None else None,
        },
    }
    _cache_set(cache_key, out)
    return out


def _ts_to_time(ts: float | None) -> str:
    if ts is None:
        return ""
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def _hop_ip_seq(hops: list | None) -> list[str | None]:
    return [h.get("ip") for h in (hops or [])]


def _route_diff_text(old_ips: list, new_ips: list) -> str:
    if not old_ips or not new_ips:
        return "路径变化"
    n = max(len(old_ips), len(new_ips))
    parts = []
    for i in range(n):
        o = old_ips[i] if i < len(old_ips) else None
        nv = new_ips[i] if i < len(new_ips) else None
        if o != nv:
            o_s = o or "*"
            n_s = nv or "*"
            parts.append(f"Hop{i + 1}: {o_s}→{n_s}")
    if not parts:
        return "路径变化"
    head = ", ".join(parts[:3])
    if len(parts) > 3:
        head += f" 等 {len(parts)} 处"
    return head


def build_route_diff(old_hops: list | None, new_hops: list | None) -> dict | None:
    old_ips = _hop_ip_seq(old_hops)
    new_ips = _hop_ip_seq(new_hops)
    if not old_ips or not new_ips or old_ips == new_ips:
        return None
    changed = [i for i, (o, n) in enumerate(zip(old_ips, new_ips)) if o != n]
    if len(old_ips) != len(new_ips):
        changed.extend(range(min(len(old_ips), len(new_ips)),
                         max(len(old_ips), len(new_ips))))
    return {
        "old_ips": old_ips,
        "new_ips": new_ips,
        "changed_hops": sorted(set(changed)),
        "text": _route_diff_text(old_ips, new_ips),
    }


def _alert_to_screen_event(row: dict) -> dict:
    old = row.get("old_status") or ""
    new = row.get("new_status") or ""
    cat = (row.get("category") or "").strip()
    ts = row.get("ts")
    if new in ("red", "orange") and old not in ("red", "orange"):
        etype = "incident_open"
        level = new
        text = f"故障开始 · {old} → {new}"
    elif new == "green" and old in ("red", "orange"):
        etype = "recovery"
        level = "green"
        text = f"已恢复 · {old} → green"
    elif cat == "paused":
        etype = "paused"
        level = "orange"
        text = "监测已暂停"
    elif cat == "resumed":
        etype = "resumed"
        level = "green"
        text = "监测已恢复"
    else:
        etype = "status_change"
        level = new or old or "gray"
        text = f"{old} → {new}"
    reason = (row.get("failure_reason") or "").strip()
    if reason and etype in ("incident_open", "status_change"):
        text += f" · {describe_failure(reason)}"
    return {
        "id": f"alert-{row.get('id')}",
        "time": _ts_to_time(ts),
        "ts": ts,
        "tid": row.get("target_id") or "",
        "label": row.get("label") or row.get("target_id") or "",
        "ip": row.get("ip") or "",
        "level": level,
        "type": etype,
        "text": text,
        "incident_id": row.get("incident_id"),
        "category": cat,
    }


def _collect_route_change_events(
        ds, query_tids: list[str], targets: dict[str, dict],
        start_ts: float, limit: int) -> list[dict]:
    events: list[dict] = []
    for tid in query_tids:
        if len(events) >= limit:
            break
        try:
            hist = ds.get_traceroute_history(tid, limit=8)
        except Exception:
            hist = []
        meta = targets.get(tid) or {}
        for i, row in enumerate(hist):
            if not row.get("route_changed"):
                continue
            ts = float(row.get("ts") or 0)
            if ts < start_ts:
                continue
            prev_hops = (hist[i + 1].get("hops") if i + 1 < len(hist) else []) or []
            new_hops = row.get("hops") or []
            diff = build_route_diff(prev_hops, new_hops)
            events.append({
                "id": f"route-{tid}-{int(ts * 1000)}",
                "time": _ts_to_time(ts),
                "ts": ts,
                "tid": tid,
                "label": meta.get("label") or tid,
                "ip": meta.get("ip") or "",
                "level": "green",
                "type": "route_changed",
                "text": (diff or {}).get("text") or "路径变化",
                "route_diff": diff,
            })
            if len(events) >= limit:
                break
    return events


def build_topn(web, *, window: str = "today", n: int = 5) -> dict:
    cache_key = ("topn", id(web), window, n)
    ttl = _CACHE_TTL.get(window, 30.0)
    cached = _cache_get(cache_key, ttl)
    if cached is not None:
        return cached

    with web._lock:
        targets = {tid: dict(t) for tid, t in web._targets.items()}
    query_tids = web._tids_for_history_query(list(targets.keys()))
    rows = []
    ds = web._data_store
    if ds and query_tids:
        start, end, _ = parse_window(window)
        try:
            batch = ds.get_sla_stats_batch(query_tids, start, end)
        except Exception:
            batch = {}
        for tid in query_tids:
            if not web._history_data_available(tid):
                continue
            meta = targets.get(tid) or {}
            s = batch.get(tid) or web._empty_sla_stats()
            rows.append({
                "tid": tid,
                "label": meta.get("label") or tid,
                "ip": meta.get("ip") or "",
                "uptime_pct": s.get("uptime_pct"),
                "outage_count": s.get("outage_count") or 0,
                "outage_seconds": s.get("outage_seconds") or 0.0,
                "lat_p95": s.get("lat_p95"),
                "lat_avg": s.get("lat_avg"),
            })

    def _key_outage(r):
        return (r["outage_seconds"], r["outage_count"])

    def _key_latency(r):
        v = r.get("lat_p95")
        if v is None:
            v = r.get("lat_avg")
        return v if v is not None else -1

    out = {
        "window": window,
        "lowest_sla": sorted(
            [r for r in rows if r.get("uptime_pct") is not None],
            key=lambda r: r["uptime_pct"])[:n],
        "highest_latency": sorted(
            rows, key=_key_latency, reverse=True)[:n],
        "most_outages": sorted(rows, key=_key_outage, reverse=True)[:n],
    }
    _cache_set(cache_key, out)
    return out


def build_events(web, *, window: str = "today", limit: int = 30) -> list[dict]:
    start_ts, _, _ = parse_window(window)
    with web._lock:
        targets = {tid: dict(t) for tid, t in web._targets.items()}
    query_tids = web._tids_for_history_query(list(targets.keys()))
    events: list[dict] = []
    pinned: list[dict] = []
    ds = web._data_store
    if ds and query_tids:
        try:
            open_map = ds.get_open_incidents(query_tids)
        except Exception:
            open_map = {}
        for tid, inc in open_map.items():
            meta = targets.get(tid) or {}
            started = float(inc.get("started_at") or time.time())
            reason = (inc.get("failure_reason") or "").strip()
            text = f"未恢复 · 自 {_ts_to_time(started)} 起"
            if reason:
                text += f" · {describe_failure(reason)}"
            pinned.append({
                "id": f"open-{inc.get('incident_id') or tid}",
                "time": _ts_to_time(started),
                "ts": started,
                "tid": tid,
                "label": meta.get("label") or tid,
                "ip": meta.get("ip") or "",
                "level": inc.get("last_status") or "red",
                "type": "open_incident",
                "text": text,
                "incident_id": inc.get("incident_id"),
                "pinned": True,
                "open": True,
            })
        try:
            rows = ds.get_alert_history(
                target_id=None, start_ts=int(start_ts), limit=max(limit * 3, 60))
            for row in rows:
                if row.get("target_id") not in query_tids:
                    continue
                events.append(_alert_to_screen_event(row))
        except Exception:
            pass
        try:
            events.extend(_collect_route_change_events(
                ds, query_tids, targets, start_ts, limit))
        except Exception:
            pass
        try:
            for row in (ds.get_last_webhook_failures(5) or []):
                ts = row.get("updated_at")
                if ts is not None and float(ts) < start_ts:
                    continue
                row = enrich_webhook_failure(row)
                events.append({
                    "id": f"webhook-{row.get('id') or ts}",
                    "time": _ts_to_time(ts),
                    "ts": ts,
                    "tid": row.get("target_id") or "",
                    "label": row.get("target_id") or "Webhook",
                    "ip": "",
                    "level": "orange",
                    "type": "webhook_fail",
                    "text": row.get("error_text") or row.get("error") or "投递失败",
                })
        except Exception:
            pass
    else:
        with web._lock:
            hist = list(reversed(web._history))
        for h in hist[:limit]:
            tid = h.get("tid") or ""
            meta = targets.get(tid) or {}
            events.append({
                "id": f"mem-{tid}-{h.get('time')}",
                "time": h.get("time") or "",
                "ts": None,
                "tid": tid,
                "label": h.get("label") or meta.get("label") or tid,
                "ip": h.get("ip") or meta.get("ip") or "",
                "level": h.get("new_status") or "",
                "type": "status_change",
                "text": f"{h.get('old_status')} → {h.get('new_status')}",
            })

    seen: set[str] = set()
    merged: list[dict] = []
    for ev in pinned + sorted(
            events,
            key=lambda e: (float(e.get("ts") or 0), str(e.get("id") or "")),
            reverse=True):
        eid = str(ev.get("id") or "")
        if eid and eid in seen:
            continue
        if eid:
            seen.add(eid)
        merged.append(ev)
        if len(merged) >= limit:
            break
    return merged


def _break_hop_info(summary: dict | None) -> dict | None:
    ba = (summary or {}).get("break_at")
    if not isinstance(ba, dict):
        return None
    hop = ba.get("hop")
    ip = (ba.get("ip") or "").strip()
    if hop is None and not ip:
        return None
    return {
        "hop": hop,
        "ip": ip or None,
        "error": (ba.get("error") or "").strip() or None,
    }


def _break_label(summary: dict | None) -> str | None:
    ba = (summary or {}).get("break_at")
    if not isinstance(ba, dict) or ba.get("hop") is None:
        return None
    hop = ba.get("hop")
    ip = (ba.get("ip") or "").strip()
    if ip and ip != "*":
        return f"断点约第 {hop} 跳 · {ip}"
    return f"断点约第 {hop} 跳"


def build_geo(
        web,
        *,
        window: str = "today",
        limit: int = 50,
        resolver: Any | None = None,
) -> dict:
    """Geographic scatter payload for /api/screen/geo."""
    if GeoResolver is None:
        raise RuntimeError("geo_resolver unavailable")
    res = resolver or getattr(web, "_geo_resolver", None) or GeoResolver()
    with web._lock:
        targets = []
        for tid, t in web._targets.items():
            d = dict(t)
            d.setdefault("tid", tid)
            targets.append(d)
        target_geos = dict(getattr(web, "_target_geos", {}) or {})
        monitor_geo = getattr(web, "_monitor_geo", None)

    open_map: dict[str, dict] = {}
    ds = web._data_store
    tids = [t["tid"] for t in targets if t.get("tid")]
    if ds and tids:
        try:
            open_map = ds.get_open_incidents(tids)
        except Exception:
            open_map = {}

    def _prio(t):
        st = t.get("status") or "gray"
        rank = {"red": 0, "orange": 1, "gray": 2, "green": 3, "paused": 4}
        return (rank.get(st, 5), t.get("label") or t.get("tid") or "")

    ordered = sorted(targets, key=_prio)[: max(1, min(limit, 100))]
    rows: list[dict] = []
    inset: list[dict] = []

    for t in ordered:
        tid = t.get("tid") or ""
        if not tid or not web._history_data_available(tid):
            continue
        ip = t.get("ip") or ""
        status = t.get("status") or "gray"
        open_inc = open_map.get(tid)
        trace, _source = _read_traceroute(web, tid, ip, open_inc)
        hops = (trace or {}).get("hops") or []
        resolve_ip = (trace or {}).get("resolve_ip") or ip
        summary = summarize_for_display(
            hops,
            tcp_checks=(trace or {}).get("tcp_checks"),
            status=status,
            ping_type=t.get("ping_type"),
            probe_success=t.get("probe_success"),
            failure_reason=t.get("failure_reason"),
            target_ip=resolve_ip,
        )
        manual_geo = target_geos.get(tid) or t.get("geo")
        ptype = (t.get("ping_type") or "icmp").lower()
        probe_order = None
        if ptype == "dns":
            dd = (t.get("dns_domain") or "").strip()
            if dd:
                probe_order = [dd, resolve_ip, ip]
        placed = res.resolve_target(
            ip=ip,
            resolve_ip=resolve_ip,
            manual_geo=manual_geo,
            probe_order=probe_order,
            allow_dns_resolve=False,
        )
        break_hop = _break_hop_info(summary)
        break_geo = None
        if break_hop and break_hop.get("ip"):
            break_geo = res.resolve_break_geo(break_hop["ip"])
        row = {
            "tid": tid,
            "label": t.get("label") or tid,
            "ip": ip,
            "resolve_ip": resolve_ip,
            "status": status,
            "kind": placed["kind"],
            "geo": placed.get("geo"),
            "break_hop": break_hop,
            "break_geo": break_geo,
            "break_label": _break_label(summary),
            "summary_text": (summary or {}).get("text") or "",
        }
        rows.append(row)
        if placed["kind"] == "private":
            inset.append({
                "tid": tid,
                "label": row["label"],
                "status": status,
                "break_label": row["break_label"],
                "inset_kind": "private",
            })
        elif placed["kind"] == "public" and not row.get("geo"):
            inset.append({
                "tid": tid,
                "label": row["label"],
                "status": status,
                "break_label": row.get("break_label"),
                "inset_kind": "unlocated",
            })

    if resolve_monitor_source is not None:
        # Read-only request path: use cached egress IP only; kick background
        # prewarm when still unset so the arc appears on the next poll.
        src = resolve_monitor_source(res, monitor_geo, allow_egress_fetch=False)
        if src is None and prewarm_monitor_source is not None:
            prewarm_monitor_source(monitor_geo)
    else:
        src = parse_manual_geo(monitor_geo) if parse_manual_geo else None
    if not res.is_xdb_loaded():
        res.prewarm_xdb_async()
    map_count = sum(1 for r in rows if r.get("geo"))
    return {
        "window": window,
        "updated_at": int(time.time()),
        "source": src,
        "geo_db_ready": res.is_xdb_loaded(),
        "targets": rows,
        "inset": inset,
        "stats": {
            "total": len(rows),
            "on_map": map_count,
            "private": sum(1 for r in rows if r.get("kind") == "private"),
            "unlocated": sum(
                1 for r in rows
                if r.get("kind") == "public" and not r.get("geo")),
        },
    }


def demo_geo() -> dict:
    return {
        "window": "today",
        "updated_at": int(time.time()),
        "demo": True,
        "source": {
            "lat": 31.2304,
            "lon": 121.4737,
            "label": "监控主机 · 上海",
            "city": "上海",
        },
        "targets": [
            {
                "tid": "demo-red",
                "label": "电信DNS",
                "ip": "202.98.198.167",
                "resolve_ip": "202.98.198.167",
                "status": "red",
                "kind": "public",
                "geo": {"lat": 30.5728, "lon": 104.0668,
                        "city": "成都", "region": "四川"},
                "break_hop": {"hop": 7, "ip": "202.98.198.167",
                              "error": "timeout"},
                "break_geo": {"lat": 30.5728, "lon": 104.0668,
                              "city": "成都", "region": "四川"},
                "break_label": "断点约第 7 跳 · 202.98.198.167",
                "summary_text": "最后可达 第6跳 → 第7跳起中断",
            },
            {
                "tid": "demo-green",
                "label": "百度",
                "ip": "220.181.38.148",
                "resolve_ip": "220.181.38.148",
                "status": "green",
                "kind": "public",
                "geo": {"lat": 39.9042, "lon": 116.4074,
                        "city": "北京", "region": "北京"},
                "break_hop": None,
                "break_geo": None,
                "break_label": None,
                "summary_text": "路径完整",
            },
            {
                "tid": "demo-overseas",
                "label": "Google DNS",
                "ip": "8.8.8.8",
                "resolve_ip": "8.8.8.8",
                "status": "green",
                "kind": "public",
                "geo": {"lat": 36.7783, "lon": -119.4179,
                        "region": "California", "country": "United States",
                        "precision": "region", "source": "ip2region"},
                "break_hop": None,
                "break_geo": None,
                "break_label": None,
                "summary_text": "海外目标 · 自动切换世界地图",
            },
            {
                "tid": "demo-private",
                "label": "内网OA",
                "ip": "10.0.0.50",
                "resolve_ip": "10.0.0.50",
                "status": "orange",
                "kind": "private",
                "geo": None,
                "break_hop": {"hop": 3, "ip": "10.0.0.9", "error": None},
                "break_geo": None,
                "break_label": "断点约第 3 跳 · 10.0.0.9",
                "summary_text": "内网路径异常",
            },
        ],
        "inset": [
            {"tid": "demo-private", "label": "内网OA",
             "status": "orange", "break_label": "断点约第 3 跳 · 10.0.0.9"},
        ],
        "stats": {"total": 4, "on_map": 3, "private": 1, "unlocated": 0},
    }


def demo_overview() -> dict:
    return {
        "updated_at": int(time.time()),
        "window": "today",
        "uptime_days": 428,
        "counts": {"targets": 8, "green": 5, "orange": 2, "red": 1,
                   "paused": 0, "gray": 0, "online": 8},
        "open_incidents": 1,
        "webhook_failures": 0,
        "risk": {"score": 33.0, "grade": "中"},
        "health": {"score": 8.6, "grade": "良"},
        "avg_uptime_pct": 99.95,
        "score_meta": SCORE_META,
        "demo": True,
    }


def demo_paths() -> dict:
    summary = {
        "reached": False,
        "last_ok": {"hop": 6, "ip": "219.1.1.1"},
        "break_at": {"hop": 7, "ip": "202.98.198.167", "error": "timeout"},
        "total_hops": 8,
        "text": "最后可达 第6跳 219.1.1.1 → 第7跳起中断（断点 202.98.198.167）",
        "break_kind": "real",
    }
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok", "rtt_ms": 1.2},
        {"hop": 6, "ip": "219.1.1.1", "status": "ok", "rtt_ms": 8.4},
        {"hop": 7, "ip": "202.98.198.167", "status": "break", "rtt_ms": None},
    ]
    prev_hops = [
        {"hop": 1, "ip": "10.0.0.1", "status": "ok", "rtt_ms": 1.2},
        {"hop": 6, "ip": "219.1.1.1", "status": "ok", "rtt_ms": 8.4},
        {"hop": 7, "ip": "202.98.198.166", "status": "ok", "rtt_ms": 9.1},
    ]
    route_diff = build_route_diff(prev_hops, hops) or {
        "old_ips": ["10.0.0.1", "219.1.1.1", "202.98.198.166"],
        "new_ips": ["10.0.0.1", "219.1.1.1", "202.98.198.167"],
        "changed_hops": [2],
        "text": "Hop3: 202.98.198.166→202.98.198.167",
    }
    graph = _path_graph(hops, "demo-red", "电信DNS", "red", summary,
                        target_ip="202.98.198.167")
    paths = [{
            "tid": "demo-red",
            "label": "电信DNS",
            "ip": "202.98.198.167",
            "resolve_ip": "202.98.198.167",
            "target_merged": graph.get("target_merged", False),
            "status": "red",
            "trace_status": "completed",
            "route_changed": True,
            "route_diff": route_diff,
            "prev_hops": prev_hops,
            "summary": summary,
            "graph": graph,
            "hops": hops,
            "demo": True,
        },
        {
            "tid": "demo-green",
            "label": "百度",
            "ip": "220.181.38.148",
            "status": "green",
            "trace_status": "completed",
            "route_changed": False,
            "hops": [
                {"hop": 1, "ip": "10.0.0.1", "status": "ok", "rtt_ms": 1.0},
                {"hop": 2, "ip": "220.181.38.148", "status": "ok", "rtt_ms": 12.0},
            ],
            "summary": {"reached": True, "text": "路径完整", "break_kind": "none"},
            "resolve_ip": "220.181.38.148",
            "demo": True,
        }]
    green_graph = _path_graph(
        paths[1]["hops"], "demo-green", "百度", "green",
        paths[1]["summary"], target_ip="220.181.38.148")
    paths[1]["graph"] = green_graph
    paths[1]["target_merged"] = green_graph.get("target_merged", False)
    return {
        "window": "today",
        "origin": {"id": "source", "label": "监控主机", "type": "source"},
        "paths": paths,
        "merged": build_merged_graph(paths),
        "demo": True,
    }


def demo_topn() -> dict:
    return {
        "window": "today",
        "lowest_sla": [
            {"label": "电信DNS", "uptime_pct": 99.991, "outage_count": 1,
             "outage_seconds": 4.0},
        ],
        "highest_latency": [
            {"label": "台OA移动端", "lat_p95": 180.0},
        ],
        "most_outages": [
            {"label": "电信DNS", "outage_count": 1, "outage_seconds": 4.0},
        ],
        "demo": True,
    }


def demo_events() -> list[dict]:
    return [
        {"id": "demo-open", "time": "15:58:02", "label": "电信DNS", "level": "red",
         "type": "open_incident", "text": "未恢复 · 自 15:58:02 起 · timeout",
         "pinned": True, "open": True, "tid": "demo-red"},
        {"id": "demo-1", "time": "16:03:21", "label": "电信DNS", "level": "red",
         "type": "incident_open", "text": "故障开始 · green → red · 疑似断点 Hop 7 后",
         "tid": "demo-red"},
        {"id": "demo-2", "time": "16:04:10", "label": "百度", "level": "green",
         "type": "route_changed", "text": "Hop2: 220.181.38.147→220.181.38.148",
         "route_diff": {
             "old_ips": ["10.0.0.1", "220.181.38.147"],
             "new_ips": ["10.0.0.1", "220.181.38.148"],
             "changed_hops": [1],
             "text": "Hop2: 220.181.38.147→220.181.38.148",
         },
         "tid": "demo-green"},
        {"id": "demo-3", "time": "16:05:44", "label": "台OA", "level": "green",
         "type": "recovery", "text": "已恢复 · red → green"},
    ]
