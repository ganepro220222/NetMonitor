"""Regression: Web alert history active count uses tid, not label|ip."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.web_server import WebServer


class _MockDS:
    def get_cum_stats(self):
        return {}

    def set_wipe_complete_callback(self, _cb):
        pass


def _update(w, *, tid, label, ip, status, is_probe_result=True, probe_success=None):
    if probe_success is None:
        probe_success = status == "green"
    w.update_target(
        tid=tid,
        label=label,
        ip=ip,
        status=status,
        latency_ms=10.0,
        jitter_ms=1.0,
        loss_rate=0.0,
        ping_type="icmp",
        alert_category="ok",
        probe_success=probe_success,
        is_probe_result=is_probe_result,
    )


def _browser_hist_from_server(history_newest_first):
    """Mirror SSE init → hist rebuild (newest-first unshift order)."""
    hist = []
    for ev in history_newest_first:
        hist.append({
            "t": ev["time"],
            "tid": ev.get("tid"),
            "label": ev["label"],
            "ip": ev["ip"],
            "oldSt": ev["old_status"],
            "newSt": ev["new_status"],
        })
    return hist


def _active_count(hist, *, use_tid, live_tids=None):
    last_st = {}
    for h in hist:
        if use_tid:
            tid = h.get("tid")
            if tid and live_tids is not None and tid not in live_tids:
                continue
            key = tid or (h["label"] + "|" + h["ip"])
            if key not in last_st:
                last_st[key] = h["newSt"]
        else:
            key = h["label"] + "|" + h["ip"]
            last_st[key] = h["newSt"]
    return sum(1 for s in last_st.values() if s in ("red", "orange"))


def _sse_init_history(w):
    with w._lock:
        live_tids = set(w._targets)
        return [h for h in reversed(w._history) if h.get("tid") in live_tids]


def _source_has_tid_fix():
    path = os.path.join(ROOT, "src", "web_server.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    compact = src.replace(" ", "")
    checks = [
        ('"tid": tid' in src,
         '_history append includes tid'),
        ("tid:ev.tid" in compact,
         'SSE init hist rebuild preserves tid'),
        ("addHist(t.tid" in compact,
         'live addHist passes tid'),
        ("h.tid||(h.label" in compact,
         'renderHist keys by tid with label|ip fallback'),
        ("if(!(keyinlastSt))" in compact,
         'renderHist keeps newest event per key'),
        ("h.tid&&!(h.tidintargets)" in compact,
         'renderHist ignores deleted tids for active count'),
        ('self._history = [h for h in self._history if h.get("tid") != tid]'
         in src,
         'remove_target purges alert history for tid'),
        ("hist=hist.filter(h=>h.tid!==msg.tid)" in compact,
         'remove SSE drops hist rows for deleted tid'),
        ("ifh.get(\"tid\")inlive_tids" in compact,
         'SSE init history excludes deleted tids'),
    ]
    for passed, label in checks:
        print(f"    {label}: {'OK' if passed else 'FAIL'}")
    return all(p for p, _ in checks)


def main():
    ok = True
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(_MockDS())

    tid = "T1"
    ip = "10.0.0.1"

    _update(w, tid=tid, label="old-label", ip=ip, status="green")
    _update(w, tid=tid, label="old-label", ip=ip, status="red",
            probe_success=False)
    # Label-only meta sync while still red (no status change → no history row).
    _update(w, tid=tid, label="new-label", ip=ip, status="red",
            is_probe_result=False)
    _update(w, tid=tid, label="new-label", ip=ip, status="green")

    with w._lock:
        server_hist = list(reversed(w._history))

    print("history:", server_hist)

    tids_ok = all(h.get("tid") == tid for h in w._history)
    ok = ok and tids_ok
    print(f"  all history rows carry tid={tid!r}: {'OK' if tids_ok else 'FAIL'}")

    hist = _browser_hist_from_server(server_hist)
    active_old = _active_count(hist, use_tid=False)
    active_new = _active_count(hist, use_tid=True, live_tids={tid})

    print(f"  browser_active_by_label_ip: {active_old} (legacy bug path)")
    print(f"  browser_active_by_tid: {active_new} (expected 0 after recovery)")

    ok = ok and active_old == 1
    ok = ok and active_new == 0

    # Same tid, same label: recovery must also read as 0 active.
    w2 = WebServer(port=0)
    w2._running = True
    w2.set_data_store(_MockDS())
    _update(w2, tid="T2", label="stable", ip="10.0.0.2", status="green")
    _update(w2, tid="T2", label="stable", ip="10.0.0.2", status="red", probe_success=False)
    _update(w2, tid="T2", label="stable", ip="10.0.0.2", status="green")
    with w2._lock:
        hist2 = _browser_hist_from_server(list(reversed(w2._history)))
    stable_active = _active_count(hist2, use_tid=True, live_tids={"T2"})
    ok = ok and stable_active == 0
    print(f"  stable-label recovery active: {stable_active} (expected 0)")

    # Delete while red: server history + SSE init + active count must not ghost.
    w3 = WebServer(port=0)
    w3._running = True
    w3.set_data_store(_MockDS())
    del_tid = "t-del"
    _update(w3, tid=del_tid, label="deleted-while-red", ip="10.0.0.9", status="green")
    _update(w3, tid=del_tid, label="deleted-while-red", ip="10.0.0.9", status="red",
            probe_success=False)
    w3.remove_target(del_tid)
    with w3._lock:
        targets_after = dict(w3._targets)
        ghost_hist = [h for h in w3._history if h.get("tid") == del_tid]
    init_hist = _sse_init_history(w3)
    browser_hist = _browser_hist_from_server(init_hist)
    delete_active = _active_count(browser_hist, use_tid=True, live_tids=set(targets_after))

    print(f"targets_after_delete: {targets_after}")
    print(f"sse_init_style_history: {init_hist}")
    print(f"browser_unrecovered_count: {delete_active}")
    print(f"expected_unrecovered_count_after_delete: 0")

    ok = ok and del_tid not in targets_after
    ok = ok and len(ghost_hist) == 0
    ok = ok and init_hist == []
    ok = ok and delete_active == 0

    src_ok = _source_has_tid_fix()
    ok = ok and src_ok
    print(f"  source contains tid wiring: {'OK' if src_ok else 'FAIL'}")

    if ok:
        print("PASS verify_web_alert_history_tid")
        return 0
    print("FAIL verify_web_alert_history_tid")
    return 1


if __name__ == "__main__":
    sys.exit(main())
