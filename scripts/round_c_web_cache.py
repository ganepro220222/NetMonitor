"""
Round C: Web Pending / SSE / Front-end Cache Audit
===================================================
Tests WebServer internal state management — _targets, _stats,
_history_wipe_pending, SSE init payload — without starting
a real HTTP server.

Test areas:
  C1 — _targets/_stats consistency under update_target
  C2 — SSE init payload correctness
  C3 — Wipe sequence integrity (stats_reset → history_wiped)
  C4 — Stats accumulation (CMA, total/success invariants)
  C5 — History tracking and edge cases
  C6 — Pending-wipe exclusion (API guards, SSE init)
"""

import sys, os, json, threading, time
from unittest.mock import MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

# ── Patch DataStore dependency before importing web_server ──
# DataStore is imported by web_server module; we mock it entirely.
import src.data_store as ds_mod
# We need web_server without starting werkzeug

# ── Create a mock DataStore ──
class MockDataStore:
    def get_cum_stats(self):
        return {}
    def set_wipe_complete_callback(self, cb):
        pass
    def get_dashboard_stats_batch(self, tids, start, end):
        return {}
    def get_sla_stats_batch(self, tids, start, end):
        return {}
    def get_waveform(self, *args, **kwargs):
        return {"resolution": "1m", "points": [], "summary": {}}
    def get_history(self, *args, **kwargs):
        return []

# Patch the module-level dependencies
# web_server imports DataStore normally; we'll override at the WebServer level
# Actually, let's import web_server carefully

# To avoid the full import chain, let's directly import and test
# the WebServer class internals via a lightweight approach.
# We'll create WebServer with port=0 (won't start server)

from src.web_server import WebServer

# ── helpers ────────────────────────────────────────────────────────

_passed = 0
_failed = 0

def check(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


def update(w, tid, label="Test", ip="10.0.0.1", status="green",
           latency_ms=10.0, jitter_ms=1.0, loss_rate=0.0,
           ping_type="icmp", alert_category="ok",
           probe_success=True, is_probe_result=True,
           failure_reason=None, status_code=None):
    """Shorthand for web_server.update_target()."""
    w.update_target(
        tid=tid, label=label, ip=ip, status=status,
        latency_ms=latency_ms, jitter_ms=jitter_ms,
        loss_rate=loss_rate, ping_type=ping_type,
        alert_category=alert_category,
        probe_success=probe_success,
        is_probe_result=is_probe_result,
        failure_reason=failure_reason,
        status_code=status_code,
    )


def sse_init_snapshot(w):
    """Simulate the SSE init payload builder (matches sse_events() exactly)."""
    with w._lock:
        targets = {tid: dict(d) for tid, d in w._targets.items()}
        history = list(reversed(w._history))   # newest first
        stats = {tid: dict(s) for tid, s in w._stats.items()
                 if tid in w._targets
                 and tid not in w._history_wipe_pending}
    return {"targets": targets, "history": history, "stats": stats}


# ════════════════════════════════════════════════════════════════════
#  C1: _targets / _stats consistency
# ════════════════════════════════════════════════════════════════════
def test_c1_targets_stats_consistency():
    print("\n── C1: _targets / _stats consistency ──")
    w = WebServer(port=0)
    w._running = True  # allow update_target to proceed
    w.set_data_store(MockDataStore())

    # C1a: After updates, every target in _targets should have a _stats entry
    update(w, "T1")
    update(w, "T2")
    update(w, "T3")
    for tid in ["T1", "T2", "T3"]:
        check(tid in w._targets,
              f"C1a: {tid} in _targets")
        check(tid in w._stats,
              f"C1a: {tid} in _stats (got keys: {list(w._stats.keys())})")

    # C1b: _stats totals are consistent (total >= success)
    for tid in ["T1", "T2", "T3"]:
        s = w._stats[tid]
        check(s["total"] >= s["success"],
              f"C1b: {tid} total({s['total']}) >= success({s['success']})")
        check(s["total"] >= s["latency_n"],
              f"C1b: {tid} total({s['total']}) >= latency_n({s['latency_n']})")

    # C1c: Failed probes increment total but NOT success
    update(w, "T1", probe_success=False, failure_reason="timeout", latency_ms=None)
    s1 = w._stats["T1"]
    check(s1["total"] == 2 and s1["success"] == 1,
          f"C1c: failure total=2 success=1 (got total={s1['total']} success={s1['success']})")

    # C1d: Meta-sync (is_probe_result=False) does NOT affect _stats
    update(w, "T1", is_probe_result=False, label="Renamed")
    s1 = w._stats["T1"]
    check(s1["total"] == 2,
          f"C1d: meta-sync doesn't increment total (got {s1['total']})")
    check(w._targets["T1"]["label"] == "Renamed",
          f"C1d: meta-sync updates label in _targets (got {w._targets['T1']['label']})")

    # C1e: No ghost _stats entries (stats without target)
    # Create a ghost by manually inserting into _stats
    w._stats["GHOST"] = {"total": 5, "success": 3, "latency_avg": 10.0, "latency_n": 3}
    snap = sse_init_snapshot(w)
    check("GHOST" not in snap["stats"],
          f"C1e: ghost _stats entry excluded from SSE init stats")
    check("GHOST" not in snap["targets"],
          f"C1e: ghost not in SSE init targets")
    # Clean up
    del w._stats["GHOST"]


# ════════════════════════════════════════════════════════════════════
#  C2: SSE init payload correctness
# ════════════════════════════════════════════════════════════════════
def test_c2_sse_init_payload():
    print("\n── C2: SSE init payload correctness ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    # Populate targets with various states
    update(w, "T_GREEN",  status="green",  latency_ms=10.0)
    update(w, "T_ORANGE", status="orange", latency_ms=200.0, alert_category="performance")
    update(w, "T_RED",    status="red",    probe_success=False,
           failure_reason="timeout", latency_ms=None)

    snap = sse_init_snapshot(w)

    # C2a: All targets present in init payload
    for tid in ["T_GREEN", "T_ORANGE", "T_RED"]:
        check(tid in snap["targets"],
              f"C2a: {tid} in SSE init targets")
        check(tid in snap["stats"],
              f"C2a: {tid} in SSE init stats")

    # C2b: Target data fields preserved
    check(snap["targets"]["T_RED"]["status"] == "red",
          f"C2b: RED status preserved in init")
    check(snap["targets"]["T_RED"]["failure_reason"] == "timeout",
          f"C2b: failure_reason preserved in init")
    check(snap["targets"]["T_ORANGE"]["alert_category"] == "performance",
          f"C2b: alert_category preserved in init")

    # C2c: Stats snapshot is a deep copy (not a reference)
    snap["stats"]["T_GREEN"]["total"] = 99999  # mutate copy
    check(w._stats["T_GREEN"]["total"] == 1,
          f"C2c: stats snapshot copy doesn't mutate original (original={w._stats['T_GREEN']['total']})")

    # C2d: History is reversed (newest first)
    # Feed some status transitions
    update(w, "T_HIST", status="green")
    update(w, "T_HIST", status="orange", alert_category="availability",
           probe_success=False)
    update(w, "T_HIST", status="red", probe_success=False,
           failure_reason="no_reply")
    snap2 = sse_init_snapshot(w)
    check(len(snap2["history"]) == 2,
          f"C2d: history has 2 transitions (got {len(snap2['history'])})")
    if len(snap2["history"]) >= 2:
        # First entry should be orange→red (newest)
        check(snap2["history"][0]["new_status"] == "red",
              f"C2d: history[0] newest=red (got {snap2['history'][0]['new_status']})")
        # Second entry should be green→orange
        check(snap2["history"][1]["new_status"] == "orange",
              f"C2d: history[1]=orange (got {snap2['history'][1]['new_status']})")


# ════════════════════════════════════════════════════════════════════
#  C3: Wipe sequence integrity
# ════════════════════════════════════════════════════════════════════
def test_c3_wipe_sequence():
    print("\n── C3: Wipe sequence integrity ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    # Setup: T1 has accumulated stats
    update(w, "T1", latency_ms=10.0)
    update(w, "T1", latency_ms=12.0)
    update(w, "T1", latency_ms=8.0)
    check(w._stats["T1"]["total"] == 3,
          f"C3_pre: T1 stats.total=3 before wipe (got {w._stats['T1']['total']})")

    # C3a: begin_target_history_wipe clears stats and adds to pending
    w.begin_target_history_wipe("T1")
    check("T1" in w._history_wipe_pending,
          f"C3a: T1 added to _history_wipe_pending")
    check("T1" not in w._stats,
          f"C3a: T1 _stats cleared (got: {list(w._stats.keys())})")

    # C3b: SSE init excludes wipe-pending from stats
    snap = sse_init_snapshot(w)
    check("T1" in snap["targets"],
          f"C3b: T1 still in SSE init targets (card visible)")
    check("T1" not in snap["stats"],
          f"C3b: T1 excluded from SSE init stats (donut hidden)")

    # C3c: Probes during wipe still update _targets and _stats
    update(w, "T1", latency_ms=15.0)
    check("T1" in w._stats,
          f"C3c: probe during wipe recreates _stats entry")
    check(w._stats["T1"]["total"] == 1,
          f"C3c: stats restart from 1 (got {w._stats['T1']['total']})")

    # C3d: on_target_history_wiped clears stats AND removes from pending
    # First verify probe during wipe was counted
    check(w._stats["T1"]["total"] == 1,
          f"C3d_pre: stats during wipe exist (total={w._stats['T1']['total']})")
    w.on_target_history_wiped("T1")
    check("T1" not in w._history_wipe_pending,
          f"C3d: T1 removed from _history_wipe_pending")
    check("T1" not in w._stats,
          f"C3d: T1 _stats cleared again after wipe completion")

    # C3e: After wipe, SSE init includes T1 in stats (fresh, empty)
    update(w, "T1", latency_ms=20.0)  # first probe after wipe
    snap2 = sse_init_snapshot(w)
    check("T1" in snap2["stats"],
          f"C3e: after wipe+probe, T1 in SSE init stats")
    check(snap2["stats"]["T1"]["total"] == 1,
          f"C3e: fresh stats total=1 (got {snap2['stats']['T1']['total']})")


# ════════════════════════════════════════════════════════════════════
#  C4: Stats accumulation correctness
# ════════════════════════════════════════════════════════════════════
def test_c4_stats_accumulation():
    print("\n── C4: Stats accumulation correctness ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    # C4a: CMA latency calculation
    # latencies: 10, 20, 30
    update(w, "T1", latency_ms=10.0)
    update(w, "T1", latency_ms=20.0)
    update(w, "T1", latency_ms=30.0)
    s = w._stats["T1"]
    expected_avg = (10.0 + 20.0 + 30.0) / 3.0
    check(abs(s["latency_avg"] - expected_avg) < 0.001,
          f"C4a: CMA latency_avg={s['latency_avg']:.2f} expected={expected_avg}")

    # C4b: Failed probes don't affect latency_avg
    update(w, "T1", probe_success=False, latency_ms=None,
           failure_reason="timeout")
    s2 = w._stats["T1"]
    check(s2["total"] == 4 and s2["success"] == 3,
          f"C4b: total=4 success=3 after failure (got total={s2['total']} success={s2['success']})")
    check(abs(s2["latency_avg"] - expected_avg) < 0.001,
          f"C4b: latency_avg unchanged by failure (got {s2['latency_avg']:.2f})")
    check(s2["latency_n"] == 3,
          f"C4b: latency_n=3 unchanged (got {s2['latency_n']})")

    # C4c: High-latency successful probe contributes to latency_avg
    update(w, "T1", latency_ms=100.0)
    s3 = w._stats["T1"]
    # CMA: avg was 20.0, n was 3; new avg = 20.0 + (100-20)/(3+1) = 20.0 + 20.0 = 40.0
    expected_new = 20.0 + (100.0 - 20.0) / 4.0
    check(abs(s3["latency_avg"] - expected_new) < 0.001,
          f"C4c: CMA after 100ms = {s3['latency_avg']:.2f} expected={expected_new:.2f}")
    check(s3["latency_n"] == 4,
          f"C4c: latency_n=4 (got {s3['latency_n']})")

    # C4d: Stats initialized lazily (first probe creates entry)
    update(w, "T_NEW", latency_ms=5.0)
    check("T_NEW" in w._stats,
          f"C4d: lazy init creates _stats entry for T_NEW")
    check(w._stats["T_NEW"]["total"] == 1,
          f"C4d: new target total=1 (got {w._stats['T_NEW']['total']})")

    # C4e: Multiple targets accumulate independently
    update(w, "T_A", latency_ms=5.0)
    update(w, "T_B", latency_ms=15.0)
    update(w, "T_A", latency_ms=7.0)
    check(w._stats["T_A"]["total"] == 2 and w._stats["T_B"]["total"] == 1,
          f"C4e: independent accumulation (T_A={w._stats['T_A']['total']}, T_B={w._stats['T_B']['total']})")


# ════════════════════════════════════════════════════════════════════
#  C5: History tracking and edge cases
# ════════════════════════════════════════════════════════════════════
def test_c5_history():
    print("\n── C5: History tracking ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    # C5a: First probe creates no history (no old_status to compare)
    update(w, "T1", status="green")
    check(len(w._history) == 0,
          f"C5a: first probe → no history (got {len(w._history)})")

    # C5b: Status change creates history entry
    update(w, "T1", status="orange", alert_category="availability",
           probe_success=False)
    check(len(w._history) == 1,
          f"C5b: green→orange creates history entry (got {len(w._history)})")
    check(w._history[0]["old_status"] == "green",
          f"C5b: old_status=green (got {w._history[0]['old_status']})")
    check(w._history[0]["new_status"] == "orange",
          f"C5b: new_status=orange (got {w._history[0]['new_status']})")

    # C5c: Same status no change → no history
    update(w, "T1", status="orange")
    check(len(w._history) == 1,
          f"C5c: same status → no new history (got {len(w._history)})")

    # C5d: gray→green transition skipped in history
    update(w, "T2", status="gray")
    update(w, "T2", status="green")
    hist_t2 = [h for h in w._history if h["label"] == "Test"]
    # gray→green is filtered: line 6399
    gray_to_green = [h for h in w._history
                     if h["old_status"] == "gray" and h["new_status"] == "green"]
    check(len(gray_to_green) == 0,
          f"C5d: gray→green filtered from history (got {len(gray_to_green)} entries)")

    # C5e: MAX_HISTORY cap (60)
    for i in range(65):
        st = "orange" if i % 2 == 0 else "green"
        update(w, "T_CAP", status=st)
    check(len(w._history) <= WebServer.MAX_HISTORY,
          f"C5e: history capped at {WebServer.MAX_HISTORY} (got {len(w._history)})")


# ════════════════════════════════════════════════════════════════════
#  C6: Pending-wipe exclusion & API guards
# ════════════════════════════════════════════════════════════════════
def test_c6_pending_wipe_guards():
    print("\n── C6: Pending-wipe exclusion guards ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    update(w, "T1", status="green")
    update(w, "T2", status="green")
    update(w, "T3", status="green")

    # C6a: _history_data_available returns False for wipe-pending
    w.begin_target_history_wipe("T1")
    check(not w._history_data_available("T1"),
          f"C6a: T1 wipe-pending → data NOT available")
    check(w._history_data_available("T2"),
          f"C6a: T2 not wipe-pending → data available")

    # C6b: _tids_for_history_query excludes wipe-pending
    result = w._tids_for_history_query(["T1", "T2", "T3"])
    check(result == ["T2", "T3"],
          f"C6b: _tids_for_history_query excludes T1 (got {result})")

    # C6c: _empty_sla_stats returns defaults
    empty = WebServer._empty_sla_stats()
    check(empty["uptime_pct"] == 100.0,
          f"C6c: empty SLA uptime_pct=100.0")
    check(empty["sample_n"] == 0,
          f"C6c: empty SLA sample_n=0")
    check(empty["lat_avg"] is None,
          f"C6c: empty SLA lat_avg=None")

    # C6d: After wipe completes, data available again
    w.on_target_history_wiped("T1")
    check(w._history_data_available("T1"),
          f"C6d: after wipe complete, T1 data available")
    result2 = w._tids_for_history_query(["T1", "T2", "T3"])
    check(result2 == ["T1", "T2", "T3"],
          f"C6d: _tids_for_history_query includes T1 after wipe (got {result2})")

    # C6e: SSE init during wipe — target visible but stats excluded
    w.begin_target_history_wipe("T2")
    snap = sse_init_snapshot(w)
    check("T2" in snap["targets"],
          f"C6e: T2 in SSE init targets during wipe")
    check("T2" not in snap["stats"],
          f"C6e: T2 excluded from SSE init stats during wipe")
    # T1 was wiped and cleared → not in _stats → absent from init_stats
    # (correct: no cumulative stats until next probe lands)
    check("T1" not in snap["stats"],
          f"C6e: T1 absent from SSE init stats after wipe (stats cleared, no probes yet)")
    check("T1" in snap["targets"],
          f"C6e: T1 still in SSE init targets (card remains visible)")


# ════════════════════════════════════════════════════════════════════
#  C7: Paused target isolation
# ════════════════════════════════════════════════════════════════════
def test_c7_paused_isolation():
    print("\n── C7: Paused target isolation ──")
    w = WebServer(port=0)
    w._running = True
    w.set_data_store(MockDataStore())

    update(w, "T1", status="green", latency_ms=10.0)
    check(w._stats["T1"]["total"] == 1,
          f"C7_pre: T1 total=1 before pause")

    # C7a: Probes for paused targets are silently dropped
    w._paused.add("T1")
    update(w, "T1", status="green", latency_ms=15.0)
    check(w._stats["T1"]["total"] == 1,
          f"C7a: paused target probe NOT counted (total still 1)")
    check(w._targets["T1"]["status"] == "green",
          f"C7a: paused target _targets still shows old status")

    # C7b: Meta-sync (is_probe_result=False) for paused targets forces status="paused"
    update(w, "T1", is_probe_result=False, label="RenamedPaused")
    check(w._targets["T1"]["label"] == "RenamedPaused",
          f"C7b: meta-sync updates label for paused target")
    check(w._targets["T1"]["status"] == "paused",
          f"C7b: meta-sync for paused target forces status=paused (got {w._targets['T1']['status']})")

    # C7c: Un-pausing (removing from _paused) allows probes again
    w._paused.discard("T1")
    update(w, "T1", status="green", latency_ms=20.0)
    check(w._stats["T1"]["total"] == 2,
          f"C7c: after unpause, probe counted (total=2)")


# ════════════════════════════════════════════════════════════════════
#  Runner
# ════════════════════════════════════════════════════════════════════

def main():
    global _passed, _failed
    test_c1_targets_stats_consistency()
    test_c2_sse_init_payload()
    test_c3_wipe_sequence()
    test_c4_stats_accumulation()
    test_c5_history()
    test_c6_pending_wipe_guards()
    test_c7_paused_isolation()

    total = _passed + _failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {_passed} passed, {_failed} failed out of {total}")
    if _failed == 0:
        print("✓  All checks passed")
    else:
        print("⚠️  SOME CHECKS FAILED — review output above")
    return _failed


if __name__ == "__main__":
    sys.exit(main())
