"""
Round B: State Machine Sequence Fuzz / Table-Driven Verification
================================================================
Tests TargetMonitor._compute_state() by constructing PingResult sequences
directly — no threads, no sockets, no DataStore.

Test areas:
  B1 — Basic state transitions (GREEN→ORANGE→RED)
  B2 — Recovery hysteresis (debounce, red→orange→green stair-step)
  B3 — Alert category semantics (availability vs performance)
  B4 — Sequence fuzzing (interleaved, boundary, flapping)
  B5 — SLA / alert_events semantic conflicts
"""

import sys, os, math

# Make sure we can import from project root and src/
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.ping_engine import PingResult, TargetState, TargetMonitor

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


def make_monitor(target_id="T", settings=None, initial_status="green"):
    """Create a TargetMonitor without starting any thread."""
    if settings is None:
        settings = {}
    s = dict(settings)
    monitor = TargetMonitor(
        target_id=target_id,
        ip="10.0.0.1",
        settings=s,
        on_state_change=lambda _: None,
        initial_status=initial_status,
    )
    # Pre-populate window so loss_rate/latency aren't degenerate
    monitor._window.append(PingResult(success=True, latency_ms=10.0, timestamp=0))
    return monitor


def ok(rtt=10.0):
    """Successful probe with given latency."""
    return PingResult(success=True, latency_ms=rtt)


def ok_high(rtt=200.0):
    """Successful probe with high latency (above DEFAULT_WARN_LAT=150)."""
    return PingResult(success=True, latency_ms=rtt)


def fail(reason="no_reply"):
    """Failed probe (no latency)."""
    return PingResult(success=False, latency_ms=None, failure_reason=reason)


def fail_with_latency(rtt=50.0):
    """Failed probe WITH measured RTT (HTTP 5xx-like)."""
    return PingResult(success=False, latency_ms=rtt, failure_reason="status_5xx")


def feed(monitor, results):
    """Feed a sequence of PingResults through _compute_state, returning states."""
    states = []
    for r in results:
        monitor._window.append(r)
        st = monitor._compute_state(r)
        states.append(st)
    return states


def state_seq(states):
    """Return list of (status, alert_category) tuples."""
    return [(s.status, s.alert_category) for s in states]


def status_seq(states):
    return [s.status for s in states]


# ════════════════════════════════════════════════════════════════════
#  B1: Basic state transitions
# ════════════════════════════════════════════════════════════════════
def test_b1_basic_transitions():
    print("\n── B1: Basic state transitions ──")

    # B1a: GREEN stays GREEN with successes
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    states = feed(m, [ok(), ok(), ok()])
    seq = status_seq(states)
    check(seq == ["green", "green", "green"],
          f"B1a: successes → all green (got {seq})")

    # B1b: GREEN → ORANGE at exactly consecutive_loss_orange
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    states = feed(m, [fail(), fail(), fail()])
    seq = status_seq(states)
    check(seq == ["green", "green", "orange"],
          f"B1b: 3 losses → orange on 3rd (got {seq})")

    # B1c: Category for loss-induced ORANGE must be "availability"
    check(states[-1].alert_category == "availability",
          f"B1c: loss→orange category=availability (got {states[-1].alert_category})")

    # B1d: GREEN → RED at exactly consecutive_loss_red (5)
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    states = feed(m, [fail(), fail(), fail(), fail(), fail()])
    seq = status_seq(states)
    check(seq == ["green", "green", "orange", "orange", "red"],
          f"B1d: 5 losses → green,green,orange,orange,red (got {seq})")

    # B1e: Category for RED must be "availability"
    check(states[-1].alert_category == "availability",
          f"B1e: red category=availability (got {states[-1].alert_category})")

    # B1f: GREEN → ORANGE via high latency (performance)
    m = make_monitor(settings={"consecutive_lat_orange": 3})
    states = feed(m, [ok_high(200), ok_high(200), ok_high(200)])
    seq = status_seq(states)
    check(seq == ["green", "green", "orange"],
          f"B1f: 3 high-lat → orange on 3rd (got {seq})")

    # B1g: High-latency ORANGE category must be "performance"
    check(states[-1].alert_category == "performance",
          f"B1g: high-lat→orange category=performance (got {states[-1].alert_category})")

    # B1h: performance NEVER escalates to RED
    m = make_monitor(settings={"consecutive_lat_orange": 3})
    states = feed(m, [ok_high(200)] * 10)
    seq = status_seq(states)
    reds = [s for s in seq if s == "red"]
    check(len(reds) == 0,
          f"B1h: performance caps at orange (no reds in {seq})")
    check(all(s == "orange" for s in seq[2:]),
          f"B1h: stays orange after threshold (tail={seq[2:]})")

    # B1i: latency exactly at warn_lat threshold
    m = make_monitor(settings={"consecutive_lat_orange": 3})
    states = feed(m, [ok_high(150), ok_high(150), ok_high(150)])  # exactly 150ms = warn_lat default
    seq = status_seq(states)
    check(seq == ["green", "green", "orange"],
          f"B1i: latency exactly at warn_lat=150 → orange (got {seq})")

    # B1ia: latency just below warn_lat (149ms) does NOT count
    m = make_monitor(settings={"consecutive_lat_orange": 3})
    states = feed(m, [ok(149), ok(149), ok(149)])
    seq = status_seq(states)
    check(seq == ["green", "green", "green"],
          f"B1ia: latency=149 (<150) stays green (got {seq})")


# ════════════════════════════════════════════════════════════════════
#  B2: Recovery hysteresis
# ════════════════════════════════════════════════════════════════════
def test_b2_recovery_hysteresis():
    print("\n── B2: Recovery hysteresis ──")

    # B2a: RED → ORANGE on first success (stair-step)
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 5})
    # First drive to RED
    feed(m, [fail()] * 5)
    check(m._status == "red", f"B2a precondition: status=red (got {m._status})")
    # Then one success → should go to orange (not green)
    states = feed(m, [ok()])
    check(states[0].status == "orange",
          f"B2a: red→orange on 1st success (got {states[0].status})")
    check(states[0].alert_category == "availability",
          f"B2a: red→orange intermediate category=availability (got {states[0].alert_category})")

    # B2b: Orange stays orange until recovery_count consecutive greens
    more = feed(m, [ok()] * 3)  # total 4 greens since red
    seq = status_seq([states[0]] + more)
    check(all(s == "orange" for s in seq[:-1]),
          f"B2b: 4/5 recovery → still orange (seq={seq})")
    # 5th green → final recovery to green
    final = feed(m, [ok()])
    check(final[0].status == "green",
          f"B2b: 5th success → green (got {final[0].status})")

    # B2c: A single failure during recovery resets the counter
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 5})
    feed(m, [fail()] * 5)           # → RED
    feed(m, [ok(), ok(), ok()])     # 3/5 greens → orange, recovery_counter=3
    feed(m, [fail()])               # failure → resets counter
    check(m._recovery_counter == 0,
          f"B2c: failure resets recovery_counter to 0 (got {m._recovery_counter})")
    check(m._pending_natural is None,
          f"B2c: failure resets _pending_natural (got {m._pending_natural})")
    # Status stays orange (not red) — recovery had already progressed to orange,
    # and 1 failure doesn't reach loss_red=5 for re-escalation.
    check(m._status == "orange",
          f"B2c: failure during recovery stays orange, not red (got {m._status})")

    # B2d: Flapping during recovery — non-contiguous greens don't count
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 5})
    feed(m, [fail()] * 5)           # → RED
    # green → orange → green (flap) → orange → green ...
    # On first success from RED → orange, pending_natural="green", counter=1
    feed(m, [ok()])                  # orange, pending_natural=green, counter=1
    feed(m, [fail()])                # resets → red, counter=0
    feed(m, [ok()])                  # orange again, counter=1
    feed(m, [fail()])                # red again
    feed(m, [ok(), ok(), ok(), ok(), ok()])  # 5 consecutive greens → green
    check(m._status == "green",
          f"B2d: contiguous greens after flaps → green (got {m._status})")

    # B2e: recovery_need=1 skips orange entirely
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 1})
    feed(m, [fail()] * 5)           # → RED
    states = feed(m, [ok()])
    check(states[0].status == "green",
          f"B2e: recovery_need=1 → red→green directly (got {states[0].status})")

    # B2f: recovery_need=0 also skips orange
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 0})
    feed(m, [fail()] * 5)
    states = feed(m, [ok()])
    check(states[0].status == "green",
          f"B2f: recovery_need=0 → red→green directly (got {states[0].status})")

    # B2g: ORANGE→GREEN recovery (non-red de-escalation)
    m = make_monitor(settings={"consecutive_loss_orange": 3, "recovery_count": 3})
    feed(m, [fail(), fail(), fail()])    # → ORANGE
    feed(m, [ok(), ok()])                # 2/3 green → still orange
    check(m._status == "orange",
          f"B2g: 2/3 recovery from orange → still orange (got {m._status})")
    states = feed(m, [ok()])             # 3/3 → green
    check(states[0].status == "green",
          f"B2g: 3/3 recovery → green (got {states[0].status})")


# ════════════════════════════════════════════════════════════════════
#  B3: Alert category semantics
# ════════════════════════════════════════════════════════════════════
def test_b3_alert_categories():
    print("\n── B3: Alert category semantics ──")

    # B3a: orange/performance ↔ orange/availability swap (same severity)
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_lat_orange": 3})
    # First: loss → orange/availability
    feed(m, [fail(), fail(), fail()])
    check(m._status == "orange" and m._last_category == "availability",
          f"B3a_pre: loss→orange/availability (status={m._status}, cat={m._last_category})")
    # Then: 3 high-lat successes override → orange/performance
    # First high-lat success resets consecutive_loss to 0
    states1 = feed(m, [ok_high(200)])
    check(states1[0].status == "orange",
          f"B3a: after 1 high-lat, status stays orange (got {states1[0].status})")
    check(states1[0].alert_category == "availability",
          f"B3a: cat still availability after 1st high-lat (got {states1[0].alert_category})")
    # 2 more high-lat → now _consecutive_high_lat=3 → natural=orange/performance
    # Same severity, so: stays orange, category updates to "performance"
    states2 = feed(m, [ok_high(200), ok_high(200)])
    check(states2[-1].status == "orange",
          f"B3a: stays orange after 3 high-lat (got {states2[-1].status})")
    check(states2[-1].alert_category == "performance",
          f"B3a: cat flips to performance (got {states2[-1].alert_category})")
    # Then go back: 3 failures → back to availability
    feed(m, [fail(), fail(), fail()])
    check(m._last_category == "availability",
          f"B3a: back to availability after 3 failures (got {m._last_category})")

    # B3b: Alert category on TargetState vs what alert_events records
    # In _on_state_update, RED transitions ALWAYS use "availability"
    # But TargetState.alert_category reflects _last_category from state machine
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 3})
    feed(m, [fail()] * 5)           # → RED, _last_category="availability"
    check(m._last_category == "availability",
          f"B3b: red _last_category=availability (got {m._last_category})")
    # Recovery: red→orange→green
    feed(m, [ok(), ok(), ok()])      # After 3 greens → green
    # At green, _last_category should be "ok" (from natural=green)
    check(m._last_category == "ok",
          f"B3b: recovered green _last_category=ok (got {m._last_category})")
    # BUT alert_events for red→green transition will be "availability"
    # (overridden in _on_state_update: old_st=red → cat="availability")
    # This is a known semantic difference between TargetState and alert_events

    # B3c: Orange→red escalation uses "availability"
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    feed(m, [fail(), fail(), fail()])   # → ORANGE/availability
    states = feed(m, [fail(), fail()])  # → RED
    check(states[-1].alert_category == "availability",
          f"B3c: orange→red escalation category=availability (got {states[-1].alert_category})")

    # B3d: Green→red escalation (skip orange with large consecutive_loss_red)
    # Not possible with default settings, but test with orange/red same threshold
    m = make_monitor(settings={"consecutive_loss_orange": 1, "consecutive_loss_red": 1})
    states = feed(m, [fail()])
    check(states[0].status == "red",
          f"B3d: loss_orange=loss_red=1 → direct to red (got {states[0].status})")
    check(states[0].alert_category == "availability",
          f"B3d: direct red category=availability (got {states[0].alert_category})")


# ════════════════════════════════════════════════════════════════════
#  B4: Sequence fuzzing
# ════════════════════════════════════════════════════════════════════
def test_b4_sequence_fuzzing():
    print("\n── B4: Sequence fuzzing ──")

    # B4a: Mixed loss + high-lat → performance caps at orange, loss escalates to red
    # Pattern: high-lat, high-lat, fail, fail, fail, fail, fail
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "consecutive_lat_orange": 3, "recovery_count": 3})
    # First 2 high-lat → green (counter=2)
    feed(m, [ok_high(200), ok_high(200)])
    # Then fail → resets high_lat to 0, loss=1
    feed(m, [fail()])
    check(m._consecutive_high_lat == 0,
          f"B4a: failure clears _consecutive_high_lat (got {m._consecutive_high_lat})")
    check(m._consecutive_loss == 1,
          f"B4a: loss=1 after fail (got {m._consecutive_loss})")
    # loss=2 → green, loss=3 → orange, loss=4 → orange, loss=5 → red
    states = feed(m, [fail(), fail(), fail(), fail()])
    seq = status_seq(states)
    check(seq == ["green", "orange", "orange", "red"],
          f"B4a: loss 2,3,4,5 → green,orange,orange,red (got {seq})")

    # B4b: Rapid oscillation: fail-ok-fail-ok pattern
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    # fail, ok, fail, ok, fail → each success resets consecutive_loss to 0
    states = feed(m, [fail(), ok(), fail(), ok(), fail()])
    seq = status_seq(states)
    check(all(s == "green" for s in seq),
          f"B4b: fail-ok-fail-ok-fail stays green (got {seq})")
    check(m._consecutive_loss == 1,
          f"B4b: consecutive_loss=1 after pattern (got {m._consecutive_loss})")

    # B4c: Burst of high-lat then recovery
    m = make_monitor(settings={"consecutive_lat_orange": 3, "recovery_count": 3})
    feed(m, [ok_high(200)] * 3)                 # → orange/performance
    check(m._status == "orange", f"B4c: burst → orange (got {m._status})")
    feed(m, [ok(10)] * 3)                        # 3 normal successes → green
    check(m._status == "green", f"B4c: 3 low-lat → green (got {m._status})")

    # B4d: Loss during high-lat orange → should convert to availability
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_lat_orange": 3})
    feed(m, [ok_high(200)] * 3)                 # orange/performance
    check(m._last_category == "performance",
          f"B4d_pre: high-lat orange=performance (got {m._last_category})")
    # 3 failures → orange/availability (same severity, category swaps)
    feed(m, [fail(), fail(), fail()])
    check(m._last_category == "availability",
          f"B4d: failures swap category to availability (got {m._last_category})")

    # B4e: failed-with-latency probe — treated as failure (NOT a high-lat success)
    m = make_monitor(settings={"consecutive_lat_orange": 3, "consecutive_loss_orange": 3})
    # failed-with-latency should increment consecutive_loss, not consecutive_high_lat
    states = feed(m, [fail_with_latency(50), fail_with_latency(50), fail_with_latency(50)])
    check(states[-1].status == "orange",
          f"B4e: failed-with-latency triggers loss→orange (got {states[-1].status})")
    check(states[-1].alert_category == "availability",
          f"B4e: failed-with-latency category=availability (got {states[-1].alert_category})")
    check(m._consecutive_high_lat == 0,
          f"B4e: failed-with-latency does NOT increment _consecutive_high_lat (got {m._consecutive_high_lat})")

    # B4f: Gray initial state → any natural is escalation (instant)
    m = make_monitor(initial_status="gray", settings={"consecutive_loss_orange": 3})
    states = feed(m, [fail(), fail(), fail()])
    check(states[0].status == "green",
          f"B4f: gray+1st fail → green (got {states[0].status})")
    check(states[2].status == "orange",
          f"B4f: gray+3rd fail → orange (instant escalation, got {states[2].status})")
    check(states[2].alert_category == "availability",
          f"B4f: gray→orange escalation, category=availability (got {states[2].alert_category})")


# ════════════════════════════════════════════════════════════════════
#  B5: SLA / alert_events semantic conflicts
# ════════════════════════════════════════════════════════════════════
def test_b5_sla_semantics():
    print("\n── B5: SLA / alert_events semantic conflicts ──")

    # B5a: Red→Green recovery: TargetState says "ok", alert_events records "availability"
    # This is correct behavior (documented in _on_state_update) but verify the mismatch
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 3})
    feed(m, [fail()] * 5)           # → RED
    states = feed(m, [ok(), ok(), ok()])
    final = states[-1]
    check(final.status == "green",
          f"B5a: recovered to green (got {final.status})")
    check(final.alert_category == "ok",
          f"B5a: TargetState.alert_category=ok on recovery (got {final.alert_category})")
    # _on_state_update persists state.alert_category — red→green recovery
    # writes category='ok' to alert_events (same as TargetState).

    # B5b: Green→Red (direct): alert_category=availability on both TargetState and alert_event
    m = make_monitor(settings={"consecutive_loss_orange": 1, "consecutive_loss_red": 1})
    states = feed(m, [fail()])
    check(states[0].alert_category == "availability",
          f"B5b: direct green→red, TargetState.alert_category=availability (got {states[0].alert_category})")

    # B5c: Orange/performance→red gets category=availability in both
    m = make_monitor(settings={"consecutive_lat_orange": 3,
                                "consecutive_loss_orange": 3, "consecutive_loss_red": 5})
    feed(m, [ok_high(200)] * 3)                 # orange/performance
    feed(m, [fail()] * 5)                        # → red
    check(m._status == "red" and m._last_category == "availability",
          f"B5c: orange/performance→red → category=availability (got {m._last_category})")

    # B5d: orange/performance→green (no red involved): TargetState says "ok"
    # alert_events records "performance" (state.alert_category, which is "ok")
    # Wait - after recovery, natural is "green" with category="ok"
    # So alert_events category = "ok" (not "performance")
    # This is correct: performance issues that recover don't leave outage traces
    m = make_monitor(settings={"consecutive_lat_orange": 3, "recovery_count": 3})
    feed(m, [ok_high(200)] * 3)                 # orange/performance
    states = feed(m, [ok(10)] * 3)               # → green
    check(states[-1].alert_category == "ok",
          f"B5d: orange/performance→green, alert_category=ok (got {states[-1].alert_category})")

    # B5e: Consecutive loss counter vs recovery counter interplay
    # After red→green recovery, consecutive_loss should be 0
    m = make_monitor(settings={"consecutive_loss_orange": 3, "consecutive_loss_red": 5,
                                "recovery_count": 3})
    feed(m, [fail()] * 5)           # → RED
    feed(m, [ok(), ok(), ok()])      # → green
    check(m._consecutive_loss == 0,
          f"B5e: after recovery, consecutive_loss=0 (got {m._consecutive_loss})")
    check(m._recovery_counter == 0,
          f"B5e: after recovery, recovery_counter=0 (got {m._recovery_counter})")

    # B5f: Window size validation — loss_rate computed from rolling window
    m = make_monitor(settings={"window_size": 5})
    # Feed successes to clear out initial seed
    feed(m, [ok()] * 5)
    # Now feed 3 failures, 2 successes (window=[f,f,f,ok,ok])
    feed(m, [fail(), fail(), fail(), ok(), ok()])
    loss_rate = sum(1 for r in m._window if not r.success) / len(m._window)
    check(abs(loss_rate - 0.6) < 0.01,
          f"B5f: loss_rate=0.6 with 3/5 failures (got {loss_rate:.2f})")


# ════════════════════════════════════════════════════════════════════
#  Runner
# ════════════════════════════════════════════════════════════════════

def main():
    global _passed, _failed
    test_b1_basic_transitions()
    test_b2_recovery_hysteresis()
    test_b3_alert_categories()
    test_b4_sequence_fuzzing()
    test_b5_sla_semantics()

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
