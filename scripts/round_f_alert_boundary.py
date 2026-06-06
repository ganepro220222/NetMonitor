#!/usr/bin/env python3
"""Round F: Ping-Type Alert Boundary Audit
===========================================
Tests failure_layer classification, traceroute gating,
ICMP-filtered detection, and trace_skip_summary correctness
across all 4 ping types (icmp, tcp, http, dns).

Test areas:
  F1 - failure_layer() classification table
  F2 - should_request_traceroute() gating
  F3 - ICMP-filtered detection (summarize_for_alert)
  F4 - trace_skip_summary() per-type messages
  F5 - Dead code / unreachable paths
  F6 - WebhookIncident trace_applicable propagation
  F7 - Boundary / edge cases
  F8 - Integration: alert_manager skip / trace paths
"""

import sys, os, json, tempfile, time, threading, unittest.mock
from collections import namedtuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.trace_policy import (
    failure_layer, should_request_traceroute,
    trace_skip_summary, summarize_for_alert,
    trace_signature_from_summary,
    _hops_have_break, _tcp_checks_ok, _describe_failure,
)

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

# ====================================================================
#  F1: failure_layer() classification table
# ====================================================================
def test_f1_classification():
    print("\n-- F1: failure_layer() classification --")

    # ── Reason-first: shared across all types ──
    for pt in ("icmp", "tcp", "http", "dns"):
        check(failure_layer(pt, "no_reply") == "network",
              f"F1a: {pt}+no_reply → network")
        check(failure_layer(pt, "timeout") == "network",
              f"F1a: {pt}+timeout → network")
        check(failure_layer(pt, "error:PermissionError") == "network",
              f"F1a: {pt}+error:* → network")

    # ── TCP-specific endpoint codes ──
    for code in ("tcp_timeout", "connection_refused", "invalid_port"):
        for pt in ("tcp", "http"):
            check(failure_layer(pt, code) == ("config" if code == "invalid_port" else "endpoint"),
                  f"F1b: {pt}+{code} → {'config' if code == 'invalid_port' else 'endpoint'}")

    check(failure_layer("tcp", "tcp_failed:ECONNRESET") == "endpoint",
          "F1b: tcp+tcp_failed:* → endpoint")

    # ── HTTP-specific endpoint codes ──
    for code in ("http_timeout", "too_many_redirects", "invalid_url",
                 "keyword_not_found", "keyword_found"):
        check(failure_layer("http", code) == "endpoint",
              f"F1c: http+{code} → endpoint")

    # HTTP specific failure_reason NOT in HTTP_ENDPOINT_EXACT but type-fallback
    check(failure_layer("http", "body_recv_timeout") == "endpoint",
          "F1c: http+body_recv_timeout → endpoint (type fallback)")
    check(failure_layer("http", "chunked_premature_eof") == "endpoint",
          "F1c: http+chunked_premature_eof → endpoint (type fallback)")

    # ── DNS-specific codes ──
    for code in ("dns_timeout", "dns_bad_response", "dns_no_a_record",
                 "dns_no_domain", "nxdomain"):
        check(failure_layer("dns", code) == "endpoint",
              f"F1d: dns+{code} → endpoint")

    # Prefix codes for dns
    for code in ("dns_hijack:1.2.3.4", "dns_rcode_SERVFAIL", "dns_error:timeout"):
        check(failure_layer("dns", code) == "endpoint",
              f"F1d: dns+{code} → endpoint")

    # ── Prefix codes for HTTP/TLS ──
    for code in ("dns_failed:Timeout", "tls_failed:Handshake",
                 "url_parse:bad", "status_500", "ssl_error"):
        check(failure_layer("http", code) == "endpoint",
              f"F1e: http+{code} → endpoint")

    # ── Type fallback: ICMP ──
    check(failure_layer("icmp", "") == "network",
          "F1f: icmp+'' → network (empty reason)")
    check(failure_layer("icmp", "unknown_code") == "network",
          "F1f: icmp+unknown → network (any ICMP failure)")
    check(failure_layer("icmp", None) == "network",
          "F1f: icmp+None → network")

    # ── Type fallback: TCP ──
    check(failure_layer("tcp", "") == "endpoint",
          "F1g: tcp+'' → endpoint")
    check(failure_layer("tcp", "unknown_tcp_error") == "endpoint",
          "F1g: tcp+unknown → endpoint")
    check(failure_layer("tcp", "dns_failed:getaddrinfo") == "endpoint",
          "F1g: tcp+dns_failed:* → endpoint (caught twice: prefix + type fallback)")

    # ── Type fallback: HTTP ──
    check(failure_layer("http", "") == "endpoint",
          "F1h: http+'' → endpoint")
    check(failure_layer("https", "") == "endpoint",
          "F1h: https+'' → endpoint")

    # ── Type fallback: DNS ──
    check(failure_layer("dns", "") == "endpoint",
          "F1i: dns+'' → endpoint")

    # ── Config layer ──
    check(failure_layer("tcp", "invalid_port") == "config",
          "F1j: invalid_port → config (regardless of type)")

    # ── None ping_type treated as icmp ──
    check(failure_layer(None, "timeout") == "network",
          "F1k: None+timeout → network (defaults to icmp)")
    check(failure_layer(None, "connection_refused") == "endpoint",
          "F1k: None+connection_refused → endpoint")
    check(failure_layer(None, "") == "network",
          "F1k: None+'' → network (defaults to icmp)")

# ====================================================================
#  F2: should_request_traceroute() gating
# ====================================================================
def test_f2_traceroute_gating():
    print("\n-- F2: should_request_traceroute() gating --")

    # Network → trace
    check(should_request_traceroute("icmp", "no_reply") == True,
          "F2a: icmp no_reply → trace")
    check(should_request_traceroute("icmp", "timeout") == True,
          "F2a: icmp timeout → trace")
    check(should_request_traceroute("icmp", "") == True,
          "F2a: icmp empty reason → trace")

    # Endpoint → NO trace
    check(should_request_traceroute("tcp", "connection_refused") == False,
          "F2b: tcp connection_refused → no trace")
    check(should_request_traceroute("http", "http_timeout") == False,
          "F2b: http http_timeout → no trace")
    check(should_request_traceroute("dns", "nxdomain") == False,
          "F2b: dns nxdomain → no trace")
    check(should_request_traceroute("http", "status_503") == False,
          "F2b: http status_503 → no trace")

    # Config → NO trace
    check(should_request_traceroute("tcp", "invalid_port") == False,
          "F2c: invalid_port → no trace")

    # TCP timeout → trace (borderline design decision)
    check(should_request_traceroute("tcp", "timeout") == True,
          "F2d: tcp timeout → trace (reason-first: 'timeout' always network)")

    # ICMP filtered scenario: TCP probe fails with connection_refused
    # → should not request trace (correct, since it's endpoint-layer)
    check(should_request_traceroute("tcp", "connection_refused") == False,
          "F2e: TCP port closed → no ICMP traceroute (correct)")

# ====================================================================
#  F3: ICMP-filtered detection (summarize_for_alert)
# ====================================================================
def test_f3_icmp_filtered():
    print("\n-- F3: ICMP-filtered detection --")

    # F3a: Endpoint failure → skip summary (not network)
    result = summarize_for_alert([], ping_type="tcp", failure_reason="connection_refused")
    check(result.get("skipped") == True,
          "F3a: endpoint failure → skipped summary")
    check(result.get("break_at") is None,
          "F3a: skipped summary has no break_at")

    # F3b: Network failure, no hops break, no tcp_checks → normal summary
    hops_no_break = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "10.0.0.2", "rtt_ms": 2.0, "status": "ok"},
    ]
    result = summarize_for_alert(hops_no_break, ping_type="icmp", failure_reason="timeout")
    check(result.get("icmp_filtered") is not True,
          "F3b: no break + no tcp → no icmp_filtered flag")
    check(result.get("skipped") is not True,
          "F3b: network failure with hops → not skipped")

    # F3c: Hops break + tcp_checks OK → ICMP filtered
    hops_with_break = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "10.0.0.2", "rtt_ms": None, "status": "after"},
        {"hop": 3, "ip": "*", "rtt_ms": None, "status": "break"},
    ]
    tcp_ok = [{"port": 443, "success": True}]
    result = summarize_for_alert(
        hops_with_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=tcp_ok)
    check(result.get("icmp_filtered") == True,
          "F3c: hops break + tcp ok → icmp_filtered=True")
    check(result.get("break_at") is None,
          "F3c: icmp_filtered → break_at nullified")

    # F3d: Hops break + tcp_checks empty → NOT filtered
    result = summarize_for_alert(
        hops_with_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=[])
    check(result.get("icmp_filtered") is not True,
          "F3d: hops break + empty tcp_checks → no icmp_filtered flag")

    # F3e: Hops break + tcp_checks None → NOT filtered
    result = summarize_for_alert(
        hops_with_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=None)
    check(result.get("icmp_filtered") is not True,
          "F3e: hops break + None tcp_checks → no icmp_filtered flag")

    # F3f: Hops break + tcp_checks all failed → NOT filtered
    tcp_fail = [{"port": 443, "success": False}]
    result = summarize_for_alert(
        hops_with_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=tcp_fail)
    check(result.get("icmp_filtered") is not True,
          "F3f: hops break + all tcp fail → no icmp_filtered flag (real outage)")

    # F3g: tcp_checks with partial success (one ok, one fail) → filtered
    tcp_partial = [{"port": 80, "success": False}, {"port": 443, "success": True}]
    result = summarize_for_alert(
        hops_with_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=tcp_partial)
    check(result.get("icmp_filtered") == True,
          "F3g: hops break + partial tcp ok → icmp_filtered (any ok = filtered)")

    # F3h: `after` status counts as break
    hops_after = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "10.0.0.2", "rtt_ms": None, "status": "after"},
    ]
    check(_hops_have_break(hops_after) == True,
          "F3h: 'after' status counts as break")

    # F3i: `break` status counts as break
    hops_break = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": None, "status": "break"},
    ]
    check(_hops_have_break(hops_break) == True,
          "F3i: 'break' status counts as break")

# ====================================================================
#  F4: trace_skip_summary() per-type messages
# ====================================================================
def test_f4_skip_messages():
    print("\n-- F4: trace_skip_summary() per-type messages --")

    # F4a: Config layer → config message
    s = trace_skip_summary("tcp", "invalid_port")
    check("端口配置无效" in s["text"],
          f"F4a: config skip mentions detail (got: {s['text'][:40]}...)")
    check(s["skipped"] == True,
          "F4a: config skip has skipped=True")

    # F4b: HTTP → HTTP message
    s = trace_skip_summary("http", "http_timeout")
    check("HTTP" in s["text"] and "ICMP" in s["text"],
          f"F4b: http skip mentions HTTP/ICMP (got: {s['text'][:50]}...)")
    check(s["break_at"] is None,
          "F4b: skip has break_at=None")
    check(s["reached"] is None,
          "F4b: skip has reached=None")
    check(s["last_ok"] is None,
          "F4b: skip has last_ok=None")
    check(s["total_hops"] == 0,
          "F4b: skip has total_hops=0")

    # F4c: DNS → DNS message
    s = trace_skip_summary("dns", "nxdomain")
    check("域名不存在" in s["text"],
          f"F4c: dns skip describes NXDOMAIN (got: {s['text'][:50]}...)")

    # F4d: TCP → TCP message
    s = trace_skip_summary("tcp", "connection_refused")
    check("端口" in s["text"],
          f"F4d: tcp skip mentions port (got: {s['text'][:50]}...)")

    # F4e: ICMP with endpoint reason (shouldn't normally happen) → generic
    s = trace_skip_summary("icmp", "unknown_endpoint_reason")
    check(s["skipped"] == True,
          "F4e: generic skip for unexpected combo")

    # F4f: Unknown ping_type → generic fallback
    s = trace_skip_summary("unknown_proto", "some_reason")
    check(s["skipped"] == True,
          "F4f: unknown type → generic fallback")

    # F4g: None ping_type → treated as icmp
    s = trace_skip_summary(None, None)
    check(s["skipped"] == True
          or ("探测失败" in (s.get("text") or "")),
          f"F4g: None/None → skip (got: {s.get('text', '')[:50]}...)")

# ====================================================================
#  F5: Dead code / unreachable paths
# ====================================================================
def test_f5_dead_code():
    print("\n-- F5: Dead code / unreachable paths --")

    # F5a: _ICMP_NETWORK dead constant removed; failure_layer has no no-op ternaries
    import inspect
    import src.trace_policy as tp
    check(not hasattr(tp, "_ICMP_NETWORK"),
          "F5a: _ICMP_NETWORK removed (was unused dead code)")
    src = inspect.getsource(failure_layer)
    check('if fr else "network"' not in src and 'if fr else "endpoint"' not in src,
          "F5a: failure_layer has no no-op if-fr-else branches")

    # F5b: Line 84 is unreachable — all 4 types covered at lines 70-82
    # We can verify this by ensuring every known type hits a return before line 84
    for pt in ("icmp", "tcp", "http", "https", "dns"):
        for fr in ("", "no_reply", "connection_refused", "http_timeout", "nxdomain"):
            # Just verify classification works (produces valid layer)
            layer = failure_layer(pt, fr)
            check(layer in ("network", "endpoint", "config"),
                  f"F5b: {pt}+{fr} → valid layer '{layer}'")
    # Final fallback only triggers for unknown ping_type with unrecognized reason.
    # failure_layer("unknown_proto", "unrecognized_code") → "endpoint"
    check(failure_layer("unknown_proto", "unrecognized_code") == "endpoint",
          "F5b: line 84 reachable for unknown ping_type → endpoint (correct)")

# ====================================================================
#  F6: WebhookIncident trace_applicable / trace_signature
# ====================================================================
def test_f6_incident_propagation():
    print("\n-- F6: WebhookIncident trace propagation --")

    # F6a: trace_signature_from_summary for skipped summary
    skip = trace_skip_summary("http", "http_timeout")
    sig = trace_signature_from_summary(skip)
    check(sig[0] == "skipped",
          f"F6a: skipped summary → signature=('skipped', ...) (got {sig[0]})")

    # F6b: trace_signature_from_summary for real trace
    from src.traceroute_summary import summarize_break
    hops = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "10.0.0.2", "rtt_ms": 2.0, "status": "ok"},
    ]
    real = summarize_break(hops)
    sig = trace_signature_from_summary(real)
    check(sig[0] != "skipped",
          f"F6b: real summary → non-skipped signature")

    # F6c: ICMP-filtered summary signature
    hops_break = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "*", "rtt_ms": None, "status": "break"},
    ]
    filtered = summarize_for_alert(
        hops_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=[{"port": 443, "success": True}])
    sig = trace_signature_from_summary(filtered)
    check(filtered.get("icmp_filtered") == True,
          f"F6c: filtered summary has icmp_filtered=True")
    check(sig[0] != "skipped",
          f"F6c: filtered summary NOT skipped (real trace, just annotated)")

# ====================================================================
#  F7: Boundary / edge cases
# ====================================================================
def test_f7_boundary():
    print("\n-- F7: Boundary / edge cases --")

    # F7a: TCP timeout IS network (reason-first: "timeout" always network)
    # This means TCP probes that timeout trigger traceroute — arguably correct
    # because a timeout could be network-layer, and the ICMP-filtered detection
    # will suppress false break_at if needed
    check(failure_layer("tcp", "timeout") == "network",
          "F7a: TCP timeout → network (reason-first: timeout is always network)")
    check(should_request_traceroute("tcp", "timeout") == True,
          "F7a: TCP timeout → trace requested")

    # F7b: HTTP connection timeout as generic "timeout" (NOT "http_timeout")
    # If HTTPMonitor produces "timeout" instead of "http_timeout" for socket timeout,
    # failure_layer would classify it as "network" → could trigger traceroute.
    # Verify this is correct by checking the HTTPMonitor code:
    # HTTPMonitor uses "http_timeout" for overall timeout, "dns_failed:*" for DNS,
    # and "tls_failed:*" for TLS. Generic "timeout" shouldn't appear for HTTP.
    # But if it does, failure_layer("http", "timeout") → "network" (reason-first).
    check(failure_layer("http", "timeout") == "network",
          "F7b: http+'timeout' → network (generic timeout is always network)")

    # F7c: Empty hops list → summarize_break handles it
    result = summarize_for_alert([], ping_type="icmp", failure_reason="timeout")
    check(result.get("skipped") is not True,
          "F7c: empty hops with network failure → not skipped, returns base summary")

    # F7d: None hops → handles gracefully
    result = summarize_for_alert(None, ping_type="icmp", failure_reason="timeout")
    check(result.get("skipped") is not True,
          "F7d: None hops → not skipped, returns base summary")

    # F7e: TCP probe fails with dns_failed (DNS resolution failure during TCP connect)
    # This should be "endpoint" since DNS failure is not a path issue
    check(failure_layer("tcp", "dns_failed:getaddrinfo") == "endpoint",
          "F7e: TCP+dns_failed → endpoint (DNS failure is endpoint)")

    # F7f: HTTP probe fails with dns_failed
    check(failure_layer("http", "dns_failed:Timeout") == "endpoint",
          "F7f: HTTP+dns_failed → endpoint")

    # F7g: Case insensitivity for ping_type
    check(failure_layer("ICMP", "no_reply") == "network",
          "F7g: uppercase ICMP → network")
    check(failure_layer("Http", "http_timeout") == "endpoint",
          "F7g: mixed-case Http → endpoint")

# ====================================================================
#  F8: Integration: alert_manager trace flow
# ====================================================================
def test_f8_alert_manager_flow():
    print("\n-- F8: Integration: alert_manager trace flow --")

    # Simulate the critical path: TCP probe fails, alert manager decides
    # whether to request traceroute

    # F8a: TCP connection_refused → _open_or_update_webhook_incident sets trace_applicable=False
    # Immediately stores trace_skip_summary as placeholder
    skip = trace_skip_summary("tcp", "connection_refused")
    check(skip["skipped"] == True,
          "F8a: TCP connection_refused → skip summary stored immediately")
    check("TCP" in skip["text"].upper(),
          f"F8a: skip mentions TCP (got: {skip['text'][:50]}...)")

    # F8b: ICMP no_reply → trace_applicable=True, no skip summary yet (waits for trace result)
    check(should_request_traceroute("icmp", "no_reply") == True,
          "F8b: ICMP no_reply → trace_applicable=True, waits for actual trace")

    # F8c: When trace result arrives for ICMP with TCP checks passing
    hops_break = [
        {"hop": 1, "ip": "10.0.0.1", "rtt_ms": 1.0, "status": "ok"},
        {"hop": 2, "ip": "*", "rtt_ms": None, "status": "break"},
    ]
    tcp_ok = [{"port": 443, "success": True}]
    summary = summarize_for_alert(
        hops_break, ping_type="icmp", failure_reason="timeout",
        tcp_checks=tcp_ok)
    check(summary.get("icmp_filtered") == True,
          "F8c: trace arrives → ICMP-filtered detected → break_at nullified")
    check(summary.get("break_at") is None,
          "F8c: break_at is None (filtered)")

    # F8d: Trace refresh disabled for endpoint-layer incidents
    check(should_request_traceroute("http", "status_503") == False,
          "F8d: HTTP 503 → trace_applicable=False → no trace refresh")

    # F8e: Trace refresh still requested for network-layer incidents
    check(should_request_traceroute("icmp", "no_reply") == True,
          "F8e: ICMP no_reply → trace_applicable=True → trace refresh enabled")

# ====================================================================
#  Runner
# ====================================================================

def main():
    global _passed, _failed
    test_f1_classification()
    test_f2_traceroute_gating()
    test_f3_icmp_filtered()
    test_f4_skip_messages()
    test_f5_dead_code()
    test_f6_incident_propagation()
    test_f7_boundary()
    test_f8_alert_manager_flow()

    total = _passed + _failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {_passed} passed, {_failed} failed out of {total}")
    if _failed == 0:
        print("All checks passed")
    else:
        print("SOME CHECKS FAILED - review output above")
    return _failed

if __name__ == "__main__":
    sys.exit(main())
