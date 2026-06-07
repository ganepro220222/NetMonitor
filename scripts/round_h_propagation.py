#!/usr/bin/env python3
"""Round H: Probe-context end-to-end propagation audit (post Bug 142)."""

import sys, os, json, tempfile, sqlite3, time, inspect

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

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


def test_h1_db_schema():
    print("\n-- H1: DB schema column existence --")
    test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    test_db.close()
    try:
        from src.data_store import DataStore
        ds = DataStore(test_db.name)
        ds.shutdown()
        conn = sqlite3.connect(test_db.name)
        cols = {c[1] for c in conn.execute("PRAGMA table_info(alert_events)").fetchall()}
        check("failure_reason" in cols, "H1a: alert_events has failure_reason")
        check("ping_type" in cols, "H1b: alert_events has ping_type column")
        conn.close()
    finally:
        for p in (test_db.name, test_db.name + "-shm", test_db.name + "-wal"):
            try:
                os.unlink(p)
            except OSError:
                pass


def test_h2_api_signatures():
    print("\n-- H2: record_alert API signature --")
    import src.data_store as ds_mod
    sig = inspect.signature(ds_mod.DataStore.record_alert)
    params = set(sig.parameters.keys())
    check("failure_reason" in params, "H2a: record_alert accepts failure_reason")
    check("ping_type" in params, "H2b: record_alert accepts ping_type")


def test_h3_webhook_payloads():
    print("\n-- H3: Webhook payload coverage --")
    import src.alert_manager as am_mod
    probe_src = inspect.getsource(am_mod.AlertManager._incident_probe_fields)
    check("ping_type" in probe_src, "H3a: _incident_probe_fields includes ping_type")
    check("failure_reason" in probe_src, "H3a: _incident_probe_fields includes failure_reason")
    for name, fn in (
        ("_build_incident_extra", am_mod.AlertManager._build_incident_extra),
        ("_build_recovery_extra", am_mod.AlertManager._build_recovery_extra),
        ("_build_reminder_extra", am_mod.AlertManager._build_reminder_extra),
    ):
        src = inspect.getsource(fn)
        check("_incident_probe_fields" in src, f"H3b: {name} merges probe fields")

    src_snap = inspect.getsource(am_mod.AlertManager._snapshot_incident)
    check("ping_type" in src_snap, "H3e: _snapshot_incident includes ping_type")
    check("failure_reason" in src_snap, "H3e: _snapshot_incident includes failure_reason")
    check("trace_applicable" in src_snap, "H3e: _snapshot_incident includes trace_applicable")

    src_fmt = inspect.getsource(am_mod.AlertManager._format_webhook_text)
    check("探测类型" in src_fmt, "H3f: webhook text shows ping type")
    check("失败原因" in src_fmt, "H3f: webhook text shows failure reason")


def test_h4_export_excel():
    print("\n-- H4: Export Excel column coverage --")
    import src.data_store as ds_mod
    src = inspect.getsource(ds_mod.DataStore.export_excel)
    check("探测类型" in src, "H4a: timeline sheet has ping_type column header")
    sql_src = inspect.getsource(ds_mod.DataStore._get_export_alert_events)
    check("ping_type" in sql_src, "H4b: alert timeline SQL selects ping_type")
    check("describe_failure" in src, "H4c: export uses describe_failure for reasons")


def test_h5_snapshot_fidelity():
    print("\n-- H5: WebhookIncident snapshot fidelity --")
    from src.alert_manager import AlertManager, WebhookIncident
    inc = WebhookIncident(
        tid="test-1", label="Test", ip="10.0.0.1", started_at=time.time(),
        ping_type="tcp", failure_reason="connection_refused", trace_applicable=False)
    snap = AlertManager._snapshot_incident(inc)
    check(snap["ping_type"] == "tcp", "H5a: snapshot ping_type")
    check(snap["failure_reason"] == "connection_refused", "H5b: snapshot failure_reason")
    check(snap["trace_applicable"] is False, "H5c: snapshot trace_applicable")


def test_h6_old_data_compat():
    print("\n-- H6: Old-data compatibility --")
    from src.trace_policy import failure_layer, describe_failure
    check(failure_layer("icmp", None) == "network", "H6a: None failure_reason ICMP")
    check(describe_failure("") == "", "H6b: empty failure_reason")
    check(describe_failure(None) == "", "H6c: None failure_reason label")


def test_h7_describe_for_export():
    print("\n-- H7: describe_failure completeness --")
    from src.trace_policy import describe_failure, _HTTP_ENDPOINT_EXACT
    gaps = []
    for code in sorted(_HTTP_ENDPOINT_EXACT):
        desc = describe_failure(code)
        if not desc or desc == code:
            gaps.append(code)
    check(len(gaps) == 0, f"H7: all HTTP exact codes described ({len(gaps)} gaps)")


def main():
    test_h1_db_schema()
    test_h2_api_signatures()
    test_h3_webhook_payloads()
    test_h4_export_excel()
    test_h5_snapshot_fidelity()
    test_h6_old_data_compat()
    test_h7_describe_for_export()
    total = _passed + _failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {_passed} passed, {_failed} failed out of {total}")
    return _failed


if __name__ == "__main__":
    sys.exit(main())
