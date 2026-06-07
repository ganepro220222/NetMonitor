"""Regression checks for probe-context propagation (Bug 142)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.alert_manager import AlertManager, WebhookIncident
from src.config_manager import DEFAULT_CONFIG
from src.trace_policy import (
    _HTTP_ENDPOINT_EXACT,
    describe_failure,
    ping_type_label,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Cfg:
    def __init__(self, **overrides):
        self._s = dict(DEFAULT_CONFIG["settings"])
        self._s.update(overrides)

    def get_setting(self, key):
        return self._s.get(key)


def test_http_endpoint_exact_complete():
    needed = {
        "bad_response", "body_incomplete", "body_recv_timeout",
        "chunked_premature_eof", "header_incomplete", "recv_closed",
        "recv_timeout", "tcp_failed", "tls_timeout",
    }
    ok = needed.issubset(_HTTP_ENDPOINT_EXACT)
    print(f"Bug142 HTTP endpoint exact set complete -> {ok}")
    return ok


def test_describe_failure_coverage():
    codes = [
        "too_many_redirects", "bad_response", "body_recv_timeout",
        "header_incomplete", "recv_closed", "tls_timeout", "status_503",
        "dns_hijack:1.2.3.4", "tcp_failed:reset",
    ]
    ok = all(describe_failure(c) and describe_failure(c) != c for c in codes)
    ok = ok and describe_failure(None) == ""
    ok = ok and describe_failure("too_many_redirects") == "HTTP 重定向过多"
    print(f"Bug142 describe_failure coverage -> {ok}")
    return ok


def test_record_alert_persists_ping_type():
    from src.data_store import DataStore
    import sqlite3

    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db.close()
    try:
        ds = DataStore(db.name)
        ds.record_alert(
            target_id="t1", label="GW", ip="10.0.0.1",
            ts=time.time(), old_status="green", new_status="red",
            category="availability", failure_reason="connection_refused",
            ping_type="tcp")
        ds.flush()
        ds.shutdown()
        conn = sqlite3.connect(db.name)
        row = conn.execute(
            "SELECT failure_reason, ping_type FROM alert_events WHERE target_id='t1'"
        ).fetchone()
        conn.close()
        ok = row == ("connection_refused", "tcp")
        print(f"Bug142 record_alert ping_type persisted -> {ok} ({row})")
        return ok
    finally:
        for p in (db.name, db.name + "-shm", db.name + "-wal"):
            try:
                os.unlink(p)
            except OSError:
                pass


def test_snapshot_and_webhook_extra():
    a = AlertManager(enabled=False, assets_dir=os.path.join(ROOT, "assets"))
    a.set_config(_Cfg())
    a.on_status_change(
        "t1", "GW", "10.0.0.1", "red",
        ping_type="http", failure_reason="too_many_redirects")
    extra = a._build_incident_extra("t1")
    inc = extra.get("incident") or {}
    ok = (
        inc.get("ping_type") == "http"
        and inc.get("failure_reason") == "too_many_redirects"
        and inc.get("failure_reason_text") == "HTTP 重定向过多"
        and inc.get("ping_type_label") == "HTTP"
    )
    text = AlertManager._format_webhook_text(
        "🔴", "网络监控告警", "alert_red", "GW", "10.0.0.1", "red",
        "连接中断", "2026-01-01 00:00:00", extra)
    ok = ok and "探测类型：HTTP" in text and "失败原因：HTTP 重定向过多" in text
    print(f"Bug142 webhook incident probe fields -> {ok}")
    return ok


def test_snapshot_roundtrip():
    inc = WebhookIncident(
        tid="t1", label="T", ip="1.1.1.1", started_at=time.time(),
        ping_type="dns", failure_reason="nxdomain", trace_applicable=False)
    snap = AlertManager._snapshot_incident(inc)
    ok = (
        snap["ping_type"] == "dns"
        and snap["failure_reason"] == "nxdomain"
        and snap["trace_applicable"] is False
    )
    print(f"Bug142 snapshot preserves probe fields -> {ok}")
    return ok


def test_excel_wiring():
    path = os.path.join(ROOT, "src", "data_store.py")
    with open(path, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "ping_type FROM alert_events" in src
        and ("探测类型" in src)
        and "ping_type_label(ev_pt)" in src
        and "describe_failure(fr)" in src
    )
    print(f"Bug142 excel timeline wiring -> {ok}")
    return ok


def main():
    results = [
        test_http_endpoint_exact_complete(),
        test_describe_failure_coverage(),
        test_record_alert_persists_ping_type(),
        test_snapshot_and_webhook_extra(),
        test_snapshot_roundtrip(),
        test_excel_wiring(),
    ]
    if not all(results):
        print("FAILED")
        sys.exit(1)
    print("All bug 142 checks passed.")


if __name__ == "__main__":
    main()
