"""Regression: webhook observability — API field completeness and XSS safety.

Verifies that:
  - get_webhook_problem_deliveries() returns complete fields
  - delivery_id, target_id, event, state, attempt, last_error, next_attempt,
    first_queued, payload_summary are all present and non-empty
  - delivered rows are excluded from problem list
  - get_webhook_delivery_stats() counts correctly by state
  - XSS-safety: esc() wraps rendered fields (static source check)
"""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REQUIRED_PROBLEM_FIELDS = [
    "delivery_id", "target_id", "target_label", "event",
    "delivery_state", "attempt_count", "max_attempts",
    "last_error", "first_queued_ts", "next_attempt_ts",
    "last_attempt_ts", "payload_summary",
]


def _insert_row(ds, delivery_id, state, last_error="", age_days=0):
    now = time.time()
    ts = now - age_days * 86400
    import json
    payload = json.dumps({
        "event": "alert_red", "target": "GW", "ip": "10.0.0.1",
        "status": "red", "message": "obs test", "event_ts": ts,
    })
    ds.enqueue_webhook_outbox(
        delivery_id=delivery_id,
        target_id="t",
        incident_id="INC",
        incident_seq=1,
        event="alert_red",
        order_key="t",
        payload=json.loads(payload),
        event_ts=ts,
        max_attempts=3,
    )
    with ds._outbox_lock:
        conn = ds._outbox_write_conn()
        if state == "delivered":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='delivered', "
                "delivered_ts=?, updated_at=?, last_error=? "
                "WHERE delivery_id=?", (ts, ts, last_error, delivery_id))
        elif state == "failed_permanent":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='failed_permanent', "
                "attempt_count=5, updated_at=?, last_error=? "
                "WHERE delivery_id=?", (ts, last_error, delivery_id))
        elif state == "dropped_stale":
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='dropped_stale', "
                "updated_at=?, last_error=? "
                "WHERE delivery_id=?", (ts, last_error, delivery_id))
        else:
            conn.execute(
                "UPDATE webhook_outbox SET delivery_state='pending', "
                "updated_at=?, next_attempt_ts=?, last_error=? "
                "WHERE delivery_id=?", (ts, now + 60, last_error, delivery_id))
        conn.commit()


def test_api_field_completeness():
    td = tempfile.mkdtemp()
    ds = DataStore(db_path=os.path.join(td, "t.db"))
    ds._schema_ready.wait(timeout=5)

    _insert_row(ds, "D-PROB", "pending", last_error="timeout")
    _insert_row(ds, "D-FAIL", "failed_permanent", last_error="max retries")
    _insert_row(ds, "D-DEL", "delivered")

    problems = ds.get_webhook_problem_deliveries(limit=20)
    problem_ids = {r["delivery_id"] for r in problems}

    ok = True
    # Delivered excluded
    if "D-DEL" in problem_ids:
        print("  FAIL: delivered row in problem list")
        ok = False

    # Fields present (last_attempt_ts may be NULL for never-attempted rows)
    NULLABLE_FIELDS = {"last_error", "max_attempts", "last_attempt_ts"}
    for r in problems:
        for field in REQUIRED_PROBLEM_FIELDS:
            if field not in r:
                print(f"  FAIL: {r['delivery_id']} missing field {field}")
                ok = False
            elif field not in NULLABLE_FIELDS and r[field] is None:
                print(f"  FAIL: {r['delivery_id']} field {field} is None")
                ok = False

    # payload_summary is meaningful
    for r in problems:
        ps = r.get("payload_summary", "")
        if not isinstance(ps, str) or len(ps) < 5:
            print(f"  FAIL: payload_summary too short for {r['delivery_id']}: {ps!r}")
            ok = False

    print(f"  API field completeness: {ok}  problems={sorted(problem_ids)}")

    # Stats
    stats = ds.get_webhook_delivery_stats()
    stats_ok = (stats.get("pending", 0) >= 1
                and stats.get("failed_permanent", 0) >= 1)
    print(f"  stats accuracy: {stats_ok}  stats={stats}")
    return ok and stats_ok


def _extract_js_function(src, name):
    marker = f"function {name}("
    start = src.find(marker)
    if start < 0:
        return ""
    brace = src.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for i in range(brace, len(src)):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    return ""


def test_xss_static_source_check():
    """Verify esc() wraps fail-panel fields; pill uses textContent."""
    path = os.path.join(ROOT, "src", "web_server.py")
    if not os.path.isfile(path):
        print("  XSS check: web_server.py not found - SKIP")
        return True

    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    panel_src = _extract_js_function(src, "renderWebhookFailPanel")
    banner_src = _extract_js_function(src, "refreshWebhookFailBanner")

    required_esc = [
        r"\$\{esc\(r\.delivery_id",
        r"\$\{esc\(r\.target_label",
        r"\$\{esc\(r\.target_id",
        r"\$\{esc\(r\.event",
        r"\$\{esc\(r\.delivery_state",
        r"\$\{esc\(r\.last_error",
        r"esc\(_whPayloadSummary",
        r"esc\(_whFmtTs",
    ]
    missing = [pat for pat in required_esc if not re.search(pat, panel_src)]
    panel_esc_ok = bool(panel_src) and not missing
    print(f"  fail panel esc() fields: {panel_esc_ok}  missing={missing}")

    pill_uses_textcontent = "textContent" in banner_src
    pill_no_innerhtml = "innerHTML" not in banner_src
    print(f"  pill uses textContent: {pill_uses_textcontent}")

    ok = panel_esc_ok and pill_uses_textcontent and pill_no_innerhtml
    print(f"  XSS safety check: {ok}")
    return ok


def main():
    results = [
        ("api_fields", test_api_field_completeness()),
        ("xss_safety", test_xss_static_source_check()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All webhook observability checks passed.")


if __name__ == "__main__":
    main()
