"""Regression checks for bug 88 (Excel alert timeline spans export window)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)


def _alert(ds, tid, ts, old, new, cat="availability", fr=""):
    ds.record_alert(
        target_id=tid, label="n", ip="1.2.3.4", ts=ts,
        old_status=old, new_status=new, category=cat, failure_reason=fr)


def _export_alert_text(ds, tid, start_ts, end_ts):
    import openpyxl

    fd, path = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    meta = {tid: {"label": "NodeT", "ip": "1.2.3.4"}}
    ds.export_excel(path, [tid], start_ts, end_ts, meta)
    wb = openpyxl.load_workbook(path)
    ws = wb["告警时间线"]
    lines = []
    for row in ws.iter_rows(values_only=True):
        lines.append(" | ".join(str(c) if c is not None else "" for c in row))
    os.unlink(path)
    return "\n".join(lines)


def test_long_outage_covers_window():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        end_ts = int(time.time())
        start_ts = end_ts - 86400
        tid = "T"
        _alert(ds, tid, start_ts - 48 * 3600, "green", "red")
        ds.flush()
        sla = ds.get_sla_stats(tid, start_ts, end_ts)
        text = _export_alert_text(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = (
            sla.get("uptime_pct") == 0.0
            and sla.get("outage_count", 0) >= 1
            and "查询时段内无故障事件记录" not in text
            and ("仍未恢复" in text or "查询范围外" in text or "故障事件" in text)
        )
        print(f"Bug88 long outage: uptime={sla.get('uptime_pct')} "
              f"no_fault_msg={'查询时段内无故障事件记录' in text} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_outage_started_before_recovers_in_window():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        end_ts = int(time.time())
        start_ts = end_ts - 86400
        tid = "T2"
        _alert(ds, tid, start_ts - 48 * 3600, "green", "red")
        _alert(ds, tid, start_ts + 12 * 3600, "red", "green", cat="ok")
        ds.flush()
        text = _export_alert_text(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = (
            "查询时段内无故障事件记录" not in text
            and "故障事件" in text
            and ("正常" in text or "恢复" in text)
        )
        print(f"Bug88 recover in window -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_in_window_fault_unchanged():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        end_ts = int(time.time())
        start_ts = end_ts - 3600
        tid = "T3"
        _alert(ds, tid, start_ts + 600, "green", "red")
        _alert(ds, tid, start_ts + 1200, "red", "green", cat="ok")
        ds.flush()
        text = _export_alert_text(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = "故障事件" in text and "查询时段内无故障事件记录" not in text
        print(f"Bug88 in-window fault -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_boundary_query():
    with open(DATA_STORE, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_get_export_alert_events" in src
        and "ORDER BY ts DESC, id DESC LIMIT 1" in src.split(
            "_get_export_alert_events", 1)[1].split("def export_excel", 1)[0]
        and "extended_start = start_ts - 86400" not in src
    )
    print(f"Bug88 source boundary export query -> {ok}")
    return ok


def main():
    results = [
        ("long", test_long_outage_covers_window()),
        ("recover", test_outage_started_before_recovers_in_window()),
        ("in_window", test_in_window_fault_unchanged()),
        ("source", test_source_boundary_query()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 88 checks passed.")


if __name__ == "__main__":
    main()
