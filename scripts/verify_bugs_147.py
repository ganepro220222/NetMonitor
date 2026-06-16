"""Regression: Excel timeline marks/duration for pre-window incidents (Bug 147)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore


def _alert(ds, tid, ts, old, new, cat="availability"):
    ds.record_alert(
        target_id=tid, label="Node", ip="1.2.3.4", ts=float(ts),
        old_status=old, new_status=new, category=cat)


def _export_headers(ds, tid, start_ts, end_ts):
    import openpyxl

    fd, path = tempfile.mkstemp(suffix=".xlsx")
    os.close(fd)
    meta = {tid: {"label": "Node", "ip": "1.2.3.4", "ping_type": "icmp"}}
    ds.export_excel(path, [tid], start_ts, end_ts, meta)
    wb = openpyxl.load_workbook(path)
    ws = wb["告警时间线"]
    headers = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        cell = row[0] if row else None
        if isinstance(cell, str) and "故障事件" in cell:
            headers.append(cell)
    os.unlink(path)
    return headers


def test_pre_window_start_truncated_label_and_duration():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        # Window: today 00:00 .. 24:00 (86400s span)
        start_ts = 1_700_000_000
        end_ts = start_ts + 86400
        tid = "T1"
        # Fault: 1h before window -> red; 1h into window -> green (2h total,
        # 1h inside window).
        _alert(ds, tid, start_ts - 3600, "green", "red")
        _alert(ds, tid, start_ts + 3600, "red", "green", cat="ok")
        ds.flush()
        headers = _export_headers(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = len(headers) == 1
        ok = ok and "开始于查询范围外" in headers[0]
        ok = ok and "1时00分00秒" in headers[0]
        ok = ok and "2时00分00秒" not in headers[0]
        print(f"Bug147 truncated header + window duration -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_in_window_fault_not_truncated():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        start_ts = int(time.time()) - 7200
        end_ts = int(time.time())
        tid = "T2"
        _alert(ds, tid, start_ts + 600, "green", "red")
        _alert(ds, tid, start_ts + 1200, "red", "green", cat="ok")
        ds.flush()
        headers = _export_headers(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = (
            len(headers) == 1
            and "开始于查询范围外" not in headers[0]
            and "故障事件 #1" in headers[0]
        )
        print(f"Bug147 in-window fault normal header -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_recovery_at_window_start_shows_zero_not_ongoing():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        start_ts = 1_700_100_000
        end_ts = start_ts + 86400
        tid = "T3"
        _alert(ds, tid, start_ts - 3600, "green", "red")
        _alert(ds, tid, start_ts, "red", "green", cat="ok")
        ds.flush()
        headers = _export_headers(ds, tid, start_ts, end_ts)
        ds.shutdown()
        ok = len(headers) == 1
        ok = ok and "开始于查询范围外" in headers[0]
        ok = ok and "仍在持续" not in headers[0]
        ok = ok and "0秒" in headers[0]
        print(f"Bug147 recovery at window start -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def main():
    results = [
        ("truncated", test_pre_window_start_truncated_label_and_duration()),
        ("in_window", test_in_window_fault_not_truncated()),
        ("window_start_recovery", test_recovery_at_window_start_shows_zero_not_ongoing()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 147 checks passed.")


if __name__ == "__main__":
    main()
