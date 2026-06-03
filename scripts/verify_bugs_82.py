"""Regression checks for bug 82 (probe_success vs alert status in stats)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore
from src.ping_engine import PingResult, TargetMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_STORE = os.path.join(ROOT, "src", "data_store.py")
PING_ENGINE = os.path.join(ROOT, "src", "ping_engine.py")

CFG = {
    "window_size": 10,
    "ping_interval": 1.0,
    "consecutive_loss_orange": 3,
    "consecutive_loss_red": 5,
    "latency_warn_ms": 1000,
    "consecutive_lat_orange": 3,
    "recovery_count": 5,
}


def test_failed_probe_keeps_green_but_probe_success_false():
    mon = TargetMonitor("t", "1.2.3.4", CFG, lambda *a, **k: None,
                        initial_status="green")
    mon._status = "green"
    state = mon._compute_state(
        PingResult(success=False, latency_ms=None, failure_reason="timeout"))
    ok = (state.status == "green" and state.probe_success is False
          and state.latency_ms is None and state.consecutive_loss == 1)
    print(f"Bug82 state green + probe_success=False: status={state.status} "
          f"probe_success={state.probe_success} loss={state.consecutive_loss} "
          f"-> {ok}")
    return ok


def test_hourly_bucket_failed_green_row():
    row = (None, "green", "timeout", 0)
    bucket = DataStore._compute_hourly_bucket([row])
    ok = (
        bucket is not None
        and bucket["sample_n"] == 1
        and bucket["success_n"] == 0
        and bucket["loss_rate"] == 1.0
    )
    print(f"Bug82 hourly green+fail row: {bucket} -> {ok}")
    return ok


def test_http_fail_with_rtt_not_counted_success():
    row = (150.0, "green", "http_status_mismatch", 0)
    bucket = DataStore._compute_hourly_bucket([row])
    ok = bucket and bucket["success_n"] == 0
    print(f"Bug82 HTTP fail with RTT: success_n={bucket and bucket['success_n']} "
          f"-> {ok}")
    return ok


def _ds_with_pings(pings):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    ds = DataStore(path)
    ds._schema_ready.wait(timeout=5)
    base = int(time.time()) - 3600
    for i, (ok, lat, fr) in enumerate(pings):
        ds.record_ping(
            target_id="T", label="n", ip="1.2.3.4", ping_type="icmp",
            ts=base + i, status="green",
            latency_ms=lat if ok else None,
            loss_rate=0.0 if ok else 1.0,
            probe_success=ok,
            failure_reason=None if ok else fr,
        )
    ds.flush()
    return ds, path, base


def test_nine_success_one_fail_consistent_stats():
    pings = [(True, 10.0, None)] * 9 + [(False, None, "timeout")]
    ds, path, base = _ds_with_pings(pings)
    try:
        end = base + 20
        wf = ds.get_waveform("T", base, end)
        sla = ds.get_sla_stats("T", base, end)
        rows = ds.get_history("T", base, end, use_hourly=False)
        excel_ok = sum(
            1 for r in rows
            if ds.row_probe_success(
                r["latency_ms"], r["status"],
                r.get("failure_reason"), r.get("probe_success"))) == 9
        wf_ok = (
            wf["summary"].get("sample_n") == 10
            and wf["summary"].get("loss_rate") == 0.1
        )
        sla_ok = sla.get("sample_n") == 10
        ok = wf_ok and sla_ok and excel_ok
        print(f"Bug82 9+1: wf_loss={wf['summary'].get('loss_rate')} "
              f"sla_sample_n={sla.get('sample_n')} excel_success=9 -> {ok}")
        return ok
    finally:
        ds.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_probe_success_wiring():
    with open(DATA_STORE, encoding="utf-8") as f:
        ds_src = f.read()
    with open(PING_ENGINE, encoding="utf-8") as f:
        pe_src = f.read()
    ok = (
        "probe_success" in ds_src
        and "_PROBE_OK_SQL" in ds_src
        and "_PROBE_OK_SQL" in ds_src.split("_raw_window_bucket", 1)[1].split(
            "def _raw_covers_window_start", 1)[0]
        and "probe_success: bool" in pe_src
        and "probe_success" in pe_src.split("return TargetState", 1)[1]
        and "latest.success" in pe_src.split("return TargetState", 1)[1]
        and "probe_success=state.probe_success" in open(
            os.path.join(ROOT, "src", "ui", "main_window.py"),
            encoding="utf-8").read()
        and "probe_success" in open(
            os.path.join(ROOT, "src", "web_server.py"), encoding="utf-8").read()
    )
    print(f"Bug82 source wiring -> {ok}")
    return ok


def main():
    results = [
        ("state", test_failed_probe_keeps_green_but_probe_success_false()),
        ("hourly", test_hourly_bucket_failed_green_row()),
        ("http_rtt", test_http_fail_with_rtt_not_counted_success()),
        ("nine_one", test_nine_success_one_fail_consistent_stats()),
        ("source", test_source_probe_success_wiring()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 82 checks passed.")


if __name__ == "__main__":
    main()
