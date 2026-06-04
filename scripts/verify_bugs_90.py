"""Regression checks for bug 90 (cum_stats latency excludes failed-probe RTT)."""
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


def test_cum_stats_latency_only_successful_probes():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        tid = "T"
        ts = time.time()
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=ts, status="green", latency_ms=10.0, loss_rate=0.0,
            probe_success=True)
        ds.record_ping(
            target_id=tid, label="node", ip="1.2.3.4", ping_type="http",
            ts=ts + 1, status="green", latency_ms=1000.0, loss_rate=1.0,
            probe_success=False, failure_reason="status_500")
        ds.flush()
        cum = ds.get_cum_stats().get(tid, {})
        ds.shutdown()
        ok = (
            cum.get("total") == 2
            and cum.get("success") == 1
            and cum.get("latency_avg") == 10.0
            and cum.get("latency_n") == 1
        )
        print(f"Bug90 cum_stats={cum} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_cum_stats_matches_web_semantics():
    with open(DATA_STORE, encoding="utf-8") as f:
        block = f.read().split("def _update_cum_stats", 1)[1].split(
            "def _hourly_agg", 1)[0]
    ok = (
        "probe_ok" in block
        and "if probe_ok and p[\"latency_ms\"] is not None:" in block
        and block.count("row_probe_success") == 1
    )
    with open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src", "web_server.py"), encoding="utf-8") as f:
        web = f.read().split("def update_target(", 1)[1].split(
            "def remove_target", 1)[0]
    web_ok = "probe_success and latency_ms is not None" in web
    print(f"Bug90 source cum_stats probe_ok lat gate -> {ok}")
    print(f"Bug90 web realtime same semantics -> {web_ok}")
    return ok and web_ok


def main():
    results = [
        ("cum", test_cum_stats_latency_only_successful_probes()),
        ("source", test_source_cum_stats_matches_web_semantics()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 90 checks passed.")


if __name__ == "__main__":
    main()
