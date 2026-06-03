"""Regression checks for bug 77 (SLA table shows 0.0 ms, not --)."""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_store import DataStore

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _sla_ms_js(v):
    """Mirror fixed renderSLATable ms() helper."""
    return "--" if v is None else f"{v} ms"


def test_sla_ms_formatter_accepts_zero():
    ok = (
        _sla_ms_js(0.0) == "0.0 ms"
        and _sla_ms_js(0) == "0 ms"
        and _sla_ms_js(None) == "--"
        and _sla_ms_js(12.5) == "12.5 ms"
        and _sla_ms_js(0.0) != "--"
    )
    print(f"Bug77 ms() 0.0 -> {_sla_ms_js(0.0)!r} null -> {_sla_ms_js(None)!r} -> {ok}")
    return ok


def test_backend_returns_zero_latency():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        ds = DataStore(path)
        ds._schema_ready.wait(timeout=5)
        base = float(int(time.time()))
        ds.record_ping(
            target_id="T", label="n", ip="127.0.0.1", ping_type="icmp",
            ts=base, status="green", latency_ms=0.0, loss_rate=0.0)
        ds.flush()
        start = int(base) - 60
        end = int(base) + 60
        sla = ds.get_sla_stats("T", start, end)
        dash = ds.get_dashboard_stats_batch(["T"], start, end)["T"]
        ds.shutdown()
        ok = (
            sla["lat_avg"] == 0.0
            and sla["lat_max"] == 0.0
            and sla["lat_p95"] == 0.0
            and dash["lat_avg"] == 0.0
        )
        print(f"Bug77 backend sla={sla} dash={dash} -> {ok}")
        return ok
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_source_sla_ms_only_null_is_dash():
    with open(WEB_SERVER, encoding="utf-8") as f:
        block = f.read().split("function renderSLATable()", 1)[1].split(
            "function exportSLAExcel()", 1)[0]
    ok = (
        re.search(r'const ms\s*=\s*v\s*=>\s*v\s*==\s*null\s*\?', block) is not None
        and "v===0" not in block.split("const fmtMin")[0]
        and "fmtMin" in block
    )
    print(f"Bug77 source SLA ms() null-only dash -> {ok}")
    return ok


def main():
    results = [
        ("formatter", test_sla_ms_formatter_accepts_zero()),
        ("backend", test_backend_returns_zero_latency()),
        ("source", test_source_sla_ms_only_null_is_dash()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 77 checks passed.")


if __name__ == "__main__":
    main()
