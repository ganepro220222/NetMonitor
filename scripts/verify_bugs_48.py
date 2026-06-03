"""Regression checks for bug 48 (stats range async race / stale response)."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def test_source_has_stats_req_guard():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    block = text.split("async function _refreshStatsCharts()", 1)[1].split(
        "// 导出 Excel", 1)[0]
    ok = (
        "let _statsReqId = 0" in text
        and "const reqId=++_statsReqId;" in block
        and "const start=_statsStart;" in block
        and "const end=_statsEnd;" in block
        and "if(reqId!==_statsReqId) return;" in block
        and "`/api/stats?start=${start}&end=${end}`" in block
        and "_fmt(_statsStart)" not in block
        and "_fmt(_statsEnd)" not in block
    )
    print(f"Bug48 source _statsReqId guard -> {ok}")
    return ok


async def _refresh_sim(stats_req_id: dict, start: int, end: int, delay: float, payload: str):
    """Mirror _refreshStatsCharts stale-guard (render + time-info only)."""
    req_id = stats_req_id["id"] = stats_req_id["id"] + 1
    captured_start, captured_end = start, end
    await asyncio.sleep(delay)
    if req_id != stats_req_id["id"]:
        return None
    rendered = payload
    time_info = f"{captured_start}-{captured_end}"
    return {"rendered": rendered, "time_info": time_info, "req_id": req_id}


async def test_stale_response_discarded():
    """New request finishes first; late old response must not overwrite."""
    stats_req_id = {"id": 0}
    global_start, global_end = 2000, 3000

    old = asyncio.create_task(
        _refresh_sim(stats_req_id, 1000, 1500, 0.05, "OLD_RANGE")
    )
    new = asyncio.create_task(
        _refresh_sim(stats_req_id, global_start, global_end, 0.01, "NEW_RANGE")
    )
    new_res = await new
    old_res = await old

    ok = (
        new_res is not None
        and new_res["rendered"] == "NEW_RANGE"
        and new_res["time_info"] == f"{global_start}-{global_end}"
        and old_res is None
    )
    print(f"Bug48 stale response discarded -> {ok}")
    return ok


def test_waveform_pattern_parity():
    with open(WEB_SERVER, encoding="utf-8") as f:
        text = f.read()
    ok = "_waveReqId" in text and "_statsReqId" in text
    print(f"Bug48 waveform/stats req-id parity -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_has_stats_req_guard()),
        ("stale", asyncio.run(test_stale_response_discarded())),
        ("parity", test_waveform_pattern_parity()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 48 checks passed.")


if __name__ == "__main__":
    main()
