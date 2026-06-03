"""Regression checks for bug 80 (waveform summary when Chart.js missing)."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _render_waveform_body(text: str) -> str:
    return text.split("function _renderWaveform(data, alerts){", 1)[1].split(
        "async function _refreshStatsCharts", 1)[0]


def test_summary_before_chart_guard():
    body = _render_waveform_body(open(WEB_SERVER, encoding="utf-8").read())
    guard_pos = body.find("typeof Chart")
    res_pos = body.find("waveform-resolution")
    sum_pos = body.find("waveform-summary")
    chart_pos = body.find("new Chart(")
    ok = (
        res_pos != -1 and sum_pos != -1 and guard_pos != -1 and chart_pos != -1
        and res_pos < guard_pos
        and sum_pos < guard_pos
        and guard_pos < chart_pos
        and not re.match(
            r"\s*if\s*\(\s*typeof\s+Chart\s*===\s*['\"]undefined['\"]\s*\)\s*return\s*;",
            body.lstrip(),
        )
    )
    print(f"Bug80 summary before Chart guard -> {ok}")
    return ok


def test_no_early_return_at_function_start():
    body = _render_waveform_body(open(WEB_SERVER, encoding="utf-8").read())
    head = body.strip()[:400]
    ok = "typeof Chart" not in head.split("waveform-resolution", 1)[0]
    print(f"Bug80 no Chart guard at function start -> {ok}")
    return ok


def test_chart_guard_shows_empty_hint():
    body = _render_waveform_body(open(WEB_SERVER, encoding="utf-8").read())
    block = body.split("typeof Chart==='undefined'", 1)[1].split("new Chart(", 1)[0]
    ok = (
        "emptyEl" in block
        and "图表库加载失败" in block
        and "摘要数据已显示" in block
    )
    print(f"Bug80 Chart-missing empty hint -> {ok}")
    return ok


def test_empty_points_before_chart():
    body = _render_waveform_body(open(WEB_SERVER, encoding="utf-8").read())
    ok = (
        body.find("pts.length===0") < body.find("typeof Chart")
        and "该时间段暂无波形数据" in body
    )
    print(f"Bug80 no-points empty before chart -> {ok}")
    return ok


def main():
    results = [
        ("summary_first", test_summary_before_chart_guard()),
        ("no_early", test_no_early_return_at_function_start()),
        ("empty_hint", test_chart_guard_shows_empty_hint()),
        ("no_points", test_empty_points_before_chart()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 80 checks passed.")


if __name__ == "__main__":
    main()
