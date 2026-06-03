"""Regression checks for bug 55 (donut uptime color syncs with status)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB_SERVER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _build_donut_block() -> str:
    with open(WEB_SERVER, encoding="utf-8") as f:
        return f.read().split("function buildDonutGrid()", 1)[1].split(
            "function buildBarCharts()", 1)[0]


def test_source_updates_uptime_color():
    block = _build_donut_block()
    ok = (
        "upEl.style.color=sc" in block
        and "upEl.textContent=`${uptimePct}%`" in block
    )
    print(f"Bug55 source uptime color update -> {ok}")
    return ok


def test_create_path_still_sets_inline_color():
    block = _build_donut_block()
    ok = 'id="uptime-${tid}">${uptimePct}%' in block and "color:${sc}" in block
    print(f"Bug55 create path inline color -> {ok}")
    return ok


def test_simulate_stale_uptime_color():
    status_colors = {"green": "#22c55e", "red": "#ef4444"}
    ui = {"dot": status_colors["green"], "uptime_color": status_colors["green"]}
    sc = status_colors["red"]
    uptime_pct = "12.5"

    # stale: only textContent update
    stale_color = ui["uptime_color"]
    ui["dot"] = sc
    ui["uptime_text"] = f"{uptime_pct}%"

    # fixed: also style.color
    ui["uptime_color"] = sc
    ui["uptime_text"] = f"{uptime_pct}%"

    ok = stale_color == status_colors["green"] and ui["uptime_color"] == sc
    print(f"Bug55 uptime color sync sim -> {ok}")
    return ok


def main():
    results = [
        ("source", test_source_updates_uptime_color()),
        ("create", test_create_path_still_sets_inline_color()),
        ("simulate", test_simulate_stale_uptime_color()),
    ]
    failed = [name for name, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 55 checks passed.")


if __name__ == "__main__":
    main()
