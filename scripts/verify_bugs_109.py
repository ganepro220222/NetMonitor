"""Regression checks for bug 109 (mini-chart warn line follows threshold changes)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHART_PANEL = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "chart_panel.py",
)
MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def test_chart_panel_set_warn_latency():
    with open(CHART_PANEL, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def set_warn_latency" in src
        and "_warn_line.set_ydata" in src
        and "self.warn_latency = value" in src
    )
    print(f"Bug109 ChartPanel.set_warn_latency -> {ok}")
    return ok


def test_render_syncs_ydata():
    with open(CHART_PANEL, encoding="utf-8") as f:
        block = f.read().split("def _render_chart", 1)[1].split(
            "def ", 2)[0]
    ok = "_warn_line.set_ydata([self.warn_latency" in block
    print(f"Bug109 _render_chart syncs warn line y -> {ok}")
    return ok


def test_apply_settings_uses_set_warn_latency():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split("def _apply_settings", 1)[1].split(
            "def _on_add", 1)[0]
    ok = (
        "set_warn_latency" in block
        and "warn_latency =" not in block.replace("set_warn_latency", "")
    )
    print(f"Bug109 _apply_settings uses set_warn_latency -> {ok}")
    return ok


def test_on_edit_syncs_chart_line():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        edit_block = f.read().split("def _on_edit", 1)[1].split(
            "def _on_delete", 1)[0]
    ok = (
        "def _sync_card_chart_warn_line" in open(MAIN_WINDOW, encoding="utf-8").read()
        and "_sync_card_chart_warn_line(target_id)" in edit_block
    )
    print(f"Bug109 _on_edit syncs chart warn line -> {ok}")
    return ok


def main():
    results = [
        ("set_method", test_chart_panel_set_warn_latency()),
        ("render_y", test_render_syncs_ydata()),
        ("apply_settings", test_apply_settings_uses_set_warn_latency()),
        ("on_edit", test_on_edit_syncs_chart_line()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 109 checks passed.")


if __name__ == "__main__":
    main()
