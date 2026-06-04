"""Regression checks for bug 104 (chart clear + Web pause on start)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import WebServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART_PANEL = os.path.join(ROOT, "src", "ui", "chart_panel.py")
IP_CARD = os.path.join(ROOT, "src", "ui", "ip_card.py")
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


def test_web_start_respects_paused_cards():
    """Simulate _push_web_target_snapshots: paused card -> pause_target."""
    ws = WebServer(port=18766)
    ws._running = True
    ws.update_target(
        "t1", "n", "1.2.3.4", "gray",
        latency_ms=None, jitter_ms=None, loss_rate=0.0,
        is_probe_result=False)
    ws.pause_target("t1")
    ok = (
        "t1" in ws._paused
        and ws._targets.get("t1", {}).get("status") == "paused"
    )
    print(f"Bug104 web pause_target sets paused status -> {ok}")
    return ok


def test_source_chart_clear_on_empty_history():
    with open(CHART_PANEL, encoding="utf-8") as f:
        cp = f.read()
    block = cp.split("def _render_chart(self):", 1)[1].split(
        "except Exception as e:", 1)[0]
    ok = (
        "def clear_chart(self):" in cp
        and "self.clear_chart()" in block
        and "history.is_empty()" in block
    )
    print(f"Bug104 chart clear_chart on empty history -> {ok}")
    return ok


def test_source_main_window_hooks():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        mw = f.read()
    edit = mw.split("self.history.remove_target(target_id)", 1)[1][:800]
    ok = (
        "clear_chart_display" in edit
        and "_push_web_target_snapshots" in mw
        and "card.is_paused" in mw
        and "pause_target(tid)" in mw
    )
    print(f"Bug104 main_window chart + web pause hooks -> {ok}")
    return ok


def test_source_ip_card_wrapper():
    with open(IP_CARD, encoding="utf-8") as f:
        ok = "def clear_chart_display(self):" in f.read()
    print(f"Bug104 ip_card clear_chart_display -> {ok}")
    return ok


def main():
    results = [
        ("web_pause", test_web_start_respects_paused_cards()),
        ("chart", test_source_chart_clear_on_empty_history()),
        ("main", test_source_main_window_hooks()),
        ("ip_card", test_source_ip_card_wrapper()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 104 checks passed.")


if __name__ == "__main__":
    main()
