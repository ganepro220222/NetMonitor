"""Regression checks for bug 111 (Web _stats cleared on history wipe)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)
MAIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def test_web_clears_stats_on_wipe_complete():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    block = src.split("def on_target_history_wiped", 1)[1].split(
        "def reset_target_stats", 1)[0]
    ok = (
        "def on_target_history_wiped" in src
        and '_stats.pop(tid, None)' in block
        and '"type": "history_wiped"' in block
    )
    print(f"Bug111 on_target_history_wiped clears _stats -> {ok}")
    return ok


def test_main_wipe_begins_pending():
    with open(MAIN, encoding="utf-8") as f:
        block = f.read().split("if wipe_intent:", 1)[1].split(
            "# The probe target changed identity", 1)[0]
    ok = "begin_target_history_wipe(target_id)" in block
    print(f"Bug111 wipe path begins pending shield -> {ok}")
    return ok


def test_sse_client_handles_stats_reset():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = "msg.type==='stats_reset'" in src and "purgeDonutTarget(msg.tid)" in src
    print(f"Bug111 browser stats_reset handler -> {ok}")
    return ok


def main():
    results = [
        ("web_wiped", test_web_clears_stats_on_wipe_complete()),
        ("main_wipe", test_main_wipe_begins_pending()),
        ("sse_js", test_sse_client_handles_stats_reset()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 111 checks passed.")


if __name__ == "__main__":
    main()
