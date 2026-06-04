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


def test_web_reset_target_stats():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def reset_target_stats" in src
        and '_stats.pop(tid, None)' in src.split("def reset_target_stats", 1)[1].split(
            "def invalidate_traceroute", 1)[0]
        and '"type": "stats_reset"' in src
    )
    print(f"Bug111 WebServer.reset_target_stats -> {ok}")
    return ok


def test_main_wipe_calls_reset():
    with open(MAIN, encoding="utf-8") as f:
        block = f.read().split("if wipe_intent:", 1)[1].split(
            "# The probe target changed identity", 1)[0]
    ok = "reset_target_stats(target_id)" in block
    print(f"Bug111 wipe path calls reset_target_stats -> {ok}")
    return ok


def test_sse_client_handles_stats_reset():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = "msg.type==='stats_reset'" in src and "purgeDonutTarget(msg.tid)" in src
    print(f"Bug111 browser stats_reset handler -> {ok}")
    return ok


def main():
    results = [
        ("web_method", test_web_reset_target_stats()),
        ("main_wipe", test_main_wipe_calls_reset()),
        ("sse_js", test_sse_client_handles_stats_reset()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 111 checks passed.")


if __name__ == "__main__":
    main()
