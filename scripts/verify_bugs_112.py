"""Regression checks for bug 112 (defer Web history reload until DB wipe completes)."""
import os

DATA_STORE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "data_store.py",
)
WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)
MAIN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def test_data_store_wipe_callback():
    with open(DATA_STORE, encoding="utf-8") as f:
        src = f.read()
    wipe_block = src.split('elif kind == "wipe_target"', 1)[1].split(
        'elif kind == "diag"', 1)[0]
    ok = (
        "set_wipe_complete_callback" in src
        and "_wipe_complete_callback" in wipe_block
        and "cb(tid)" in wipe_block
    )
    print(f"Bug112 DataStore wipe complete callback -> {ok}")
    return ok


def test_web_wipe_pending_and_history_wiped():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_history_wipe_pending" in src
        and "begin_target_history_wipe" in src
        and "on_target_history_wiped" in src
        and '"type": "history_wiped"' in src
        and "set_wipe_complete_callback(self.on_target_history_wiped)" in src
    )
    print(f"Bug112 WebServer wipe lifecycle -> {ok}")
    return ok


def test_stats_reset_no_immediate_db_reload():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    reset_block = src.split("msg.type==='stats_reset'", 1)[1].split(
        "msg.type==='history_wiped'", 1)[0]
    wiped_block = src.split("msg.type==='history_wiped'", 1)[1].split(
        "msg.type==='remove'", 1)[0]
    ok = (
        "_refreshStatsCharts" not in reset_block
        and "loadWaveform" not in reset_block
        and "_refreshStatsCharts" in wiped_block
        and "loadWaveform" in wiped_block
    )
    print(f"Bug112 stats_reset vs history_wiped handlers -> {ok}")
    return ok


def test_api_shield_while_pending():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_history_data_available" in src
        and "_tids_for_history_query" in src
        and "get_dashboard_stats_batch(tids" in src
    )
    print(f"Bug112 API shields pending wipe -> {ok}")
    return ok


def test_main_begin_before_wipe():
    with open(MAIN, encoding="utf-8") as f:
        block = f.read().split("if wipe_intent:", 1)[1].split(
            "_ds.wipe_target_history", 1)[0]
    ok = (
        "begin_target_history_wipe(target_id)" in block
        and "reset_target_stats(target_id)" not in block
    )
    print(f"Bug112 main wipe order -> {ok}")
    return ok


def main():
    results = [
        ("callback", test_data_store_wipe_callback()),
        ("web_lifecycle", test_web_wipe_pending_and_history_wiped()),
        ("sse_handlers", test_stats_reset_no_immediate_db_reload()),
        ("api_shield", test_api_shield_while_pending()),
        ("main_order", test_main_begin_before_wipe()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 112 checks passed.")


if __name__ == "__main__":
    main()
