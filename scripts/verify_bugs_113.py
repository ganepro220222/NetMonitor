"""Regression checks for bug 113 (complete pending-wipe guards on all history APIs)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _route_block(src: str, route: str) -> str:
    marker = f'@app.route("{route}"'
    return src.split(marker, 1)[1].split("@app.route", 1)[0]


def test_api_sla_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/sla")
    ok = "_tids_for_history_query" in block and "_history_data_available" in block
    print(f"Bug113 /api/sla pending guard -> {ok}")
    return ok


def test_api_export_sla_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/export/sla")
    ok = "_tids_for_history_query" in block and "_history_data_available" in block
    print(f"Bug113 /api/export/sla pending guard -> {ok}")
    return ok


def test_api_history_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/history")
    ok = "_history_data_available(tid)" in block
    print(f"Bug113 /api/history pending guard -> {ok}")
    return ok


def test_api_waveform_export_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/waveform/export")
    ok = (
        "_history_data_available(tid)" in block
        and "历史正在清空" in block
    )
    print(f"Bug113 /api/waveform/export pending guard -> {ok}")
    return ok


def test_api_export_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/export")
    ok = "_tids_for_history_query(tids)" in block
    print(f"Bug113 /api/export pending guard -> {ok}")
    return ok


def main():
    src = open(WEB, encoding="utf-8").read()
    results = [
        ("sla", test_api_sla_guard()),
        ("export_sla", test_api_export_sla_guard()),
        ("history", test_api_history_guard()),
        ("waveform_export", test_api_waveform_export_guard()),
        ("export", test_api_export_guard()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 113 checks passed.")


if __name__ == "__main__":
    main()
