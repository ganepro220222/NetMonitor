"""Regression checks for bug 114 (traceroute/diag history pending-wipe guards)."""
import os

WEB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "web_server.py",
)


def _route_block(src: str, route: str) -> str:
    return src.split(f'@app.route("{route}"', 1)[1].split("@app.route", 1)[0]


def test_traceroute_history_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/traceroute/history")
    ok = "_history_data_available(tid)" in block
    print(f"Bug114 /api/traceroute/history guard -> {ok}")
    return ok


def test_icmp_diag_history_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/icmp_diag/history")
    ok = (
        "_history_data_available(tid)" in block
        and "_filter_rows_excluding_pending_wipe" in block
    )
    print(f"Bug114 /api/icmp_diag/history guard -> {ok}")
    return ok


def test_dns_diag_history_guard():
    block = _route_block(open(WEB, encoding="utf-8").read(), "/api/dns_diag/history")
    ok = (
        "_history_data_available(tid)" in block
        and "_filter_rows_excluding_pending_wipe" in block
    )
    print(f"Bug114 /api/dns_diag/history guard -> {ok}")
    return ok


def test_filter_helper_defined():
    with open(WEB, encoding="utf-8") as f:
        src = f.read()
    ok = "def _filter_rows_excluding_pending_wipe" in src
    print(f"Bug114 row filter helper -> {ok}")
    return ok


def main():
    results = [
        ("traceroute", test_traceroute_history_guard()),
        ("icmp", test_icmp_diag_history_guard()),
        ("dns", test_dns_diag_history_guard()),
        ("helper", test_filter_helper_defined()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 114 checks passed.")


if __name__ == "__main__":
    main()
