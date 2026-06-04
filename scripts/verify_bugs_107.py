"""Regression checks for bug 107 (diag windows refresh after node edit)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def test_on_edit_calls_refresh_helper():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    edit_block = src.split("def _on_edit", 1)[1].split("def _on_delete", 1)[0]
    ok = (
        "_refresh_open_diag_windows_after_edit" in edit_block
        and "dns_domain_changed" in edit_block
    )
    print(f"Bug107 _on_edit sync hook -> {ok}")
    return ok


def test_identity_change_closes_diag_windows():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split(
            "def _refresh_open_diag_windows_after_edit", 1)[1].split(
            "def _open_icmp_diag", 1)[0]
    ok = (
        "identity_changed" in block
        and "_close_registered_window(self._icmp_diag_windows" in block
        and "_close_registered_window(self._dns_diag_windows" in block
    )
    print(f"Bug107 identity change closes ICMP/DNS -> {ok}")
    return ok


def test_label_only_refreshes_not_closes():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split(
            "def _refresh_open_diag_windows_after_edit", 1)[1].split(
            "def _open_icmp_diag", 1)[0]
    ok = (
        "icmp.update_host" in block
        and "dns.update_target" in block
        and "wf.update_target" in block
    )
    print(f"Bug107 label-only refresh path -> {ok}")
    return ok


def test_dns_prefill_helper_shared():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "def _dns_diag_host_prefill" in src
        and "_dns_diag_host_prefill(target, target_id)" in src
    )
    print(f"Bug107 shared DNS prefill helper -> {ok}")
    return ok


def test_delete_still_closes_registries():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        delete_block = f.read().split("def _on_delete", 1)[1].split(
            "def _on_target_pause", 1)[0]
    ok = (
        "_icmp_diag_windows" in delete_block
        and "_dns_diag_windows" in delete_block
        and "_on_close" in delete_block
    )
    print(f"Bug107 delete path unchanged -> {ok}")
    return ok


def main():
    results = [
        ("on_edit_hook", test_on_edit_calls_refresh_helper()),
        ("close_identity", test_identity_change_closes_diag_windows()),
        ("label_refresh", test_label_only_refreshes_not_closes()),
        ("dns_prefill", test_dns_prefill_helper_shared()),
        ("delete", test_delete_still_closes_registries()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("All bug 107 checks passed.")


if __name__ == "__main__":
    main()
