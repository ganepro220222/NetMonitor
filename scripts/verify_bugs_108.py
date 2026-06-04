"""Regression checks for bug 108 (close waveform window on wipe after edit)."""
import os

MAIN_WINDOW = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "ui", "main_window.py",
)


def test_refresh_passes_wipe_intent():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        edit_block = f.read().split("def _on_edit", 1)[1].split(
            "def _on_delete", 1)[0]
    ok = "wipe_intent=wipe_intent" in edit_block
    print(f"Bug108 _on_edit passes wipe_intent -> {ok}")
    return ok


def test_wipe_closes_waveform_not_update():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split(
            "def _refresh_open_diag_windows_after_edit", 1)[1].split(
            "def _open_icmp_diag", 1)[0]
    ok = (
        "wipe_intent: bool" in block
        and "if wipe_intent:" in block
        and "_close_registered_window(self._waveform_windows" in block
        and block.find("if wipe_intent:") < block.find("wf.update_target")
    )
    print(f"Bug108 wipe closes waveform window -> {ok}")
    return ok


def test_keep_history_still_updates_waveform():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        block = f.read().split(
            "def _refresh_open_diag_windows_after_edit", 1)[1].split(
            "def _open_icmp_diag", 1)[0]
    else_branch = block.split("if wipe_intent:", 1)[1]
    ok = "wf.update_target" in else_branch
    print(f"Bug108 non-wipe still update_target -> {ok}")
    return ok


def main():
    results = [
        ("pass_wipe", test_refresh_passes_wipe_intent()),
        ("close_on_wipe", test_wipe_closes_waveform_not_update()),
        ("keep_update", test_keep_history_still_updates_waveform()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 108 checks passed.")


if __name__ == "__main__":
    main()
