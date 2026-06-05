"""Regression checks for bug 123 (semantic reseed snapshot before update_target)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import ConfigManager
from src.ping_engine import TargetMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


def test_live_dict_semantic_diff_lost_after_update():
    with tempfile.TemporaryDirectory() as td:
        cm = ConfigManager(os.path.join(td, "config.json"))
        tid = cm.add_target("n", "1.2.3.4", ping_type="http", extra={
            "http_url": "http://old.local",
        })["id"]
        ref = {t["id"]: t for t in cm.get_targets()}[tid]
        _MISSING = object()
        _SEM = TargetMonitor.PROBE_SEMANTIC_KEYS
        combined = {"http_url": "http://new.local"}
        pre_old = {k: ref.get(k, _MISSING) for k in _SEM}
        pre_new = {k: combined.get(k, _MISSING) for k in _SEM}
        pre_changed = pre_old != pre_new
        cm.update_target(tid, "n", "1.2.3.4", ping_type="http",
                         extra={"http_url": "http://new.local"})
        post_old = {k: ref.get(k, _MISSING) for k in _SEM}
        post_new = {k: combined.get(k, _MISSING) for k in _SEM}
        post_changed = post_old != post_new
        ok = pre_changed and not post_changed
    print(f"Bug123 pre_persist semantic diff true, post false -> {ok}")
    return ok


def test_on_edit_uses_pre_persist_semantic_snapshot():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "old_semantic_view" in src
        and "new_semantic_view" in src
        and "semantic_changed_for_reseed" in src
        and "if semantic_changed_for_reseed:" in src
        and src.find("semantic_changed_for_reseed") < src.find("self.config.update_target")
        and "old_view = {k: target.get(k, _MISSING)" not in src
    )
    print(f"Bug123 _on_edit snapshots semantic view before update_target -> {ok}")
    return ok


def main():
    results = [
        ("mutate", test_live_dict_semantic_diff_lost_after_update()),
        ("source", test_on_edit_uses_pre_persist_semantic_snapshot()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 123 checks passed.")


if __name__ == "__main__":
    main()
