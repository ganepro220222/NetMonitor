"""Regression checks for bug 121 (type change: new Monitor not started after edit)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import ConfigManager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


def test_config_shallow_copy_mutates_ref():
    with tempfile.TemporaryDirectory() as td:
        cfg_path = os.path.join(td, "config.json")
        cm = ConfigManager(cfg_path)
        tid = cm.add_target("n", "1.2.3.4", ping_type="icmp")["id"]
        ref = {t["id"]: t for t in cm.get_targets()}[tid]
        before = ref.get("ping_type")
        cm.update_target(tid, "n", "1.2.3.4", ping_type="tcp")
        after = ref.get("ping_type")
        ok = before == "icmp" and after == "tcp"
    print(f"Bug121 get_targets ref mutates on update_target -> {ok}")
    return ok


def test_on_edit_uses_pre_persist_type_snapshot():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "old_ping_type = target.get(\"ping_type\", \"icmp\")" in src
        and "new_ping_type = r.get(\"ping_type\", \"icmp\")" in src
        and "type_changed = old_ping_type != new_ping_type" in src
        and "if type_changed:" in src
        and "ping_type=new_ping_type" in src
    )
    # Late re-read that caused the bug must be gone
    bad = 'old_type = target.get("ping_type", "icmp")' in src
    ok = ok and not bad
    print(f"Bug121 _on_edit snapshots type before persist, add uses type_changed -> {ok}")
    return ok


def test_add_target_after_type_change_not_late_compare():
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        src = f.read()
    marker = "which update_target() already mutated to new_ping_type"
    idx = src.find(marker)
    block = src[idx:idx + 1500] if idx != -1 else ""
    ok = (
        idx != -1
        and "if type_changed:" in block
        and "self.engine.add_target" in block
        and "old_type = target.get" not in block
        and "old_type != new_type" not in block
    )
    print(f"Bug121 add_target branch gated on type_changed only -> {ok}")
    return ok


def main():
    results = [
        ("shallow_mutate", test_config_shallow_copy_mutates_ref()),
        ("snapshot", test_on_edit_uses_pre_persist_type_snapshot()),
        ("branch", test_add_target_after_type_change_not_late_compare()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 121 checks passed.")


if __name__ == "__main__":
    main()
