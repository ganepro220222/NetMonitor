"""Regression checks for bug 125 (config.json structure validation on load)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import ConfigManager, DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_MANAGER = os.path.join(ROOT, "src", "config_manager.py")


def _init_with_payload(payload, td):
    path = os.path.join(td, "config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return ConfigManager(path)


def test_array_root_falls_back_to_default():
    with tempfile.TemporaryDirectory() as td:
        try:
            cm = _init_with_payload([], td)
            ok = (
                isinstance(cm.config, dict)
                and isinstance(cm.config.get("settings"), dict)
                and cm.config.get("targets") == []
                and cm.get_setting("web_port") == DEFAULT_CONFIG["settings"]["web_port"]
            )
        except Exception as exc:
            print(f"Bug125 array root init_error {type(exc).__name__} {exc}")
            ok = False
    print(f"Bug125 array root falls back to default -> {ok}")
    return ok


def test_bad_settings_type_uses_default_settings():
    with tempfile.TemporaryDirectory() as td:
        try:
            cm = _init_with_payload({"settings": []}, td)
            ok = (
                isinstance(cm.config.get("settings"), dict)
                and cm.get_setting("web_port") == DEFAULT_CONFIG["settings"]["web_port"]
                and cm.get_setting("ping_interval") == DEFAULT_CONFIG["settings"]["ping_interval"]
            )
        except Exception as exc:
            print(f"Bug125 bad settings init_error {type(exc).__name__} {exc}")
            ok = False
    print(f"Bug125 bad settings type merges defaults -> {ok}")
    return ok


def test_bad_targets_type_becomes_empty_list():
    with tempfile.TemporaryDirectory() as td:
        try:
            cm = _init_with_payload({"targets": {"bad": 1}}, td)
            targets = cm.get_targets()
            ok = (
                isinstance(cm.config.get("settings"), dict)
                and targets == []
            )
        except Exception as exc:
            print(f"Bug125 bad targets init_error {type(exc).__name__} {exc}")
            ok = False
    print(f"Bug125 bad targets type becomes empty list -> {ok}")
    return ok


def test_invalid_target_entries_filtered():
    with tempfile.TemporaryDirectory() as td:
        good = {
            "id": "good-id",
            "label": "Good",
            "ip": "1.2.3.4",
            "ping_type": "icmp",
            "enabled": True,
        }
        payload = {
            "targets": [
                good,
                "not-a-dict",
                {"id": "", "label": "x", "ip": "1.1.1.1"},
                {"id": "no-label", "ip": "1.1.1.1"},
            ],
        }
        cm = _init_with_payload(payload, td)
        targets = cm.get_targets()
        ok = len(targets) == 1 and targets[0]["id"] == "good-id"
    print(f"Bug125 invalid target entries filtered -> {ok}")
    return ok


def test_valid_config_unchanged():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "targets": [{
                "id": "t1",
                "label": "Host",
                "ip": "8.8.8.8",
                "ping_type": "icmp",
                "enabled": True,
            }],
            "settings": {"web_port": 9999, "ping_interval": 2.0},
        }
        cm = _init_with_payload(payload, td)
        ok = (
            len(cm.get_targets()) == 1
            and cm.get_targets()[0]["ip"] == "8.8.8.8"
            and cm.get_setting("web_port") == 9999
            and cm.get_setting("ping_interval") == 2.0
            and cm.get_setting("window_size") == DEFAULT_CONFIG["settings"]["window_size"]
        )
    print(f"Bug125 valid config still merges normally -> {ok}")
    return ok


def test_source_has_structure_validation():
    with open(CONFIG_MANAGER, encoding="utf-8") as f:
        src = f.read()
    ok = (
        "_normalize_loaded_config" in src
        and "config root must be object" in src
        and "_backup_broken_config" in src
        and "except (json.JSONDecodeError, IOError, ValueError)" in src
        and "if not isinstance(raw_targets, list):" in src
    )
    print(f"Bug125 source has structure validation -> {ok}")
    return ok


def main():
    results = [
        ("array_root", test_array_root_falls_back_to_default()),
        ("bad_settings", test_bad_settings_type_uses_default_settings()),
        ("bad_targets", test_bad_targets_type_becomes_empty_list()),
        ("filter_targets", test_invalid_target_entries_filtered()),
        ("valid_config", test_valid_config_unchanged()),
        ("source", test_source_has_structure_validation()),
    ]
    failed = [n for n, ok in results if not ok]
    if failed:
        print("FAILED:", failed)
        raise SystemExit(1)
    print("All bug 125 checks passed.")


if __name__ == "__main__":
    main()
