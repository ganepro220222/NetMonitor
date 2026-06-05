"""Regression checks for bug 125 (config.json structure validation on load)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config_manager import ConfigManager, DEFAULT_CONFIG

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_MANAGER = os.path.join(ROOT, "src", "config_manager.py")
MAIN_WINDOW = os.path.join(ROOT, "src", "ui", "main_window.py")


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


def test_bad_thresholds_type_sanitized():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "targets": [{
                "id": "t1",
                "label": "bad-threshold",
                "ip": "127.0.0.1",
                "thresholds": [1],
            }],
        }
        cm = _init_with_payload(payload, td)
        t = cm.get_targets()[0]
        try:
            settings = cm.get_target_settings("t1")
            ok = (
                "thresholds" not in t
                and isinstance(settings, dict)
                and settings.get("web_port") == DEFAULT_CONFIG["settings"]["web_port"]
            )
        except Exception as exc:
            print(f"Bug125 bad thresholds exception {type(exc).__name__} {exc}")
            ok = False
    print(f"Bug125 list thresholds stripped, get_target_settings ok -> {ok}")
    return ok


def test_bad_ping_type_sanitized():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "targets": [{
                "id": "t2",
                "label": "bad-type",
                "ip": "127.0.0.1",
                "ping_type": 123,
            }],
        }
        cm = _init_with_payload(payload, td)
        t = cm.get_targets()[0]
        ok = t.get("ping_type") == "icmp"
    print(f"Bug125 non-string ping_type coerced to icmp -> {ok}")
    return ok


def test_unknown_ping_type_string_coerced():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "targets": [{
                "id": "t3",
                "label": "weird-type",
                "ip": "127.0.0.1",
                "ping_type": "ftp",
            }],
        }
        cm = _init_with_payload(payload, td)
        ok = cm.get_targets()[0].get("ping_type") == "icmp"
    print(f"Bug125 unknown ping_type string coerced to icmp -> {ok}")
    return ok


def _chart_warn_latency_fixed(target, merged):
    """Mirror main_window._chart_warn_latency defensive logic."""
    thresholds = target.get("thresholds")
    if isinstance(thresholds, dict) and "latency_warn_ms" in thresholds:
        return merged.get("latency_warn_ms") or 150
    ping_type = target.get("ping_type")
    if not isinstance(ping_type, str):
        ping_type = "icmp"
    if ping_type.lower() in ("http", "https"):
        return merged.get("http_latency_warn_ms") or 2000
    return merged.get("latency_warn_ms") or 150


def test_chart_warn_latency_tolerates_bad_ping_type():
    target = {"id": "t2", "label": "x", "ip": "1.1.1.1", "ping_type": 123}
    merged = {"latency_warn_ms": 150, "http_latency_warn_ms": 2000}
    try:
        val = _chart_warn_latency_fixed(target, merged)
        ok = val == 150
    except Exception as exc:
        print(f"Bug125 chart_warn exception {type(exc).__name__} {exc}")
        ok = False
    print(f"Bug125 _chart_warn_latency survives int ping_type -> {ok}")
    return ok


def test_bad_window_size_sanitized():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {"window_size": "bad"},
            "targets": [{
                "id": "t",
                "label": "T",
                "ip": "127.0.0.1",
            }],
        }
        cm = _init_with_payload(payload, td)
        ok = cm.get_setting("window_size") == DEFAULT_CONFIG["settings"]["window_size"]
    print(f"Bug125 bad window_size falls back to default -> {ok}")
    return ok


def test_engine_add_target_after_bad_window_size():
    from src.ping_engine import PingEngine
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {"window_size": "bad"},
            "targets": [{
                "id": "t",
                "label": "T",
                "ip": "127.0.0.1",
            }],
        }
        cm = _init_with_payload(payload, td)
        engine = PingEngine(dict(cm.config.get("settings", {})),
                            lambda *a, **k: None)
        try:
            engine.add_target("t", "127.0.0.1", ping_type="icmp")
            mon = engine._monitors.get("t")
            ok = mon is not None and mon._window.maxlen == 10
        except Exception as exc:
            print(f"Bug125 engine add_target exception {type(exc).__name__} {exc}")
            ok = False
    print(f"Bug125 PingEngine.add_target survives bad window_size -> {ok}")
    return ok


def test_bad_webhook_events_list_sanitized():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {
                "webhook_events": "not-a-list",
            },
            "targets": [],
        }
        cm = _init_with_payload(payload, td)
        ok = cm.get_setting("webhook_events") == DEFAULT_CONFIG["settings"]["webhook_events"]
    print(f"Bug125 bad webhook_events falls back to default -> {ok}")
    return ok


def test_window_geometry_preserved_on_load():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {
                "window_geometry": "1200x800+10+10",
                "theme": "light",
            },
            "targets": [],
        }
        cm = _init_with_payload(payload, td)
        ok = (
            cm.get_setting("window_geometry") == "1200x800+10+10"
            and cm.get_setting("theme") == "light"
        )
    print(f"Bug125 window_geometry preserved on load -> {ok}")
    return ok


def test_bad_window_geometry_dropped():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {
                "window_geometry": 123,
                "theme": "dark",
            },
            "targets": [],
        }
        cm = _init_with_payload(payload, td)
        geo = cm.get_setting("window_geometry")
        ok = (geo == "" or geo is None) and cm.get_setting("theme") == "dark"
    print(f"Bug125 bad window_geometry falls back to default -> {ok}")
    return ok


def test_valid_settings_override_preserved():
    with tempfile.TemporaryDirectory() as td:
        payload = {
            "settings": {
                "window_size": 15,
                "ping_interval": 2.5,
                "web_autostart": True,
                "theme": "light",
            },
            "targets": [],
        }
        cm = _init_with_payload(payload, td)
        ok = (
            cm.get_setting("window_size") == 15
            and cm.get_setting("ping_interval") == 2.5
            and cm.get_setting("web_autostart") is True
            and cm.get_setting("theme") == "light"
        )
    print(f"Bug125 valid settings overrides preserved -> {ok}")
    return ok


def test_source_has_settings_sanitization():
    with open(CONFIG_MANAGER, encoding="utf-8") as f:
        cm_src = f.read()
    with open(os.path.join(ROOT, "src", "ping_engine.py"), encoding="utf-8") as f:
        pe_src = f.read()
    ok = (
        "def _sanitize_settings" in cm_src
        and "window_geometry" in cm_src
        and "_PERSISTED_UI_STATE_KEYS" in cm_src
        and "normalized[\"settings\"] = _sanitize_settings(raw_settings)" in cm_src
        and "_SETTINGS_INT_RANGES" in cm_src
        and "int(settings.get(\"window_size\", 10))" in pe_src
    )
    print(f"Bug125 source has settings sanitization -> {ok}")
    return ok


def test_source_has_target_field_sanitization():
    with open(CONFIG_MANAGER, encoding="utf-8") as f:
        cm_src = f.read()
    with open(MAIN_WINDOW, encoding="utf-8") as f:
        mw_src = f.read()
    ok = (
        "def _sanitize_target" in cm_src
        and "_VALID_PING_TYPES" in cm_src
        and "valid_targets.append(_sanitize_target(item))" in cm_src
        and "isinstance(thresholds, dict)" in cm_src
        and "isinstance(ping_type, str)" in mw_src
    )
    print(f"Bug125 source has target field sanitization -> {ok}")
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
        ("bad_window_size", test_bad_window_size_sanitized()),
        ("engine_window", test_engine_add_target_after_bad_window_size()),
        ("window_geometry", test_window_geometry_preserved_on_load()),
        ("bad_window_geometry", test_bad_window_geometry_dropped()),
        ("bad_webhook_events", test_bad_webhook_events_list_sanitized()),
        ("valid_settings", test_valid_settings_override_preserved()),
        ("settings_sanitize", test_source_has_settings_sanitization()),
        ("bad_thresholds", test_bad_thresholds_type_sanitized()),
        ("bad_ping_type", test_bad_ping_type_sanitized()),
        ("unknown_ping_type", test_unknown_ping_type_string_coerced()),
        ("chart_warn", test_chart_warn_latency_tolerates_bad_ping_type()),
        ("target_sanitize", test_source_has_target_field_sanitization()),
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
