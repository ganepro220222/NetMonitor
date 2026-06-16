#!/usr/bin/env python3
"""Round D: Config / Edit Flow Audit
====================================
Tests ConfigManager write integrity, per-target threshold merge,
EDIT_MANAGED_KEYS semantics, same-type vs type-change paths,
wipe vs keep, and config fuzzing.

Test areas:
  D1 - Config file atomic write and corruption recovery
  D2 - Per-target settings merge (global defaults + overrides)
  D3 - EDIT_MANAGED_KEYS field clearing / preservation
  D4 - Same-type edit (thresholds update, type-specific field survival)
  D5 - Type-change edit (old fields cleared, new fields set)
  D6 - Wipe vs Keep intent simulation
  D7 - Config fuzzing (extreme values, boundary validation)
  D8 - _sanitize_target validation
"""

import sys, os, json, tempfile, copy, glob as _glob, uuid, pathlib

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.config_manager import (ConfigManager, DEFAULT_CONFIG,
    EDIT_MANAGED_KEYS, _sanitize_target, _sanitize_settings,
    _SETTINGS_INT_RANGES, _SETTINGS_BOOL_KEYS)

_passed = 0
_failed = 0

def check(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")

def make_cfg(initial_config=None):
    """Create a ConfigManager with a temp file."""
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    if initial_config:
        with open(tmp.name, "w", encoding="utf-8") as f:
            json.dump(initial_config, f)
    return ConfigManager(config_path=tmp.name), tmp.name

# ====================================================================
#  D1: Config file atomic write and corruption recovery
# ====================================================================
def test_d1_atomic_write():
    print("\n-- D1: Atomic write and corruption recovery --")
    cfg, path = make_cfg()

    # D1a: Set a setting and verify it was written to disk
    cfg.set_setting("sound_alert_enabled", False)
    with open(path, "r") as f:
        disk = json.load(f)
    check(disk["settings"]["sound_alert_enabled"] == False,
          f"D1a: setting written to disk (got {disk['settings']['sound_alert_enabled']})")

    # D1b: Add a target, verify on disk
    cfg.add_target("TestNode", "192.168.1.1", "icmp")
    targets = cfg.get_targets()
    check(len(targets) == 1,
          f"D1b: 1 target after add")
    check(targets[0]["label"] == "TestNode",
          f"D1b: label correct on disk")

    # D1c: Remove a target, verify
    tid = targets[0]["id"]
    cfg.remove_target(tid)
    check(len(cfg.get_targets()) == 0,
          f"D1c: target removed")

    # D1d: Corrupted JSON recovery - reuse SAME file path
    with open(path, "w") as f:
        f.write("not valid json {{{")
    cfg2 = ConfigManager(config_path=path)
    targets2 = cfg2.get_targets()
    check(len(targets2) == 0,
          f"D1d: corrupt JSON -> empty targets list")
    check(cfg2.get_setting("sound_alert_enabled") == DEFAULT_CONFIG["settings"]["sound_alert_enabled"],
          f"D1d: corrupt JSON -> default settings preserved")
    pp = pathlib.Path(path)
    broken_files = _glob.glob(str(pp.parent / (pp.stem + ".broken-*" + pp.suffix)))
    check(len(broken_files) > 0,
          f"D1d: broken config backed up (.broken-* exists, found {len(broken_files)})")

    # Clean up broken backups before D1e
    for bf in broken_files:
        try:
            os.unlink(bf)
        except OSError:
            pass

    # D1e: Non-dict root -> recovery - reuse SAME file path
    with open(path, "w") as f:
        f.write("[]")
    cfg3 = ConfigManager(config_path=path)
    check(cfg3.get_setting("web_port") == DEFAULT_CONFIG["settings"]["web_port"],
          f"D1e: non-dict root -> default settings (got {cfg3.get_setting('web_port')})")

    # Cleanup
    for p in [path] + _glob.glob(str(pp.parent / (pp.stem + ".broken-*" + pp.suffix))):
        try:
            os.unlink(p)
        except OSError:
            pass

# ====================================================================
#  D2: Per-target settings merge
# ====================================================================
def test_d2_per_target_merge():
    print("\n-- D2: Per-target settings merge --")
    cfg, path = make_cfg()

    # D2a: Global defaults are used when target has no overrides
    t = cfg.add_target("T_NoOverride", "10.0.0.1", "icmp")
    settings = cfg.get_target_settings(t["id"])
    check(settings["window_size"] == 10,
          f"D2a: global window_size=10 (got {settings['window_size']})")
    check(settings["consecutive_loss_orange"] == 3,
          f"D2a: global consecutive_loss_orange=3 (got {settings['consecutive_loss_orange']})")

    # D2b: Per-target override takes precedence
    t2 = cfg.add_target("T_Override", "10.0.0.2", "icmp",
                        thresholds={"consecutive_loss_orange": 5, "window_size": 20})
    settings2 = cfg.get_target_settings(t2["id"])
    check(settings2["window_size"] == 20,
          f"D2b: override window_size=20 (got {settings2['window_size']})")
    check(settings2["consecutive_loss_orange"] == 5,
          f"D2b: override loss_orange=5 (got {settings2['consecutive_loss_orange']})")
    check(settings2["consecutive_loss_red"] == 5,
          f"D2b: no override -> global loss_red=5 (got {settings2['consecutive_loss_red']})")

    # D2c: Edit clears all thresholds -> reverts to global
    cfg.update_target(t2["id"], t2["label"], t2["ip"],
                      ping_type="icmp", thresholds={}, extra={})
    settings3 = cfg.get_target_settings(t2["id"])
    check(settings3["window_size"] == 10,
          f"D2c: cleared thresholds -> global window_size=10 (got {settings3['window_size']})")
    check(settings3["consecutive_loss_orange"] == 3,
          f"D2c: cleared thresholds -> global loss_orange=3 (got {settings3['consecutive_loss_orange']})")

    try:
        os.unlink(path)
    except OSError:
        pass

# ====================================================================
#  D3: EDIT_MANAGED_KEYS field clearing / preservation
# ====================================================================
def test_d3_managed_keys():
    print("\n-- D3: EDIT_MANAGED_KEYS field management --")
    cfg, path = make_cfg()

    # D3a: Add HTTP target with all extras set
    t = cfg.add_target("HTTP_Node", "10.0.0.3", "http", extra={
        "http_url": "https://example.com/api",
        "http_keyword": "OK",
        "http_keyword_mode": "contains",
        "http_verify_ssl": True,
        "http_follow_redirects": False,
        "http_timeout": 10.0,
        "http_expected_status": 200,
        "tcp_probe_ports": "80,443",
        "timeout": 5.0,
    })
    targets = cfg.get_targets()
    t_disk = [x for x in targets if x["id"] == t["id"]][0]
    check(t_disk.get("http_keyword") == "OK",
          f"D3a: http_keyword set (got {t_disk.get('http_keyword')})")
    check(t_disk.get("http_verify_ssl") == True,
          f"D3a: http_verify_ssl set")

    # D3b: Edit that omits http_keyword (user cleared it in dialog)
    cfg.update_target(t["id"], "HTTP_Node_V2", "10.0.0.4",
                      ping_type="http",
                      thresholds=None,
                      extra={
                          "http_url": "https://example.com/v2",
                          "http_verify_ssl": True,
                          "http_timeout": 15.0,
                      })
    targets2 = cfg.get_targets()
    t2_disk = [x for x in targets2 if x["id"] == t["id"]][0]
    check("http_keyword" not in t2_disk,
          f"D3b: omitted http_keyword -> removed from disk")
    check("http_keyword_mode" not in t2_disk,
          f"D3b: omitted http_keyword_mode -> removed from disk")
    check(t2_disk.get("http_url") == "https://example.com/v2",
          f"D3b: http_url updated (got {t2_disk.get('http_url')})")
    check(t2_disk.get("http_verify_ssl") == True,
          f"D3b: http_verify_ssl preserved")

    # D3c: Keys NOT in EDIT_MANAGED_KEYS survive edits
    check(t2_disk.get("enabled") == True,
          f"D3c: non-managed key 'enabled' survives edit (got {t2_disk.get('enabled')})")

    # D3d: None extra -> all managed keys cleared
    cfg.update_target(t["id"], "HTTP_Node_V3", "10.0.0.5",
                      ping_type="http", thresholds=None, extra=None)
    targets3 = cfg.get_targets()
    t3_disk = [x for x in targets3 if x["id"] == t["id"]][0]
    for k in EDIT_MANAGED_KEYS:
        check(k not in t3_disk,
              f"D3d: None extra -> '{k}' cleared from disk")

    try:
        os.unlink(path)
    except OSError:
        pass

# ====================================================================
#  D4: Same-type edit path
# ====================================================================
def test_d4_same_type_edit():
    print("\n-- D4: Same-type edit path --")
    cfg, path = make_cfg()

    t = cfg.add_target("TCP_Node", "10.0.0.10", "tcp",
                       thresholds={"consecutive_loss_orange": 4},
                       extra={"tcp_port": 8080, "tcp_probe_ports": "80,443,8080",
                              "timeout": 3.0})
    tid = t["id"]

    # D4a: Same-type edit with new thresholds but same type fields
    cfg.update_target(tid, "TCP_Node_V2", "10.0.0.11",
                      ping_type="tcp",
                      thresholds={"consecutive_loss_orange": 6, "recovery_count": 3},
                      extra={"tcp_port": 9090, "tcp_probe_ports": "9090", "timeout": 5.0})
    targets = cfg.get_targets()
    td = [x for x in targets if x["id"] == tid][0]
    check(td["label"] == "TCP_Node_V2",
          f"D4a: label updated (got {td['label']})")
    check(td["ip"] == "10.0.0.11",
          f"D4a: ip updated (got {td['ip']})")
    check(td["ping_type"] == "tcp",
          f"D4a: ping_type unchanged (got {td['ping_type']})")
    check(td["tcp_port"] == 9090,
          f"D4a: tcp_port updated (got {td['tcp_port']})")

    settings = cfg.get_target_settings(tid)
    check(settings.get("consecutive_loss_orange") == 6,
          f"D4a: threshold override updated to 6 (got {settings.get('consecutive_loss_orange')})")
    check(settings.get("recovery_count") == 3,
          f"D4a: new threshold recovery_count=3 (got {settings.get('recovery_count')})")

    # D4b: Same-type edit with thresholds cleared
    cfg.update_target(tid, "TCP_Node_V3", "10.0.0.11",
                      ping_type="tcp",
                      thresholds=None,
                      extra={"tcp_port": 9090, "timeout": 5.0})
    settings2 = cfg.get_target_settings(tid)
    check(settings2.get("consecutive_loss_orange") == 3,
          f"D4b: cleared thresholds -> global loss_orange=3 (got {settings2.get('consecutive_loss_orange')})")

    # D4c: IP-only change
    cfg.update_target(tid, "TCP_Node_V3", "10.0.0.99",
                      ping_type="tcp",
                      thresholds=None,
                      extra={"tcp_port": 9090, "timeout": 5.0})
    targets2 = cfg.get_targets()
    td2 = [x for x in targets2 if x["id"] == tid][0]
    check(td2["ip"] == "10.0.0.99",
          f"D4c: IP-only change (got {td2['ip']})")
    check(td2["tcp_port"] == 9090,
          f"D4c: tcp_port preserved after IP-only change (got {td2['tcp_port']})")

    try:
        os.unlink(path)
    except OSError:
        pass

# ====================================================================
#  D5: Type-change edit path
# ====================================================================
def test_d5_type_change():
    print("\n-- D5: Type-change edit path --")
    cfg, path = make_cfg()

    t = cfg.add_target("Node", "10.0.0.20", "tcp",
                       extra={"tcp_port": 25, "tcp_probe_ports": "25,587"})
    tid = t["id"]

    # D5a: TCP -> HTTP
    cfg.update_target(tid, "HTTP_Node", "10.0.0.21",
                      ping_type="http",
                      thresholds={"consecutive_loss_orange": 5},
                      extra={"http_url": "https://example.com/health",
                             "http_verify_ssl": True,
                             "http_timeout": 5.0})
    targets = cfg.get_targets()
    td = [x for x in targets if x["id"] == tid][0]
    check(td["ping_type"] == "http",
          f"D5a: ping_type changed to http (got {td['ping_type']})")
    check("tcp_port" not in td,
          f"D5a: old tcp_port cleared")
    check("tcp_probe_ports" not in td,
          f"D5a: old tcp_probe_ports cleared")
    check(td.get("http_url") == "https://example.com/health",
          f"D5a: http_url set (got {td.get('http_url')})")
    check(td.get("http_verify_ssl") == True,
          f"D5a: http_verify_ssl set")

    # D5b: HTTP -> ICMP
    cfg.update_target(tid, "ICMP_Node", "10.0.0.22",
                      ping_type="icmp",
                      thresholds=None,
                      extra=None)
    targets2 = cfg.get_targets()
    td2 = [x for x in targets2 if x["id"] == tid][0]
    check(td2["ping_type"] == "icmp",
          f"D5b: ping_type changed to icmp (got {td2['ping_type']})")
    for k in EDIT_MANAGED_KEYS:
        check(k not in td2,
              f"D5b: '{k}' cleared after http->icmp")

    try:
        os.unlink(path)
    except OSError:
        pass

# ====================================================================
#  D6: Wipe vs Keep intent simulation
# ====================================================================
def test_d6_wipe_vs_keep():
    print("\n-- D6: Wipe vs Keep simulation --")
    cfg, path = make_cfg()

    t = cfg.add_target("Node_With_History", "10.0.0.30", "tcp",
                       extra={"tcp_port": 80})
    tid = t["id"]

    # D6a: Keep intent (same identity, IP change only)
    cfg.update_target(tid, "Node_With_History", "10.0.0.31",
                      ping_type="tcp", thresholds=None,
                      extra={"tcp_port": 80, "timeout": 5.0})
    targets = cfg.get_targets()
    td = [x for x in targets if x["id"] == tid][0]
    check(td["id"] == tid,
          f"D6a: keep -> same id preserved ({tid})")
    check(td["ip"] == "10.0.0.31",
          f"D6a: keep -> IP updated (got {td['ip']})")
    check(td["ping_type"] == "tcp",
          f"D6a: keep -> type unchanged")

    # D6b: Wipe intent (new physical node)
    cfg.remove_target(tid)
    t_new = cfg.add_target("NewPhysicalNode", "10.0.0.50", "http",
                           extra={"http_url": "https://new.example.com",
                                  "http_verify_ssl": True})
    check(t_new["id"] != tid,
          f"D6b: wipe -> new id generated ({t_new['id'][:8]}...)")
    check(len(cfg.get_targets()) == 1,
          f"D6b: wipe -> old removed, new added, 1 target")
    check(t_new["label"] == "NewPhysicalNode",
          f"D6b: wipe -> new label set")

    try:
        os.unlink(path)
    except OSError:
        pass

# ====================================================================
#  D7: Config fuzzing (extreme values, boundary)
# ====================================================================
def test_d7_config_fuzzing():
    print("\n-- D7: Config fuzzing --")
    cfg, path = make_cfg()

    # D7a: Setting at min boundary
    cfg.set_setting("consecutive_loss_orange", 1)
    check(cfg.get_setting("consecutive_loss_orange") == 1,
          f"D7a: loss_orange=1 (min boundary)")

    # D7b: Setting at max boundary
    cfg.set_setting("consecutive_loss_red", 30)
    check(cfg.get_setting("consecutive_loss_red") == 30,
          f"D7b: loss_red=30 (max boundary)")

    # D7c: String settings don't corrupt on invalid input
    cfg.set_setting("sound_alert_enabled", "not_a_bool")
    check(cfg.get_setting("sound_alert_enabled") == "not_a_bool",
          f"D7c: raw value stored as-is (sanitize only on load)")

    # D7d: Add_target bypasses _sanitize_target, string values survive as-is
    t = cfg.add_target("T_Fuzz", "10.0.0.99", "icmp",
                       thresholds={"window_size": "15"})
    targets = cfg.get_targets()
    td = [x for x in targets if x["id"] == t["id"]][0]
    th = td.get("thresholds", {})
    check(th.get("window_size") == "15",
          f"D7d: string threshold survives as-is in add_target (got {type(th.get('window_size')).__name__}: {th.get('window_size')})")
    check(not isinstance(th.get("window_size"), int),
          f"D7d: add_target bypasses _sanitize (only called on file load)")

    # D7e: Whitespace stripping on label/ip
    cfg.add_target("  TrimMe  ", "  10.0.0.100  ", "icmp")
    targets2 = cfg.get_targets()
    td2 = targets2[-1]
    check(td2["label"] == "TrimMe",
          f"D7e: label stripped (got '{td2['label']}')")
    check(td2["ip"] == "10.0.0.100",
          f"D7e: ip stripped (got '{td2['ip']}')")

    # D7f: Invalid ping_type defaults to "icmp"
    cfg_with_bad = {
        "settings": {},
        "targets": [{"id": "x", "label": "Bad", "ip": "1.1.1.1",
                      "ping_type": "invalid_type"}]
    }
    cfg2, path2 = make_cfg(cfg_with_bad)
    targets3 = cfg2.get_targets()
    check(len(targets3) == 1 and targets3[0]["ping_type"] == "icmp",
          f"D7f: invalid ping_type -> icmp (got {targets3[0]['ping_type']})")

    for p in [path, path2]:
        try:
            os.unlink(p)
        except OSError:
            pass

# ====================================================================
#  D8: _sanitize_target validation
# ====================================================================
def test_d8_sanitize_target():
    print("\n-- D8: _sanitize_target validation --")

    # D8a: Boolean values in thresholds are rejected
    raw = {"id": "t1", "label": "OK", "ip": "1.1.1.1",
           "thresholds": {"window_size": True, "latency_warn_ms": 150}}
    clean = _sanitize_target(raw)
    check("window_size" not in clean.get("thresholds", {}),
          f"D8a: bool thresholds rejected (got {clean.get('thresholds', {})})")
    check(clean["thresholds"].get("latency_warn_ms") == 150,
          f"D8a: valid threshold preserved (got {clean['thresholds']['latency_warn_ms']})")

    # D8b: String numeric values in thresholds coerced
    raw2 = {"id": "t2", "label": "Test", "ip": "2.2.2.2",
            "thresholds": {"window_size": "20", "latency_warn_ms": "250"}}
    clean2 = _sanitize_target(raw2)
    check(clean2["thresholds"]["window_size"] == 20,
          f"D8b: string '20' -> int 20 (got {clean2['thresholds']['window_size']})")
    check(clean2["thresholds"]["latency_warn_ms"] == 250,
          f"D8b: string '250' -> int 250 (got {clean2['thresholds']['latency_warn_ms']})")

    # D8c: String digit tcp_port coerced to int by _sanitize_target
    raw3 = {"id": "t3", "label": "Test", "ip": "3.3.3.3",
            "tcp_port": "8080"}
    clean3 = _sanitize_target(raw3)
    check(clean3.get("tcp_port") == 8080,
          f"D8c: string digit '8080' coerced to int 8080 (got {clean3.get('tcp_port')})")

    # D8d: Valid int tcp_port preserved
    raw4 = {"id": "t4", "label": "Test", "ip": "4.4.4.4",
            "tcp_port": 443}
    clean4 = _sanitize_target(raw4)
    check(clean4.get("tcp_port") == 443,
          f"D8d: int tcp_port=443 preserved (got {clean4.get('tcp_port')})")

    # D8e: Bool keys correctly preserved
    raw5 = {"id": "t5", "label": "Test", "ip": "5.5.5.5",
            "http_verify_ssl": True, "http_follow_redirects": False,
            "ipv6_only": True}
    clean5 = _sanitize_target(raw5)
    check(clean5.get("http_verify_ssl") == True,
          f"D8e: http_verify_ssl=True preserved")
    check(clean5.get("http_follow_redirects") == False,
          f"D8e: http_follow_redirects=False preserved")
    check(clean5.get("ipv6_only") == True,
          f"D8e: ipv6_only=True preserved")

    # D8f: String bool values NOT coerced for bool keys
    raw6 = {"id": "t6", "label": "Test", "ip": "6.6.6.6",
            "http_verify_ssl": "true"}
    clean6 = _sanitize_target(raw6)
    check("http_verify_ssl" not in clean6,
          f"D8f: string 'true' for bool key -> rejected (correctly requires bool type)")

# ====================================================================
#  Runner
# ====================================================================

def main():
    global _passed, _failed
    test_d1_atomic_write()
    test_d2_per_target_merge()
    test_d3_managed_keys()
    test_d4_same_type_edit()
    test_d5_type_change()
    test_d6_wipe_vs_keep()
    test_d7_config_fuzzing()
    test_d8_sanitize_target()

    total = _passed + _failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {_passed} passed, {_failed} failed out of {total}")
    if _failed == 0:
        print("All checks passed")
    else:
        print("SOME CHECKS FAILED - review output above")
    return _failed

if __name__ == "__main__":
    sys.exit(main())
