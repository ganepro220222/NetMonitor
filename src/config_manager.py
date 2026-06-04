from __future__ import annotations

"""
config_manager.py
-----------------
负责所有配置数据的读取、写入和管理。
程序里的任何模块需要读取或修改配置，都通过这个类来操作，
而不是直接去碰 config.json 文件。这样做的好处是：
如果将来我们要换一种存储方式（比如数据库），只需要改这一个文件。
"""

import json
import copy
import uuid
import os


# Per-target optional config keys that the edit dialog has authoritative
# control over.  When update_target() is called from the edit flow with a
# given `extra` dict, any key in this tuple that's NOT in `extra` is
# considered "cleared by the user" and gets removed from the target.
# Without this, clearing a field in the dialog (e.g. emptying the
# "response keyword" input) would leave the old value alive on disk
# because the previous .update()-style merge was strictly additive.
EDIT_MANAGED_KEYS = (
    "tcp_port", "tcp_probe_ports",
    "http_url", "http_success_codes",
    "http_timeout", "http_verify_ssl",
    "http_follow_redirects", "http_expected_status",
    "http_keyword", "http_keyword_mode",
    "dns_domain", "dns_expected",
    "ipv6_only", "timeout",
)
import math
import threading
from pathlib import Path


# Shortest ping interval the product formally supports (50 ms).
# Below this, ICMP subprocess round-trips dominate; values are clamped
# at runtime and rejected in settings / per-target dialogs.
MIN_PING_INTERVAL_S: float = 0.05
MAX_PING_INTERVAL_S: float = 120.0


def is_valid_ping_interval(value) -> bool:
    """True when value is a finite float within [MIN, MAX] seconds."""
    try:
        iv = float(value)
    except (TypeError, ValueError):
        return False
    return (math.isfinite(iv)
            and MIN_PING_INTERVAL_S <= iv <= MAX_PING_INTERVAL_S)


def normalize_ping_interval(value, default: float = 1.0) -> float:
    """Clamp configured ping_interval to a finite supported [MIN, MAX] range."""
    try:
        fallback = float(default)
    except (TypeError, ValueError):
        fallback = 1.0
    if not math.isfinite(fallback):
        fallback = 1.0
    fallback = min(MAX_PING_INTERVAL_S, max(MIN_PING_INTERVAL_S, fallback))

    try:
        interval = float(value)
    except (TypeError, ValueError):
        interval = fallback
    if not math.isfinite(interval):
        interval = fallback

    return min(MAX_PING_INTERVAL_S, max(MIN_PING_INTERVAL_S, interval))


# 配置文件的默认内容。如果用户是第一次运行程序，
# config.json 不存在，我们就用这个内容创建一个。
DEFAULT_CONFIG = {
    "targets": [],
    "settings": {
        # 每次 Ping 的间隔（秒）
        "ping_interval": 1.0,

        # 滑动窗口大小：用最近 N 次 Ping 的结果来计算丢包率
        # 设为 10 意味着我们看"最近 10 次"的表现
        "window_size": 10,

        # 橙色告警阈值：在滑动窗口内，连续丢包超过此数量触发橙色
        "consecutive_loss_orange": 3,

        # 红色告警阈值：在滑动窗口内，连续丢包超过此数量触发红色
        "consecutive_loss_red": 5,

        # 橙色延时阈值（ms）：ICMP/TCP/DNS 节点平均延时超过此值即变橙色
        "latency_warn_ms": 150,

        # HTTP/HTTPS 专用橙色延时阈值（ms）：网站请求含 DNS+TLS+服务器处理，
        # 天然比 ICMP/TCP/DNS 慢，故单列默认 2000，避免误报性能告警
        "http_latency_warn_ms": 2000,

        # 红色延时阈值（ms）：平均延时超过此值变红色
        "latency_error_ms": 400,

        # 从告警状态恢复到正常需要连续成功的次数（防止反复抖动）
        "recovery_count": 5,

        # 连续高延时告警阈值（P3: 防止单次抖动误报）
        "consecutive_lat_orange": 3,   # 连续 N 次延时超过 warn_ms 才变橙色

        # 路由追踪间隔（秒）
        # 注意：单次完整 tracert 最多需要 60-90 秒，建议最小设置 120 秒
        "traceroute_interval": 300,

        # Web dashboard port (访问地址: http://<本机IP>:<port>)
        "web_port": 8765,

        # 启动时自动开启 Web 监控服务
        "web_autostart": False,

        # 数据库持久化配置
        "db_path": "data/monitor.db",
        "db_raw_retention_days": 8,
        "db_hourly_retention_days": 90,
        "db_alert_retention_days": 365,
        "db_traceroute_retention_days": 30,
        "db_diag_retention_days": 180,
    "webhook_url":    "",
    "webhook_events": ["red", "green"],

        # 系统托盘
        "tray_minimize": False,

        # 路由追踪最大跳数（Windows 默认 30）
        "tracert_max_hops": 30,

        # 主题: "dark" 或 "light"
        "theme": "dark",

        # 是否启用声音告警（关闭后只静音；颜色变化、桌面通知、
        # webhook 仍照常推送）。新增于 sound-persistence 修复以前
        # 没有这个 key 的配置文件，仍然按默认 True 处理。
        "sound_alert_enabled": True
    }
}


class ConfigManager:
    """
    配置管理器。整个程序只需要创建一个实例，
    然后把它传递给需要它的模块。
    """

    def __init__(self, config_path: str = "config.json"):
        if not os.path.isabs(config_path):
            import sys as _sys
            if getattr(_sys, "frozen", False):
                base_dir = os.path.dirname(_sys.executable)
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, config_path)
        self.config_path = Path(config_path)
        self.config = {}
        self._lock = threading.Lock()   # guards file I/O against concurrent saves
        self._load()

    def _load(self):
        """从文件加载配置。如果文件不存在，使用默认配置并保存。"""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # 用加载的内容覆盖默认值，这样即使将来我们在
                # DEFAULT_CONFIG 里加了新字段，老用户的配置文件
                # 也不会缺少这些新字段
                self.config = self._merge(DEFAULT_CONFIG, loaded)
                self._apply_config_migrations(loaded)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[ConfigManager] 配置文件读取失败，使用默认配置: {e}")
                self.config = copy.deepcopy(DEFAULT_CONFIG)
                self._mark_config_migrations_done()
        else:
            print("[ConfigManager] 配置文件不存在，创建默认配置。")
            self.config = copy.deepcopy(DEFAULT_CONFIG)
            self._mark_config_migrations_done()
            self.save()

    def _apply_config_migrations(self, loaded: dict) -> None:
        """One-time upgrades for legacy on-disk settings (Bug99).

        Merges user overrides before this runs, so an untouched legacy
        db_raw_retention_days=7 (old product default) is bumped to 8 so
        SLA \"滚动近 7 天\" can compute exact P95.  Users who later set
        7 explicitly in Settings are left alone once the marker is set.
        """
        settings = self.config.setdefault("settings", {})
        mig = settings.get("_config_migrations")
        if not isinstance(mig, dict):
            mig = {}
            settings["_config_migrations"] = mig
        if mig.get("raw_retention_7_to_8"):
            return

        loaded_settings = loaded.get("settings")
        if not isinstance(loaded_settings, dict):
            loaded_settings = {}
        if loaded_settings.get("db_raw_retention_days") == 7:
            settings["db_raw_retention_days"] = 8
            print("[ConfigManager] 已迁移 db_raw_retention_days: 7 → 8 "
                  "（支持 SLA「近 7 天」精确 P95）")
        mig["raw_retention_7_to_8"] = True
        self.save()

    def _mark_config_migrations_done(self) -> None:
        settings = self.config.setdefault("settings", {})
        mig = settings.get("_config_migrations")
        if not isinstance(mig, dict):
            mig = {}
            settings["_config_migrations"] = mig
        mig.setdefault("raw_retention_7_to_8", True)

    def _merge(self, default: dict, override: dict) -> dict:
        """
        深度合并两个字典。override 的值优先，
        但 default 中有而 override 中没有的键会被保留。
        注意：targets 列表直接用 override 的，不做合并。

        Must use deepcopy here, NOT default.copy(): the shallow copy
        kept nested dicts (e.g. "settings") as ALIASES into the module-
        level DEFAULT_CONFIG.  A legacy / truncated config file that
        omitted the "settings" key would then mutate DEFAULT_CONFIG
        in place on every set_setting() call -- subsequent
        ConfigManager instances created later in the same process
        would inherit those mutations as if they were the canonical
        defaults.
        """
        result = copy.deepcopy(default)
        for key, value in override.items():
            if key == "targets":
                # targets 是列表，直接用用户的数据，不与默认值合并
                result[key] = value
            elif isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._merge(result[key], value)
            else:
                result[key] = value
        return result

    def save(self):
        """将当前配置原子写回 config.json（先写 .tmp，再 rename）。"""
        with self._lock:
            self._save_unlocked()

    def _save_unlocked(self):
        """调用方已持 _lock 时使用——写入 .tmp 后原子 rename，防止崩溃截断。"""
        try:
            tmp = self.config_path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
                f.flush()
                import os as _os
                _os.fsync(f.fileno())   # flush to disk, not just OS buffer
            tmp.replace(self.config_path)   # atomic on Windows & POSIX
        except IOError as e:
            print(f"[ConfigManager] 配置保存失败: {e}")

    # ----------------------------------------------------------------
    # 以下是对外提供的 targets（IP 目标）操作接口
    # ----------------------------------------------------------------

    def get_targets(self) -> list:
        """返回所有监测目标的列表（浅拷贝，防止调用方遍历时被并发修改）。"""
        return list(self.config.get("targets", []))

    def add_target(self, label: str, ip: str, ping_type: str = "icmp",
                   thresholds: dict = None, extra: dict = None) -> dict:
        """
        添加一个新的监测目标。
        ping_type: "icmp" / "tcp" / "http"
        extra: 类型相关的额外配置，如 tcp_port、http_url 等。
        """
        new_target = {
            "id": str(uuid.uuid4()),
            "label": label.strip(),
            "ip": ip.strip(),
            "ping_type": ping_type or "icmp",
            "enabled": True
        }
        if thresholds:
            new_target["thresholds"] = thresholds
        if extra:
            new_target.update(extra)
        with self._lock:
            self.config["targets"].append(new_target)
            self._save_unlocked()
        return new_target

    def update_target(self, target_id: str, label: str, ip: str,
                      ping_type: str = None, thresholds: dict = None, extra: dict = None):
        """根据 ID 修改某个目标的配置并保存。

        SEMANTIC NOTE (2024 fix): (thresholds, extra) are treated as the
        target's CANONICAL optional-config snapshot from the edit dialog,
        not as an additive patch:
          - thresholds: empty / None → all per-target threshold overrides
            cleared (revert to global defaults).  Non-empty dict → set.
          - extra: any key in EDIT_MANAGED_KEYS that is NOT present in
            `extra` is removed from the target (treat as "user cleared
            this field in the dialog").  Any key in `extra` is set.
            Keys outside EDIT_MANAGED_KEYS are left untouched.

        Previous behaviour was strictly additive (could only set, never
        remove), so emptying an http_keyword / dns_expected / latency
        threshold in the edit dialog silently left the stale value on
        disk forever -- breaking the UI's "leave empty = use global
        default" promise.  This method is only called from the edit
        flow (main_window._on_edit), so changing the contract is safe.
        """
        with self._lock:
            for target in self.config["targets"]:
                if target["id"] == target_id:
                    target["label"] = label.strip()
                    target["ip"] = ip.strip()
                    if ping_type is not None:
                        target["ping_type"] = ping_type
                    # Thresholds: empty / None = clear
                    if thresholds:
                        target["thresholds"] = thresholds
                    else:
                        target.pop("thresholds", None)
                    # Optional extras: sync against EDIT_MANAGED_KEYS so
                    # cleared dialog fields actually disappear from disk.
                    e = extra or {}
                    for k in EDIT_MANAGED_KEYS:
                        if k in e:
                            target[k] = e[k]
                        else:
                            target.pop(k, None)
                    break
            self._save_unlocked()

    def get_target_settings(self, target_id: str) -> dict:
        """
        返回某个目标的有效告警阈值。
        先取全局 settings 作为基础，再用该目标自己的 thresholds 覆盖，
        实现"per-target 优先，全局兜底"的两级配置。
        """
        base = dict(self.config.get("settings", {}))
        for target in self.config.get("targets", []):
            if target["id"] == target_id:
                base.update(target.get("thresholds", {}))
                break
        return base

    def remove_target(self, target_id: str):
        """根据 ID 删除某个监测目标，并保存。"""
        with self._lock:
            self.config["targets"] = [
                t for t in self.config["targets"] if t["id"] != target_id
            ]
            self._save_unlocked()

    # ----------------------------------------------------------------
    # 以下是对外提供的 settings（程序设置）操作接口
    # ----------------------------------------------------------------

    def get_setting(self, key: str):
        """读取某个设置项的值。"""
        return self.config["settings"].get(key)

    def set_setting(self, key: str, value):
        """修改某个设置项的值，并保存。"""
        with self._lock:
            self.config["settings"][key] = value
            self._save_unlocked()
