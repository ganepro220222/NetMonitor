from __future__ import annotations
"""
settings_dialog.py
------------------
Global settings panel. Organises all configurable parameters into
labelled sections so users don't need to edit config.json by hand.

Settings are validated before saving.  Changes are applied immediately
via on_save callback (engine settings, web-server state, etc.).
"""

import math

import customtkinter as ctk
from tkinter import messagebox
from src.config_manager import MAX_PING_INTERVAL_S, MIN_PING_INTERVAL_S
from src.ui.fonts import make as F


# Each setting descriptor: (config_key, label, type, min, max, hint)
# type: "float" | "int" | "bool"

_SECTIONS = [
    ("监测参数", [
        ("ping_interval",           "全局 Ping 间隔 (秒)",      "float",
         MIN_PING_INTERVAL_S, MAX_PING_INTERVAL_S,
         "0.05~120 秒；ICMP 建议 1~2 秒，HTTP 建议 30~60 秒"),
        ("window_size",             "滑动窗口大小",              "int",   5,   30,  "用最近 N 次 ping 计算丢包率和抖动"),
        ("consecutive_loss_orange", "连续丢包 → 橙色 (次)",     "int",   1,   20,  "连续丢包达到此次数变为警告"),
        ("consecutive_loss_red",    "连续丢包 → 红色 (次)",     "int",   2,   30,  "连续丢包达到此次数变为告警"),
        ("recovery_count",          "恢复确认次数",              "int",   1,   20,  "连续成功 N 次才恢复绿色，防抖动"),
    ]),
    ("延时告警阈值", [
        ("latency_warn_ms",        "警告延时阈值·ICMP/TCP/DNS (ms)", "int",  10, 2000,
         "ICMP / TCP / DNS 节点：单次延时超过此值开始计数（默认 150）"),
        ("http_latency_warn_ms",   "警告延时阈值·HTTP (ms)",        "int", 100, 10000,
         "HTTP/HTTPS 节点：网站含 DNS+TLS+服务器处理天然较慢，故单列（默认 2000）"),
        ("consecutive_lat_orange", "连续高延时 → 橙色 (次)",   "int",   1,   20,  "连续 N 次延时 ≥ 警告阈值才变橙色，防抖动"),
        # latency_error_ms / consecutive_lat_red removed: engine design caps
        # performance degradation at ORANGE — latency never escalates to RED.
    ]),
    ("告警与通知", [
        ("webhook_url", "Webhook 推送地址", "str", None, None,
         "故障时自动推送到企业微信/钉钉/飞书/自定义接口。留空不推送。"),
        ("webhook_reminder_enabled", "红色未恢复重复提醒", "bool", None, None,
         "仅针对红色可用性故障；短故障在下次提醒前恢复则不会重复推送。"),
        ("webhook_reminder_interval_min", "重复提醒间隔 (分钟)", "int", 3, 120,
         "红色未恢复且未确认时，每隔 N 分钟重复推送一次（默认 5，最短 3）"),
        ("webhook_reminder_max_count", "最多提醒次数", "int", 0, 999,
         "0 = 不限制次数"),
        ("webhook_reminder_aggregate_enabled", "多节点汇总重复提醒", "bool", None, None,
         "未恢复 red 数达到阈值时合并为一条 reminder，避免群消息风暴。"),
        ("webhook_reminder_aggregate_threshold", "汇总提醒阈值 (节点数)", "int", 2, 99,
         "当前仍有 ≥ 此数量的 red 节点时发送汇总 reminder。"),
        ("webhook_include_trace", "Webhook 附带 traceroute 摘要", "bool", None, None,
         "控制 reminder/recovery 诊断摘要及 diagnostic_update 推送；关闭后不发诊断更新。"
         " traceroute 为疑似定位（tracert -d / traceroute -n）。"),
        ("webhook_trace_update_enabled", "traceroute 变化时发送诊断更新", "bool", None, None, ""),
        ("webhook_trace_refresh_interval_min", "诊断刷新间隔 (分钟)", "int", 5, 120, ""),
        ("webhook_trace_change_only", "仅故障点变化时推送诊断", "bool", None, None, ""),
    ]),
    ("Web 服务", [
        ("web_port",             "监控端口号",              "int",  1024, 65535, "更改后需重启 Web 服务生效"),
        ("web_autostart",        "启动程序时自动开启 Web",  "bool", None, None,  ""),
        ("traceroute_interval",  "路由追踪间隔（秒）",      "int",  120,  3600,
         "建议 ≥120 秒（单次 tracert 最长需 60-90 秒，间隔过短会导致任务堆积）"),
        ("tracert_max_hops",     "追踪最大跳数",            "int",   10,   64,
         "Windows 默认 30。增大覆盖更长路径，减小加快超时场景下的追踪速度。"),
    ]),
    # Note: HTTP monitoring uses much higher latency by nature (~1000-3000ms)
    # Users should edit per-target thresholds in the card edit dialog for HTTP nodes.
    ("界面", [
        ("default_columns", "默认列数", "int", 1, 2, "1 = 单列，2 = 双列（也可运行时切换）"),
    ]),
    ("系统托盘", [
        ("tray_minimize", "关闭按钮→最小化到托盘", "bool", None, None,
         "启用后，点击窗口关闭按钮不退出程序，而是缩入系统托盘。"
         "右键托盘图标可彻底退出。"),
        ("autostart", "开机自动启动（静默进托盘）", "bool", None, None,
         "开机后程序自动在后台启动，直接进入托盘，不弹出主界面。仅支持 Windows。"),
    ]),
    ("数据存储", [
        ("db_raw_retention_days",         "原始记录保留天数",     "int", 1,  90,
         "秒级探测记录的保留时长（1-90 天）。超出后自动清理。"),
        ("db_hourly_retention_days",      "小时聚合保留天数",     "int", 7,  365,
         "每小时聚合记录的保留时长（7-365 天）。用于长期趋势分析。"),
        ("db_alert_retention_days",       "告警事件保留天数",     "int", 30, 730,
         "状态变化事件的保留时长（30-730 天）。用于故障复盘。"),
        ("db_traceroute_retention_days",  "路由追踪记录保留天数", "int", 7,  365,
         "自动路由追踪快照的保留时长（7-365 天）。"),
        ("db_diag_retention_days",        "诊断历史保留天数",     "int", 7,  730,
         "ICMP / DNS 高级诊断结果的保留时长（7-730 天）。诊断结果体积较小，可较久保留。"),
    ]),
]


class SettingsDialog(ctk.CTkToplevel):
    """
    Modal settings dialog.

    Parameters
    ----------
    parent
        The main window.
    config_manager
        ConfigManager instance (reads current values, saves on apply).
    alert_manager
        AlertManager – for reading/writing the sound-enabled flag.
    on_save
        Callable(changed: dict) – called after saving.
        `changed` contains {key: new_value} for every key that changed.
    """

    def __init__(self, parent, config_manager, alert_manager, on_save):
        super().__init__(parent)
        self.title("⚙ 全局设置")
        self.geometry("520x720")
        self.resizable(False, True)
        self.transient(parent)
        self.grab_set()

        self._config   = config_manager
        self._alerter  = alert_manager
        self._on_save  = on_save
        self._entries  = {}      # key → widget (Entry or CTkSwitch)
        self._originals = {}     # key → original value (for change detection)

        self._build()
        self._center()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _bind_settings_scrollbar(self, scroll):
        """Scrollbar visibility for a static form.

        Strategy differs from the main-window dynamic approach:
        - Judge by content_h > viewport_h (overflow), not yview() position
        - Only re-check on dialog HEIGHT changes and after initial build
        - State cache: skip grid/grid_remove when visibility is already correct
        - No binding to scroll position changes (those are irrelevant here)
        """
        _state = [None]          # None=unknown, True=visible, False=hidden
        _last_dlg_h = [0]        # last dialog height we acted on

        def _check():
            try:
                canvas    = scroll._parent_canvas
                sbar      = scroll._scrollbar
                content_h = scroll.winfo_reqheight()
                viewport_h = canvas.winfo_height()
                needs = content_h > viewport_h + 2   # +2: float-rounding tolerance
                if needs == _state[0]:
                    return                             # no change — skip redundant call
                _state[0] = needs
                if needs:
                    sbar.grid()
                else:
                    sbar.grid_remove()
            except Exception:
                pass

        def _on_height_change(event=None):
            try:
                new_h = self.winfo_height()
                if abs(new_h - _last_dlg_h[0]) < 3:
                    return                             # sub-pixel noise — ignore
                _last_dlg_h[0] = new_h
                if hasattr(self, '_sbar_check_timer'):
                    try: self.after_cancel(self._sbar_check_timer)
                    except Exception: pass
                self._sbar_check_timer = self.after(150, _check)
            except Exception:
                pass

        # Hide immediately so it doesn't flash before the first check.
        try:
            scroll._scrollbar.grid_remove()
            _state[0] = False
        except Exception:
            pass

        # Two-stage initial check: after_idle (layout pass done) and a
        # 100 ms follow-up (geometry fully settled on all platforms).
        scroll.after_idle(_check)
        scroll.after(100, _check)

        # Re-check only when the dialog window itself is resized.
        self.bind("<Configure>", _on_height_change, add="+")

        # Expose a manual refresh hook for future use.
        # If sections ever become dynamically shown/hidden (collapsible sections,
        # conditional fields, theme-driven font-size changes, etc.), callers
        # should invoke self.refresh_scrollbar() after the layout change to
        # ensure the scrollbar visibility stays correct.
        self.refresh_scrollbar = _check

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        # Scrollable main area
        scroll = ctk.CTkScrollableFrame(self, fg_color=self.cget("fg_color"))
        scroll.pack(fill="both", expand=True, padx=0, pady=0)

        # Settings dialog uses a dedicated lightweight scrollbar strategy instead
        # of the generic bind_scrollbar_visibility (which fires on every Configure
        # event including scrolling).  Static forms only need to recheck when:
        #  - the form is first built (content height now known)
        #  - the dialog window height changes (user resizes)
        # Comparison: content_h > viewport_h, with state cache to suppress
        # redundant grid/grid_remove calls.
        self._bind_settings_scrollbar(scroll)

        for section_title, fields in _SECTIONS:
            self._add_section(scroll, section_title, fields)

        # Sound toggle (special case: lives in AlertManager, not config)
        self._add_sound_toggle(scroll)

        # Buttons
        btn_bar = ctk.CTkFrame(self, fg_color="transparent", height=48)
        btn_bar.pack(fill="x", side="bottom")
        btn_bar.pack_propagate(False)

        ctk.CTkButton(btn_bar, text="取消", width=100,
                      fg_color="gray30", hover_color="gray40",
                      font=F(13), command=self.destroy).pack(side="right", padx=(8, 16))
        ctk.CTkButton(btn_bar, text="保存并应用", width=130,
                      font=F(13), command=self._save).pack(side="right")

        ctk.CTkFrame(self, height=1, fg_color="gray25").pack(
            fill="x", side="bottom")

        self.bind("<Escape>", lambda e: self.destroy())

    def _add_section(self, parent, title: str, fields: list):
        if not fields:
            return

        # Section header
        header = ctk.CTkLabel(parent, text=title,
                               font=F(13, "bold"), anchor="w",
                               text_color="gray70")
        header.pack(fill="x", padx=16, pady=(14, 4))

        frame = ctk.CTkFrame(parent, fg_color=("gray92", "gray17"), corner_radius=8)
        frame.pack(fill="x", padx=12, pady=(0, 4))

        for i, (key, label, dtype, lo, hi, hint) in enumerate(fields):
            self._add_field(frame, key, label, dtype, lo, hi, hint, i)

    def _add_sound_toggle(self, parent):
        """Sound enable/disable lives in AlertManager, not ConfigManager."""
        # No extra section header here — _add_section already created
        # "告警与通知" as the section title above this block.
        frame = ctk.CTkFrame(parent, fg_color=("gray92", "gray17"), corner_radius=8)
        frame.pack(fill="x", padx=12, pady=(0, 4))

        row = ctk.CTkFrame(frame, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=8)

        ctk.CTkLabel(row, text="启用声音告警",
                     font=F(12), anchor="w").pack(side="left", fill="x", expand=True)

        current = self._alerter.enabled
        self._originals["_sound_enabled"] = current
        switch = ctk.CTkSwitch(row, text="", width=46, height=22,
                               command=lambda: None)
        if current:
            switch.select()
        else:
            switch.deselect()
        switch.pack(side="right")
        self._entries["_sound_enabled"] = switch

        ctk.CTkLabel(frame, text="关闭后程序仍会显示颜色变化，只是不播放声音",
                     font=F(11), text_color="gray50", anchor="w").pack(
            fill="x", padx=14, pady=(0, 8))

    def _add_field(self, parent, key, label, dtype, lo, hi, hint, index):
        # autostart state lives in the Windows registry, not config.json.
        # Reading from config.json could show stale data if the registry
        # entry was modified outside the app.
        if key == "autostart":
            try:
                from src.utils_autostart import is_autostart_enabled
                current = is_autostart_enabled()
            except Exception:
                current = False
        else:
            current = self._config.get_setting(key)
        if current is None:
            # Key absent from the user's config.json (older config file that
            # predates this setting). Use a sensible default rather than
            # hiding the field entirely — an empty section is confusing.
            if dtype == "bool":
                current = False
            elif dtype == "float":
                current = float(lo) if lo is not None else 1.0
            else:
                current = int(lo) if lo is not None else 1
        self._originals[key] = current

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(8 if index == 0 else 4, 0))

        if dtype == "bool":
            # Toggle switch
            ctk.CTkLabel(row, text=label, font=F(12), anchor="w").pack(
                side="left", fill="x", expand=True)
            switch = ctk.CTkSwitch(row, text="", width=46, height=22,
                                   command=lambda: None)
            if current:
                switch.select()
            else:
                switch.deselect()
            switch.pack(side="right")
            self._entries[key] = switch
        else:
            # Text entry with label on left, entry on right
            ctk.CTkLabel(row, text=label, font=F(12), anchor="w").pack(
                side="left", fill="x", expand=True)
            entry = ctk.CTkEntry(row, width=80, height=28, font=F(12),
                                 justify="center")
            entry.insert(0, str(current))
            entry.pack(side="right")
            self._entries[key] = entry

        # Hint text below
        if hint:
            ctk.CTkLabel(parent, text=hint, font=F(10),
                         text_color="gray50", anchor="w").pack(
                fill="x", padx=14, pady=(1, 0))

        # Separator (except after last field – we don't know if last here,
        # so add a very thin frame that blends in)
        ctk.CTkFrame(parent, height=1,
                     fg_color=("gray85", "gray22")).pack(
            fill="x", padx=14, pady=(5, 0))

    # ------------------------------------------------------------------
    # Save logic
    # ------------------------------------------------------------------

    def _save(self):
        """Validate, collect changed values, call on_save, close."""
        changed = {}
        errors  = []

        for key, widget in self._entries.items():
            # ── Bool (CTkSwitch) ──────────────────────────────────────
            if isinstance(widget, ctk.CTkSwitch):
                new_val = widget.get() == 1
                if new_val != self._originals[key]:
                    changed[key] = new_val
                continue

            # ── Numeric / string entry ──────────────────────────────
            raw = widget.get().strip()

            # Find the descriptor for this key to get dtype and bounds
            dtype, lo, hi = self._get_field_meta(key)
            if dtype is None:
                continue  # shouldn't happen

            # str fields (e.g. webhook_url) may be empty — that means "disabled"
            if not raw and dtype != "str":
                errors.append(f"「{key}」不能为空")
                continue

            try:
                if dtype == "float":
                    new_val = float(raw)
                elif dtype == "str":
                    new_val = raw          # keep as-is, empty string is valid
                    # Webhook URL: if non-empty, must start with http:// or https://
                    if key == "webhook_url" and raw:
                        if not raw.lower().startswith(("http://", "https://")):
                            errors.append("Webhook 地址必须以 http:// 或 https:// 开头")
                            continue
                else:
                    new_val = int(raw)
            except ValueError:
                errors.append(f"「{key}」必须是{'小数' if dtype=='float' else '整数'}")
                continue

            if dtype == "float" and not math.isfinite(new_val):
                errors.append(f"「{key}」必须是有限数值")
                continue

            if lo is not None and new_val < lo:
                errors.append(f"「{key}」最小值为 {lo}")
                continue
            if hi is not None and new_val > hi:
                errors.append(f"「{key}」最大值为 {hi}")
                continue

            if new_val != self._originals[key]:
                changed[key] = new_val

        if errors:
            messagebox.showerror("输入有误", "\n".join(errors), parent=self)
            return

        if not changed:
            self.destroy()
            return

        # Apply and close
        # Handle autostart immediately (registry write)
        if "autostart" in changed:
            try:
                from src.utils_autostart import set_autostart
                set_autostart(bool(changed["autostart"]))
            except Exception as e:
                print(f"[Autostart] {e}")
        self._on_save(changed)
        self.destroy()

    def _get_field_meta(self, key):
        """Look up dtype and bounds for a given key."""
        for _, fields in _SECTIONS:
            for fkey, _, dtype, lo, hi, _ in fields:
                if fkey == key:
                    return dtype, lo, hi
        return None, None, None
