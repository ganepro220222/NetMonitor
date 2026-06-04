from __future__ import annotations

from src.config_manager import MIN_PING_INTERVAL_S, is_valid_ping_interval
from src.host_validation import (
    is_valid_host as _is_valid_host,
    normalize_dns_expected_ipv4 as _normalize_dns_expected_ipv4,
    normalize_http_success_codes as _normalize_http_success_codes,
    effective_latency_warn_ms_hint as _effective_latency_warn_ms_hint,
)

"""
dialogs.py
==========
Dialog design philosophy (fixes repeated window-size issues):

  ┌──────────────────────────────────────────────────┐
  │  CTkToplevel                                     │
  │  ┌────────────────────────────────────────────┐  │
  │  │  CTkScrollableFrame  (fill=both,expand=1)  │  │
  │  │   • label entry                            │  │
  │  │   • ip entry                               │  │
  │  │   • type selector                          │  │
  │  │   • type-specific fields (grid_remove/grid)│  │
  │  │   • threshold section (EditTargetDialog)   │  │
  │  └────────────────────────────────────────────┘  │
  │  error_label  (always visible, outside scroll)   │
  │  button_row   (always visible, outside scroll)   │
  └──────────────────────────────────────────────────┘

The scrollable body means:
  - We NEVER need to auto-resize the dialog on type change.
  - No winfo_reqheight() hacks. No before= pack tricks.
  - Type-specific frames use grid_remove()/grid() inside a container,
    which is the only reliable way to show/hide without affecting siblings.
  - Dialog is resizable by the user if needed.
"""

import re
import customtkinter as ctk
from src.ui.fonts import make as F
from src.ui.fonts import bind_scrollbar_visibility

PING_TYPES        = ["ICMP Ping", "TCP 端口", "HTTP/HTTPS", "DNS 监控"]
PING_TYPE_VALUES  = {"ICMP Ping": "icmp", "TCP 端口": "tcp",
                     "HTTP/HTTPS": "http", "DNS 监控": "dns"}
PING_TYPE_LABELS  = {v: k for k, v in PING_TYPE_VALUES.items()}


def _is_positive_int(s: str) -> bool:
    try:
        return int(s) > 0
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────
class _BaseDialog(ctk.CTkToplevel):
    """Base class. All content goes into self.scroll_body (CTkScrollableFrame)."""

    def __init__(self, parent, title: str, width: int = 450, height: int = 480):
        super().__init__(parent)
        self.title(title)
        self.geometry(f"{width}x{height}")
        self.resizable(True, True)
        self.minsize(400, 320)
        self.transient(parent)
        self.grab_set()
        self.result = None

        # Bottom row (pack first so it gets space before expand-fill)
        self._btn_outer = ctk.CTkFrame(self, fg_color="transparent")
        self._btn_outer.pack(side="bottom", fill="x", padx=16, pady=(4, 10))

        self._error_lbl = ctk.CTkLabel(self, text="", text_color="#FF6B6B",
                                        anchor="w", font=F(11))
        self._error_lbl.pack(side="bottom", fill="x", padx=16)

        # Scrollable body fills remaining space
        self.scroll_body = ctk.CTkScrollableFrame(self, fg_color=self.cget("fg_color"))
        self.scroll_body.pack(fill="both", expand=True, padx=4, pady=(6, 0))
        bind_scrollbar_visibility(self.scroll_body)

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _field(self, parent, label: str, placeholder: str = "", value: str = "") -> ctk.CTkEntry:
        ctk.CTkLabel(parent, text=label, anchor="w", font=F(12)).pack(
            fill="x", padx=16, pady=(8, 2))
        e = ctk.CTkEntry(parent, placeholder_text=placeholder, font=F(12), height=30)
        if value:
            e.insert(0, value)
        e.pack(fill="x", padx=16, pady=(0, 4))
        return e

    def _error(self, msg: str):
        self._error_lbl.configure(text=f"⚠ {msg}")

    def _clear_error(self):
        self._error_lbl.configure(text="")

    # ── Ping-type selector ────────────────────────────────────────────

    def _build_type_section(self, parent, initial_type: str = "icmp",
                             tcp_port: int = 80, tcp_probe: str = "",
                             http_url: str = "", http_codes: str = "2xx,3xx",
                             ipv6_only: bool = False,
                             dns_domain: str = "", dns_expected: str = ""):
        """
        Build the ping-type selector and type-specific field containers.

        Key design: type-specific frames sit inside a container that uses
        grid layout. Switching types uses grid_remove() / grid() — which
        preserves the grid slot and correctly collapses/reveals height.
        No pack(before=...) needed, no dialog resize needed.
        """
        ctk.CTkLabel(parent, text="监测类型", anchor="w", font=F(12)).pack(
            fill="x", padx=16, pady=(8, 2))

        type_row = ctk.CTkFrame(parent, fg_color="transparent")
        type_row.pack(fill="x", padx=16, pady=(0, 6))

        self._type_var = ctk.StringVar(value=PING_TYPE_LABELS.get(initial_type, "ICMP Ping"))
        ctk.CTkOptionMenu(type_row, values=PING_TYPES, variable=self._type_var,
                          font=F(12), dropdown_font=F(12), width=130, height=30,
                          anchor="center",
                          command=self._on_type_changed).pack(side="left")
        self._type_hint = ctk.CTkLabel(type_row, text="", font=F(10), text_color="gray50")
        self._type_hint.pack(side="left", padx=(10, 0))

        # Container for type-specific fields; uses grid internally
        self._type_container = ctk.CTkFrame(parent, fg_color="transparent")
        self._type_container.pack(fill="x")
        self._type_container.grid_columnconfigure(0, weight=1)

        # ── TCP frame ─────────────────────────────────────────────────
        self._tcp_frame = ctk.CTkFrame(self._type_container, fg_color="transparent")
        self._tcp_frame.grid(row=0, column=0, sticky="ew")

        r1 = ctk.CTkFrame(self._tcp_frame, fg_color="transparent")
        r1.pack(fill="x", padx=16, pady=(4, 2))
        ctk.CTkLabel(r1, text="监测端口（主）", font=F(12), anchor="w").pack(side="left")
        self._tcp_port = ctk.CTkEntry(r1, width=80, height=28, font=F(12), justify="center")
        self._tcp_port.insert(0, str(tcp_port))
        self._tcp_port.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(r1, text="告警唯一依据，留空默认 80", font=F(10),
                     text_color="gray50").pack(side="left", padx=(8, 0))

        ctk.CTkLabel(self._tcp_frame, text="诊断端口列表（逗号分隔，最多 6 个）",
                     anchor="w", font=F(12)).pack(fill="x", padx=16, pady=(6, 2))
        self._tcp_probe_ports = ctk.CTkEntry(self._tcp_frame, height=28, font=F(12),
                                              placeholder_text="例如：80,443,8080（留空默认检测 80 和 443）")
        if tcp_probe:
            self._tcp_probe_ports.insert(0, tcp_probe)
        self._tcp_probe_ports.pack(fill="x", padx=16, pady=(0, 4))
        ctk.CTkLabel(self._tcp_frame,
                     text="仅用于 Web 端诊断展示，不触发告警声。留空默认探测 80 和 443。",
                     font=F(10), text_color="gray50", anchor="w",
                     wraplength=360).pack(fill="x", padx=16, pady=(0, 6))

        # ── HTTP frame ────────────────────────────────────────────────
        self._http_frame = ctk.CTkFrame(self._type_container, fg_color="transparent")
        self._http_frame.grid(row=0, column=0, sticky="ew")

        ctk.CTkLabel(self._http_frame, text="URL（含协议头）",
                     anchor="w", font=F(12)).pack(fill="x", padx=16, pady=(4, 2))
        self._http_url = ctk.CTkEntry(self._http_frame, height=28, font=F(12),
                                       placeholder_text="https://www.example.com/health")
        if http_url:
            self._http_url.insert(0, http_url)
        self._http_url.pack(fill="x", padx=16, pady=(0, 6))

        r2 = ctk.CTkFrame(self._http_frame, fg_color="transparent")
        r2.pack(fill="x", padx=16, pady=(0, 2))
        ctk.CTkLabel(r2, text="成功状态码", font=F(12), anchor="w").pack(side="left")
        self._http_success_codes = ctk.CTkEntry(r2, width=110, height=28, font=F(12),
                                                  justify="center")
        self._http_success_codes.insert(0, http_codes)
        self._http_success_codes.pack(side="left", padx=(10, 0))

        ctk.CTkLabel(self._http_frame,
                     text="2xx=成功  3xx=重定向（通常正常）  4xx=客户端错误  5xx=服务器错误",
                     font=F(10), text_color="gray50", anchor="w").pack(
            fill="x", padx=16, pady=(2, 0))
        ctk.CTkLabel(self._http_frame,
                     text="支持组合：2xx,3xx  精确码：200,201  范围：2xx",
                     font=F(10), text_color="gray50", anchor="w").pack(
            fill="x", padx=16, pady=(0, 2))
        ctk.CTkLabel(self._http_frame,
                     text="HTTP 监测建议在设置中将 Ping 间隔调整为 30~60 秒",
                     font=F(10), text_color="#F39C12", anchor="w").pack(
            fill="x", padx=16, pady=(0, 8))

        # ── 关键字匹配配置（可选）─────────────────────────────────
        ctk.CTkFrame(self._http_frame, height=1, fg_color="gray25").pack(
            fill="x", padx=16, pady=(2, 6))
        ctk.CTkLabel(self._http_frame, text="响应内容关键字匹配（可选）",
                     anchor="w", font=F(12)).pack(fill="x", padx=16, pady=(0, 2))

        _kw_row = ctk.CTkFrame(self._http_frame, fg_color="transparent")
        _kw_row.pack(fill="x", padx=16, pady=(0, 2))

        # Read saved keyword from _init_extra (only exists on Edit dialog)
        _kw_val   = getattr(self, "_init_extra", {}).get("http_keyword", "")
        _kw_mode  = getattr(self, "_init_extra", {}).get("http_keyword_mode", "contains")

        self._http_keyword = ctk.CTkEntry(
            _kw_row, height=28, font=F(12),
            placeholder_text="例如：服务正常  （留空=禁用关键字检测）")
        if _kw_val:
            self._http_keyword.insert(0, _kw_val)
        self._http_keyword.pack(side="left", fill="x", expand=True)

        self._http_keyword_mode = ctk.CTkSegmentedButton(
            _kw_row, values=["包含", "排除"], font=F(11), width=110)
        self._http_keyword_mode.set("包含" if _kw_mode == "contains" else "排除")
        self._http_keyword_mode.pack(side="left", padx=(8, 0))

        ctk.CTkLabel(self._http_frame,
                     text="包含：页面必须含有该词才算成功  |  排除：页面出现该词则视为异常",
                     font=F(10), text_color="gray50", anchor="w",
                     justify="left", wraplength=370).pack(
            fill="x", padx=16, pady=(0, 8))

        # ── DNS frame
        self._dns_frame = ctk.CTkFrame(self._type_container, fg_color="transparent")
        self._dns_frame.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(self._dns_frame, text="查询域名", anchor="w", font=F(12)).pack(fill="x", padx=16, pady=(6,2))
        self._dns_domain = ctk.CTkEntry(self._dns_frame, height=28, font=F(12), placeholder_text="例如：www.baidu.com")
        if dns_domain: self._dns_domain.insert(0, dns_domain)
        self._dns_domain.pack(fill="x", padx=16, pady=(0,6))
        ctk.CTkLabel(self._dns_frame, text="预期解析 IP（留空仅测可用性）", anchor="w", font=F(12)).pack(fill="x", padx=16, pady=(0,2))
        self._dns_expected = ctk.CTkEntry(self._dns_frame, height=28, font=F(12), placeholder_text="多 IP 逗号分隔，留空仅检测存活")
        if dns_expected: self._dns_expected.insert(0, dns_expected)
        self._dns_expected.pack(fill="x", padx=16, pady=(0,4))
        ctk.CTkLabel(self._dns_frame, text="填 IP 后若解析结果不在列表中则触发劫持告警。", font=F(10), text_color="gray50", anchor="w", wraplength=360).pack(fill="x", padx=16, pady=(0,6))
        # ── IPv6 checkbox — lives in row=1 of _type_container (same grid as
        # type frames) so grid_remove()/grid() keeps its position stable.
        # Using pack_forget()/pack() on the parent loses position and appends
        # the widget to the end of all pack-managed siblings (below threshold).
        self._ipv6_frame = ctk.CTkFrame(self._type_container, fg_color="transparent")
        self._ipv6_frame.grid(row=1, column=0, sticky="ew", padx=0, pady=(2,4))
        self._ipv6_var = ctk.BooleanVar(value=ipv6_only)
        ctk.CTkCheckBox(self._ipv6_frame, text="仅使用 IPv6 探测",
                        variable=self._ipv6_var, font=F(12),
                        checkbox_width=16, checkbox_height=16).pack(side="left", padx=16)
        ctk.CTkLabel(self._ipv6_frame, text="（目标需支持 IPv6）",
                     font=F(10), text_color="gray50").pack(side="left", padx=(0,0))
        # Initially hide all
        self._tcp_frame.grid_remove()
        self._http_frame.grid_remove()
        self._dns_frame.grid_remove()

        self._on_type_changed(self._type_var.get())

    def _on_type_changed(self, selected: str):
        """
        Show/hide type-specific fields using grid_remove()/grid().
        NO dialog resize — the scrollable body handles overflow.
        """
        hints = {
            "ICMP Ping":  "标准网络可达性检测",
            "TCP 端口":   "检测特定端口是否开放（如 80/443/22/3389）",
            "HTTP/HTTPS": "检测网站或 API 的响应时间和状态码",
            "DNS 监控":   "检测 DNS 服务器可用性并防劫持验证",
        }
        self._type_hint.configure(text=hints.get(selected, ""))
        self._tcp_frame.grid_remove()
        self._http_frame.grid_remove()
        if hasattr(self, "_dns_frame"): self._dns_frame.grid_remove()
        is_dns = selected == "DNS 监控"
        if hasattr(self, "_ipv6_frame"):
            if is_dns: self._ipv6_frame.grid_remove()
            else:      self._ipv6_frame.grid()
        if selected == "TCP 端口":
            self._tcp_frame.grid()
        elif selected == "HTTP/HTTPS":
            self._http_frame.grid()
        elif selected == "DNS 监控" and hasattr(self, "_dns_frame"):
            self._dns_frame.grid()
        self._refresh_latency_warn_placeholder()

    def _refresh_latency_warn_placeholder(self) -> None:
        if not hasattr(self, "e_wlat"):
            return
        ptype = PING_TYPE_VALUES.get(self._type_var.get(), "icmp")
        hint = _effective_latency_warn_ms_hint(
            ptype, getattr(self, "_global", {}))
        try:
            self.e_wlat.configure(placeholder_text=hint)
        except Exception:
            pass

    def _collect_type_result(self) -> dict | None:
        ptype = PING_TYPE_VALUES.get(self._type_var.get(), "icmp")
        extra: dict = {}
        if ptype == "tcp":
            port_str = self._tcp_port.get().strip()
            if not _is_positive_int(port_str) or not (1 <= int(port_str) <= 65535):
                self._error("监测端口必须是 1-65535 之间的整数")
                return None
            extra["tcp_port"] = int(port_str)
            probe_raw = self._tcp_probe_ports.get().strip()
            if probe_raw:
                try:
                    ports = [int(p.strip()) for p in probe_raw.split(",") if p.strip()]
                    if len(ports) > 6:
                        self._error("诊断端口最多填 6 个（逗号分隔）")
                        return None
                    if any(not (1 <= p <= 65535) for p in ports):
                        self._error("诊断端口列表中存在无效端口号（1-65535）")
                        return None
                    extra["tcp_probe_ports"] = ",".join(str(p) for p in ports)
                except ValueError:
                    self._error("诊断端口格式错误，请用逗号分隔，例如：80,443,8080")
                    return None
        elif ptype == "http":
            url = self._http_url.get().strip()
            if not url or not url.startswith(("http://", "https://")):
                self._error("URL 必须以 http:// 或 https:// 开头")
                return None
            codes, codes_err = _normalize_http_success_codes(
                self._http_success_codes.get().strip())
            if codes_err:
                self._error(codes_err)
                return None
            extra["http_url"]           = url
            extra["http_success_codes"] = codes
            kw = self._http_keyword.get().strip() if hasattr(self, "_http_keyword") else ""
            if kw:
                extra["http_keyword"]      = kw
                kw_sel = self._http_keyword_mode.get() if hasattr(self, "_http_keyword_mode") else "包含"
                extra["http_keyword_mode"] = "contains" if kw_sel == "包含" else "absent"
            else:
                extra.pop("http_keyword", None)
                extra.pop("http_keyword_mode", None)
        elif ptype == "dns":
            domain = self._dns_domain.get().strip() if hasattr(self,"_dns_domain") else ""
            if not domain:
                self._error("DNS 监控必须填写查询域名"); return None
            extra["dns_domain"] = domain
            exp = self._dns_expected.get().strip() if hasattr(self,"_dns_expected") else ""
            if exp:
                normalized, err = _normalize_dns_expected_ipv4(exp)
                if err:
                    self._error(err)
                    return None
                extra["dns_expected"] = normalized
        if ptype != "dns" and hasattr(self,"_ipv6_var") and self._ipv6_var.get():
            extra["ipv6_only"] = True
        return {"ping_type": ptype, **extra}


# ─────────────────────────────────────────────────────────────────────
class AddTargetDialog(_BaseDialog):

    def __init__(self, parent, global_settings: dict = None):
        super().__init__(parent, "添加监测目标", width=460, height=540)
        self._global    = global_settings or {}
        self._init_extra = {}  # 统一路径供 _build_type_section 读取
        self._build()
        self._center()

    def _build(self):
        self.label_entry = self._field(self.scroll_body, "备注名称",
                                        "例如：办公室主路由")
        self.ip_entry    = self._field(self.scroll_body, "IP 地址 / 域名",
                                        "例如：192.168.1.1 或 www.example.com")
        self._build_type_section(self.scroll_body)

        # ── 告警阈值（折叠，与编辑弹窗保持一致）─────────────────────────
        ctk.CTkFrame(self.scroll_body, height=1, fg_color="gray25").pack(
            fill="x", padx=16, pady=(6, 0))
        self._thresh_header = ctk.CTkLabel(
            self.scroll_body,
            text="▶  告警阈值（可选，留空使用全局默认值）",
            font=F(11), text_color="gray60", anchor="w", cursor="hand2")
        self._thresh_header.pack(fill="x", padx=16, pady=(6, 2))
        self._thresh_header.bind("<Button-1>", lambda e: self._toggle_thresh())

        self._thresh_frame   = ctk.CTkFrame(self.scroll_body, fg_color="transparent")
        self._thresh_visible = False
        g = self._global

        def _mk(parent, row, label, key, default):
            ctk.CTkLabel(parent, text=label, font=F(11), anchor="w").grid(
                row=row, column=0, sticky="w", padx=(0, 8), pady=3)
            # Use placeholder (not pre-fill) so that "留空使用全局默认值"
            # is literally true: empty field → no target-specific override →
            # engine falls back to global setting.  Pre-filling would silently
            # create an override even when the user doesn't intend to customize.
            hint = str(g.get(key, default))   # global value as grey hint
            e = ctk.CTkEntry(parent, width=72, height=26, font=F(11),
                              justify="center", placeholder_text=hint)
            e.grid(row=row, column=1, sticky="w", pady=3)
            return e

        tf = self._thresh_frame
        tf.grid_columnconfigure(0, weight=0)
        tf.grid_columnconfigure(2, weight=1)
        self.e_orange  = _mk(tf, 0, "连续丢包 → 橙色（次）",   "consecutive_loss_orange",  3)
        self.e_red     = _mk(tf, 1, "连续丢包 → 红色（次）",   "consecutive_loss_red",     5)
        self.e_lat_o   = _mk(tf, 2, "连续高延时 → 橙色（次）", "consecutive_lat_orange",   3)
        # consecutive_lat_red hidden: engine caps latency at ORANGE, not RED
        self.e_lat_r = None  # noqa
        ctk.CTkLabel(tf, text="延时警告阈值（ms）", font=F(11), anchor="w").grid(
            row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        ptype0 = PING_TYPE_VALUES.get(self._type_var.get(), "icmp")
        hint_wlat = _effective_latency_warn_ms_hint(ptype0, g)
        self.e_wlat = ctk.CTkEntry(tf, width=72, height=26, font=F(11),
                                    justify="center", placeholder_text=hint_wlat)
        self.e_wlat.grid(row=4, column=1, sticky="w", pady=3)
        self.e_elat    = None  # latency_error_ms hidden (same reason)
        ctk.CTkLabel(tf, text="Ping 间隔（秒）", font=F(11), anchor="w").grid(
            row=6, column=0, sticky="w", padx=(0, 8), pady=3)
        hint_iv = str(g.get("ping_interval", 1))
        self.e_interval = ctk.CTkEntry(tf, width=72, height=26, font=F(11),
                                        justify="center", placeholder_text=hint_iv)
        self.e_interval.grid(row=6, column=1, sticky="w", pady=3)
        ctk.CTkLabel(tf, text="ICMP 建议 1~5 秒，HTTP 建议 30~60 秒",
                     font=F(9), text_color="gray50", anchor="w").grid(
            row=6, column=2, sticky="w", padx=(6, 0))
        self._refresh_latency_warn_placeholder()

        ctk.CTkButton(self._btn_outer, text="取消", width=100,
                      fg_color="gray30", hover_color="gray40",
                      font=F(13), command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(self._btn_outer, text="添加", width=100, font=F(13),
                      command=self._confirm).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

    def _toggle_thresh(self):
        self._thresh_visible = not self._thresh_visible
        if self._thresh_visible:
            self._thresh_header.configure(text="▼  告警阈值（可选，留空使用全局默认值）")
            self._thresh_frame.pack(fill="x", padx=28, pady=(2, 4))
        else:
            self._thresh_header.configure(text="▶  告警阈值（可选，留空使用全局默认值）")
            self._thresh_frame.pack_forget()

    def _confirm(self):
        self._clear_error()
        label = self.label_entry.get().strip()
        ip    = self.ip_entry.get().strip()
        if not label:
            self._error("请填写备注名称"); return
        if not ip:
            self._error("请填写 IP 地址或域名"); return
        ptype = PING_TYPE_VALUES.get(self._type_var.get(), "icmp")
        if not _is_valid_host(ip):
            self._error("IP 地址或域名格式不正确"); return
        type_result = self._collect_type_result()
        if type_result is None:
            return

        thresholds: dict = {}
        for entry, key in [
            (self.e_orange, "consecutive_loss_orange"),
            (self.e_red,    "consecutive_loss_red"),
            (self.e_lat_o,  "consecutive_lat_orange"),
            (self.e_wlat,   "latency_warn_ms"),
        ]:
            val = entry.get().strip()
            if val:
                if not _is_positive_int(val):
                    self._error(f"「{key}」必须是正整数"); return
                thresholds[key] = int(val)
        iv_str = self.e_interval.get().strip()
        if iv_str:
            try:
                iv = float(iv_str)
                if not is_valid_ping_interval(iv):
                    raise ValueError
                thresholds["ping_interval"] = iv
            except ValueError:
                self._error("Ping 间隔必须是 0.05~120 秒之间的有效数值"); return

        self.result = {"label": label, "ip": ip,
                       "thresholds": thresholds or None, **type_result}
        self.destroy()


class EditTargetDialog(_BaseDialog):

    def __init__(self, parent, current_label: str, current_ip: str,
                 current_thresholds: dict = None, global_settings: dict = None,
                 current_ping_type: str = "icmp", current_extra: dict = None):
        super().__init__(parent, "编辑监测目标", width=460, height=540)
        self._init_label  = current_label
        self._init_ip     = current_ip
        self._thresh      = current_thresholds or {}
        self._global      = global_settings or {}
        self._init_ptype  = current_ping_type or "icmp"
        self._init_extra  = current_extra or {}
        self._build()
        self._center()

    def _build(self):
        self.label_entry = self._field(self.scroll_body, "备注名称")
        self.label_entry.insert(0, self._init_label)

        self.ip_entry = self._field(self.scroll_body, "IP 地址 / 域名")
        self.ip_entry.insert(0, self._init_ip)

        ctk.CTkFrame(self.scroll_body, height=1, fg_color="gray25").pack(
            fill="x", padx=16, pady=(6, 0))

        self._build_type_section(
            self.scroll_body,
            initial_type=self._init_ptype,
            tcp_port=str(self._init_extra.get("tcp_port", "80")),
            tcp_probe=self._init_extra.get("tcp_probe_ports", ""),
            http_url=self._init_extra.get("http_url", ""),
            http_codes=self._init_extra.get("http_success_codes", "2xx,3xx"),
            ipv6_only=bool(self._init_extra.get("ipv6_only", False)),
            dns_domain=self._init_extra.get("dns_domain", ""),
            dns_expected=self._init_extra.get("dns_expected", ""))

        # Collapsible threshold section
        ctk.CTkFrame(self.scroll_body, height=1, fg_color="gray25").pack(
            fill="x", padx=16, pady=(6, 0))
        self._thresh_header = ctk.CTkLabel(
            self.scroll_body,
            text="▶  告警阈值（可选，留空使用全局默认值）",
            font=F(11), text_color="gray60", anchor="w", cursor="hand2")
        self._thresh_header.pack(fill="x", padx=16, pady=(6, 2))
        self._thresh_header.bind("<Button-1>", lambda e: self._toggle_thresh())

        self._thresh_frame = ctk.CTkFrame(self.scroll_body, fg_color="transparent")
        self._thresh_visible = False

        g, th = self._global, self._thresh

        def _mk(parent, row, label, key, default):
            ctk.CTkLabel(parent, text=label, font=F(11), anchor="w").grid(
                row=row, column=0, sticky="w", padx=(0, 8), pady=3)
            hint = str(g.get(key, default))   # global/fallback as placeholder
            e = ctk.CTkEntry(parent, width=72, height=26, font=F(11),
                              justify="center", placeholder_text=hint)
            # Pre-fill ONLY if the target has an explicit override.
            # Leaving the field empty means "use global" (matches the hint text).
            if key in th:
                e.insert(0, str(th[key]))
            e.grid(row=row, column=1, sticky="w", pady=3)
            return e

        tf = self._thresh_frame
        tf.grid_columnconfigure(0, weight=0)
        tf.grid_columnconfigure(2, weight=1)

        self.e_orange  = _mk(tf, 0, "连续丢包 → 橙色（次）",   "consecutive_loss_orange",  3)
        self.e_red     = _mk(tf, 1, "连续丢包 → 红色（次）",   "consecutive_loss_red",     5)
        self.e_lat_o   = _mk(tf, 2, "连续高延时 → 橙色（次）", "consecutive_lat_orange",   3)
        # consecutive_lat_red hidden: engine caps latency at ORANGE, not RED
        self.e_lat_r = None  # noqa
        ctk.CTkLabel(tf, text="延时警告阈值（ms）", font=F(11), anchor="w").grid(
            row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        hint_wlat = _effective_latency_warn_ms_hint(self._init_ptype, g)
        self.e_wlat = ctk.CTkEntry(tf, width=72, height=26, font=F(11),
                                    justify="center", placeholder_text=hint_wlat)
        if "latency_warn_ms" in th:
            self.e_wlat.insert(0, str(th["latency_warn_ms"]))
        self.e_wlat.grid(row=4, column=1, sticky="w", pady=3)
        self.e_elat    = None  # latency_error_ms hidden (same reason)
        self._refresh_latency_warn_placeholder()

        # Per-target ping interval
        ctk.CTkLabel(tf, text="Ping 间隔（秒）", font=F(11), anchor="w").grid(
            row=6, column=0, sticky="w", padx=(0, 8), pady=3)
        default_interval = "30" if self._init_ptype in ("http", "https") else "1"
        hint_iv = str(self._global.get("ping_interval") or default_interval)
        self.e_interval = ctk.CTkEntry(tf, width=72, height=26, font=F(11),
                                        justify="center", placeholder_text=hint_iv)
        if "ping_interval" in self._thresh:   # only pre-fill if target has an explicit override
            self.e_interval.insert(0, str(self._thresh["ping_interval"]))
        self.e_interval.grid(row=6, column=1, sticky="w", pady=3)
        hint_text = "HTTP 建议 30~60 秒" if self._init_ptype in ("http", "https") else "ICMP 建议 1~5 秒"
        ctk.CTkLabel(tf, text=hint_text, font=F(9), text_color="gray50",
                     anchor="w").grid(row=6, column=2, sticky="w", padx=(6, 0))

        # Button row (always visible, outside scroll)
        ctk.CTkButton(self._btn_outer, text="取消", width=100,
                      fg_color="gray30", hover_color="gray40",
                      font=F(13), command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(self._btn_outer, text="保存", width=100, font=F(13),
                      command=self._confirm).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

    def _toggle_thresh(self):
        self._thresh_visible = not self._thresh_visible
        if self._thresh_visible:
            self._thresh_header.configure(
                text="▼  告警阈值（可选，留空使用全局默认值）")
            self._thresh_frame.pack(fill="x", padx=28, pady=(2, 4))
        else:
            self._thresh_header.configure(
                text="▶  告警阈值（可选，留空使用全局默认值）")
            self._thresh_frame.pack_forget()

    def _confirm(self):
        self._clear_error()
        label = self.label_entry.get().strip()
        ip    = self.ip_entry.get().strip()
        if not label:
            self._error("请填写备注名称")
            return
        if not ip:
            self._error("请填写 IP 地址或域名")
            return
        ptype = PING_TYPE_VALUES.get(self._type_var.get(), "icmp")
        if not _is_valid_host(ip):
            self._error("IP 地址或域名格式不正确")
            return
        type_result = self._collect_type_result()
        if type_result is None:
            return

        thresholds: dict = {}
        int_fields = [
            (self.e_orange, "consecutive_loss_orange"),
            (self.e_red,    "consecutive_loss_red"),
            (self.e_lat_o,  "consecutive_lat_orange"),
            (self.e_wlat,   "latency_warn_ms"),
        ]
        for entry, key in int_fields:
            val = entry.get().strip()
            if val:
                if not _is_positive_int(val):
                    self._error(f"「{key}」必须是正整数")
                    return
                thresholds[key] = int(val)

        # Validate per-target ping_interval (float)
        iv_str = self.e_interval.get().strip()
        if iv_str:
            try:
                iv = float(iv_str)
                if not is_valid_ping_interval(iv):
                    raise ValueError
                thresholds["ping_interval"] = iv
            except ValueError:
                self._error("Ping 间隔必须是 0.05~120 秒之间的有效数值")
                return

        self.result = {
            "label": label, "ip": ip,
            "thresholds": thresholds or None,
            **type_result
        }
        self.destroy()
