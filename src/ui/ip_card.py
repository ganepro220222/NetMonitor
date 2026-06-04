from __future__ import annotations
import customtkinter as ctk
from src.ui.chart_panel import ChartPanel, MATPLOTLIB_AVAILABLE
from src.ui.fonts import make as F

STATUS_COLORS = {
    "green":  "#2ECC71",
    "orange": "#F39C12",
    "red":    "#E74C3C",
    "gray":   "#7F8C8D",
}


class IPCard(ctk.CTkFrame):
    """
    Compact monitoring card with:
    - Horizontal button row (C — buttons no longer stacked vertically)
    - Per-card pause / resume toggle (C5)
    - Chart that expands downward from the card bottom (C4)

    The card deliberately avoids setting a fixed height so that tkinter
    can let the chart panel expand the card downward without disturbing
    the card's top edge position.
    """

    def __init__(self, parent, target, on_edit, on_delete,
                 on_pause=None, on_resume=None,
                 get_history=None, warn_latency=150,
                 on_detail=None, on_icmp_diag=None,
                 on_dns_diag=None):
        super().__init__(parent, corner_radius=8, border_width=1, border_color="gray30")
        self.target_id      = target["id"]
        self.on_edit        = on_edit
        self.on_delete      = on_delete
        self.on_pause       = on_pause
        self.on_resume      = on_resume
        self._on_detail     = on_detail
        self._on_icmp_diag  = on_icmp_diag
        self._on_dns_diag   = on_dns_diag
        self._is_chart_open = False
        self._is_paused     = False
        self._build_main_row(target)

        if get_history is not None and MATPLOTLIB_AVAILABLE:
            self._chart_panel = ChartPanel(
                parent=self, target_id=target["id"],
                get_history=get_history, warn_latency=warn_latency)
        else:
            self._chart_panel = None

    def _build_main_row(self, target):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x")
        row.grid_columnconfigure(1, weight=1)

        # ── Status dot ────────────────────────────────────────────────
        self.status_dot = ctk.CTkLabel(
            row, text="●", font=F(18),
            text_color=STATUS_COLORS["gray"], width=30)
        self.status_dot.grid(row=0, column=0, rowspan=2, padx=(12, 4), pady=8)

        # ── Name + IP + loss badge ────────────────────────────────────
        info = ctk.CTkFrame(row, fg_color="transparent")
        info.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(0, 8), pady=6)

        top = ctk.CTkFrame(info, fg_color="transparent")
        top.pack(fill="x")
        self.label_text = ctk.CTkLabel(
            top, text=target["label"], font=F(13, "bold"), anchor="w")
        self.label_text.pack(side="left")
        self.loss_text = ctk.CTkLabel(
            top, text="", font=F(10), text_color="#E74C3C")
        self.loss_text.pack(side="left", padx=(6, 0))

        self.ip_text = ctk.CTkLabel(
            info, text=target["ip"], font=F(11), text_color="gray60", anchor="w")
        self.ip_text.pack(fill="x")

        # ── Latency + jitter ──────────────────────────────────────────
        metrics = ctk.CTkFrame(row, fg_color="transparent")
        metrics.grid(row=0, column=2, rowspan=2, padx=10, pady=6)

        self.latency_label = ctk.CTkLabel(
            metrics, text="-- ms",
            font=F(18, "bold"), text_color="gray60", anchor="e", width=96)
        self.latency_label.pack()
        self.jitter_label = ctk.CTkLabel(
            metrics, text="抖动 -- ms",
            font=F(10), text_color="gray50", anchor="e")
        self.jitter_label.pack()

        # ── Buttons: horizontal row ───────────────────────────────────
        # All buttons in one row reduces card height by ~56px compared
        # to the previous vertical stack arrangement.
        btn_outer = ctk.CTkFrame(row, fg_color="transparent")
        btn_outer.grid(row=0, column=3, rowspan=2, padx=(0, 10), sticky="e")

        btns = ctk.CTkFrame(btn_outer, fg_color="transparent")
        btns.pack(expand=True, fill="both")

        col = 0

        # Chart toggle button — requires matplotlib
        if MATPLOTLIB_AVAILABLE:
            self._chart_btn = ctk.CTkButton(
                btns, text="📈", width=30, height=26,
                fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"),
                font=F(13), command=self._toggle_chart)
            self._chart_btn.grid(row=0, column=col, padx=(0, 3))
            col += 1

            # Large-chart detail window button — also matplotlib-dependent
            if self._on_detail is not None:
                ctk.CTkButton(
                    btns, text="⛶", width=30, height=26,
                    fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"),
                    font=F(13),
                    command=lambda: self._on_detail(self.target_id)
                ).grid(row=0, column=col, padx=(0, 3))
                col += 1

        # ICMP advanced diagnostics — NOT gated by matplotlib (uses only
        # subprocess + tk text widgets).  Previously nested inside the
        # matplotlib block which meant minimal/headless deploys without
        # matplotlib silently lost the diagnostics entry.
        if self._on_icmp_diag is not None:
            ctk.CTkButton(
                btns, text="🔬", width=30, height=26,
                fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"),
                font=F(13),
                command=lambda: self._on_icmp_diag(self.target_id)
            ).grid(row=0, column=col, padx=(0, 3))
            col += 1

        # DNS diagnostics — like 🔬, NOT gated by matplotlib.  Kept at
        # peer level (not nested under MATPLOTLIB_AVAILABLE) so headless
        # deploys keep this entry too.  Pure dnspython, no chart deps.
        if self._on_dns_diag is not None:
            ctk.CTkButton(
                btns, text="🌐", width=30, height=26,
                fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"),
                font=F(13),
                command=lambda: self._on_dns_diag(self.target_id)
            ).grid(row=0, column=col, padx=(0, 3))
            col += 1

        # Pause / resume button (C5)
        self._pause_btn = ctk.CTkButton(
            btns, text="⏸", width=30, height=26,
            fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"),
            font=F(12), command=self._toggle_pause)
        self._pause_btn.grid(row=0, column=col, padx=(0, 3))
        col += 1

        ctk.CTkButton(
            btns, text="编辑", width=44, height=26,
            fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"),
            font=F(11), command=lambda: self.on_edit(self.target_id)
        ).grid(row=0, column=col, padx=(0, 3))
        col += 1

        ctk.CTkButton(
            btns, text="删除", width=44, height=26,
            fg_color="#922B21", hover_color="#C0392B",
            font=F(11), command=lambda: self.on_delete(self.target_id)
        ).grid(row=0, column=col)

    # ------------------------------------------------------------------
    # Chart toggle (C4: expands downward from card bottom)
    # ------------------------------------------------------------------

    def _toggle_chart(self):
        if self._chart_panel is None:
            return
        if self._is_chart_open:
            self._chart_panel.stop_updates()
            self._chart_panel.pack_forget()
            self._is_chart_open = False
            self._chart_btn.configure(fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"))
        else:
            # pack() appends BELOW the main row, so the chart grows the card
            # downward and the card's top edge stays fixed in the grid row.
            self._chart_panel.pack(fill="x", padx=8, pady=(0, 8))
            self._is_chart_open = True
            self._chart_btn.configure(fg_color="#1F6AA5", hover_color="#1a5a8f")
            self._chart_panel.start_updates()

    # ------------------------------------------------------------------
    # Pause / resume (C5)
    # ------------------------------------------------------------------

    def _toggle_pause(self):
        self._is_paused = not self._is_paused
        if self._is_paused:
            self._pause_btn.configure(text="▶", fg_color="#1a5c3a", hover_color="#1e7a4e")
            self.status_dot.configure(text_color="gray50")
            self.latency_label.configure(text="已暂停", text_color="gray50",
                                          font=F(12, "bold"))
            # Clear secondary display so stale jitter/loss/alert text doesn't
            # linger next to "已暂停" and confuse the operator.
            self.jitter_label.configure(text="")
            self.loss_text.configure(text="")
            if self.on_pause:
                self.on_pause(self.target_id)
        else:
            self._pause_btn.configure(text="⏸", fg_color=("#5B7FA6","gray25"), hover_color=("#4A6E94","gray35"))
            self.status_dot.configure(text_color=STATUS_COLORS["gray"])
            self.latency_label.configure(text="探测中...",
                                         text_color="gray60", font=F(12))
            # Reset secondary display on resume — real values arrive after next probe.
            self.jitter_label.configure(text="")
            self.loss_text.configure(text="")
            if self.on_resume:
                self.on_resume(self.target_id)

    @property
    def is_paused(self):
        return self._is_paused

    # ------------------------------------------------------------------
    # Theme and chart theme
    # ------------------------------------------------------------------

    def clear_chart_display(self):
        """Clear the mini-chart canvas when history for this target was wiped."""
        if self._chart_panel is not None:
            self._chart_panel.clear_chart()

    def apply_chart_theme(self):
        # Apply theme to the chart object regardless of whether it is
        # currently open. This ensures that when a collapsed chart is
        # expanded, it already shows the correct theme colours.
        if self._chart_panel:
            self._chart_panel.apply_theme()

    # ------------------------------------------------------------------
    # Data updates (skipped when paused)
    # ------------------------------------------------------------------

    def update_status(self, status, latency_ms=None, jitter_ms=None, loss_rate=0.0,
                    ping_type="icmp", alert_category="ok",
                    status_code=None, failure_reason=None,
                    response_latency_ms=None):
        """
        Update the card visuals from a state observation.

        New parameters (Availability vs Performance model):
          alert_category : "ok" | "performance" | "availability"
                            — drives sub-label colour / wording
          status_code    : last-seen HTTP status code (HTTP type only)
          failure_reason : machine code if last probe failed
        """
        if self._is_paused:
            return   # don't overwrite the "已暂停" display
        color = STATUS_COLORS.get(status, STATUS_COLORS["gray"])
        self.status_dot.configure(text_color=color)

        # ── Latency / failure display ──────────────────────────────
        if latency_ms is not None:
            self.latency_label.configure(
                text=f"{latency_ms:.1f} ms", text_color=color, font=F(18, "bold"))
        elif status == "gray" and not failure_reason:
            # Reset / waiting for first probe — not a failure (Bug103).
            self.latency_label.configure(
                text="探测中...",
                text_color=STATUS_COLORS["gray"],
                font=F(12, "bold"))
        else:
            fail_text = self._format_failure(failure_reason)
            if response_latency_ms is not None:
                fail_text = f"{fail_text}  {response_latency_ms:.0f} ms"
            self.latency_label.configure(
                text=fail_text, text_color=STATUS_COLORS["red"], font=F(13, "bold"))

        # ── Sub-label: alert category + HTTP context ───────────────
        sub_parts = []
        if status == "orange" and alert_category == "performance":
            sub_parts.append("⚡ 性能告警")
        elif status in ("orange", "red") and alert_category == "availability":
            sub_parts.append("🔴 可用性告警")

        if ping_type in ("http", "https"):
            if status_code is not None:
                sub_parts.append(f"HTTP {status_code}")
            elif not sub_parts:
                sub_parts.append("含DNS+TLS")

        if jitter_ms is not None:
            sub_parts.append(f"抖动 {jitter_ms:.1f} ms")

        self.jitter_label.configure(
            text="  ".join(sub_parts) if sub_parts else "抖动 -- ms")
        self.loss_text.configure(
            text=f"⚠ {loss_rate*100:.0f}%" if loss_rate > 0.01 else "")

    @staticmethod
    def _format_failure(reason: str | None) -> str:
        """Translate machine failure codes into short Chinese labels."""
        if not reason:
            return "超时"
        r = reason.lower()   # normalise once; handles old uppercase data + new lowercase
        if r.startswith("dns_hijack:"):
            resolved = reason.split(":", 1)[1]
            return f"⚠ DNS劫持 {resolved}"
        if r == "nxdomain":            return "域名不存在"
        if r == "dns_no_a_record":     return "无 A 记录"
        if r.startswith("dns_rcode_"): return f"DNS错误码{r[10:]}"
        if r == "dns_timeout":         return "DNS 超时"
        if "dns" in r:    return "DNS 失败"
        if "tls" in r:    return "TLS 失败"
        if "ssl" in r:    return "SSL 失败"
        if "tcp" in r:    return "TCP 失败"
        if "timeout" in r: return "超时"
        if r.startswith("status_"):
            return f"HTTP {r.split('_', 1)[1]}"
        if "refused" in r: return "连接拒绝"
        return "请求失败"

    def update_info(self, label, ip):
        self.label_text.configure(text=label)
        self.ip_text.configure(text=ip)

    def matches_search(self, query: str) -> bool:
        """Return True if label, IP, or DNS query domain matches the search."""
        q = query.lower()
        if q in self.label_text.cget("text").lower():
            return True
        if q in self.ip_text.cget("text").lower():
            return True
        # DNS nodes: search the probed domain so users can type e.g. "baidu.com"
        dns_domain = getattr(self, "_dns_domain", "") or ""
        return bool(dns_domain and q in dns_domain.lower())
