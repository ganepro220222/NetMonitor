from __future__ import annotations
import tkinter as tk
import customtkinter as ctk
from datetime import datetime
from src.ui.fonts import FONT_FAMILY, make as F

_HEADER_BG = ("gray88", "gray15")
_PANEL_BG  = ("gray95", "gray18")

STATUS_LABELS = {
    "green":  ("正常", "#2ECC71"),
    "orange": ("警告", "#F39C12"),
    "red":    ("告警", "#E74C3C"),
    "gray":   ("未知", "#7F8C8D"),
    "paused": ("暂停", "#7F8C8D"),
}

MAX_EVENTS = 60

_C_DARK  = {"bg":"#1e2029","fg":"#d0d0d0","ts":"#6b7280","sep":"#3a3f52","sbg":"#2a2e3a"}
_C_LIGHT = {"bg":"#f0f2f5","fg":"#1a202c","ts":"#9ca3af","sep":"#d0d5e0","sbg":"#e2e5ec"}


class HistoryPanel(ctk.CTkFrame):
    """
    Collapsible alert-history panel.

    Architecture
    ────────────
    Content area: ONE plain tk.Text (native Tk, zero canvas overhead).
      • Window resize fires 1 repaint, not 420 (old CTK-widget design).
    Scrollbar: ctk.CTkScrollbar connected directly to the tk.Text.
      • CTK-styled, theme-aware, looks identical to the rest of the app.
      • Safe: CTkScrollbar.set() is called only when text changes
        (idle-time full-rebuild), not on every layout event.
        The re-entrancy guard in fonts.py covers any residual risk.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color=_PANEL_BG, corner_radius=6)
        self._expanded      = False
        self._events: list[dict] = []
        self._pending_flush = False
        self._vsb_visible   = False   # tracks actual grid state of scrollbar
        self._build()

    # ──────────────────────────────────────────────────────────── build ──────

    def _build(self):
        # Header (3 CTK labels – acceptable widget count)
        hdr = ctk.CTkFrame(self, fg_color=_HEADER_BG, corner_radius=6)
        hdr.pack(fill="x")

        self._arrow = ctk.CTkLabel(hdr, text="▶", font=F(11),
                                   text_color="gray50", width=20)
        self._arrow.pack(side="left", padx=(8, 2), pady=6)
        self._title_lbl = ctk.CTkLabel(hdr, text="告警历史", font=F(12),
                                        text_color="gray60")
        self._title_lbl.pack(side="left", pady=6)
        self._count_lbl = ctk.CTkLabel(hdr, text="", font=F(11),
                                       text_color="gray50")
        self._count_lbl.pack(side="right", padx=12, pady=6)
        for w in (hdr, self._arrow, self._title_lbl, self._count_lbl):
            w.bind("<Button-1>", lambda e: self._toggle())

        # ── Content area ──────────────────────────────────────────────────
        self._content = ctk.CTkFrame(self, fg_color=_PANEL_BG, corner_radius=0)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        c = self._palette()
        self._txt = tk.Text(
            self._content, wrap=tk.NONE, height=7,
            state=tk.DISABLED, cursor="arrow",
            relief=tk.FLAT, bd=0, highlightthickness=0,
            font=(FONT_FAMILY, 11),
            bg=c["bg"], fg=c["fg"],
            selectbackground=c["sbg"],
            insertbackground=c["fg"],
        )
        self._txt.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=2)

        # CTkScrollbar in grid col 1 — always allocated, shown/hidden via
        # grid_remove() / grid() which is deferred via after(0) so it never
        # runs synchronously inside the Text widget's yscrollcommand chain.
        self._vsb = ctk.CTkScrollbar(
            self._content, orientation="vertical",
            command=self._txt_yview,
            width=12,
        )
        self._vsb.grid(row=0, column=1, sticky="ns", padx=(0, 2), pady=2)
        self._vsb.grid_remove()   # hidden until content overflows

        self._txt.configure(yscrollcommand=self._on_yscroll)

        # Mouse-wheel scrolling
        self._txt.bind("<MouseWheel>",
                       lambda e: self._txt.yview_scroll(
                           -1 * (e.delta // 120), "units"))

        self._configure_tags()

        # Follow CTK theme changes by overriding the built-in lifecycle hook
        # instead of registering a lambda in the global AppearanceModeTracker.
        # Tracker registration leaks if HistoryPanel is ever destroyed and
        # recreated — the dead lambda stays in the global singleton forever.

    # ─────────────────────────────────────────────────────── scrollbar ───────

    def _txt_yview(self, *args):
        self._txt.yview(*args)

    def _on_yscroll(self, first: str, last: str) -> None:
        """
        yscrollcommand callback — show/hide scrollbar based on overflow.
        grid_remove()/grid() is deferred via after(0) so it NEVER runs
        synchronously inside the Text widget's yscrollcommand chain.
        The CTkBaseClass._update_dimensions_event guard in fonts.py prevents
        any cascade from the grid layout change.
        """
        self._vsb.set(first, last)
        overflows = not (float(first) <= 0.0 and float(last) >= 1.0)
        if overflows != self._vsb_visible:
            self._vsb_visible = overflows
            self.after(0, self._apply_vsb_visibility)

    def _apply_vsb_visibility(self) -> None:
        if self._vsb_visible:
            self._vsb.grid()
        else:
            self._vsb.grid_remove()

    # ──────────────────────────────────────────────────────────── theme ──────

    def _palette(self) -> dict:
        return _C_DARK if ctk.get_appearance_mode() != "Light" else _C_LIGHT

    def _configure_tags(self):
        """Create colour / font tags (called once at build time)."""
        t = self._txt
        for key, (_lbl, col) in STATUS_LABELS.items():
            t.tag_configure(f"s_{key}", foreground=col)
        t.tag_configure("bold",  font=(FONT_FAMILY, 11, "bold"))
        t.tag_configure("ts",    foreground="#6b7280")
        t.tag_configure("arrow", foreground="#4b5563")
        t.tag_configure("dim",   foreground="#6b7280")
        # Apply correct theme colours immediately — don't rely on the
        # _set_appearance_mode CTK hook which only fires on theme CHANGE,
        # not at widget creation time.  Without this, light-mode users
        # would see dark-coded grey values until the first theme switch.
        self._apply_colors()

    def _set_appearance_mode(self, mode_string: str) -> None:
        """CTK lifecycle hook — called automatically on theme change."""
        super()._set_appearance_mode(mode_string)
        # Apply theme-correct colours immediately (not via after_idle) so the
        # widget never briefly flashes the hardcoded dark-theme colours in
        # light mode before the idle callback would have corrected them.
        self._apply_colors()
        # Also register for future appearance-mode changes.
        self.after_idle(self._apply_colors)

    def _apply_colors(self):
        """Re-apply widget colours on theme change."""
        c = self._palette()
        self._txt.configure(
            bg=c["bg"], fg=c["fg"],
            selectbackground=c["sbg"],
            insertbackground=c["fg"],
        )
        self._txt.tag_configure("ts",    foreground=c["ts"])
        self._txt.tag_configure("arrow", foreground=c["sep"])
        self._txt.tag_configure("dim",   foreground=c["ts"])

    # ──────────────────────────────────────────────────────────── toggle ─────

    def _toggle(self):
        self._expanded = not self._expanded
        self._arrow.configure(text="▼" if self._expanded else "▶")
        if self._expanded:
            self._content.pack(fill="x", pady=(1, 0))
        else:
            self._content.pack_forget()

    # ──────────────────────────────────────────────────────────── public ─────

    def add_event(self, label: str, ip: str,
                  old_status: str, new_status: str) -> None:
        if old_status == "gray" and new_status == "green":
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self._events.append({"time": ts, "label": label, "ip": ip,
                              "old": old_status, "new": new_status})
        if len(self._events) > MAX_EVENTS:
            self._events.pop(0)
        self._update_count()
        if not self._pending_flush:
            self._pending_flush = True
            self.after_idle(self._flush_pending)

    # ────────────────────────────────────────────────────────── internals ────

    def _flush_pending(self) -> None:
        """
        Full-rebuild of Text content (newest first).

        60 text lines + tag ops ≈ microseconds.
        after_idle coalescing: N rapid alerts → 1 rebuild.
        """
        self._pending_flush = False
        txt = self._txt
        txt.configure(state=tk.NORMAL)
        txt.delete("1.0", "end")

        for line_idx, ev in enumerate(reversed(self._events)):
            new_lbl, _ = STATUS_LABELS.get(ev["new"], ("?", "#7F8C8D"))
            ln = str(line_idx + 1)

            ts_s   = ev["time"] + "  "
            arr_s  = " → "
            lab_s  = "  " + ev["label"]
            ip_s   = "  " + ev["ip"]
            stat_s = "  " + new_lbl

            line = ts_s + "●" + arr_s + "●" + lab_s + ip_s + stat_s + "\n"
            txt.insert("end", line)

            # Apply tags by character position
            p = 0
            txt.tag_add("ts",             f"{ln}.{p}", f"{ln}.{p+len(ts_s)}")
            p += len(ts_s)
            txt.tag_add(f"s_{ev['old']}", f"{ln}.{p}", f"{ln}.{p+1}")
            p += 1
            txt.tag_add("arrow",          f"{ln}.{p}", f"{ln}.{p+len(arr_s)}")
            p += len(arr_s)
            txt.tag_add(f"s_{ev['new']}", f"{ln}.{p}", f"{ln}.{p+1}")
            p += 1
            p += 2                          # spaces before label
            txt.tag_add("bold",           f"{ln}.{p}", f"{ln}.{p+len(ev['label'])}")
            p += len(ev["label"])
            p += 2                          # spaces before ip
            txt.tag_add("dim",            f"{ln}.{p}", f"{ln}.{p+len(ev['ip'])}")
            p += len(ev["ip"])
            p += 2                          # spaces before stat
            txt.tag_add(f"s_{ev['new']}", f"{ln}.{p}", f"{ln}.{p+len(new_lbl)}")

        txt.configure(state=tk.DISABLED)

    def _update_count(self) -> None:
        n = len(self._events)
        # Count targets whose LAST recorded event is still orange/red.
        # Without this, every alert adds to the counter even after recovery.
        # Use (label, ip) as identity — sufficient given the UI shows these fields.
        last_status: dict[tuple, str] = {}
        for e in self._events:
            last_status[(e["label"], e["ip"])] = e["new"]
        active = sum(1 for s in last_status.values() if s in ("orange", "red"))
        text = f"{n} 条记录"
        if active:
            text += f"  ⚠ {active} 条未恢复"
        self._count_lbl.configure(text=text)
