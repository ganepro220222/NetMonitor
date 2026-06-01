"""
traceroute_result_window.py — minimal C-side traceroute result viewer.

Triggered from the DNS-diag window's "追踪此 IP" button on each A/AAAA
answer row.  Keeps a tiny visible footprint because the DNS window is the
primary surface — this window is just "show me the hops".

Design constraints (per the implementation plan):
  • Shares DIAG_TASK_SEM with ICMP / DNS — only one diagnostic at a time.
  • Background thread runs the (blocking) traceroute_util.run_traceroute;
    UI updates marshalled back via after().
  • Stop button kills the underlying tracert / traceroute subprocess via
    a stop Event + thread join attempt (we don't track Popen here because
    run_traceroute() encapsulates Popen and uses subprocess.run with a
    timeout — Phase 1 settles for "let it finish or hit timeout").
  • Does NOT write to traceroute_logs — that table is for the Web
    scheduler's periodic captures, not on-demand C-side runs.
"""
from __future__ import annotations

import threading
from typing import Optional

import customtkinter as ctk

from src.ui.fonts import make as F
from src.diag_sem import DIAG_TASK_SEM
from src.traceroute_util import run_traceroute


class TracerouteResultWindow(ctk.CTkToplevel):
    """Run + display a single traceroute toward a specific IP."""

    _saved_geometry: str = "640x500"

    def __init__(self, parent, ip: str, max_hops: int = 30,
                 on_close_callback=None):
        super().__init__(parent)
        self._ip       = ip
        self._max_hops = max_hops
        self._on_close_cb = on_close_callback

        # Background-thread state.  _stop is checked only at coarse
        # boundaries (between completed run + UI update); the actual
        # subprocess inside run_traceroute is bounded by its own 120 s
        # internal timeout, so cancel is "best effort" — the window
        # closes immediately but the tracert process may linger briefly.
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._sem_held = False     # tracks whether we hold DIAG_TASK_SEM

        self.title(f"路由追踪 — {ip}")
        self._restore_geometry()
        self.minsize(520, 360)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.lift()
        self.focus_force()

        self._build_ui()
        # Auto-start: opening this window implies "start tracing now".
        self.after(80, self._start)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray88", "gray15"))
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text=f"🛰  路由追踪  →  {self._ip}",
                     font=F(13, "bold"), anchor="w").pack(side="left",
                                                          padx=14, pady=8)

        btn_frm = ctk.CTkFrame(self, fg_color="transparent")
        btn_frm.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 4))
        self._start_btn = ctk.CTkButton(
            btn_frm, text="▶ 重新追踪", width=110, height=30, font=F(12),
            command=self._start)
        self._start_btn.pack(side="left", padx=(0, 8))
        self._stop_btn = ctk.CTkButton(
            btn_frm, text="■ 停止", width=80, height=30, font=F(12),
            text_color=("gray15", "gray90"),
            fg_color=("gray65", "gray35"),
            hover_color=("gray50", "gray45"),
            state="disabled", command=self._stop_clicked)
        self._stop_btn.pack(side="left")
        self._status_lbl = ctk.CTkLabel(
            btn_frm, text="", font=F(11), text_color="gray50")
        self._status_lbl.pack(side="left", padx=16)

        # Hop list — text box because there's no native Treeview in CTk;
        # a fixed-width font keeps columns aligned with simple spacing.
        self._log = ctk.CTkTextbox(
            self, font=F(12), wrap="none", state="disabled")
        self._log.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _start(self):
        if self._worker is not None and self._worker.is_alive():
            return   # already running
        self._stop.clear()
        self._set_buttons(running=True)
        self._clear_log()
        self._set_status(f"追踪中 {self._ip} … (最多 {self._max_hops} 跳)")

        def _run():
            # Acquire the shared diagnostic semaphore — this is what gives
            # the user the "one diagnosis at a time" guarantee with ICMP
            # and DNS.  blocking=False keeps the failure path obvious.
            if not DIAG_TASK_SEM.acquire(blocking=False):
                try:
                    self.after(0, lambda: self._set_status(
                        "当前有诊断任务正在进行，请稍后再试", error=True))
                    self.after(0, lambda: self._set_buttons(running=False))
                except Exception:
                    pass
                return
            self._sem_held = True
            try:
                hops = run_traceroute(self._ip, max_hops=self._max_hops)
                if self._stop.is_set():
                    try:
                        self.after(0, lambda: self._set_status("已停止"))
                        self.after(0, lambda: self._set_buttons(running=False))
                    except Exception:
                        pass
                    return
                try:
                    self.after(0, lambda h=hops: self._render_hops(h))
                except Exception:
                    pass
            finally:
                try:
                    DIAG_TASK_SEM.release()
                finally:
                    self._sem_held = False

        self._worker = threading.Thread(target=_run, daemon=True,
                                         name="dns-tracert")
        self._worker.start()

    def _stop_clicked(self):
        # We can't reach into run_traceroute's Popen from here (it owns the
        # subprocess lifetime), so cancel is best-effort: flip the flag,
        # mark UI idle, and let the worker observe stop on completion.
        self._stop.set()
        self._set_status("已请求停止…")
        self._set_buttons(running=False)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    def _render_hops(self, hops: list):
        """Render the hop list as a monospace table."""
        lines: list[str] = []
        lines.append(f"{'跳':>3}  {'IP 地址':<22}  {'延时':>8}  状态")
        lines.append(f"{'─'*3}  {'─'*22}  {'─'*8}  {'─'*10}")
        for h in hops:
            hop  = h.get("hop", "?")
            ip   = h.get("ip") or "* * *"
            rtt  = h.get("rtt_ms")
            stat = h.get("status", "")
            rtt_s = f"{rtt:>5.1f} ms" if rtt is not None else "      —"
            stat_s = {
                "ok":       "✓ 正常",
                "filtered": "·  过滤",
                "break":    "✗  断点",
                "after":    "·  断后",
                "timeout_raw": "·  超时",
            }.get(stat, stat)
            lines.append(f"{hop:>3}  {ip:<22}  {rtt_s}  {stat_s}")
        if not hops:
            lines.append("(无返回数据)")

        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.insert("end", "\n".join(lines) + "\n")
        self._log.configure(state="disabled")

        self._set_buttons(running=False)
        # If any hop reported an error string in its dict, surface it.
        first_err = next((h.get("error") for h in hops if h.get("error")), None)
        if first_err:
            self._set_status(f"完成（含错误）：{first_err}", error=True)
        else:
            ok_n = sum(1 for h in hops if h.get("status") == "ok")
            self._set_status(f"完成：{ok_n}/{len(hops)} 跳成功")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_buttons(self, running: bool):
        try:
            self._start_btn.configure(state="disabled" if running else "normal")
            self._stop_btn.configure(state="normal" if running else "disabled")
        except Exception:
            pass

    def _set_status(self, msg: str, error: bool = False):
        try:
            color = "#ef4444" if error else "gray50"
            self._status_lbl.configure(text=msg, text_color=color)
        except Exception:
            pass

    def _restore_geometry(self):
        # Same screen-clamp pattern as IcmpDiagWindow — avoids a window
        # restored at -2000,-1000 from being effectively invisible.
        try:
            self.geometry(TracerouteResultWindow._saved_geometry)
            self.update_idletasks()
            wx, wy = self.winfo_x(), self.winfo_y()
            ww, wh = self.winfo_width(), self.winfo_height()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            cx = max(-ww + 100, min(wx, sw - 100))
            cy = max(0,         min(wy, sh - 50))
            if cx != wx or cy != wy:
                self.geometry(f"{ww}x{wh}+{cx}+{cy}")
        except Exception:
            self.geometry("640x500")

    def _on_close(self):
        try:
            geo = self.geometry()
            if geo and "x" in geo:
                TracerouteResultWindow._saved_geometry = geo
        except Exception:
            pass
        self._stop.set()
        if self._on_close_cb:
            try:
                self._on_close_cb()
            except Exception:
                pass
        self.destroy()
