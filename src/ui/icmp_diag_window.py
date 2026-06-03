"""
icmp_diag_window.py — ICMP advanced diagnostics window (C-side, Phase 1)

Phase 1 scope:
  - Single-shot probing with custom payload size
  - DF (Don't-Fragment) toggle
  - Per-probe result table
  - Aggregated statistics + human-readable conclusion
  - Cancel in-flight task
"""
from __future__ import annotations

import customtkinter as ctk
from typing import Optional

from src.ui.fonts import make as F
from src.icmp_diag import (
    IcmpDiagRequest, IcmpDiagResult, IcmpProbeSample,
    DiagTask, run_icmp_diag_async, run_pmtu_async,
    ERROR_OK, ERROR_FRAG_NEEDED, ERROR_TIMEOUT,
    ERROR_UNREACHABLE, ERROR_NET_UNREACH,
    ERROR_PERM_DENIED, ERROR_TOOL_UNAVAIL, ERROR_UNKNOWN,
)

# Human-readable error labels (displayed in per-probe table)
_ERROR_LABELS = {
    ERROR_OK:           "成功",
    ERROR_TIMEOUT:      "超时",
    ERROR_FRAG_NEEDED:  "需要分片（DF 阻止）",
    ERROR_UNREACHABLE:  "目标不可达",
    ERROR_NET_UNREACH:  "网络不可达",
    ERROR_PERM_DENIED:  "权限不足",
    ERROR_TOOL_UNAVAIL: "ping 命令不可用",
    ERROR_UNKNOWN:      "未知错误",
}

# Quick payload presets (ICMP payload bytes, NOT total IP packet size)
_PAYLOAD_PRESETS = [0, 32, 256, 512, 1200, 1400, 1472]


class IcmpDiagWindow(ctk.CTkToplevel):
    """Independent window for ICMP advanced diagnostics."""

    _saved_geometry: str = "620x580"   # class-level size memory

    def __init__(self, parent, target_label: str, host: str,
                 on_close_callback=None,
                 data_store=None,
                 target_id: Optional[str] = None):
        """
        on_close_callback: optional zero-arg callable invoked when this window
        is closed (via WM_DELETE_WINDOW or destroy).  Lets the parent clean
        up its window-tracking dict without overriding our protocol handler
        — overriding it from outside was fragile because lambda-based
        overrides leak the dict entry if the window is destroyed by any
        path OTHER than the close button (parent quit, exception, etc.).

        data_store + target_id: optional persistence hook.  When provided,
        each completed diagnostic run is persisted via
        DataStore.record_diag_result(); the History button reads back via
        DataStore.get_diag_history().  Both can be None for ad-hoc/test
        instances — features just gracefully no-op.
        """
        super().__init__(parent)
        self._label    = target_label
        self._host     = host
        self._task: Optional[DiagTask] = None
        self._on_close_cb = on_close_callback
        self._data_store  = data_store
        self._target_id   = target_id

        self.title(f"ICMP 高级诊断 — {target_label}")
        self._restore_geometry()
        self.minsize(520, 480)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # Bring the window forward + actually populate the UI.  Pre-2025
        # these three lines lived here in __init__, but a previous
        # round mistakenly moved them inside update_host() (which only
        # exists to refresh the label/host of an ALREADY-built window);
        # the regression left every freshly-opened diag window as a
        # blank CTkToplevel shell with only the title bar -- no
        # parameter panel, no buttons, no result area, nothing.
        # update_host must NOT call _build_ui(): doing so on an already-
        # built window would layer a second set of widgets on top of
        # the first, leak the originals, and double-bind every
        # callback.
        self.lift()
        self.focus_force()
        self._build_ui()

    def update_host(self, target_label: str, host: str) -> None:
        """Refresh the target label / host this window probes.

        Called by main_window._open_icmp_diag when re-focusing an
        already-open diag window after the user edited the underlying
        node's IP -- without this, the window would keep using the IP
        it was constructed with, so the next "开始诊断" click would
        probe the OLD address while the main UI showed the NEW one.

        An in-flight task is intentionally left running: its
        IcmpDiagRequest was built from the previous _host at start
        time, so it continues probing the original target until done
        (avoids mid-run target switch).  The next start_*_diag click
        uses the updated _host.

        This method MUST NOT call _build_ui() or any lift/focus --
        the window is already constructed and visible; the caller
        (main_window._open_icmp_diag) handles raising the window
        right after.  Building twice would stack a second copy of
        every widget on top of the first.
        """
        self._label = target_label
        self._host  = host
        try:
            self.title(f"ICMP 高级诊断 — {target_label}")
        except Exception:
            pass
        # Header label was stashed as self._header_label in _build_ui
        # so we can refresh its text here without rebuilding the
        # whole panel.  Pre-2025 the label was anonymous; reading the
        # new identity from _host / _label was therefore invisible
        # in the UI until the next reopen.
        try:
            header = getattr(self, "_header_label", None)
            if header is not None:
                header.configure(text=f"🔬  {target_label}  ({host})")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray88","gray15"))
        hdr.grid(row=0, column=0, sticky="ew")
        # Stash header label so update_host() can refresh its text
        # when the underlying node's label / ip changes mid-session.
        self._header_label = ctk.CTkLabel(
            hdr, text=f"🔬  {self._label}  ({self._host})",
            font=F(13, "bold"), anchor="w")
        self._header_label.pack(side="left", padx=14, pady=8)

        # ── Parameter panel ───────────────────────────────────────────
        pnl = ctk.CTkFrame(self, fg_color=("gray93","gray18"), corner_radius=8)
        pnl.grid(row=1, column=0, sticky="ew", padx=12, pady=(10,4))
        pnl.grid_columnconfigure((1,3,5), weight=1)

        # Row 0: mode selector (single / stability / pmtu)
        # Stored as separate widget refs so _apply_mode() can show/hide
        # mode-specific rows below without rebuilding the whole panel.
        ctk.CTkLabel(pnl, text="诊断模式:", font=F(12)).grid(
            row=0, column=0, sticky="w", padx=(12,6), pady=(10,4))
        self._mode_var = ctk.StringVar(value="single")
        mode_frm = ctk.CTkFrame(pnl, fg_color="transparent")
        mode_frm.grid(row=0, column=1, columnspan=5, sticky="w",
                      padx=(0,12), pady=(10,4))
        for mode_key, mode_lbl in [("single",    "单次诊断"),
                                    ("stability", "稳定性测试"),
                                    ("pmtu",      "PMTU 探测")]:
            ctk.CTkRadioButton(mode_frm, text=mode_lbl, font=F(11),
                               variable=self._mode_var, value=mode_key,
                               command=self._apply_mode
                               ).pack(side="left", padx=(0, 14))

        # Row 1: payload size + presets — HIDDEN in PMTU mode (auto-searched)
        self._row_payload_label = ctk.CTkLabel(pnl, text="载荷大小 (B):", font=F(12))
        self._row_payload_label.grid(row=1, column=0, sticky="w", padx=(12,6), pady=4)
        self._payload_var = ctk.StringVar(value="32")
        self._row_payload_entry = ctk.CTkEntry(pnl, textvariable=self._payload_var,
                                                width=72, height=28, font=F(12),
                                                justify="center")
        self._row_payload_entry.grid(row=1, column=1, sticky="w", padx=(0,8), pady=4)
        self._row_preset_frm = ctk.CTkFrame(pnl, fg_color="transparent")
        self._row_preset_frm.grid(row=1, column=2, columnspan=4, sticky="w",
                                   padx=(0,12), pady=4)
        for size in _PAYLOAD_PRESETS:
            ctk.CTkButton(self._row_preset_frm, text=str(size),
                          width=44, height=24, font=F(10),
                          text_color=("gray15", "gray90"),
                          fg_color=("gray78","gray30"),
                          hover_color=("gray65","gray40"),
                          command=lambda s=size: self._payload_var.set(str(s))
                          ).pack(side="left", padx=2)

        # Row 2: DF + count + timeout + interval
        # DF + count hidden in PMTU mode (DF is forced on, count = log2(1472))
        # Interval visible only in stability mode.
        self._row_df_label = ctk.CTkLabel(pnl, text="禁止分片 DF:", font=F(12))
        self._row_df_label.grid(row=2, column=0, sticky="w", padx=(12,6), pady=4)
        self._df_var = ctk.BooleanVar(value=False)
        self._row_df_switch = ctk.CTkSwitch(pnl, text="开启", variable=self._df_var,
                                             font=F(11), width=60)
        self._row_df_switch.grid(row=2, column=1, sticky="w", pady=4)

        self._row_count_label = ctk.CTkLabel(pnl, text="探测次数:", font=F(12))
        self._row_count_label.grid(row=2, column=2, sticky="w", padx=(16,6), pady=4)
        self._count_var = ctk.StringVar(value="4")
        self._row_count_entry = ctk.CTkEntry(pnl, textvariable=self._count_var,
                                              width=56, height=28, font=F(12),
                                              justify="center")
        self._row_count_entry.grid(row=2, column=3, sticky="w", padx=(0,8), pady=4)

        self._row_timeout_label = ctk.CTkLabel(pnl, text="超时 (s):", font=F(12))
        self._row_timeout_label.grid(row=2, column=4, sticky="w", padx=(16,6), pady=4)
        self._timeout_var = ctk.StringVar(value="2")
        self._row_timeout_entry = ctk.CTkEntry(pnl, textvariable=self._timeout_var,
                                                width=56, height=28, font=F(12),
                                                justify="center")
        self._row_timeout_entry.grid(row=2, column=5, sticky="w", padx=(0,12), pady=4)

        # Row 3: interval — stability mode only
        self._row_interval_label = ctk.CTkLabel(pnl, text="探测间隔 (s):", font=F(12))
        self._interval_var = ctk.StringVar(value="1")
        self._row_interval_entry = ctk.CTkEntry(pnl, textvariable=self._interval_var,
                                                  width=56, height=28, font=F(12),
                                                  justify="center")
        # Initial layout via _apply_mode() — single mode hides interval row.

        # Row 4: mode-specific hint text
        self._mode_hint_lbl = ctk.CTkLabel(pnl, text="", font=F(10),
                                            text_color="gray50", anchor="w",
                                            wraplength=560, justify="left")
        self._mode_hint_lbl.grid(row=4, column=0, columnspan=6, sticky="w",
                                  padx=12, pady=(2,10))

        # Apply initial mode (also sets hint + row visibility)
        self._apply_mode()

        # ── Action buttons ────────────────────────────────────────────
        btn_frm = ctk.CTkFrame(self, fg_color="transparent")
        btn_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=(2,4))
        self._start_btn = ctk.CTkButton(
            btn_frm, text="▶ 开始诊断", width=110, height=32, font=F(12),
            command=self._start)
        self._start_btn.pack(side="left", padx=(0,8))
        self._stop_btn = ctk.CTkButton(
            btn_frm, text="■ 停止", width=80, height=32, font=F(12),
            text_color=("gray15", "gray90"),
            fg_color=("gray65","gray35"), hover_color=("gray50","gray45"),
            state="disabled", command=self._stop)
        self._stop_btn.pack(side="left")
        # History button — only meaningful when a data_store is wired in.
        # When None (test/standalone use), the button is hidden rather than
        # disabled so the user isn't confused by an inert control.
        if self._data_store is not None:
            self._history_btn = ctk.CTkButton(
                btn_frm, text="📜 历史", width=90, height=32, font=F(12),
                text_color=("gray15", "gray90"),
                fg_color=("gray70","gray30"), hover_color=("gray55","gray40"),
                command=self._open_history)
            self._history_btn.pack(side="left", padx=(8, 0))
        self._status_lbl = ctk.CTkLabel(
            btn_frm, text="", font=F(11), text_color="gray50")
        self._status_lbl.pack(side="left", padx=16)

        # ── Results area ──────────────────────────────────────────────────
        results = ctk.CTkFrame(self, fg_color=self.cget("fg_color"))
        results.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0,8))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(0, weight=2)
        results.grid_rowconfigure(1, weight=1)

        # Per-probe log — CTkTextbox handles:
        #   1. CTk-styled scrollbar (no ugly native scrollbar)
        #   2. Theme-aware colors (auto-follows dark/light switch)
        #   3. Larger font (Consolas 12 instead of 10)
        self._log = ctk.CTkTextbox(
            results,
            font=F(12),
            wrap="none",
            state="disabled")
        self._log.grid(row=0, column=0, sticky="nsew")

        # Conclusion box
        self._conclusion = ctk.CTkTextbox(results, height=90, font=F(12),
                                           wrap="word", state="disabled",
                                           fg_color=("gray88","gray20"))
        self._conclusion.grid(row=1, column=0,
                               sticky="nsew", pady=(6,0))

    # ------------------------------------------------------------------
    # Mode-aware parameter panel layout
    # ------------------------------------------------------------------

    # Each entry: (widgets to show in this mode, hint text)
    _MODE_CONFIG = {
        "single":    {"hint": "单次诊断：用指定包长和 DF 设置探测一次，"
                              "用于快速验证当前路径的连通性与延迟。",
                      "default_count": "4"},
        "stability": {"hint": "稳定性测试：以受控频率连续发送指定包长，"
                              "观察成功率与延迟波动（默认 10 次，可调至 50）。",
                      "default_count": "10"},
        "pmtu":      {"hint": "PMTU 探测：自动二分查找 DF=on 下最大可通过的 "
                              "ICMP 载荷（0–1472 字节），约需 11 次探测。"
                              "可估算路径 MTU。",
                      "default_count": ""},
    }

    def _apply_mode(self):
        """Show/hide parameter rows based on current mode selection.

        Uses grid_remove() (preserves grid settings, just hides) and grid()
        (re-displays).  This is more robust than destroy+recreate because
        widget refs stay valid and state (text content, switch position)
        is preserved across mode switches.
        """
        mode = self._mode_var.get()
        cfg  = self._MODE_CONFIG.get(mode, self._MODE_CONFIG["single"])

        is_pmtu      = mode == "pmtu"
        is_stability = mode == "stability"

        # Payload row: hidden in PMTU mode (auto-searched)
        for w in (self._row_payload_label, self._row_payload_entry,
                  self._row_preset_frm):
            (w.grid_remove if is_pmtu else w.grid)()

        # DF row: hidden in PMTU mode (DF forced on internally)
        for w in (self._row_df_label, self._row_df_switch):
            (w.grid_remove if is_pmtu else w.grid)()

        # Count row: hidden in PMTU mode
        for w in (self._row_count_label, self._row_count_entry):
            (w.grid_remove if is_pmtu else w.grid)()

        # Interval row: visible only in stability mode
        if is_stability:
            self._row_interval_label.grid(row=3, column=0, sticky="w",
                                           padx=(12,6), pady=4)
            self._row_interval_entry.grid(row=3, column=1, sticky="w",
                                           pady=4)
        else:
            self._row_interval_label.grid_remove()
            self._row_interval_entry.grid_remove()

        # Update default count when switching to stability
        if cfg["default_count"] and not is_pmtu:
            cur = self._count_var.get().strip()
            if cur in ("", "4", "10"):     # only overwrite untouched values
                self._count_var.set(cfg["default_count"])

        self._mode_hint_lbl.configure(text=cfg["hint"])

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _start(self):
        mode = self._mode_var.get()
        try:
            timeout = float(self._timeout_var.get())
        except ValueError:
            self._set_status("超时格式不正确", error=True)
            return

        self._clear_results()
        self._set_buttons(running=True)

        # ── PMTU branch: separate engine entry point, no payload/df/count
        if mode == "pmtu":
            self._set_status(f"PMTU 二分探测 {self._host} …")
            self._task = run_pmtu_async(
                host        = self._host,
                timeout_s   = timeout,
                on_progress = self._on_pmtu_progress,
                on_done     = self._on_done,
                on_error    = self._on_error,
                data_store  = self._data_store,
                target_id   = self._target_id,
            )
            return

        # ── Single + stability branch
        try:
            payload = int(self._payload_var.get())
            count   = int(self._count_var.get())
        except ValueError:
            self._set_status("参数格式不正确", error=True)
            self._set_buttons(running=False)
            return

        interval = 1.0
        if mode == "stability":
            try:
                interval = float(self._interval_var.get())
            except ValueError:
                self._set_status("间隔格式不正确", error=True)
                self._set_buttons(running=False)
                return

        req = IcmpDiagRequest(
            host         = self._host,
            mode         = mode,
            payload_size = payload,
            df           = self._df_var.get(),
            count        = count,
            timeout_s    = timeout,
            interval_s   = interval,
            # Raise the per-task wall ceiling for stability mode so a
            # legitimate count=50 / interval=2s run isn't clipped by the
            # default 30 s; cap at 5 min to keep accidental hangs bounded.
            max_runtime_s = min(300.0, count * (timeout + interval) + 10.0),
        )

        from src.icmp_diag import validate_request
        err = validate_request(req)
        if err:
            self._set_status(err, error=True)
            self._set_buttons(running=False)
            return

        self._set_status(f"正在探测 {self._host} …")
        self._task = run_icmp_diag_async(
            req,
            on_progress = self._on_progress,
            on_done     = self._on_done,
            on_error    = self._on_error,
            data_store  = self._data_store,
            target_id   = self._target_id,
        )

    def _stop(self):
        if self._task:
            self._task.cancel()
        self._set_status("已停止", error=False)
        self._set_buttons(running=False)

    # ------------------------------------------------------------------
    # Callbacks (must re-enter via after() — called from background thread)
    # ------------------------------------------------------------------

    def _on_progress(self, sample: IcmpProbeSample, done: int, total: int):
        try:
            self.after(0, lambda s=sample, d=done, t=total:
                       self._append_sample(s, d, t))
        except Exception:
            pass

    def _on_pmtu_progress(self, payload: int, success: bool, error_code: str):
        """PMTU has a different progress signature: (payload, success, code)
        instead of (sample, done, total) since iteration count isn't known
        in advance (binary search ends when low > high)."""
        try:
            self.after(0, lambda p=payload, s=success, ec=error_code:
                       self._append_pmtu_step(p, s, ec))
        except Exception:
            pass

    def _append_pmtu_step(self, payload: int, success: bool, error_code: str):
        if success:
            line = f"  测试 payload={payload:>4} B  ✓  通过\n"
        else:
            label = _ERROR_LABELS.get(error_code, error_code)
            line = f"  测试 payload={payload:>4} B  ✗  {label}\n"
        self._log.configure(state="normal")
        self._log.insert("end", line)
        try: self._log._textbox.see("end")
        except Exception: pass
        self._log.configure(state="disabled")
        self._set_status(f"二分搜索中… 当前 {payload} B")

    def _on_done(self, result: IcmpDiagResult):
        try:
            self.after(0, lambda r=result: self._show_result(r))
        except Exception:
            pass

    def _on_error(self, msg: str):
        try:
            self.after(0, lambda m=msg: (
                self._set_status(m, error=True),
                self._set_buttons(running=False)
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Result rendering
    # ------------------------------------------------------------------

    def _clear_results(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._conclusion.configure(state="normal")
        self._conclusion.delete("1.0", "end")
        self._conclusion.configure(state="disabled")

    def _append_sample(self, sample: IcmpProbeSample, done: int, total: int):
        label = _ERROR_LABELS.get(sample.error_code, sample.error_code)
        if sample.success:
            line = f"  探测 {sample.seq:>2}/{total}  ✓  {sample.rtt_ms:.1f} ms\n"
        else:
            line = f"  探测 {sample.seq:>2}/{total}  ✗  {label}\n"
        self._log.configure(state="normal")
        self._log.insert("end", line)
        try:
            self._log._textbox.see("end")   # scroll to bottom
        except Exception:
            pass
        self._log.configure(state="disabled")
        self._set_status(f"进行中 {done}/{total}…")

    def _show_result(self, result: IcmpDiagResult):
        self._set_buttons(running=False)

        # ── Build mode-specific summary line ─────────────────────────
        if result.mode == "pmtu":
            # PMTU summary: max payload + estimated MTU + iteration count
            if result.max_df_payload is not None:
                summary = (f"\n  ── PMTU 结果 ──  最大成功载荷 "
                           f"{result.max_df_payload} B"
                           f"  估算路径 MTU ≈ "
                           f"{result.estimated_path_mtu} B"
                           f"  共探测 {result.count} 次\n")
            else:
                summary = (f"\n  ── PMTU 结果 ──  未能成功通过任何包长，"
                           f"共探测 {result.count} 次\n")
        else:
            # Single / stability summary
            loss_pct = int(result.loss_count / result.count * 100) if result.count else 0
            summary = (f"\n  ── 汇总 ──  成功 {result.success_count}/{result.count}"
                       f"  丢包 {loss_pct}%")
            if result.avg_rtt_ms is not None:
                summary += (f"  均值 {result.avg_rtt_ms} ms"
                            f"  最小 {result.min_rtt_ms} ms"
                            f"  最大 {result.max_rtt_ms} ms")
            summary += "\n"

        self._log.configure(state="normal")
        self._log.insert("end", summary)
        try:
            self._log._textbox.see("end")
        except Exception:
            pass
        self._log.configure(state="disabled")

        # Conclusion box
        self._conclusion.configure(state="normal")
        self._conclusion.delete("1.0", "end")
        self._conclusion.insert("1.0", result.conclusion)
        self._conclusion.configure(state="disabled")

        self._set_status("诊断完成")

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

    # ------------------------------------------------------------------
    # Scrollbar autohide (history list — mirrors DnsDiagWindow)
    # ------------------------------------------------------------------

    def _hide_scrollbar_now(self, scroll) -> None:
        try:
            bar = getattr(scroll, "_scrollbar", None)
            if bar is not None:
                bar.grid_remove()
        except Exception:
            pass

    def _autohide_scrollbar(self, scroll, _retries: int = 3):
        try:
            scroll.update_idletasks()
            canvas = getattr(scroll, "_parent_canvas", None)
            bar = getattr(scroll, "_scrollbar", None)
            if canvas is None or bar is None:
                return
            canvas.update_idletasks()
            bbox = canvas.bbox("all")
            visible_h = canvas.winfo_height()
            if visible_h > 1:
                content_h = (bbox[3] - bbox[1]) if bbox else 0
                want_visible = content_h > visible_h + 2   # +2: sub-pixel slack
                # Idempotent toggle: only touch geometry on a REAL state
                # change.  grid()/grid_remove() always re-lays-out the
                # listbox and fires a <Configure>, which re-runs this sync;
                # doing it unconditionally (even when the bar is already in
                # the right state) is what made the scrollbar flicker once
                # the list overflowed -- a self-sustaining show->hide->show
                # loop.  grid_info() reflects the real shown/removed state,
                # so acting only on a change breaks the loop while the retry
                # chain below still converges on the correct final state.
                is_shown = bool(bar.grid_info())
                if want_visible and not is_shown:
                    bar.grid()
                elif not want_visible and is_shown:
                    bar.grid_remove()
            if _retries > 0:
                delay_ms = (50, 120, 280)[3 - _retries]
                self.after(
                    delay_ms,
                    lambda: self._autohide_scrollbar(scroll, _retries - 1))
        except Exception:
            pass

    def _sync_history_list_scrollbar(self, listbox, win):
        # Don't force-hide first.  The old grid_remove()-then-re-measure
        # blinked the bar away on every <Configure> even when it should
        # stay shown; the now-idempotent _autohide_scrollbar settles it to
        # the correct state directly, without the flicker.
        win.after_idle(lambda: self._autohide_scrollbar(listbox))

    def _bind_history_scrollbar_sync(self, win, listbox):
        job = [None]

        def _on_configure(_event=None):
            if job[0] is not None:
                try:
                    win.after_cancel(job[0])
                except Exception:
                    pass
            job[0] = win.after(
                150, lambda: self._sync_history_list_scrollbar(listbox, win))

        win.bind("<Configure>", _on_configure, add="+")

    # ------------------------------------------------------------------
    # History list (Phase 3)
    # ------------------------------------------------------------------

    def _open_history(self):
        """Open (or focus) the diagnostic-history list window for this target.

        Filters by target_id when available, otherwise by host string —
        ad-hoc diagnoses without a target_id still surface for the same
        host so users can compare results across instances.
        """
        # Singleton-per-parent — clicking 📜 while it's open should focus,
        # not stack windows.  Hover state survives subsequent clicks.
        existing = getattr(self, "_history_win", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift(); existing.focus_force(); return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        win.title(f"诊断历史 — {self._label}")
        win.geometry("760x440")
        win.minsize(620, 320)
        win.lift(); win.focus_force()
        self._history_win = win

        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        # Header — close button forwards to _refresh_history; clicking a
        # row populates the parent window's result panel via _replay_history_row
        hdr = ctk.CTkFrame(win, fg_color=("gray88","gray15"), corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text=f"📜 历史诊断记录  ({self._label})",
                     font=F(12, "bold")).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(hdr, text="🔄 刷新", width=70, height=26, font=F(11),
                      fg_color=("gray70","gray30"),
                      hover_color=("gray55","gray40"),
                      command=lambda: self._refresh_history_list(listbox, win)
                      ).pack(side="right", padx=8, pady=6)

        # Scrollable list — CTkScrollableFrame with one row per record.
        # Each row is a clickable frame, NOT a Treeview, because CTk has no
        # native Treeview and Tk's ttk.Treeview clashes with CTk theme.
        listbox = ctk.CTkScrollableFrame(win, fg_color=("gray95","gray16"))
        listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(8, 10))
        listbox.grid_columnconfigure(0, weight=1)
        self._hide_scrollbar_now(listbox)
        self._bind_history_scrollbar_sync(win, listbox)

        self._refresh_history_list(listbox, win)

        # Close cleanup
        def _on_close():
            self._history_win = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _refresh_history_list(self, listbox, win):
        """Re-query DB and re-render the row list.  Used on initial open
        and after explicit user refresh."""
        try:
            for child in listbox.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass

            if self._data_store is None:
                ctk.CTkLabel(listbox, text="DataStore 未初始化，无法读取历史",
                             font=F(11), text_color="gray50").grid(
                    row=0, column=0, pady=20)
                return

            try:
                rows = self._data_store.get_diag_history(
                    target_id=self._target_id, limit=100)
            except Exception as e:
                ctk.CTkLabel(listbox, text=f"读取失败：{e}",
                             font=F(11), text_color="#ef4444").grid(
                    row=0, column=0, pady=20)
                return

            if not rows:
                ctk.CTkLabel(
                    listbox,
                    text="暂无历史记录。完成一次诊断后将在此列出。",
                    font=F(11), text_color="gray50").grid(
                    row=0, column=0, pady=20)
                return

            import datetime
            _MODE_TEXT = {"single": "单次", "stability": "稳定性", "pmtu": "PMTU"}

            for i, rec in enumerate(rows):
                ts_str = datetime.datetime.fromtimestamp(
                    rec["created_ts"]).strftime("%Y-%m-%d %H:%M:%S")
                mode_txt = _MODE_TEXT.get(rec["mode"], rec["mode"])
                if rec["mode"] == "pmtu":
                    if rec.get("max_df_payload") is not None:
                        summary = (f"PMTU: 最大 {rec['max_df_payload']} B  "
                                   f"≈ {rec.get('estimated_path_mtu','?')} B MTU")
                    else:
                        summary = "PMTU: 未能通过"
                else:
                    loss = rec["loss_count"]
                    ok   = rec["success_count"]
                    df   = " DF" if rec["df"] else ""
                    avg  = (f"  avg {rec['avg_rtt_ms']} ms"
                            if rec["avg_rtt_ms"] is not None else "")
                    summary = (f"{mode_txt}{df}  payload={rec['payload_size']}B  "
                               f"{ok}/{ok+loss}{avg}")

                n_total = rec["success_count"] + rec["loss_count"]
                if n_total > 0 and rec["loss_count"] == 0:
                    fg = ("gray90", "gray22")
                elif rec["loss_count"] >= n_total and n_total > 0:
                    fg = ("#fecaca", "#451a1a")
                else:
                    fg = ("#fef3c7", "#3d3017")

                row = ctk.CTkFrame(listbox, fg_color=fg, corner_radius=6)
                row.grid(row=i, column=0, sticky="ew", padx=6, pady=3)
                row.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(row, text=ts_str, font=F(10),
                             text_color="gray50", anchor="w").grid(
                    row=0, column=0, sticky="w", padx=10, pady=(6, 0))
                ctk.CTkLabel(row, text=summary, font=F(11, "bold"),
                             anchor="w").grid(
                    row=1, column=0, sticky="w", padx=10, pady=(0, 2))
                ctk.CTkLabel(row, text=rec["conclusion"][:140],
                             font=F(10), text_color=("gray30", "gray70"),
                             anchor="w", wraplength=620, justify="left").grid(
                    row=2, column=0, sticky="w", padx=10, pady=(0, 6))

                def _bind(widget, r=rec):
                    widget.bind(
                        "<Button-1>",
                        lambda _e, rec=r: self._replay_history(rec))
                    widget.configure(cursor="hand2")
                _bind(row)
                for child in row.winfo_children():
                    _bind(child)
        finally:
            self._sync_history_list_scrollbar(listbox, win)

    def _replay_history(self, rec: dict):
        """Show a historical record's summary + conclusion back in the
        parent window's result panel.  Does NOT re-run the probe — this is
        a read-only recall."""
        # Build a synthetic pseudo-result reusing _show_result rendering.
        # We avoid re-running because the user might've clicked an hour-old
        # record and the link state has changed in between.
        from src.icmp_diag import IcmpDiagResult, IcmpProbeSample
        pseudo = IcmpDiagResult(
            host          = rec["host"],
            payload_size  = rec["payload_size"],
            df            = rec["df"],
            mode          = rec["mode"],
            count         = rec["count"],
            success_count = rec["success_count"],
            loss_count    = rec["loss_count"],
            avg_rtt_ms    = rec["avg_rtt_ms"],
            min_rtt_ms    = rec["min_rtt_ms"],
            max_rtt_ms    = rec["max_rtt_ms"],
            error_summary = rec["error_summary"],
            conclusion    = rec["conclusion"],
            samples       = [],
            max_df_payload     = rec.get("max_df_payload"),
            estimated_path_mtu = rec.get("estimated_path_mtu"),
        )
        # Replay per-probe samples from compact details_json if available.
        details = rec.get("details") or {}
        for s in (details.get("samples") or []):
            pseudo.samples.append(IcmpProbeSample(
                seq         = s.get("seq", 0),
                success     = bool(s.get("ok")),
                rtt_ms      = s.get("rtt"),
                error_code  = s.get("err", "")))

        # Clear log + replay sample lines for visual continuity
        self._clear_results()
        for s in pseudo.samples:
            self._append_sample(s, s.seq, pseudo.count)

        self._show_result(pseudo)
        import datetime
        ts_str = datetime.datetime.fromtimestamp(rec["created_ts"]).strftime("%H:%M:%S")
        self._set_status(f"已回放 {ts_str} 的历史记录")

    def _restore_geometry(self):
        try:
            self.geometry(IcmpDiagWindow._saved_geometry)
            self.update_idletasks()
            wx, wy = self.winfo_x(), self.winfo_y()
            ww, wh = self.winfo_width(), self.winfo_height()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            cx = max(-ww+100, min(wx, sw-100))
            cy = max(0,       min(wy, sh-50))
            if cx != wx or cy != wy:
                self.geometry(f"{ww}x{wh}+{cx}+{cy}")
        except Exception:
            self.geometry("620x580")

    def _on_close(self):
        try:
            geo = self.geometry()
            if geo and "x" in geo:
                IcmpDiagWindow._saved_geometry = geo
        except Exception:
            pass
        if self._task:
            self._task.cancel()
        # Close child history window if open — otherwise it becomes
        # orphaned and clicking its rows would call back into a destroyed
        # parent (Tcl error from _replay_history).
        hist = getattr(self, "_history_win", None)
        if hist is not None:
            try: hist.destroy()
            except Exception: pass
            self._history_win = None
        # Notify parent BEFORE destroy so the parent can remove dict entry
        # while self is still a live widget (just in case the callback
        # touches it).  Wrap in try/except so a misbehaving callback can't
        # block window destruction.
        if self._on_close_cb:
            try: self._on_close_cb()
            except Exception: pass
        self.destroy()
