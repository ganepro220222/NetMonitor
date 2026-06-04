from __future__ import annotations
import webbrowser
import customtkinter as ctk
from tkinter import messagebox

from src.config_manager import ConfigManager
from src.ping_engine import PingEngine, TargetState, HTTPMonitor
from src.alert_manager import AlertManager
from src.logger import Logger
from src.history_store import HistoryStore
from src.web_server import WebServer, FLASK_AVAILABLE
from src.capacity import (
    MAX_TARGETS, WARN_TARGETS,
    RECOMMENDED_LARGE_TARGET_INTERVAL_S, target_limit_state)
from src.ui.ip_card import IPCard
from src.ui.waveform_window import WaveformDetailWindow
from src.ui.icmp_diag_window import IcmpDiagWindow
from src.ui.dns_diag_window import DnsDiagWindow
from src.ui.dialogs import AddTargetDialog, EditTargetDialog
from src.ui.history_panel import HistoryPanel
from src.ui.settings_dialog import SettingsDialog
from src.ui.fonts import make as F

# Capacity policy (MAX_TARGETS / WARN_TARGETS /
# RECOMMENDED_LARGE_TARGET_INTERVAL_S / target_limit_state) lives in
# src/capacity.py — a UI-free module so the limits and the add-flow
# decision logic can be unit-tested without importing customtkinter.
# Imported above; do NOT redefine the numbers here.

_HEADER_H    = 56
_TOOLBAR_H   = 94    # toolbar(38+8) + search(34+5) + divider(1+6) + extra
_HIST_HDR_H  = 38
_STATUSBAR_H = 28
_PADDING_H   = 20    # scroll frame padding
_CARD_H_1COL = 70
_CARD_H_2COL = 74
_AUTO_2COL_W  = 920   # auto-switch threshold: wider than this → 2 cols
                       # MUST be strictly greater than _2COL_MIN_W below.
                       # Once we enter 2-col mode we call minsize(_2COL_MIN_W),
                       # which prevents the user from dragging the window
                       # below that pixel width.  If the auto-switch
                       # threshold were < _2COL_MIN_W (the previous 820
                       # vs 900 pairing), the drag-back path was a
                       # mathematical dead end: minsize forbids width <
                       # 900, but reverting to 1-col required width <
                       # 820 — the window would be permanently stuck in
                       # 2-col mode until the user restarted the app.
_1COL_W       = 680   # golden width for single-column mode
_2COL_W       = 1100  # golden width for double-column mode
_2COL_MIN_W   = 900   # hard drag-limit for 2-col (user cannot shrink below this)
_GOLDEN_MAX_H = 800   # height cap when snapping to golden geometry


def _install_tk_callback_guard(root) -> None:
    """Ignore benign TclErrors after sleep/wake or stale widget callbacks."""
    import sys
    import tkinter as tk

    def _handler(exc, val, tb):
        if isinstance(val, tk.TclError):
            msg = str(val).lower()
            if ("out of stack" in msg
                    or "invalid command name" in msg
                    or "doesn't exist" in msg):
                return
        sys.excepthook(exc, val, tb)

    root.report_callback_exception = _handler


class MainWindow(ctk.CTk):

    def __init__(self, config_manager, ping_engine, alert_manager,
                 logger, web_server, data_store=None):
        super().__init__()
        _install_tk_callback_guard(self)
        self.config     = config_manager
        self.engine     = ping_engine
        self.alerter    = alert_manager
        self.logger     = logger
        self.history    = HistoryStore()
        self.web_server     = web_server
        # Store via object.__setattr__ to bypass tkinter __setattr__ proxy
        object.__setattr__(self, "data_store",    data_store)
        object.__setattr__(self, "_last_statuses", {})
        object.__setattr__(self, "_tray_icon",    None)
        object.__setattr__(self, "_quitting",     False)

        self.title("网络连通性监测")
        self.minsize(540, 480)   # 最小可用：单列 2 张卡

        theme = self.config.get_setting("theme") or "dark"
        ctk.set_appearance_mode(theme)
        ctk.set_default_color_theme("blue")

        self._cards: dict[str, IPCard] = {}
        self._waveform_windows:   dict[str, WaveformDetailWindow] = {}
        self._icmp_diag_windows:  dict[str, IcmpDiagWindow]       = {}
        self._dns_diag_windows:   dict[str, DnsDiagWindow]        = {}
        self._current_statuses: dict[str, str] = {}
        self._status_counts = {"green": 0, "orange": 0, "red": 0, "gray": 0}
        self._target_labels:      dict[str, str] = {}
        self._target_ips:         dict[str, str] = {}
        self._target_probe_ports: dict[str, str] = {}
        self._target_dns_domain:  dict[str, str] = {}
        # ping_type cache — populated from config at add/edit time and read
        # from the ping thread (in _on_state_update) so we don't rescan
        # config.get_targets() — an O(N) linear search — on every probe.
        # With 50 nodes pinging once per second that scan happens 50 times
        # per second on the ping thread and twice again on the UI thread
        # in _apply_state_update.  Cache lookup is O(1).
        self._target_ping_types:  dict[str, str] = {}

        _saved_cols  = self.config.get_setting("default_columns")
        _n_targets   = len(self.config.get_targets())
        # Column count on startup:
        # If user has explicitly saved a preference, always respect it —
        # even when there are 0 or 1 nodes (the old _n_targets<2 override
        # caused saved single-column preference to be silently ignored).
        # Only fall back to the "< 2 nodes → single column" default when
        # no preference has ever been saved.
        if _saved_cols is not None:
            default_cols = _saved_cols
        elif _n_targets < 2:
            default_cols = 1
        else:
            default_cols = 1   # default to single column on first run
        self._columns  = default_cols
        self._auto_col        = True
        # Lock out auto-switch whenever there is an explicit saved preference,
        # regardless of current node count.
        self._user_forced_cols = (_saved_cols is not None)
        self._resize_job = None
        self._search_query = ""
        self._calculated_geometry = None   # saved for restore after maximize
        self._prev_win_state = "normal"    # track zoomed/normal transitions
        self._save_geo_job   = None        # debounce job for user-drag size save
        self._auto_resize_job = None        # debounce token for _auto_resize calls
        self._skip_geo_event  = False       # True while code calls geometry() itself

        self._build_ui()
        self._set_initial_geometry()         # 1100×700 centered on screen
        self._load_cards()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(300, self._auto_resize)   # fine-tune height after cards load
        self.after(500, self._start_engine)
        self.bind("<Configure>", self._on_window_configure)
        # Click-outside-to-blur: see _on_global_click for the rationale.
        # bind_all sees clicks on every descendant widget, including those
        # inside dialogs that share the same Tk instance.
        self.bind_all("<Button-1>", self._on_global_click, add="+")

        if self.config.get_setting("web_autostart"):
            self.after(800, self._auto_start_web)

    # ------------------------------------------------------------------
    # Window geometry helpers
    # ------------------------------------------------------------------

    def _set_initial_geometry(self):
        """
        Restore the window to exactly where the user left it (geometry saved
        in config on every close).  Falls back to the golden-ratio default
        if no saved geometry exists or it falls outside the current screen.
        """
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()

        saved = self.config.get_setting("window_geometry")  # e.g. "680x520+200+100"
        if saved:
            # Parse and clamp to current screen so multi-monitor moves don't
            # leave the window stranded off-screen.
            try:
                import re as _re
                parts = _re.fullmatch(
                    r'(\d+)x(\d+)(?:\+(-?\d+)\+(-?\d+))?', saved)
                if parts:
                    W, H = int(parts.group(1)), int(parts.group(2))
                    rx   = int(parts.group(3) or 0)
                    ry   = int(parts.group(4) or 0)
                    W = max(540, min(W, sw - 40))
                    H = max(400, min(H, sh - 40))
                    # Keep window fully on screen
                    x = max(0, min(rx, sw - W))
                    y = max(0, min(ry, sh - H))
                    geo = f"{W}x{H}+{x}+{y}"
                    self._skip_geo_event = True
                    self.geometry(geo)
                    self.after(0, lambda: setattr(self, "_skip_geo_event", False))
                    self._calculated_geometry = f"{W}x{H}"
                    return
            except Exception:
                pass  # fall through to default

        # No valid saved geometry → use golden-ratio default
        W = _2COL_W if self._columns == 2 else _1COL_W
        H = 700
        W = min(W, sw - 40)
        H = min(H, sh - 40)
        x = max(0, (sw - W) // 2)
        y = max(0, (sh - H) // 2)
        geo = f"{W}x{H}+{x}+{y}"
        self._skip_geo_event = True
        self.geometry(geo)
        self.after(0, lambda: setattr(self, "_skip_geo_event", False))
        self._calculated_geometry = f"{W}x{H}"

    def _schedule_auto_resize(self, delay_ms: int = 120):
        """
        Debounced _auto_resize: cancel any pending call and reschedule.
        Replaces bare self.after(N, self._auto_resize) at all call sites
        so rapid successive triggers (card add/delete bursts) coalesce
        into a single execution after the last event + delay_ms.
        """
        if self._auto_resize_job is not None:
            self.after_cancel(self._auto_resize_job)
        self._auto_resize_job = self.after(delay_ms, self._auto_resize)

    def _apply_golden_geometry(self):
        """
        Snap the window to the golden W×H for the current column mode.
        Called by _toggle_columns (both directions).

        Width:  _1COL_W for 1-col, _2COL_W for 2-col — fixed per mode.
        Height: calculated from actual card count (same as _auto_resize),
                capped at _GOLDEN_MAX_H so no huge blank space.
        Both width and height jump simultaneously → clean state transition.
        """
        n      = len(self._cards)
        rows   = max(1, -(-n // self._columns))           # ceiling division
        card_h = _CARD_H_2COL if self._columns == 2 else _CARD_H_1COL
        needed = (_HEADER_H + _TOOLBAR_H + rows * card_h
                  + _HIST_HDR_H + _STATUSBAR_H + _PADDING_H)
        target_w = _2COL_W if self._columns == 2 else _1COL_W
        target_h = max(480, min(needed, _GOLDEN_MAX_H))

        # Clamp to physical screen
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        target_w = min(target_w, sw - 40)
        target_h = min(target_h, sh - 80)

        self._skip_geo_event = True
        self.geometry(f"{target_w}x{target_h}")
        self.after(0, lambda: setattr(self, "_skip_geo_event", False))
        self._calculated_geometry = f"{target_w}x{target_h}"

    def _update_minsize(self):
        """
        Dynamically set the window minsize based on the current column mode.
        - 1-column: 540 px wide (single card fits comfortably)
        - 2-column: _2COL_MIN_W px wide (prevents card overlap)
        Must be called every time _columns changes.
        """
        if self._columns == 2:
            self.minsize(_2COL_MIN_W, 480)
        else:
            self.minsize(540, 480)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, height=_HEADER_H, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🌐  网络连通性监测",
                     font=F(18, "bold")).pack(side="left", padx=20)

        self.theme_btn = ctk.CTkButton(
            header, text="☀ 浅色", width=78, height=30,
            fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"),
            font=F(12), command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=(4, 16))
        if self.config.get_setting("theme") == "light":
            self.theme_btn.configure(text="🌙 深色")

        # Web service control button — always shows service state,
        # never navigates; URL is in the status bar (C12).
        self.web_btn = ctk.CTkButton(
            header,
            text="🌐 启动 Web 服务" if FLASK_AVAILABLE else "🌐 Web (需安装 flask)",
            width=130, height=30,
            fg_color=("#5B7FA6","gray30") if FLASK_AVAILABLE else ("#888","gray20"),
            hover_color=("#4A6E94","gray40") if FLASK_AVAILABLE else ("gray50","gray20"),
            font=F(12), command=self._web_btn_action,
            state="normal" if FLASK_AVAILABLE else "disabled")
        self.web_btn.pack(side="right", padx=(0, 4))

        ctk.CTkButton(
            header, text="⚙", width=36, height=30,
            fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"),
            font=F(14), command=self._open_settings
        ).pack(side="right", padx=(0, 4))

        # Toolbar
        toolbar = ctk.CTkFrame(self, height=38, fg_color="transparent")
        toolbar.pack(fill="x", padx=16, pady=(8, 0))
        toolbar.pack_propagate(False)

        ctk.CTkButton(toolbar, text="＋ 添加", width=80, height=30,
                      font=F(12), command=self._on_add).pack(side="left")
        ctk.CTkButton(toolbar, text="🔔", width=36, height=30,
                      fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"),
                      font=F(13), command=self._on_test_sound).pack(side="left", padx=(5, 0))
        self._col_btn = ctk.CTkButton(
            toolbar,
            text="⊞ 双列" if self._columns == 1 else "⊟ 单列",
            width=72, height=30,
            fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"),
            font=F(12), command=self._toggle_columns)
        self._col_btn.pack(side="left", padx=(5, 0))

        sf = ctk.CTkFrame(toolbar, fg_color="transparent")
        sf.pack(side="right")
        self.lbl_total  = ctk.CTkLabel(sf, text="共 0 个  ",  font=F(11), text_color="gray60")
        self.lbl_green  = ctk.CTkLabel(sf, text="●正常 0  ", font=F(11), text_color="#2ECC71")
        self.lbl_orange = ctk.CTkLabel(sf, text="●警告 0  ", font=F(11), text_color="#F39C12")
        self.lbl_red    = ctk.CTkLabel(sf, text="●告警 0",   font=F(11), text_color="#E74C3C")
        for lbl in (self.lbl_total, self.lbl_green, self.lbl_orange, self.lbl_red):
            lbl.pack(side="left")

        # Search bar (C6) — placed between toolbar and card grid
        search_row = ctk.CTkFrame(self, height=34, fg_color="transparent")
        search_row.pack(fill="x", padx=16, pady=(5, 0))
        search_row.pack_propagate(False)

        ctk.CTkLabel(search_row, text="🔍", font=F(14), width=24).pack(side="left")
        self._search_entry = ctk.CTkEntry(
            search_row, placeholder_text="搜索节点（名称 / IP / 域名）...",
            height=30, font=F(12))
        self._search_entry.pack(side="left", fill="x", expand=True, padx=(4, 0))
        self._search_entry.bind("<KeyRelease>", self._on_search_changed)

        ctk.CTkFrame(self, height=1, fg_color=("gray80","gray25")).pack(fill="x", padx=16, pady=(5, 0))

        # ── Bottom-anchored widgets packed BEFORE expand=True scroll area ──
        # Tkinter pack rule: side="bottom" widgets must be packed before any
        # expand=True widget, otherwise the expand widget claims all remaining
        # space first and the bottom widgets have no stable anchor.
        # If packed last (old order), hist_panel expanding pushes statusbar
        # off the bottom of the visible window.

        # Status bar (absolute bottom)
        statusbar = ctk.CTkFrame(self, height=_STATUSBAR_H, corner_radius=0, fg_color=("gray88", "gray15"))
        statusbar.pack(fill="x", side="bottom")
        statusbar.pack_propagate(False)
        self.status_label = ctk.CTkLabel(
            statusbar, text="正在启动...", font=F(11), text_color="gray50")
        self.status_label.pack(side="left", padx=12)
        self.web_url_label = ctk.CTkLabel(
            statusbar, text="", font=F(11), text_color="#4dd0e1",
            cursor="hand2")
        self.web_url_label.pack(side="right", padx=12)
        self.web_url_label.bind("<Button-1>", self._on_url_click)

        # Alert history panel (just above statusbar)
        self.hist_panel = HistoryPanel(self)
        self.hist_panel.pack(fill="x", padx=16, pady=(0, 4), side="bottom")

        # Card scroll area (fills remaining space; shrinks when hist_panel expands)
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color=self.cget("fg_color"))
        self.scroll_frame.pack(fill="both", expand=True, padx=16, pady=(8, 4))

        # Conditional scrollbar visibility.
        try:
            canvas = self.scroll_frame._parent_canvas
            self.scroll_frame.bind("<Configure>", self._sync_scrollbar_visibility, add="+")
            canvas.bind("<Configure>",            self._sync_scrollbar_visibility, add="+")
            try:
                self.scroll_frame._scrollbar.grid_remove()
            except Exception:
                pass
            self.after_idle(self._sync_scrollbar_visibility)
        except AttributeError:
            pass

        self.empty_label = ctk.CTkLabel(
            self.scroll_frame,
            text="还没有监测目标\n点击上方「＋ 添加」开始",
            font=F(13), text_color="gray50", justify="center")

    # ------------------------------------------------------------------
    # Search (C6)
    # ------------------------------------------------------------------

    def _sync_scrollbar_visibility(self, event=None):
        """
        Show the scrollbar only when content actually overflows the canvas.

        Root-cause history and why the previous two attempts failed:
        ─────────────────────────────────────────────────────────────
        Attempt 1 (winfo_reqheight):  lagged behind during multi-step layout
          passes, so it sometimes missed the "content grew" moment.
        Attempt 2 (bbox + explicit grid(row=0, col=1)):  the explicit position
          was WRONG. In vertical orientation CTkScrollableFrame places canvas at
          row=1 and scrollbar at row=1 (same row, different columns) inside
          _parent_frame.  Forcing row=0 put the scrollbar into the label row
          above the canvas — that was the "door-frame" artifact.

        Correct approach (this version):
        ─────────────────────────────────
        Uses grid_remove() / grid() for show/hide.
        Called only from after_idle / after(150) — never inside a synchronous
        event callback — so grid() never fires inside a yscrollcommand chain.
        The global CTkBaseClass._update_dimensions_event guard in fonts.py
        prevents any cascade from grid()-triggered Configure events.
        """
        def _check():
            try:
                canvas = self.scroll_frame._parent_canvas
                sbar   = self.scroll_frame._scrollbar
            except AttributeError:
                return
            try:
                top, bot = canvas.yview()
                need_scroll = top > 0.001 or bot < 0.999
                mapped = sbar.winfo_ismapped()
                if need_scroll and not mapped:
                    sbar.grid(row=1, column=1, sticky="nsew")
                elif not need_scroll and mapped:
                    sbar.grid_remove()
            except Exception:
                pass
        self.after_idle(_check)
        self.after(150, _check)

    def _on_search_changed(self, event=None):
        self._search_query = self._search_entry.get().strip()
        self._apply_search_filter()

    def _apply_search_filter(self):
        """
        Show/hide cards based on search query and reflow the grid so visible
        cards are packed densely without gaps.

        Why we can't just grid_remove() the filtered-out cards:
        ----------------------------------------------------------
        Each card was originally placed at a specific (row, col) by
        _relayout_cards(). If we hide some cards in place, their grid cells
        stay empty — which on a 2-column layout produces the "checkerboard"
        arrangement the user saw (a visible card at col 1, then a gap at
        col 0, then another card at col 1, and so on).

        The correct behaviour is to recompute (row, col) for ONLY the
        currently-visible cards, in their declaration order. Hidden cards
        keep their grid_forget() state and reappear in their original spot
        once the query is cleared.
        """
        q = self._search_query

        # First pass: detect what's visible.
        visible_cards = [c for c in self._cards.values()
                         if (not q) or c.matches_search(q)]
        hidden_cards  = [c for c in self._cards.values() if c not in visible_cards]

        # Pull every card out of the grid so leftover placements can't
        # show through. forget() also clears any old (row, col) state.
        for c in hidden_cards:
            c.grid_forget()

        # Re-place visible cards sequentially, mirroring _relayout_cards()
        # but only iterating over the visible subset. The result: a dense
        # rectangle of cards with no holes.
        for idx, c in enumerate(visible_cards):
            r, col = divmod(idx, self._columns)
            px_l = 0 if col == 0 else 3
            px_r = 3 if col < self._columns - 1 else 0
            c.grid(row=r, column=col, sticky="new", padx=(px_l, px_r), pady=3)

        self._update_empty_state()

    # ------------------------------------------------------------------
    # Responsive grid (C4: sticky="new" aligns card tops in the same row)
    # ------------------------------------------------------------------

    def _relayout_cards(self):
        """
        Re-arrange all cards using tkinter grid.

        The sticky parameter is "new" (north-east-west) rather than "ew".
        This means each card is pinned to the TOP of its grid cell.
        In 2-column mode, when one card expands downward (because a chart
        is open) while the adjacent card does not, both cards still share
        the same top edge — the expanded card simply grows downward into
        the extra row height without displacing its neighbor.
        """
        # Reset both columns first (covers switching from 2-col back to 1-col)
        for c in range(2):
            self.scroll_frame.grid_columnconfigure(c, weight=0, uniform="")
        # uniform="cols" forces all active columns to exactly equal width.
        # Without uniform, a lone card in col-0 gets its natural width +
        # half the remainder while col-1 gets only the other half → asymmetry.
        for c in range(self._columns):
            self.scroll_frame.grid_columnconfigure(c, weight=1, uniform="cols")

        for card in self._cards.values():
            card.grid_forget()

        for idx, card in enumerate(self._cards.values()):
            r, c = divmod(idx, self._columns)
            px_l = 0 if c == 0 else 3
            px_r = 3 if c < self._columns - 1 else 0
            card.grid(row=r, column=c, sticky="new", padx=(px_l, px_r), pady=3)

        # Re-apply search filter so hidden cards stay hidden after relayout
        self._apply_search_filter()
        # Card count or column count changed → recheck whether scrollbar
        # should appear. The Configure-event hooks usually cover this,
        # but firing explicitly here avoids races where bbox hasn't
        # been updated yet by the time the event handler runs.
        self._sync_scrollbar_visibility()

    def _on_global_click(self, event):
        """
        Move keyboard focus away from any Entry when the user clicks on
        something that isn't an input.

        Why this is needed: tkinter Entry widgets are "sticky" by design —
        they hold focus (and a blinking caret) until something else
        explicitly takes focus. Most desktop apps work around this with a
        global click handler that watches for clicks on "non-input" regions
        and proactively transfers focus to the window itself. Without that
        handler, the user sees a permanently-blinking caret in an Entry
        even after they have visually moved on, which is what the user
        reported.

        Implementation note: we check the widget's class string rather than
        isinstance(). CTkEntry is a composite widget (a frame containing a
        tk.Entry), and clicks land on either the outer CTk widget or the
        inner tk.Entry. Walking up the parent chain and checking class
        names catches both reliably.
        """
        try:
            w = event.widget
            # Walk up at most three ancestors to find an Entry-like host.
            for _ in range(4):
                if w is None:
                    break
                cls = w.winfo_class() if hasattr(w, "winfo_class") else ""
                # tk.Entry has class "Entry"; tk.Text "Text"; CTkEntry's
                # underlying widget reports as "Entry"; combobox listpart
                # we leave alone too.
                if cls in ("Entry", "Text", "TCombobox", "Listbox"):
                    return   # the click landed on an input; do nothing
                w = w.master
            # The click was on a non-input widget. Steal focus to the main
            # window so any focused Entry will commit its placeholder and
            # stop blinking.
            top = event.widget.winfo_toplevel() if hasattr(event.widget, "winfo_toplevel") else self
            top.focus_set()
        except Exception:
            # Focus manipulation must never crash the app — silently ignore.
            pass

    def _on_window_configure(self, event):
        if event.widget is not self:
            return

        # Detect maximize → restore transition
        try:
            current_state = self.state()
        except Exception:
            current_state = "normal"

        if (self._prev_win_state in ("zoomed", "iconic") and
                current_state == "normal" and
                self._calculated_geometry):
            self.after(80, lambda: self.geometry(self._calculated_geometry))

        self._prev_win_state = current_state

        # Window-size memory: when the user manually drags the window to a
        # new size (state == "normal"), we save the final geometry so that
        # maximize → restore brings them back to their chosen size, not to the
        # auto-calculated size. We debounce with 500 ms so we only record once
        # the user has finished dragging (not on every intermediate pixel).
        if current_state == "normal":
            # Only treat this as a user drag when _skip_geo_event is False.
            # Programmatic geometry() calls set _skip_geo_event=True so we
            # don't mistake them for intentional user resizes.
            if not self._skip_geo_event:
                if self._save_geo_job:
                    self.after_cancel(self._save_geo_job)
                def _save():
                    self._save_geo_job = None
                    try:
                        self._calculated_geometry = self.geometry()
                    except Exception:
                        pass
                    # _calculated_geometry just changed.  _check_responsive_cols
                    # now reads from it (not winfo_width), so we must re-check
                    # here to actually pick up the user's new size — otherwise
                    # the column count stays frozen at whatever it was before
                    # the drag, since no Configure event will fire after this.
                    try:
                        self._check_responsive_cols()
                    except Exception:
                        pass
                self._save_geo_job = self.after(500, _save)

        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(200, self._check_responsive_cols)

    def _check_responsive_cols(self):
        self._resize_job = None
        if not self._auto_col:
            return
        if self._user_forced_cols:
            return   # user manually chose column count — don't override

        # Width source: prefer _calculated_geometry over winfo_width().
        #
        # Why not winfo_width()?  On Windows the CTk header/toolbar widgets
        # are taller/wider than the geometry we ask for in _set_initial_geometry,
        # so Tk inflates the actual window beyond our requested width.  In
        # practice winfo_width() reports values like 1020–1350 px even when
        # we asked for 680.  Acting on that inflated value flipped _columns
        # to 2 right after startup, but the auto-switch branch deliberately
        # does NOT touch the geometry (it must yield to user drags) — leaving
        # _columns=2 with the 1-col window width, truncating card IPs.
        #
        # _calculated_geometry is updated only when:
        #   - we set the geometry ourselves (init / golden snap / auto-resize), or
        #   - the user finished dragging and the 500 ms _save_geo_job fired.
        # It therefore reflects "the width we (or the user) declared", not
        # whatever transient size Tk's layout engine produced.
        #
        # Behavioural consequence: a slow user drag no longer flips columns
        # mid-drag (winfo_width based) — it now flips ~500 ms after they let
        # go (when _save_geo_job updates _calculated_geometry, which then
        # invokes this method directly; see _on_window_configure._save).
        ref_w = None
        if self._calculated_geometry:
            try:
                ref_w = int(self._calculated_geometry.split("x")[0])
            except Exception:
                ref_w = None
        if ref_w is None:
            ref_w = self.winfo_width()

        new_cols = 2 if ref_w >= _AUTO_2COL_W else 1
        if new_cols != self._columns:
            self._columns = new_cols
            self._col_btn.configure(
                text="⊟ 单列" if self._columns == 2 else "⊞ 双列")
            self._update_minsize()   # keep minsize in sync with auto-switch
            self._relayout_cards()

    def _toggle_columns(self):
        self._columns = 2 if self._columns == 1 else 1
        self._user_forced_cols = True   # lock: don't let _check_responsive_cols override
        self._col_btn.configure(
            text="⊟ 单列" if self._columns == 2 else "⊞ 双列")

        # ── Golden geometry state machine ─────────────────────────────
        # Width is fixed by mode; height is calculated for the new layout
        # (same formula as _auto_resize) but capped at _GOLDEN_MAX_H so
        # the window never balloons when switching from tall 1-col to 2-col.
        self._apply_golden_geometry()
        self._update_minsize()   # must come AFTER geometry so Tk doesn't fight us

        self._relayout_cards()
        # Persist so the next startup restores the same column layout.
        self.config.set_setting("default_columns", self._columns)

    def _auto_resize(self):
        """
        Adjust window HEIGHT to snugly fit the current card count.

        Design rules (prevent the snap-back / window-balloon bugs):
        - Clears _auto_resize_job (debounce token) at entry.
        - Does nothing when maximized — geometry() on a zoomed window
          causes flicker without benefit.
        - NEVER changes width.  Expanding width triggers Configure →
          _check_responsive_cols which could flip columns back.
        - NOT called from _toggle_columns.  Column switches must never
          change the window size; the scrollbar handles overflow.
        """
        self._auto_resize_job = None          # clear debounce token

        if self.state() == 'zoomed':
            return                            # maximized: leave geometry alone

        # Use the width from _calculated_geometry (the last geometry()
        # we explicitly set) rather than winfo_width().  On Windows,
        # tkinter may not have fully applied the initial geometry constraint
        # by the time this 300 ms callback fires, so winfo_width() can
        # return a "virtual-fat" value that then gets baked in permanently.
        if self._calculated_geometry:
            w = int(self._calculated_geometry.split("x")[0])
        else:
            w = self.winfo_width()
        self.update_idletasks()
        n     = len(self._cards)
        rows  = max(1, -(-n // self._columns))
        card_h = _CARD_H_2COL if self._columns == 2 else _CARD_H_1COL
        needed = (_HEADER_H + _TOOLBAR_H + rows * card_h
                  + _HIST_HDR_H + _STATUSBAR_H + _PADDING_H)
        max_h  = int(self.winfo_screenheight() * 0.88)
        h = max(400, min(needed, max_h))      # 400 == minsize height
        self._calculated_geometry = f"{w}x{h}"
        self._skip_geo_event = True
        self.geometry(self._calculated_geometry)
        self.after(0, lambda: setattr(self, "_skip_geo_event", False))

    # ------------------------------------------------------------------
    # Cards
    # ------------------------------------------------------------------

    def _load_cards(self):
        for target in self.config.get_targets():
            self._create_card(target)
        self._refresh_summary()
        self._schedule_auto_resize(120)   # debounced

    @staticmethod
    def _chart_warn_latency(target, merged):
        """Chart warning line — mirrors HTTPMonitor.DEFAULT_WARN_LAT when no per-target override."""
        if "latency_warn_ms" in (target.get("thresholds") or {}):
            return merged.get("latency_warn_ms") or 150
        if (target.get("ping_type") or "icmp").lower() in ("http", "https"):
            return HTTPMonitor.DEFAULT_WARN_LAT
        return merged.get("latency_warn_ms") or 150

    def _create_card(self, target):
        tid = target["id"]
        self.history.ensure_target(tid)
        merged = self.config.get_target_settings(tid)
        card = IPCard(
            parent=self.scroll_frame, target=target,
            on_edit=self._on_edit, on_delete=self._on_delete,
            on_pause=self._on_target_pause,
            on_resume=self._on_target_resume,
            get_history=lambda tid=tid: self.history.get_history(tid),
            warn_latency=self._chart_warn_latency(target, merged),
            on_detail=self._open_waveform_detail,
            on_icmp_diag=self._open_icmp_diag,
            on_dns_diag=self._open_dns_diag)
        self._cards[tid] = card
        card._dns_domain = target.get("dns_domain", "")  # for matches_search
        self._current_statuses[tid] = "gray"
        # Seed alert-event baseline so the first probe can record gray→red
        # (or gray→orange) when the node has no _last_statuses entry yet.
        self._last_statuses.setdefault(tid, "gray")
        self._target_labels[tid]       = target["label"]
        self._target_ips[tid]          = target["ip"]
        self._target_probe_ports[tid]  = target.get("tcp_probe_ports", "")
        self._target_dns_domain[tid]   = target.get("dns_domain", "")
        self._target_ping_types[tid]   = target.get("ping_type", "icmp")
        self._relayout_cards()

    def _update_empty_state(self):
        visible_cards = sum(
            1 for c in self._cards.values()
            if not self._search_query or c.matches_search(self._search_query)
        )
        if visible_cards > 0 or (self._cards and self._search_query):
            self.empty_label.grid_forget()
        else:
            self.empty_label.grid(row=0, column=0, columnspan=self._columns, pady=50)

    def _on_target_pause(self, target_id: str):
        """
        Called when user clicks ⏸ on a card.
        Fixes _status_counts leak: transfers the real old status → gray in
        the counter, so _apply_state_update never sees a stale red/orange.
        """
        self.engine.pause_target(target_id)
        self.alerter.on_target_paused(target_id)

        # ── Fix: keep _status_counts consistent with _current_statuses ──
        # Without this, a RED node's count leaks forever because
        # _apply_state_update early-returns while paused.
        old_status = self._current_statuses.get(target_id, "gray")
        if old_status != "gray":
            self._status_counts[old_status] = max(
                0, self._status_counts.get(old_status, 0) - 1)
            self._status_counts["gray"] = self._status_counts.get("gray", 0) + 1
            self._current_statuses[target_id] = "gray"
            self._refresh_summary()

        # ── Fix: update _last_statuses to "paused" ──────────────────────
        # Without this, _last_statuses still holds the pre-pause status (e.g.
        # "red"). On resume, the first green probe would compare against "red"
        # and write a spurious red→green alert_event to the DB — which is
        # harmless for SLA (the event is ignored because fault_start is None)
        # but creates misleading raw data in alert_events.
        # Setting "paused" here pairs with _on_target_resume seeding "gray"
        # so the first post-resume probe generates "gray→…" (not "red→…").
        _lst = self.__dict__.get("_last_statuses", {})
        _lst[target_id] = "paused"

        self._evaluate_global_alarm()
        if self.web_server.is_running:
            self.web_server.pause_target(target_id)

        label = self._target_labels.get(target_id, target_id)
        ip    = self._target_ips.get(target_id, "")
        self.logger.log_target_paused(label, ip)
        _ds = self.__dict__.get("data_store")
        if _ds:
            import time as _t
            _ds.record_alert(
                target_id=target_id, label=label, ip=ip,
                ts=_t.time(),
                old_status=old_status,
                new_status="paused",
                category="paused")

    def _on_target_resume(self, target_id: str):
        """
        Called when user clicks ▶ on a card.
        _current_statuses[tid] is already "gray" (set in _on_target_pause),
        so no count adjustment needed here — just resume pinging and
        let the next real result drive the counters normally.
        """
        self.engine.resume_target(target_id)
        # _current_statuses[tid] is already "gray" from _on_target_pause.
        # Do NOT set it again — that would double-move the counter.
        self._evaluate_global_alarm()

        if self.web_server.is_running:
            self.web_server.resume_target(target_id)

        label = self._target_labels.get(target_id, target_id)
        ip    = self._target_ips.get(target_id, "")
        self.logger.log_target_resumed(label, ip)
        _ds = self.__dict__.get("data_store")
        if _ds:
            import time as _t
            _ds.record_alert(
                target_id=target_id, label=label, ip=ip,
                ts=_t.time(),
                old_status="paused",
                new_status="gray",
                category="resumed")
        # Keep in-memory baseline aligned with the DB event above so the
        # first real probe records gray→green/orange/red, not paused→….
        _lst = self.__dict__.get("_last_statuses", {})
        _lst[target_id] = "gray"

    def _refresh_summary(self):
        self.lbl_total.configure(text=f"共 {len(self._cards)} 个  ")
        self.lbl_green.configure(text=f"●正常 {self._status_counts['green']}  ")
        self.lbl_orange.configure(text=f"●警告 {self._status_counts['orange']}  ")
        self.lbl_red.configure(text=f"●告警 {self._status_counts['red']}")

    # ------------------------------------------------------------------
    # Engine
    # ------------------------------------------------------------------

    def _start_engine(self):
        # ── Seed _last_statuses from DB before probes start ──────────────
        # If the program previously crashed while nodes were RED, _last_statuses
        # would be empty (fresh dict).  The first green probe would see
        # old_st=None -> skip alert recording -> the open outage in alert_events
        # never gets a recovery event -> SLA Case B fires from that old outage
        # timestamp, giving wildly wrong cumulative interruption times.
        #
        # Solution: replay alert_events to find each target's last known status
        # and pre-populate _last_statuses BEFORE the first probe fires.
        # _load_cards() runs first and setdefault(tid, "gray") on every card,
        # so we must OVERWRITE that placeholder for current targets when the
        # DB has a real last status (e.g. crash while RED -> first green must
        # record red->green, not gray->green).
        last_statuses = {}   # default — engine starts fresh if DB read fails
        _ds = self.__dict__.get("data_store")
        if _ds:
            try:
                last_statuses = _ds.get_last_known_statuses()
                _lst = self.__dict__.get("_last_statuses", {})
                for tid, st in last_statuses.items():
                    if tid in self._cards:
                        _lst[tid] = st
            except Exception:
                pass   # never block startup on a DB read failure

        self.engine.on_state_change = self._on_state_update
        # Wire DataStore reference for _run_loop's probe-start
        # generation capture (stamped on TargetState; used by the
        # writer-thread guard in record_ping).  Safe no-op when
        # data_store is None (test paths).
        try:
            if hasattr(self.engine, "set_data_store"):
                self.engine.set_data_store(self.__dict__.get("data_store"))
        except Exception:
            pass
        self.engine.start_all(self.config.get_targets(),
                               initial_statuses=last_statuses)
        self.logger.log_startup(len(self._cards))
        self.status_label.configure(
            text=f"监测运行中，每 {self.config.get_setting('ping_interval')}s ping 一次")

    def _state_is_current(self, state) -> bool:
        """Return True iff the probe-start identity snapshot stamped on
        `state` still matches the live monitor's identity.

        Used at every commit-side hop a probe result passes through so
        an identity-boundary edit (IP change, type change, wipe,
        delete) landing AFTER _run_loop's gates but BEFORE the
        callback (or AFTER the callback but BEFORE the Tk after(0)
        deferred UI update) drops the row instead of re-attributing
        old-probe data to the new node.

        Four layered checks:
          * Monitor exists (caught delete + type-change rebuilds).
          * Per-instance _instance_token matches.  Closes the
            ABA hole where remove+add for the same target_id yields
            a NEW monitor whose _ip_version / _settings_version
            both start at 0 -- identical to the OLD monitor's
            initial values, so version-only comparison would falsely
            pass.  The token is a UUID assigned in TargetMonitor.
            __init__, so a stale callback carrying the OLD token
            never matches the NEW monitor.
          * _ip_version and _settings_version still equal the
            probe-start snapshot.  Catches in-place edits that
            don't rebuild the monitor (same-type IP change,
            same-type semantic edit).
          * DataStore target generation still equals the snapshot.
            Catches wipe_target_history -- the only identity-boundary
            operation that bumps DS gen without bumping the monitor
            versions, so the per-monitor version check above misses
            it.  Together with the version checks this covers every
            kind of edit that flows through PingEngine /
            DataStore.bump_target_generation.

        State objects whose probe_* fields are None (initial seed,
        legacy code paths) skip the corresponding check.  All four
        being None means "no probe-time capture at all" and returns
        True for backward compat.
        """
        if (state.probe_ip_version is None
            and state.probe_settings_version is None
            and state.probe_monitor_token is None
            and state.probe_data_store_generation is None):
            return True
        try:
            mon = self.engine._monitors.get(state.target_id)
        except Exception:
            mon = None
        if mon is None:
            return False
        # Instance token: strongest signal, checked first.  A new
        # monitor under the same target_id has a fresh UUID.
        if state.probe_monitor_token is not None:
            if getattr(mon, "_instance_token", None) != state.probe_monitor_token:
                return False
        if (state.probe_ip_version is not None
            and mon._ip_version != state.probe_ip_version):
            return False
        if (state.probe_settings_version is not None
            and mon._settings_version != state.probe_settings_version):
            return False
        # DataStore generation: catches wipe_target_history (which
        # does NOT touch monitor versions).  Skip when the engine
        # wasn't wired to a DataStore (synthetic test setups).
        if state.probe_data_store_generation is not None:
            try:
                _ds = self.__dict__.get("data_store")
                if _ds is not None:
                    if _ds.current_target_generation(state.target_id) \
                            != state.probe_data_store_generation:
                        return False
            except Exception:
                pass
        return True

    def _on_state_update(self, state: TargetState):
        # DataStore is thread-safe (queue-based): safe to call from ping thread
        # Use __dict__.get to bypass tkinter's __getattr__ proxy.
        # Accessing self.data_store directly would fall through to
        # tkinter's __getattr__ if the attribute isn't set yet,
        # causing AttributeError from _tkinter.tkapp.
        #
        # Defensive gate: drop DataStore writes / alert bookkeeping when
        # the card is user-paused.  _apply_state_update already early-
        # returns on is_paused, but that only blocks the *UI* update --
        # by then record_ping and record_alert have already run.  Any
        # monitor-lifecycle bypass that leaves a fresh, unpaused monitor
        # behind a paused card (e.g. add_target after a type change)
        # would otherwise silently keep polluting raw history, SLA
        # data, and _last_statuses transitions for the duration of the
        # pause.  Card lookup goes through __dict__ to avoid the
        # tkinter __getattr__ trap during early init.
        _cards = self.__dict__.get("_cards") or {}
        _card  = _cards.get(state.target_id)
        if _card is not None and _card.is_paused:
            return
        # Drop ghost callbacks for nodes the operator has already
        # deleted.  remove_target() destroys the card and clears the
        # MainWindow metadata caches, but a probe that already passed
        # _run_loop's gates can still arrive on this thread after the
        # delete completes.  Without this check the callback would
        # _ds.record_ping() with empty label/ip and ping_type="icmp"
        # (the cache .get(tid, "") fallbacks), planting a ghost row
        # under a target_id no monitor would ever update again.
        if _card is None:
            return
        # Commit-side identity re-check via shared helper.  See
        # _state_is_current docstring for what it covers; bailing
        # here means the OLD probe's data never gets attributed to
        # the NEW identity.
        if not self._state_is_current(state):
            return
        _ds = self.__dict__.get("data_store")
        if _ds:
            import time as _t
            # Read from O(1) caches instead of rescanning config.get_targets()
            # on every probe.  Previously this method ran
            # `next(t for t in config.get_targets() if t["id"] == tid)` which
            # is O(N) per probe — with 50 nodes × 1 probe/s that's 50 linear
            # scans/s on the ping-thread hot path.  Dict reads are atomic in
            # CPython (GIL), so reading concurrently with UI-thread updates
            # is safe; the worst case is reading a stale label/ip for one
            # probe after an edit, which is harmless (DataStore overwrites
            # targets_meta on the next probe).
            tid   = state.target_id
            label = self._target_labels.get(tid, "")
            ip    = self._target_ips.get(tid, "")
            ptype = self._target_ping_types.get(tid, "icmp")
            # Per-target commit lock makes the record_ping ->
            # record_alert -> _last_statuses sequence atomic relative
            # to bump_target_generation.  Producer-side record_ping
            # returning True only proves the gen was valid at the
            # moment of queue.put; an edit landing between that
            # return and the _last_statuses update below would leave
            # _last_statuses polluted with a value the writer thread
            # later rejects (gen bumped), and the next genuine probe
            # under the new identity would synthesise a phantom
            # transition against the polluted seed.  Holding the
            # per-target commit lock forces any in-flight
            # bump_target_generation to wait until our whole
            # commit sequence finishes -- then either:
            #   (a) the gen check at the top of the lock sees the
            #       pre-edit gen (edit hasn't started), we commit
            #       cleanly; or
            #   (b) the edit completed before we got the lock, the
            #       check fails, we bail without polluting state.
            _commit_lock = _ds.commit_lock_for(tid) \
                if hasattr(_ds, "commit_lock_for") else None
            if _commit_lock is not None:
                _commit_lock.acquire()
            try:
                # Re-check identity under the lock -- catches an edit
                # that landed between _state_is_current above and
                # this point.
                if _commit_lock is not None \
                   and not self._state_is_current(state):
                    return
                accepted = _ds.record_ping(
                    target_id=tid, label=label, ip=ip,
                    ping_type=ptype, ts=_t.time(), status=state.status,
                    latency_ms=state.latency_ms, loss_rate=state.loss_rate,
                    probe_success=state.probe_success,
                    status_code=state.status_code,
                    failure_reason=state.failure_reason,
                    # Forward the probe-start DataStore generation snapshot
                    # so the writer thread can drop this row if a wipe /
                    # removal landed between probe start and INSERT.
                    captured_generation=state.probe_data_store_generation)
                # If DataStore rejected the ping (gen mismatch -- caused
                # by a same-type semantic edit / IP edit / wipe / removal
                # landing between the probe start and this submit), we
                # must NOT advance the alert bookkeeping below.
                if not accepted:
                    return
                _lst = self.__dict__.get("_last_statuses", {})
                old_st = _lst.get(tid)
                if old_st and old_st != state.status:
                    # Use 'availability' for ANY transition that touches red
                    # status (both outage-start and recovery).  Previous code
                    # used state.alert_category which is 'ok' on recovery —
                    # that caused get_sla_stats to silently drop recovery
                    # events and overstate outage duration.
                    if state.status == "red" or old_st == "red":
                        cat = "availability"
                    else:
                        cat = state.alert_category or "availability"
                    _ds.record_alert(
                        target_id=tid, label=label, ip=ip,
                        ts=_t.time(), old_status=old_st,
                        new_status=state.status,
                        category=cat,
                        failure_reason=state.failure_reason or "",
                        # Same probe-start generation snapshot record_ping
                        # forwards just above -- a stale red->green that
                        # snuck through _state_is_current would otherwise
                        # plant a phantom recovery event in alert_events.
                        captured_generation=state.probe_data_store_generation)
                _lst[tid] = state.status
            finally:
                if _commit_lock is not None:
                    _commit_lock.release()
        self.after(0, lambda: self._apply_state_update(state))

    def _apply_state_update(self, state: TargetState):
        tid = state.target_id
        if tid not in self._cards:
            return
        if self._cards[tid].is_paused:
            return   # discard updates while card is user-paused
        # Re-validate identity at THIS hop too -- the after(0) queue
        # ran the original commit but the UI update was deferred to
        # the main loop, and a same-type IP edit / type change / wipe
        # / delete can land between the _on_state_update commit and
        # this deferred apply.  Without this re-check the old probe's
        # latency would briefly overwrite the new card's status,
        # push to Web under the NEW identity, and re-mix the in-memory
        # chart history.  Same helper as _on_state_update so the two
        # hops stay in lockstep.
        if not self._state_is_current(state):
            return

        self.history.update(tid, state.latency_ms)

        if self.web_server.is_running:
            # ping_type comes from the O(1) cache (see _target_ping_types
            # init for rationale); avoids constructing an N-entry dict on
            # every state update just to read one field.
            _ping_type = self._target_ping_types.get(tid, "icmp")
            self.web_server.update_target(
                tid=tid,
                label=self._target_labels.get(tid, tid),
                ip=self._target_ips.get(tid, ""),
                status=state.status,
                latency_ms=state.latency_ms,
                jitter_ms=state.jitter_ms,
                loss_rate=state.loss_rate,
                ping_type=_ping_type,
                alert_category=state.alert_category,
                status_code=state.status_code,
                failure_reason=state.failure_reason,
                timings=state.timings,
                cert_days_left=state.cert_days_left,
                tcp_probe_ports=self._target_probe_ports.get(tid, ""),
                dns_domain=self._target_dns_domain.get(tid, ""),
                keyword_ok=state.keyword_ok,
                probe_success=state.probe_success)

        old = self._current_statuses.get(tid, "gray")
        if old != state.status:
            label = self._target_labels.get(tid, tid)
            ip    = self._target_ips.get(tid, "")
            self.alerter.on_status_change(tid, label, ip, state.status)
            self.logger.log_status_change(
                label=label, ip=ip, old_status=old, new_status=state.status,
                consecutive_loss=state.consecutive_loss, latency_ms=state.latency_ms)
            self.hist_panel.add_event(label, ip, old, state.status)
            self._status_counts[old] = max(0, self._status_counts.get(old, 0) - 1)
            self._status_counts[state.status] = self._status_counts.get(state.status, 0) + 1
            self._current_statuses[tid] = state.status
            self._refresh_summary()
            self._evaluate_global_alarm()   # Dispatcher: authoritative alarm decision

        _ping_type_local = self._target_ping_types.get(tid, "icmp")
        self._cards[tid].update_status(
            status=state.status, latency_ms=state.latency_ms,
            jitter_ms=state.jitter_ms, loss_rate=state.loss_rate,
            ping_type=_ping_type_local,
            alert_category=state.alert_category,
            status_code=state.status_code,
            failure_reason=state.failure_reason)

    def _evaluate_global_alarm(self):
        """
        全局告警状态重评估（调度中心入口）。
        对 _cards 里每个活跃节点做全量扫描，交由 alerter.evaluate_alarm
        统一决定告警音启停，杜绝任何单节点事件污染全局状态。
        """
        active = {tid: s for tid, s in self._current_statuses.items()
                  if tid in self._cards}
        paused = {tid for tid, card in self._cards.items()
                  if card.is_paused}     # @property, no ()
        self.alerter.evaluate_alarm(active, paused)

    # ------------------------------------------------------------------
    # Web server + URL click (C12)
    # ------------------------------------------------------------------

    def _update_web_btn(self):
        """Sync the Web service button appearance with current service state."""
        if self.web_server.is_running:
            self.web_btn.configure(
                text="🔄 重启 Web 服务",
                fg_color="#1F6AA5", hover_color="#1a5a8f")
        else:
            self.web_btn.configure(
                text="🌐 启动 Web 服务",
                fg_color=("#5B7FA6","gray30"), hover_color=("#4A6E94","gray40"))

    def _web_btn_action(self):
        """Start or restart the Web service."""
        if self.web_server.is_running:
            # Restart: pick up any port change from settings
            new_port = self.config.get_setting("web_port") or 8765
            self.web_btn.configure(text="⏳ 重启中...", state="disabled")
            self.after(50, lambda: self._do_restart_web(int(new_port)))
        else:
            self._do_start_web()

    def _push_web_target_snapshots(self):
        """Sync metadata to Web and honour desktop pause state (Bug104)."""
        for tid, card in self._cards.items():
            self.web_server.update_target(
                tid=tid,
                label=self._target_labels.get(tid, tid),
                ip=self._target_ips.get(tid, ""),
                status=self._current_statuses.get(tid, "gray"),
                latency_ms=None, jitter_ms=None, loss_rate=0.0,
                ping_type=self._target_ping_types.get(tid, "icmp"),
                tcp_probe_ports=self._target_probe_ports.get(tid, ""),
                dns_domain=self._target_dns_domain.get(tid, ""),
                is_probe_result=False)   # meta-sync, not a real probe
            if card.is_paused:
                self.web_server.pause_target(tid)

    def _do_start_web(self):
        ok = self.web_server.start()
        if ok:
            url = self.web_server.get_url()
            self.web_url_label.configure(text=f"🌐 {url}")
            # Pass the same type-metadata fields the steady-state path
            # (_on_state_update around line 936-951) sends -- without
            # them, WebServer.update_target() falls back to its
            # ping_type='icmp' / tcp_probe_ports='' / dns_domain=''
            # defaults, so every HTTP / TCP / DNS node would briefly
            # be logged as ICMP until its next state push.  Nodes paused
            # while Web was off must call pause_target() after meta-sync
            # so the browser shows "paused", not gray.
            self._push_web_target_snapshots()
            self._update_web_btn()
        else:
            messagebox.showerror("启动失败",
                "请确保已安装 Flask：pip install flask", parent=self)

    def _do_restart_web(self, new_port: int):
        ok = self.web_server.restart(new_port)
        self.web_btn.configure(state="normal")
        if ok:
            url = self.web_server.get_url()
            self.web_url_label.configure(text=f"🌐 {url}")
            self._update_web_btn()
        else:
            # The new bind failed (port in use, permission denied, ...).
            # Without this branch the UI would silently advertise the new
            # URL even though nothing is actually listening -- operators
            # clicked a dead link with no error feedback.
            self.web_url_label.configure(text="(Web 服务未运行)")
            self._update_web_btn()
            messagebox.showerror(
                "Web 服务重启失败",
                f"无法在端口 {new_port} 上启动 Web 服务。\n"
                f"该端口可能已被其他程序占用，或被防火墙/权限拒绝。\n"
                f"请检查后重试，或换用其他端口。",
                parent=self)

    def _auto_start_web(self):
        if not self.web_server.is_running:
            self._do_start_web()

    def _on_url_click(self, event=None):
        """Clicking the URL label in the status bar opens the browser (C12)."""
        if self.web_server.is_running:
            webbrowser.open(self.web_server.get_url())

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _open_settings(self):
        dialog = SettingsDialog(
            parent=self,
            config_manager=self.config,
            alert_manager=self.alerter,
            on_save=self._apply_settings)
        self.wait_window(dialog)

    def _apply_settings(self, changed: dict):
        if "_sound_enabled" in changed:
            # Use set_enabled, not raw attribute assignment, so that
            # toggling OFF also stops any red alarm that's currently
            # looping.  Bare `alerter.enabled = False` only flipped the
            # flag; the alarm thread kept replaying the WAV until the
            # underlying red node recovered.
            new_enabled = changed.pop("_sound_enabled")
            # Persist so it survives restart.  Previously the toggle
            # only lived on alerter.enabled; main.py unconditionally
            # constructed AlertManager(enabled=True) on next launch,
            # so disabling the alarm was effectively session-only and
            # silently reverted every restart.
            self.config.set_setting("sound_alert_enabled", bool(new_enabled))
            # Pass current statuses on RE-ENABLE so the alert manager
            # can re-seed _last_alert_status / _red_targets (transitions
            # that fired while disabled were dropped at on_status_change's
            # entry guard, so its internal view drifted).  Then call
            # _evaluate_global_alarm so any currently-red node restarts
            # the alarm right now -- previously the user could disable
            # sound, see a node go red while silent, then re-enable
            # sound and get NO audio because on_status_change never
            # noticed (subsequent identical "red" probes fail the
            # transition filter).
            if new_enabled:
                self.alerter.set_enabled(True,
                                          current_statuses=dict(self._current_statuses))
                self._evaluate_global_alarm()
            else:
                self.alerter.set_enabled(False)
        if "default_columns" in changed:
            new_cols = changed.pop("default_columns")
            self.config.set_setting("default_columns", new_cols)
            # Lock manual preference unconditionally — even if the column count
            # matches the current auto-switched value. Without this, saving
            # "default = 2" while already at 2 (via auto) leaves _user_forced_cols
            # False, so the auto-switch can still override it this session.
            self._user_forced_cols = True
            if new_cols != self._columns:
                self._columns = new_cols
                self._col_btn.configure(text="⊞ 双列" if self._columns == 1 else "⊟ 单列")
                self._relayout_cards()
                self._apply_golden_geometry()   # snap window width to new column mode
                self._update_minsize()          # must come AFTER geometry
                self._schedule_auto_resize(80)
        if "web_port" in changed:
            new_port = changed.pop("web_port")
            self.config.set_setting("web_port", new_port)
            if not self.web_server.is_running:
                self.web_server.port = new_port
        if "web_autostart" in changed:
            self.config.set_setting("web_autostart", changed.pop("web_autostart"))
        if "traceroute_interval" in changed:
            new_tr_interval = changed.pop("traceroute_interval")
            self.config.set_setting("traceroute_interval", new_tr_interval)
            self.web_server.set_traceroute_interval(new_tr_interval)
        if "tracert_max_hops" in changed:
            new_hops = changed.pop("tracert_max_hops")
            self.config.set_setting("tracert_max_hops", new_hops)
            self.web_server.set_traceroute_max_hops(new_hops)

        engine_updates = {}
        retention_keys = {"db_raw_retention_days", "db_hourly_retention_days",
                          "db_alert_retention_days", "db_traceroute_retention_days",
                          "db_diag_retention_days"}
        for key, value in changed.items():
            self.config.set_setting(key, value)
            if key not in retention_keys:
                engine_updates[key] = value
        if engine_updates:
            self.engine.update_global_settings(engine_updates)
        # Propagate retention changes to the running DataStore immediately
        _ds = self.__dict__.get("data_store")
        if _ds:
            _ds.update_retention(
                raw=changed.get("db_raw_retention_days"),
                hourly=changed.get("db_hourly_retention_days"),
                alert=changed.get("db_alert_retention_days"),
                traceroute=changed.get("db_traceroute_retention_days"),
                diag=changed.get("db_diag_retention_days"),
            )
        if "latency_warn_ms" in changed:
            new_val = changed["latency_warn_ms"]
            # Build a tid → "has per-target latency_warn_ms override" map
            # once.  PingEngine.update_global_settings already preserves
            # per-target latency_warn_ms overrides at the alarm-logic
            # level (see _override_keys); the chart warning line MUST
            # follow the same rule, otherwise the visual line on a
            # custom-threshold node desyncs from the actual alarm
            # threshold and operators reading the chart get a false
            # sense of where the alarm will fire.
            has_override = {
                t["id"]: "latency_warn_ms" in (t.get("thresholds") or {})
                for t in self.config.get_targets()
            }
            for tid, card in self._cards.items():
                if not card._chart_panel:
                    continue
                if has_override.get(tid):
                    continue
                ptype = (self._target_ping_types.get(tid) or "icmp").lower()
                if ptype in ("http", "https"):
                    card._chart_panel.warn_latency = HTTPMonitor.DEFAULT_WARN_LAT
                else:
                    card._chart_panel.warn_latency = new_val

        self.status_label.configure(text="设置已应用")
        self.after(3000, lambda: self.status_label.configure(
            text=f"监测运行中，每 {self.config.get_setting('ping_interval')}s ping 一次"))

    # ------------------------------------------------------------------
    # User actions
    # ------------------------------------------------------------------

    def _on_add(self):
        # Hard limit check (C11) — capacity policy lives in src/capacity.py
        if target_limit_state(len(self._cards)) == "blocked":
            messagebox.showwarning(
                "已达到节点上限",
                f"当前已添加 {MAX_TARGETS} 个监测节点，已达当前版本推荐上限。\n\n"
                f"为保证监测精度、告警及时性和 UI 响应速度，"
                f"当前桌面版建议最多监控 {MAX_TARGETS} 个节点。\n"
                f"如果大部分是 ICMP 节点，建议在设置中将 Ping 间隔设置为 "
                f"{RECOMMENDED_LARGE_TARGET_INTERVAL_S:g} 秒或以上。",
                parent=self)
            return

        dialog = AddTargetDialog(self,
                                 global_settings=self.config.config.get("settings", {}))
        self.wait_window(dialog)
        if dialog.result:
            r = dialog.result

            # Soft warning (C11) — shown once when crossing WARN_TARGETS
            if target_limit_state(len(self._cards)) == "warn":
                messagebox.showinfo(
                    "节点数量提示",
                    f"已添加 {WARN_TARGETS} 个节点。\n\n"
                    f"当前版本推荐上限为 {MAX_TARGETS} 个节点。\n"
                    f"如果其中 ICMP 节点较多，建议将 Ping 间隔调整为 "
                    f"{RECOMMENDED_LARGE_TARGET_INTERVAL_S:g} 秒或以上，\n"
                    f"以降低 ping 子进程创建带来的 RTT 偏移和 UI 响应压力。",
                    parent=self)

            # Build extra fields for type-specific config
            _extra_keys = (
                "tcp_port", "tcp_probe_ports",
                "http_url", "http_success_codes", "http_keyword", "http_keyword_mode",
                "dns_domain", "dns_expected",
                "ipv6_only",
            )
            extra = {k: r[k] for k in _extra_keys if k in r}
            custom = dict(r.get("thresholds") or {})
            custom.update(extra)
            new_target = self.config.add_target(
                r["label"], r["ip"],
                ping_type=r.get("ping_type", "icmp"),
                thresholds=r.get("thresholds"),
                extra=extra or None)
            self._create_card(new_target)
            self._refresh_summary()
            self.engine.add_target(new_target["id"], new_target["ip"],
                                   ping_type=new_target.get("ping_type", "icmp"),
                                   custom_settings=custom or None)
            self.logger.log_target_added(new_target["label"], new_target["ip"])
            # NOTE: no _schedule_auto_resize — adding a node must NEVER
            # change the window width. Scrollbar handles content overflow.

    @staticmethod
    def _dns_diag_host_prefill(tg: dict, target_id: str) -> str:
        ptype = tg.get("ping_type", "icmp")
        if ptype == "dns":
            return tg.get("dns_domain") or tg.get("ip") or target_id
        return tg.get("ip", target_id)

    def _close_registered_window(self, registry: dict, target_id: str) -> None:
        win = registry.pop(target_id, None)
        if win is None:
            return
        try:
            if win.winfo_exists():
                win._on_close()
        except Exception:
            pass

    def _refresh_open_diag_windows_after_edit(
        self, target_id: str, r: dict, *,
        ip_changed: bool, type_changed: bool,
        dns_domain_changed: bool,
        wipe_intent: bool = False,
    ) -> None:
        """Keep ICMP/DNS diag windows in sync after _on_edit().

        Refocus paths (_open_icmp_diag / _open_dns_diag) already refresh
        stale windows, but editing without re-opening left self._host /
        domain entry frozen — the next diag run probed the old target while
        persisting under the current target_id.

        wipe_intent: operator chose to reuse this target_id as a new
        physical object and clear history — close the large waveform window
        so stale _pts_cache / matplotlib figure cannot be shown or exported
        under the new label/IP (update_target alone only rewrites the header).
        """
        identity_changed = ip_changed or type_changed or dns_domain_changed
        if identity_changed:
            self._close_registered_window(self._icmp_diag_windows, target_id)
            self._close_registered_window(self._dns_diag_windows, target_id)
        else:
            icmp = self._icmp_diag_windows.get(target_id)
            if icmp is not None:
                try:
                    if icmp.winfo_exists():
                        icmp.update_host(r["label"], r["ip"])
                except Exception:
                    pass
            dns = self._dns_diag_windows.get(target_id)
            if dns is not None:
                try:
                    if dns.winfo_exists():
                        prefill = self._dns_diag_host_prefill(r, target_id)
                        dns.update_target(r["label"], prefill)
                except Exception:
                    pass
        if wipe_intent:
            self._close_registered_window(self._waveform_windows, target_id)
        else:
            wf = self._waveform_windows.get(target_id)
            if wf is not None:
                try:
                    if wf.winfo_exists():
                        wf.update_target(r["label"], r["ip"])
                except Exception:
                    pass

    def _open_icmp_diag(self, target_id: str):
        """Open (or focus) the ICMP advanced diagnostics window."""
        # Always look up the target's CURRENT config first.  We need
        # it both for the re-focus path (to refresh a stale host on
        # an existing window after the user edited the IP) and for
        # the construction path below.
        target = next((t for t in self.config.get_targets()
                       if t["id"] == target_id), None)
        existing = self._icmp_diag_windows.get(target_id)
        if existing:
            try:
                if existing.winfo_exists():
                    # If the target's IP / label changed while this
                    # diag window was open, push the new values into
                    # the window so the next "开始诊断" click probes
                    # the current address instead of the address the
                    # window was constructed with.  An in-flight task
                    # keeps its original target (see
                    # IcmpDiagWindow.update_host docstring).
                    if target is not None:
                        new_host  = target.get("ip", target_id)
                        new_label = target.get("label", target_id)
                        if (existing._host  != new_host
                            or existing._label != new_label):
                            try:
                                existing.update_host(new_label, new_host)
                            except Exception:
                                pass
                    existing.lift(); existing.focus_force(); return
            except Exception:
                pass
        if not target:
            return
        # Use on_close_callback to remove the dict entry — robust against
        # window destruction by any path (close button, parent quit, etc.).
        # Earlier impl overrode WM_DELETE_WINDOW with a lambda; that only
        # cleaned up on the close button and leaked entries otherwise.
        win = IcmpDiagWindow(
            parent       = self,
            target_label = target.get("label", target_id),
            host         = target.get("ip", target_id),
            on_close_callback = lambda tid=target_id: (
                self._icmp_diag_windows.pop(tid, None)),
            data_store   = self.__dict__.get("data_store"),
            target_id    = target_id)
        self._icmp_diag_windows[target_id] = win

    def _open_dns_diag(self, target_id: str):
        """Open (or focus) the DNS resolution diagnostics window.

        Pre-fill rule:
          • If the node is a DNS-type monitor (ping_type == "dns"), pre-
            fill the configured probe domain (settings.dns_domain) — the
            user almost always wants to diagnose that exact name.
          • Otherwise pre-fill with the node's ip/host string; if it
            looks like a domain dnspython resolves it, if it's an IP the
            user just changes it and clicks query.

        Read the current target FIRST so the re-focus branch can
        refresh an already-open window's label / host after the
        operator edited the underlying node.  Without this the
        existing branch lift/focused a window whose title, header,
        and domain pre-fill still showed the construction-time
        identity -- and any query the operator ran in that stale
        window bound the OLD domain's result to the (now repurposed)
        target_id.  Mirrors the fix to _open_icmp_diag /
        _open_waveform_detail in earlier rounds.
        """
        target = next((t for t in self.config.get_targets()
                       if t["id"] == target_id), None)

        existing = self._dns_diag_windows.get(target_id)
        if existing:
            try:
                if existing.winfo_exists():
                    if target is not None:
                        new_label = target.get("label", target_id)
                        new_host  = self._dns_diag_host_prefill(target, target_id)
                        if (existing._label != new_label
                            or existing._host  != new_host):
                            try:
                                existing.update_target(new_label, new_host)
                            except Exception:
                                pass
                    existing.lift(); existing.focus_force(); return
            except Exception:
                pass
        if not target:
            return

        host_prefill = self._dns_diag_host_prefill(target, target_id)

        win = DnsDiagWindow(
            parent       = self,
            target_label = target.get("label", target_id),
            host         = host_prefill,
            target_id    = target_id,
            on_close_callback = lambda tid=target_id: (
                self._dns_diag_windows.pop(tid, None)),
            data_store   = self.__dict__.get("data_store"),
            get_max_hops = lambda: (
                self.config.get_setting("tracert_max_hops") or 30),
        )
        self._dns_diag_windows[target_id] = win

    def _open_waveform_detail(self, target_id: str):
        """Open (or focus) the large waveform chart window for a target."""
        # Read the current target config first so the re-focus branch
        # below can refresh a stale label / ip on an already-open
        # window after the operator edited the underlying node.
        # Mirrors the fix applied to _open_icmp_diag a few rounds
        # ago -- previously this branch only ran lift+focus, so an
        # existing waveform window kept carrying construction-time
        # label / ip into its title, header, and exported file
        # names while the chart data silently moved on to the new
        # IP under the same target_id.
        target = next((t for t in self.config.get_targets()
                       if t["id"] == target_id), None)
        existing = self._waveform_windows.get(target_id)
        if existing:
            try:
                if existing.winfo_exists():
                    if target is not None:
                        new_label = target.get("label", target_id)
                        new_ip    = target.get("ip", "")
                        if (existing._label != new_label
                            or existing._ip   != new_ip):
                            try:
                                existing.update_target(new_label, new_ip)
                            except Exception:
                                pass
                    existing.lift()
                    existing.focus_force()
                    return
            except Exception:
                pass
        if not target:
            return
        win = WaveformDetailWindow(
            parent=self,
            target_id=target_id,
            label=target.get("label", target_id),
            ip=target.get("ip", ""),
            get_history=lambda tid=target_id: self.history.get_history(tid),
            data_store=self.__dict__.get("data_store"))
        self._waveform_windows[target_id] = win
        win.protocol("WM_DELETE_WINDOW",
                     lambda: (self._waveform_windows.pop(target_id, None),
                              win._on_close()))

    def _ask_ip_change_intent(self, target_label: str,
                              old_ip: str, new_ip: str,
                              type_change: tuple | None = None) -> str:
        """Ask the operator how to treat an IP/probe-type change to a target.

        Three choices, returned as one of {"keep", "wipe", "cancel"}:
          • keep   -- service migration: same logical node, new IP.  Keep
                       the historical time series, alerts and traceroute
                       snapshots; just rebind probing to the new address.
          • wipe   -- repurposing this slot for a different physical node.
                       Delete every historical row tied to this target_id
                       (pings_raw / pings_hourly / alert_events /
                       traceroute_logs / icmp+dns diag history / cum_stats)
                       via DataStore.wipe_target_history.
          • cancel -- abort the edit entirely.  The dialog is shown BEFORE
                       any state mutation, so cancel cleanly reverts to the
                       previous IP/type with no side effects.

        Closing the window with the X button defaults to "cancel" (safer
        than silently defaulting to a destructive or data-affecting choice).
        """
        result = {"choice": "cancel"}
        win = ctk.CTkToplevel(self)
        win.title("处理历史数据")
        win.geometry("540x300")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        # Header line: what's changing.
        change_lines = []
        if old_ip != new_ip:
            change_lines.append(f"IP: {old_ip or '(空)'}  →  {new_ip}")
        if type_change:
            old_t, new_t = type_change
            change_lines.append(f"探测类型: {old_t}  →  {new_t}")
        change_text = "    ".join(change_lines)

        ctk.CTkLabel(win,
            text=f"「{target_label}」",
            font=F(14, "bold")).pack(pady=(18, 4), padx=20)
        ctk.CTkLabel(win,
            text=change_text,
            font=F(12), wraplength=500).pack(pady=(0, 12), padx=20)

        ctk.CTkLabel(win,
            text="这次修改属于以下哪种情况？",
            font=F(12, "bold")).pack(pady=(0, 6), padx=20)

        ctk.CTkLabel(win,
            text=("• 服务迁移：同一台设备换了 IP，年度 SLA 历史要续接保留\n"
                  "• 更换监控对象：本槽位改监控另一台设备，旧历史不再有意义"),
            font=F(11), justify="left",
            text_color=("gray30", "gray70")).pack(pady=(0, 14), padx=22, anchor="w")

        def pick(c):
            result["choice"] = c
            win.destroy()

        btns = ctk.CTkFrame(win, fg_color="transparent")
        btns.pack(pady=(4, 16), padx=18, fill="x")
        # Safe default first / leftmost.
        ctk.CTkButton(btns, text="服务迁移\n(保留历史)",
                      command=lambda: pick("keep"),
                      width=150, height=48).pack(side="left", padx=4, expand=True, fill="x")
        # Destructive option visually distinct.
        ctk.CTkButton(btns, text="更换监控对象\n(清空历史)",
                      command=lambda: pick("wipe"),
                      width=150, height=48,
                      fg_color="#b91c1c", hover_color="#7f1d1d").pack(side="left", padx=4, expand=True, fill="x")
        ctk.CTkButton(btns, text="取消编辑",
                      command=lambda: pick("cancel"),
                      width=100, height=48,
                      fg_color=("gray60", "gray35"),
                      hover_color=("gray50", "gray25")).pack(side="left", padx=4, expand=True, fill="x")

        # X-close defaults to cancel (NOT to "keep" -- silently keeping is
        # safer than silently wiping, but cancel makes the operator's
        # intent explicit by forcing them to re-open Edit if they meant to
        # change anything).
        win.protocol("WM_DELETE_WINDOW", lambda: pick("cancel"))
        win.wait_window()
        return result["choice"]

    def _on_edit(self, target_id):
        targets = {t["id"]: t for t in self.config.get_targets()}
        target  = targets.get(target_id)
        if not target:
            return
        extra_keys = (
            "tcp_port", "tcp_probe_ports",
            "http_url", "http_success_codes", "http_keyword", "http_keyword_mode",
            "dns_domain", "dns_expected",
            "ipv6_only",
        )
        current_extra = {k: target[k] for k in extra_keys if k in target}
        dialog = EditTargetDialog(self,
            current_label=target["label"], current_ip=target["ip"],
            current_thresholds=target.get("thresholds", {}),
            global_settings=self.config.config.get("settings", {}),
            current_ping_type=target.get("ping_type", "icmp"),
            current_extra=current_extra)
        self.wait_window(dialog)
        if not dialog.result:
            return
        r = dialog.result
        new_extra = {k: r[k] for k in extra_keys if k in r}
        # ConfigManager.update_target treats every EDIT_MANAGED_KEYS
        # field absent from `extra` as "operator cleared it" and
        # removes it from disk.  But the edit dialog only renders a
        # subset (`extra_keys` above); other fields in
        # EDIT_MANAGED_KEYS -- http_timeout / http_verify_ssl /
        # http_follow_redirects / http_expected_status / timeout --
        # are real, runtime-honoured settings the user could have
        # provided via config file, migration, or a future advanced
        # dialog.  Without this preservation pass, any ordinary edit
        # (label rename, threshold tweak, etc.) silently deletes
        # them.  Read straight from `target` (the on-disk record),
        # not `current_extra` (which is also built from extra_keys
        # and would therefore be missing the same fields).
        from src.config_manager import EDIT_MANAGED_KEYS as _MANAGED
        _ek = set(extra_keys)
        for k in _MANAGED:
            if k not in _ek and k in target:
                new_extra.setdefault(k, target[k])
        new_custom = dict(r.get("thresholds") or {})
        new_custom.update(new_extra)

        # Compute the diff BEFORE persisting anything so the intent dialog
        # below has a clean cancel path -- if it runs AFTER update_target,
        # cancel would leave the config file written with the new IP while
        # the engine and in-memory caches still point at the old one, a
        # split-brain that survives until the next app restart.
        ip_changed   = target.get("ip",        "") != r["ip"]
        type_changed = target.get("ping_type", "icmp") != r.get("ping_type", "icmp")
        # Must snapshot before config.update_target() -- get_targets() is a
        # shallow copy, so `target` is the live dict that update_target()
        # mutates in place; comparing after persist always sees the new value.
        dns_domain_changed = (
            (target.get("dns_domain") or "")
            != (r.get("dns_domain") or "")
        )

        # When the probe's IP or type changes, ask the operator what the
        # change *means*: same physical node (keep history) or a different
        # one (wipe history).  See _ask_ip_change_intent docstring for the
        # rationale.  MUST run before config.update_target() below so cancel
        # is a true no-op leaving disk state untouched.
        wipe_intent = False
        if ip_changed or type_changed:
            intent = self._ask_ip_change_intent(
                target_label=r.get("label") or target.get("label", target_id),
                old_ip=target.get("ip", ""),
                new_ip=r["ip"],
                type_change=((target.get("ping_type", "icmp"),
                              r.get("ping_type", "icmp"))
                             if type_changed else None))
            if intent == "cancel":
                # Operator backed out -- nothing has been persisted yet
                # (we deliberately deferred config.update_target below
                # until past this point), so just return.
                return
            wipe_intent = (intent == "wipe")

        self.config.update_target(target_id, r["label"], r["ip"],
                                  ping_type=r.get("ping_type"),
                                  thresholds=r.get("thresholds"),
                                  extra=new_extra or None)
        # Pass thresholds AND type-specific extras together so the live
        # monitor picks up changes to tcp_port / http_url / etc. We send
        # them through update_target_thresholds because the merge logic
        # there preserves anything not being changed.
        combined = dict(r.get("thresholds") or {})
        combined.update(new_extra)

        _EDIT_CLEAR_KEYS = (
            "tcp_port", "tcp_probe_ports",
            "http_url", "http_success_codes",
            "http_timeout", "http_verify_ssl",
            "http_follow_redirects", "http_expected_status",
            "http_keyword", "http_keyword_mode",
            "dns_domain", "dns_expected",
            "ipv6_only", "timeout",
            "consecutive_loss_orange", "consecutive_loss_red",
            "consecutive_lat_orange", "latency_warn_ms",
            "ping_interval",
        )

        # Same-type edits: swap monitor.settings + bump _settings_version
        # atomically under _commit_lock BEFORE UI metadata caches are
        # rewritten.  Bug95: a version-only pre-bump
        # (invalidate_target_settings) left probes able to capture
        # (new_version, old_settings) and commit stale results.
        # Type-change skips — remove+add rebuilds the monitor.
        if not type_changed:
            self.engine.update_target_thresholds(
                target_id, combined, clear_keys=_EDIT_CLEAR_KEYS)
            from src.ping_engine import TargetMonitor as _TM
            _SEM = _TM.PROBE_SEMANTIC_KEYS
            _MISSING = object()
            old_view = {k: target.get(k, _MISSING) for k in _SEM}
            new_view = {k: combined.get(k, _MISSING) for k in _SEM}
            if old_view != new_view:
                # Reseed _last_statuses from the LAST PERSISTED ping
                # status, NOT from an in-memory constant.  The previous
                # round set it to "gray", but `gray -> green` is not
                # recognised by get_sla_stats's outage-close clause
                # (which requires `old_status == "red"` to close), so
                # a target that recovered right after a port edit
                # left its outage open forever.  Reading the latest
                # actually-persisted status keeps SLA continuity: a
                # pre-edit red baseline produces `red -> green` /
                # `red -> red`; a pre-edit green baseline produces
                # `green -> red` / `green -> green`.  Both close /
                # open outages correctly.
                #
                # Falls back to leaving the in-memory value untouched
                # when the DataStore isn't wired or has no persisted
                # ping yet -- a never-probed target has no SLA
                # baseline to preserve.
                _lst = self.__dict__.get("_last_statuses", {})
                _ds  = self.__dict__.get("data_store")
                if _ds is not None and hasattr(_ds, "get_last_persisted_status"):
                    try:
                        last = _ds.get_last_persisted_status(target_id)
                        if last is not None:
                            _lst[target_id] = last
                    except Exception:
                        pass

        if ip_changed or type_changed:
            # Invalidate any in-flight probe issued against the OLD ip
            # BEFORE we touch the UI caches or queue the DB wipe.
            # _target_ips[target_id] is rewritten further down (line
            # ~1675); _on_state_update reads that dict to attribute
            # the probe result to a DataStore row, so once the rewrite
            # happens an old-ip probe that lands before
            # engine.update_target_ip() bumps _ip_version sails through
            # the monitor's identity check and gets recorded under the
            # NEW ip.  Bump the version up front so the gate catches
            # the in-flight probe; the actual ip field on the monitor
            # is set inside update_target_ip too -- it's a single
            # operation, just hoisted to before everything that
            # observes the new identity.  Same-type only; the type-
            # change path further down rebuilds the monitor from
            # scratch via add_target, which has its own clean slate.
            if not type_changed:
                self.engine.update_target_ip(target_id, r["ip"])
            # Type-change: stop the OLD monitor RIGHT NOW, before any
            # new-identity caches become visible.  Previously the
            # type-change branch further down called remove_target +
            # add_target back-to-back, but that ran AFTER the UI
            # cache rewrite -- leaving a window where the old monitor
            # was still running and _on_state_update looked up
            # new-identity label/ip/type from the freshly rewritten
            # caches, so any old-type probe completing in that window
            # got recorded as the NEW node.  Hoisting remove_target
            # here closes that window; the type-change branch below
            # only does the add+start.
            if type_changed:
                self.engine.remove_target(target_id)
            # If "wipe": queue the DB purge BEFORE clearing in-memory state.
            # The queue is FIFO single-consumer, so this DELETE is
            # serialised behind any record_ping/record_alert that the
            # previous IP's probe already pushed (those are queued the
            # instant a probe completes, much earlier than this user
            # action), guaranteeing no stale-write-after-wipe orphans.
            # Use __dict__.get to bypass tkinter's __getattr__ proxy --
            # same idiom as elsewhere in this file (see _on_state_update).
            if wipe_intent:
                # Invalidate any traceroute already in flight against
                # the OLD identity BEFORE queuing the wipe.  The
                # scheduler runs run_traceroute() outside the
                # DataStore write queue, so an in-flight tracert that
                # finishes after the wipe job runs would otherwise
                # immediately re-insert the very rows the user just
                # asked us to delete (and re-populate the cache with
                # OLD-ip hops to boot).  Calling invalidate first +
                # ordering "kill cache → wipe DB" matters because
                # _run_one's identity check is what makes the wipe
                # actually stick.
                if hasattr(self.web_server, "invalidate_traceroute"):
                    try:
                        self.web_server.invalidate_traceroute(target_id)
                    except Exception:
                        pass
                _ds = self.__dict__.get("data_store")
                if _ds and hasattr(_ds, "wipe_target_history"):
                    _ds.wipe_target_history(target_id)
            # The probe target changed identity — reset all state that
            # belongs to the OLD target so it doesn't pollute the new one.
            self.history.remove_target(target_id)       # clear chart history
            if target_id in self._cards:
                self._cards[target_id].clear_chart_display()
            self.alerter.on_target_removed(target_id)   # clear alert/sound state
            # _last_statuses: pop on "wipe" (operator chose to wipe
            # history, so prior status has no meaning for the new
            # target); on "keep history" reseed from the DB-side
            # last persisted status so the first probe under the
            # new identity produces a proper transition event.  An
            # earlier round used a constant "gray" seed; that
            # neither closed prior red outages (get_sla_stats's
            # outage-close clause requires `old_status == "red"`)
            # nor opened new ones cleanly, so SLA continuity was
            # broken on every IP / type edit that kept history.
            if wipe_intent:
                self._last_statuses.pop(target_id, None)
            else:
                _ds_seed = self.__dict__.get("data_store")
                if _ds_seed is not None \
                   and hasattr(_ds_seed, "get_last_persisted_status"):
                    try:
                        last = _ds_seed.get_last_persisted_status(target_id)
                        if last is not None:
                            self._last_statuses[target_id] = last
                    except Exception:
                        pass
            old = self._current_statuses.pop(target_id, "gray")
            self._status_counts[old] = max(0, self._status_counts.get(old, 0) - 1)
            self._status_counts["gray"] = self._status_counts.get("gray", 0) + 1
            self._current_statuses[target_id] = "gray"
            # Immediately reset the card visual so it doesn't sit on old orange/red
            # for the entire next probe interval (may be tens of seconds for HTTP/DNS).
            if target_id in self._cards:
                self._cards[target_id].update_status("gray")
            # Sync summary counter and alarm state now — not after next probe.
            self._refresh_summary()
            self._evaluate_global_alarm()
            # Push gray snapshot to Web so the browser doesn't keep showing
            # the old status until the next update_target() call arrives.
            if self.web_server.is_running:
                label = r.get("label", target_id)
                ip    = r.get("ip", "")
                self.web_server.update_target(
                    target_id, label, ip, "gray",
                    latency_ms=None, jitter_ms=None, loss_rate=0.0,
                    ping_type=r.get("ping_type", "icmp"),
                    is_probe_result=False)   # ip/type changed; not a probe

        # Hoist UI metadata caches before type-change add_target so a
        # new-type monitor's first probe uses the new identity columns.
        # Same-type settings were already swapped above (before this
        # block) so probes never observe new _settings_version with old
        # monitor.settings.  _on_state_update reads label/ip/type from
        # these caches for DataStore rows.
        self._target_labels[target_id]       = r["label"]
        self._target_ips[target_id]           = r["ip"]
        self._target_probe_ports[target_id]   = r.get("tcp_probe_ports", "")
        self._target_dns_domain[target_id]    = r.get("dns_domain", "")
        self._target_ping_types[target_id]    = r.get("ping_type", "icmp")
        if target_id in self._cards:
            self._cards[target_id]._dns_domain = r.get("dns_domain", "")
        if target_id in self._cards:
            self._cards[target_id].update_info(r["label"], r["ip"])

        # If ping_type changed, destroy the old probe and create a new one.
        # Merely updating settings would leave the wrong Monitor class running.
        old_type = target.get("ping_type", "icmp")
        new_type = r.get("ping_type", "icmp")
        if old_type != new_type:
            # Snapshot the card's pause flag BEFORE the engine swap.
            # Pre-2025 add_target() unconditionally start()d the fresh
            # monitor with _pause_event clear, then the call site did
            # engine.pause_target() afterwards -- a real network probe
            # could fire in the gap (the monitor thread is already
            # running by the time pause_target acquires the lock).
            # Pass start_paused= so add_target arms _pause_event BEFORE
            # the thread is started; the pause is observable from the
            # first _run_loop iteration with no probe in flight.
            was_paused = (target_id in self._cards
                          and self._cards[target_id].is_paused)
            # remove_target was already hoisted to the top of the
            # ip/type-change block above; no second call needed here.
            self.engine.add_target(target_id, r["ip"],
                                   ping_type=new_type,
                                   custom_settings=combined or None,
                                   start_paused=was_paused)
        # same-type: update_target_thresholds already applied above
        # Only propagate the IP change to the engine when it actually
        # moved.  Calling update_target_ip on a label-only edit used
        # to silently reset the monitor's recovery debounce counter
        # back to gray (TargetMonitor.update_ip also no-ops now, so
        # this is belt-and-suspenders but keeps the intent local).
        if ip_changed:
            self.engine.update_target_ip(target_id, r["ip"])

        # Push the freshly-edited label / probe_ports / dns_domain to the
        # Web snapshot even when IP and ping_type were unchanged.  The
        # earlier "gray reset" push at line ~1460 only fires on ip/type
        # change; without this second unconditional sync, an edit that
        # touched only the label or tcp_probe_ports left the Web side's
        # _targets dict carrying stale fields until the NEXT probe state
        # update propagated through _on_state_update -- and for paused
        # nodes that next update never arrives.
        if self.web_server.is_running and target_id in self._cards:
            self.web_server.update_target(
                tid=target_id,
                label=r["label"],
                ip=r["ip"],
                status=self._current_statuses.get(target_id, "gray"),
                latency_ms=None, jitter_ms=None, loss_rate=0.0,
                ping_type=r.get("ping_type", "icmp"),
                tcp_probe_ports=r.get("tcp_probe_ports", ""),
                dns_domain=r.get("dns_domain", ""),
                is_probe_result=False)   # label/extras meta-sync

        self._refresh_open_diag_windows_after_edit(
            target_id, r,
            ip_changed=ip_changed,
            type_changed=type_changed,
            dns_domain_changed=dns_domain_changed,
            wipe_intent=wipe_intent,
        )

    def _on_delete(self, target_id):
        targets = {t["id"]: t for t in self.config.get_targets()}
        target  = targets.get(target_id, {})
        label   = target.get("label", target_id)
        if not messagebox.askyesno("确认删除",
                f"确定要删除「{label}」（{target.get('ip', '')}）吗？", parent=self):
            return
        self.logger.log_target_removed(label, target.get("ip", ""))
        old = self._current_statuses.pop(target_id, "gray")
        _lst = self.__dict__.get("_last_statuses", {})
        _lst.pop(target_id, None)
        _ds = self.__dict__.get("data_store")
        if _ds:
            _ds.on_target_removed(
                target_id=target_id,
                label=label,
                ip=target.get("ip", ""),
                old_status=old,
            )
        self.engine.remove_target(target_id)
        self.alerter.on_target_removed(target_id)
        self.history.remove_target(target_id)
        self.config.remove_target(target_id)
        # Always clear the WebServer's in-process state, regardless of
        # whether the HTTP listener is currently bound.  Gating this on
        # is_running meant: if the operator stopped / failed to restart
        # the Web service and THEN deleted a node, the in-process
        # _targets / _stats / _paused / _tracer_cache / scheduler
        # snapshot still retained the deleted tid.  The subsequent
        # successful start() rebuilt the listener but inherited the
        # stale dicts, so /api/status (and the SSE init snapshot)
        # served a ghost node that no monitor would ever update again.
        # remove_target itself only touches in-process data + queues a
        # broadcaster push -- both are safe to invoke whether or not
        # the server is bound to a port.
        self.web_server.remove_target(target_id)
        if target_id in self._cards:
            self._cards[target_id].grid_forget()
            self._cards[target_id].destroy()
            del self._cards[target_id]
        for registry in (self._waveform_windows, self._icmp_diag_windows,
                         self._dns_diag_windows):
            win = registry.pop(target_id, None)
            if win is not None:
                try:
                    win._on_close()
                except Exception:
                    pass
        self._status_counts[old] = max(0, self._status_counts.get(old, 0) - 1)
        self._target_labels.pop(target_id, None)
        self._target_ips.pop(target_id, None)
        self._target_probe_ports.pop(target_id, None)
        self._target_dns_domain.pop(target_id, None)
        self._target_ping_types.pop(target_id, None)
        self._relayout_cards()
        self._refresh_summary()
        self._evaluate_global_alarm()   # Re-evaluate after deletion (card + status already removed)
        # NOTE: no _schedule_auto_resize — deleting a node must NOT
        # change the window width. Scrollbar handles any overflow.

    def _on_test_sound(self):
        self.status_label.configure(text="测试音效中（约 3 秒）...")
        self.alerter.test_sounds()
        self.after(3500, lambda: self.status_label.configure(
            text=f"监测运行中，每 {self.config.get_setting('ping_interval')}s ping 一次"))

    def _toggle_theme(self):
        # Pause chart coordinator during theme switch to prevent redundant
        # draw_idle() calls while CTk is repainting every widget.
        from src.ui.chart_panel import ChartCoordinator
        ChartCoordinator.pause()
        current = ctk.get_appearance_mode().lower()
        if current == "dark":
            ctk.set_appearance_mode("light")
            self.theme_btn.configure(text="🌙 深色")
            self.config.set_setting("theme", "light")
        else:
            ctk.set_appearance_mode("dark")
            self.theme_btn.configure(text="☀ 浅色")
            self.config.set_setting("theme", "dark")
        for card in self._cards.values():
            card.apply_chart_theme()
        # Resume chart rendering 300ms after theme switch finishes
        self.after(300, lambda: __import__(
            'src.ui.chart_panel', fromlist=['ChartCoordinator']
        ).ChartCoordinator.resume())

    def _on_close(self):
        """
        关闭行为：
        - tray_minimize=True 且未强制退出 → 隐藏窗口，程序继续在托盘运行
        - 否则 → 正常退出（flush DataStore、停引擎、销毁窗口）
        """
        quitting = object.__getattribute__(self, "_quitting")
        tray_on  = bool(self.config.get_setting("tray_minimize"))
        if tray_on and not quitting:
            # 最小化到托盘
            self.withdraw()           # 隐藏窗口，不销毁
            if not self._ensure_tray():
                # 托盘不可用：不能让窗口隐藏而无入口，重新显示主窗口，
                # 让用户在没有托盘的环境下还能正常使用程序（再次点关闭
                # 按钮可以触发真正退出，因为 tray_minimize 的用户意图
                # 在 tray 不可用时无法兑现）。
                self.deiconify()
            return

        # 真正退出
        self._destroy_tray()
        _ds = self.__dict__.get("data_store")
        if _ds:
            try: _ds.flush()
            except Exception: pass
        # Save window geometry so the next startup restores exactly this
        # position and size (Module 1: state memory).
        try:
            self.config.set_setting("window_geometry", self.geometry())
        except Exception:
            pass
        self.logger.log_shutdown()
        self.engine.stop_all()
        self.alerter.acknowledge_alarm()
        self.web_server.stop()
        self.destroy()

    def _quit_from_tray(self):
        """从托盘菜单点击'退出'时调用，先标记强制退出再触发关闭流程。"""
        object.__setattr__(self, "_quitting", True)
        # 必须在主线程执行 tkinter 操作
        self.after(0, self._on_close)

    def _show_from_tray(self):
        """从托盘菜单点击'显示窗口'时调用。"""
        self.after(0, self._restore_window)

    def _restore_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def _ensure_tray(self) -> bool:
        """按需创建并启动托盘图标，返回 True 表示创建成功。

        失败时**绝不**自己宣告程序退出 -- 由调用方根据语义决定回退
        行为（main.py 的 --minimized 路径会 deiconify 显示主窗口；
        _on_close 的 tray-minimize 分支同样回退到显示窗口）。 之前
        的实现一遇到 ImportError 就 `_quitting=True + _on_close()`，
        直接销毁主窗口、停掉引擎和 Web 服务 -- 这与 main.py 注释
        "托盘不可用时退化为普通启动" 完全相反，开机自启场景下监控
        进程会因为缺少 pystray 而被静默杀掉。
        """
        if self.__dict__.get("_tray_icon") is not None:
            return True
        try:
            import pystray
            from PIL import Image as PILImage
            import os, sys as _sys

            # 打包后用 exe 目录；开发时用相对 __file__ 的路径
            if getattr(_sys, 'frozen', False):
                icon_path = os.path.join(os.path.dirname(_sys.executable),
                                         "assets", "icon.png")
            else:
                icon_path = os.path.normpath(os.path.join(
                    os.path.dirname(__file__), "..", "..", "assets", "icon.png"))
            if os.path.isfile(icon_path):
                img = PILImage.open(icon_path).resize((64, 64))
            else:
                img = PILImage.new("RGB", (64, 64), color=(30, 58, 95))

            menu = pystray.Menu(
                pystray.MenuItem("显示窗口",
                                 lambda icon, item: self.after(0, self._show_from_tray),
                                 default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("退出监控程序",
                                 lambda icon, item: self.after(0, self._quit_from_tray)),
            )
            tray = pystray.Icon("NetMonitor", img, "网络连通性监测", menu)

            # pystray 需要在独立线程里运行它的消息循环
            import threading
            t = threading.Thread(target=tray.run, daemon=True, name="tray-loop")
            t.start()

            object.__setattr__(self, "_tray_icon", tray)
            return True
        except ImportError:
            print("[Tray] pystray / Pillow not installed — staying in windowed mode")
            return False
        except Exception as e:
            print(f"[Tray] init error: {e} — staying in windowed mode")
            return False

    def _destroy_tray(self):
        """退出前停止托盘图标。"""
        tray = self.__dict__.get("_tray_icon")
        if tray:
            try: tray.stop()
            except Exception: pass
            object.__setattr__(self, "_tray_icon", None)
