"""
dns_diag_window.py — DNS resolution diagnostic window
                     (C-side, Phases 1 + 3A + 3B + 3C-1 + 3C-1.5 + 3C-3).

Scope mirrors src/dns_diag.py:
  • Query A / AAAA / CNAME / MX / NS / TXT / SOA  (Phase 1 + 3C-2)
  • Visualise CNAME chain (when qtype is A/AAAA and trace_chain=True)
  • Per-record table with "追踪此 IP" buttons on A/AAAA rows
  • Conclusion box with a human-readable summary
  • Custom nameserver (Phase 3B)
  • 多解析器对比 — Phase 3C-1 / 3C-3.  A 查询模式 segmented control
    above the resolver row toggles between single and compare; in
    compare mode the system/custom segmented control is hidden and
    a CHIP LIST (3C-3) accepts 1..3 对照解析器 IPs.
  • 3C-1.5: compare results render as a full-width DIFF MATRIX with
    collapsible per-resolver detail panels — side-by-side full panels
    proved unworkable inside a 680 px Web modal and were similarly
    cramped here.
  • 3C-3: matrix and detail panels generalised to N (1..4) columns —
    side 0 is always the system baseline (blue accent); sides 1..N
    are operator-supplied customs (purple accent).  Detail panels are
    rebuilt on each render so a 2-side history row and a 4-side live
    run share the same code path.
  • 📜 History list (Phase 3A + 3C-1 compare badge + 3C-3 "vs X +K"
    summary) — replays past runs.  v1 (2-side) and v2 (N-side) details
    are both supported.

Mutex / cancel semantics mirror IcmpDiagWindow so users experience
identical behaviour across diagnostic tools (single Stop button,
"diagnosis already running" toast, geometry memory, close-on-X cleanup).
"""
from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from src.ui.fonts import make as F
from src.ui.traceroute_result_window import TracerouteResultWindow
from src.dns_diag import (
    DnsDiagRequest, DnsDiagResult, DnsCompareResult, DnsCompareSide,
    DnsAuthResult, DnsAuthHop,
    DnsSecResult, DnsSecLink,
    DnsDiagTask, DnsAnswer, DnsTraceStep, run_dns_diag_async,
    ERROR_OK, ERROR_CANCELLED, ERROR_LABELS,
    first_failing_step_code, build_compare_diff_matrix,
    _MAX_COMPARE_CUSTOM_NS, _validate_nameserver,
)


_QTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

# Phase 3B: common public resolvers exposed as one-click presets.  We
# deliberately keep this list short — three pills fit in one row without
# wrap, and these three cover ~all "swap to a known-good public DNS"
# diagnostics the operator typically needs (Google / Cloudflare / 114).
# Adding more goes against the keep-it-one-row UX goal; users who need
# a different IP can just type it into the entry box.
_DNS_PRESETS = ("8.8.8.8", "1.1.1.1", "114.114.114.114")

# CNAME chain box auto-sizing.  Empirically at F(12) ~= 20 px per line
# including line spacing; the +12 covers internal textbox padding.  Min
# is 3-line tall so the placeholder "(无 CNAME 链)" doesn't look cramped;
# max caps growth so a 15-step pathological chain still leaves room for
# the answer table below — anything past 8 lines is internally scrollable.
_CHAIN_LINE_PX = 20
_CHAIN_PAD_PX  = 12
_CHAIN_MIN_H   = 3 * _CHAIN_LINE_PX + _CHAIN_PAD_PX
_CHAIN_MAX_H   = 8 * _CHAIN_LINE_PX + _CHAIN_PAD_PX

# Phase 3C-4 polish — authority-trace tree tag palette.
# Mirrors the Web rev2 colour language so an operator switching
# between C-side and Web sees the same semantic colouring (dim
# prefix glyphs, bold-coloured zone label, green glue IP, red
# error, orange warn, italic info note).  Two-tuples are
# (light-theme hex, dark-theme hex); _resolve_theme_color picks
# the appropriate one at apply time based on ctk.get_appearance_mode().
_AUTH_TREE_COLORS = {
    "prefix":     ("#6b7280", "#9ca3af"),  # ├─ └─
    "zone_ok":    ("#1d4ed8", "#60a5fa"),  # blue, bold
    "zone_bad":   ("#b91c1c", "#f87171"),  # red,  bold
    "zone_warn":  ("#c2410c", "#fb923c"),  # orange, bold
    "arrow":      ("#6b7280", "#9ca3af"),  # → (the "→ host" arrow)
    "dest_host":  ("#111827", "#e5e7eb"),  # hostname — normal text colour
    "dest_ip":    ("#6b7280", "#9ca3af"),  # (192.0.2.1) — dim parentheses
    "rtt":        ("#6b7280", "#9ca3af"),  # 42.0 ms · NOERROR
    "rcode_bad":  ("#b91c1c", "#fca5a5"),  # NXDOMAIN / SERVFAIL etc
    "label":      ("#6b7280", "#9ca3af"),  # "NS:" / "glue:"
    "ns_name":    ("#374151", "#d1d5db"),  # NS hostname in list
    "glue_name":  ("#374151", "#d1d5db"),
    "glue_arrow": ("#6b7280", "#9ca3af"),
    "glue_ip":    ("#15803d", "#86efac"),  # bright green, the visual anchor
    "info":       ("#6b7280", "#9ca3af"),  # italic engine note
    "err":        ("#b91c1c", "#fca5a5"),  # bold red engine error
    "warn":       ("#c2410c", "#fb923c"),  # orange engine warning
    "apex_note":  ("#15803d", "#86efac"),  # "已到权威 zone"
    "ok_mark":    ("#15803d", "#86efac"),  # ✓ prefix on success
    "bad_mark":   ("#b91c1c", "#fca5a5"),  # ✗ prefix on failure
    "meta_key":   ("#6b7280", "#9ca3af"),  # "目标:" "类型:" "跳数:"
    "meta_val":   ("#1f2937", "#e5e7eb"),  # the value next to each key
}


def _resolve_theme_color(pair):
    """Pick the right hex out of a (light, dark) tuple for the
    current CTk appearance mode.  Defensive: if get_appearance_mode
    raises (theme not fully initialised), fall back to the dark
    variant — that's the project's default and won't surprise
    anyone."""
    try:
        mode = ctk.get_appearance_mode()  # "Light" or "Dark"
    except Exception:
        mode = "Dark"
    return pair[0] if mode == "Light" else pair[1]


class DnsDiagWindow(ctk.CTkToplevel):
    """Independent window for manual DNS-resolution diagnostics."""

    # 3C-1.5 default: wider than the old 820 because the diff matrix
    # has 3 columns (值 / 系统 / 对照) and needs ~880 to keep IPv6
    # values on a single line without wrapping inside a row.  Geometry
    # is still persisted via _saved_geometry, so a user who shrinks
    # the window keeps their preference; this only changes the first
    # paint for new installs / fresh sessions.
    _saved_geometry: str = "880x720"

    def __init__(self, parent, target_label: str, host: str,
                 target_id: Optional[str] = None,
                 on_close_callback=None,
                 data_store=None,
                 get_max_hops=None):
        """
        get_max_hops: optional zero-arg callable returning the user's
        configured tracert max hops.  Passed through to spawned
        TracerouteResultWindow instances so they respect global setting.

        data_store + target_id: optional persistence hook (Phase 3A).
        When data_store is provided, completed queries are persisted via
        run_dns_diag_async's data_store= path and the 📜 history button
        becomes visible.  Both can be None for ad-hoc / test use — the
        features just gracefully no-op.
        """
        super().__init__(parent)
        self._label        = target_label
        self._host         = host or ""
        self._target_id    = target_id
        self._on_close_cb  = on_close_callback
        self._data_store   = data_store
        self._get_max_hops = get_max_hops
        self._task: Optional[DnsDiagTask]                  = None
        self._tracert_windows: list[TracerouteResultWindow] = []
        # Phase 3C-3: source of truth for the compare-mode chip list.
        # Order matters (it dictates diff-matrix column order); de-dup
        # and IP-literal validation happen in _add_compare_ns before
        # we ever append.  Empty list is valid state — Start blocks
        # until the operator adds at least one chip.
        self._compare_ns_list: list = []

        self.title(f"DNS 诊断 — {target_label}")
        self._restore_geometry()
        # Phase 3C-3 D8: bump minsize to 760×580 so the compare chip
        # row + 4-column diff matrix have breathing room even when the
        # user resizes aggressively.  The previous 620 cap dated to
        # Phase 1's single-mode-only layout and started clipping chip
        # rows once we added 3-resolver compare.
        self.minsize(760, 580)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.lift()
        self.focus_force()

        self._build_ui()

    # ------------------------------------------------------------------
    # Identity refresh
    # ------------------------------------------------------------------

    def update_target(self, label: str, host: str) -> None:
        """Refresh the bound node's display name / probe host while
        the window stays open.

        Background:
          The window is created with a snapshot of the target's label
          and host taken when the operator clicked the DNS diag
          button.  After construction _label, _host, the window
          title, the header line, and the domain entry's seeded
          value are all frozen.  If the operator then edits the
          underlying node (renames it, swaps IP, or — for ping_type
          == "dns" — changes the probe domain) and re-opens DNS diag
          from the same card, _open_dns_diag's existing-window
          branch lift/focuses this window without ever touching that
          state, so titles, header, and the pre-filled domain still
          show the OLD identity even though the target_id underneath
          now points at a different host.

        Refresh policy:
          • _label / _host / window title / header label are
            unconditionally rewritten — they only ever reflect the
            target's identity, not operator input.
          • The domain entry is updated only if its current value
            still equals the OLD _host (i.e. the operator never
            typed in a custom domain since opening the window).
            When the operator has already typed something different
            we leave their in-progress diagnostic target alone —
            stomping it would silently lose pending work.

        Mirrors the same shape applied to the ICMP diag window and
        the waveform window after earlier rounds.
        """
        old_host = self._host
        self._label = label
        self._host  = host or ""
        try: self.title(f"DNS 诊断 — {label}")
        except Exception: pass
        try:
            hdr = getattr(self, "_header_label", None)
            if hdr is not None:
                new_title = f"🌐  {label}"
                if self._host:
                    new_title += f"  ({self._host})"
                hdr.configure(text=new_title)
        except Exception: pass
        try:
            dv = getattr(self, "_domain_var", None)
            if dv is not None:
                current = (dv.get() or "").strip()
                # Only auto-seed when the entry still holds the old
                # host verbatim -- otherwise the operator typed a
                # custom target and we leave their input intact.
                if current == (old_host or "").strip():
                    dv.set(self._host)
        except Exception: pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        # Phase 3C-1: single-view and compare-view share row 3 (the
        # results area) via grid_remove()/grid() toggling.  weight=1
        # on that row gives the visible view full vertical stretch.
        self.grid_rowconfigure(3, weight=1)

        # ── Header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray88", "gray15"))
        hdr.grid(row=0, column=0, sticky="ew")
        title = f"🌐  {self._label}"
        if self._host:
            title += f"  ({self._host})"
        # Stash the header label so update_target() can rewrite it
        # when the underlying node is edited while the window is open.
        self._header_label = ctk.CTkLabel(hdr, text=title,
                                          font=F(13, "bold"), anchor="w")
        self._header_label.pack(side="left", padx=14, pady=8)

        # ── Parameter panel ───────────────────────────────────────────
        pnl = ctk.CTkFrame(self, fg_color=("gray93", "gray18"), corner_radius=8)
        pnl.grid(row=1, column=0, sticky="ew", padx=12, pady=(10, 4))
        pnl.grid_columnconfigure(1, weight=1)

        # Row 0: domain entry
        ctk.CTkLabel(pnl, text="域名:", font=F(12)).grid(
            row=0, column=0, sticky="w", padx=(12, 6), pady=(10, 4))
        self._domain_var = ctk.StringVar(value=self._host)
        ctk.CTkEntry(pnl, textvariable=self._domain_var,
                     font=F(12), height=28).grid(
            row=0, column=1, columnspan=5, sticky="ew",
            padx=(0, 12), pady=(10, 4))

        # Row 1: qtype + timeout + trace_chain
        ctk.CTkLabel(pnl, text="查询类型:", font=F(12)).grid(
            row=1, column=0, sticky="w", padx=(12, 6), pady=4)
        self._qtype_var = ctk.StringVar(value="A")
        # anchor="center" centres the displayed value inside the
        # OptionMenu pill.  Default is "w" (left-aligned) which looks
        # cramped here because the values are short ("A" / "AAAA" /
        # "MX" / "CNAME" ...) — a single letter pushed to the left
        # edge of an 88-px-wide widget makes the chevron read as the
        # main thing on the row.  Centring restores a visual
        # equilibrium with the timeout entry next to it (which is
        # already centred via justify="center").
        ctk.CTkOptionMenu(pnl, variable=self._qtype_var,
                          values=list(_QTYPES), width=88, height=28,
                          font=F(12), anchor="center",
                          command=lambda _v: self._update_chain_hint()
                          ).grid(row=1, column=1, sticky="w", pady=4)

        ctk.CTkLabel(pnl, text="超时 (s):", font=F(12)).grid(
            row=1, column=2, sticky="w", padx=(16, 6), pady=4)
        self._timeout_var = ctk.StringVar(value="2")
        ctk.CTkEntry(pnl, textvariable=self._timeout_var,
                     width=56, height=28, font=F(12), justify="center"
                     ).grid(row=1, column=3, sticky="w", padx=(0, 12), pady=4)

        self._trace_var = ctk.BooleanVar(value=True)
        self._trace_chk = ctk.CTkCheckBox(
            pnl, text="展开 CNAME 链", font=F(11),
            variable=self._trace_var,
            command=self._update_chain_hint)
        self._trace_chk.grid(row=1, column=4, columnspan=2,
                             sticky="w", padx=(0, 12), pady=4)

        # Row 2 (Phase 3C-1 + 3C-4): 查询模式 — single vs compare vs
        # trace_auth.  Lives ABOVE the resolver row because mode dictates
        # what the resolver row itself means (an optional override vs a
        # required compare-IP vs ignored-entirely); putting it below
        # would force the operator to mentally re-read the resolver row
        # after every mode flip.  Width bumped to 360 to fit the three
        # Chinese labels without truncation under F(11).
        ctk.CTkLabel(pnl, text="查询模式:", font=F(12)).grid(
            row=2, column=0, sticky="w", padx=(12, 6), pady=4)
        self._query_mode = ctk.StringVar(value="单次查询")
        # Phase 3C-5 — adds "DNSSEC 验证" as the 4th segment.  Width
        # expanded 360 → 500 px to fit 4 ≥4-char Chinese labels without
        # internal label truncation under F(11).
        self._query_mode_seg = ctk.CTkSegmentedButton(
            pnl,
            values=["单次查询", "多解析器对比", "权威追踪", "DNSSEC 验证"],
            font=F(11),
            variable=self._query_mode,
            command=lambda _v: self._on_query_mode_change(),
            width=500, height=28)
        self._query_mode_seg.grid(row=2, column=1, columnspan=5,
                                   sticky="w", pady=4)

        # Row 3 (Phase 3B + 3C-3): resolver input.  TWO mutually
        # exclusive layouts share this row, swapped by _on_query_mode_change:
        #   • single  →  _single_resolver_row  (3B layout: label +
        #                segmented control + entry + 3 preset buttons,
        #                each click overwrites the single entry value)
        #   • compare →  _compare_resolver_row (3C-3 layout: label +
        #                chip strip + entry + Add button + counter,
        #                with the preset buttons in row 4 pushing to
        #                the chip list rather than overwriting)
        # We pack each option into its own ctk.Frame so the swap is a
        # single grid()/grid_remove() pair rather than walking all the
        # child widgets one by one.

        self._resolver_lbl = ctk.CTkLabel(pnl, text="解析器:", font=F(12))
        self._resolver_lbl.grid(row=3, column=0, sticky="nw",
                                 padx=(12, 6), pady=(8, 4))

        # ─── single-mode resolver row (Phase 3B) ───────────────────
        self._single_resolver_row = ctk.CTkFrame(pnl, fg_color="transparent")
        self._single_resolver_row.grid(row=3, column=1, columnspan=5,
                                        sticky="ew", pady=4, padx=(0, 12))
        self._resolver_mode = ctk.StringVar(value="系统默认")
        self._mode_seg = ctk.CTkSegmentedButton(
            self._single_resolver_row, values=["系统默认", "自定义"],
            font=F(11), variable=self._resolver_mode,
            command=lambda _v: self._on_resolver_mode_change(),
            width=140, height=28)
        self._mode_seg.pack(side="left")

        self._ns_var = ctk.StringVar(value="")
        self._ns_entry = ctk.CTkEntry(
            self._single_resolver_row, textvariable=self._ns_var,
            font=F(11), width=170, height=28,
            placeholder_text="例如 8.8.8.8", state="disabled")
        self._ns_entry.pack(side="left", padx=(8, 6))

        for ip in _DNS_PRESETS:
            ctk.CTkButton(
                self._single_resolver_row, text=ip, width=98, height=26,
                font=F(10),
                text_color=("gray15", "gray90"),
                fg_color=("gray80", "gray28"),
                hover_color=("gray65", "gray38"),
                command=lambda v=ip: self._apply_preset_ns(v),
            ).pack(side="left", padx=(4, 0))

        # ─── compare-mode resolver row (Phase 3C-3) ────────────────
        # Three-row stack — selected list / add controls / presets —
        # so the IP entry stays left-aligned under the chips instead
        # of being pushed to the far right by an expanding chip strip.
        # Label uses sticky="nw" to line up with row 0.
        self._compare_resolver_row = ctk.CTkFrame(pnl, fg_color="transparent")
        self._compare_resolver_row.grid_columnconfigure(0, weight=1)

        # Row 0 — selected resolver chips (display only).
        # Light: gray97 on gray93 panel → subtle lighter inset.
        # Dark:  gray14 on gray18 panel → same Δ idea; previously both
        #        were gray18 so the strip vanished into the panel bg.
        self._compare_chip_row = ctk.CTkFrame(
            self._compare_resolver_row,
            fg_color=("gray97", "gray14"),
            corner_radius=6, height=30,
            border_width=1,
            border_color=("gray82", "gray26"))
        self._compare_chip_row.grid(row=0, column=0, sticky="ew",
                                     pady=(0, 6))
        self._compare_chip_row.grid_propagate(False)

        # Row 1 — compact add controls, grouped left.
        self._compare_add_row = ctk.CTkFrame(
            self._compare_resolver_row, fg_color="transparent")
        self._compare_add_row.grid(row=1, column=0, sticky="w",
                                    pady=(0, 4))
        ctk.CTkLabel(
            self._compare_add_row, text="添加 IP:", font=F(10),
            text_color="gray50").pack(side="left", padx=(0, 6))
        self._compare_input_var = ctk.StringVar()
        self._compare_input_entry = ctk.CTkEntry(
            self._compare_add_row,
            textvariable=self._compare_input_var, font=F(11),
            width=132, height=28, placeholder_text="8.8.8.8")
        self._compare_input_entry.pack(side="left", padx=(0, 6))
        self._compare_input_entry.bind(
            "<Return>",
            lambda _e: self._add_compare_ns_from_input())
        self._compare_add_btn = ctk.CTkButton(
            self._compare_add_row, text="+ 添加", width=68,
            height=28, font=F(10),
            command=self._add_compare_ns_from_input)
        self._compare_add_btn.pack(side="left", padx=(0, 8))
        self._compare_count_lbl = ctk.CTkLabel(
            self._compare_add_row,
            text=f"已选 {0}/{_MAX_COMPARE_CUSTOM_NS}",
            font=F(10), text_color="gray50")
        self._compare_count_lbl.pack(side="left")

        # Row 2 — preset shortcuts, aligned with add row.
        self._compare_preset_row = ctk.CTkFrame(
            self._compare_resolver_row, fg_color="transparent")
        self._compare_preset_row.grid(row=2, column=0, sticky="w")
        ctk.CTkLabel(self._compare_preset_row, text="常用:", font=F(10),
                     text_color="gray50").pack(side="left", padx=(0, 6))
        self._compare_preset_btns: list = []
        for ip in _DNS_PRESETS:
            b = ctk.CTkButton(
                self._compare_preset_row, text=ip, width=98, height=24,
                font=F(10),
                text_color=("gray15", "gray90"),
                fg_color=("gray80", "gray28"),
                hover_color=("gray65", "gray38"),
                command=lambda v=ip: self._add_compare_ns(v))
            b.pack(side="left", padx=(0, 4))
            self._compare_preset_btns.append(b)

        # Compare row starts hidden — single mode is the initial state.
        self._compare_resolver_row.grid(row=3, column=1, columnspan=5,
                                         sticky="ew", pady=4, padx=(0, 12))
        self._compare_resolver_row.grid_remove()
        self._render_compare_chips()

        # Row 4: advisory hint (mode-aware) — yellow-ish so it reads as
        # a guideline, not an error.
        self._hint_lbl = ctk.CTkLabel(
            pnl, text="", font=F(10), text_color="gray50", anchor="w",
            wraplength=640, justify="left")
        self._hint_lbl.grid(row=4, column=0, columnspan=6, sticky="w",
                             padx=12, pady=(2, 10))
        self._update_chain_hint()

        # ── Action buttons ────────────────────────────────────────────
        btn_frm = ctk.CTkFrame(self, fg_color="transparent")
        btn_frm.grid(row=2, column=0, sticky="ew", padx=12, pady=(2, 4))
        self._start_btn = ctk.CTkButton(
            btn_frm, text="▶ 开始查询", width=110, height=32, font=F(12),
            command=self._start)
        self._start_btn.pack(side="left", padx=(0, 8))
        self._stop_btn = ctk.CTkButton(
            btn_frm, text="■ 停止", width=80, height=32, font=F(12),
            text_color=("gray15", "gray90"),
            fg_color=("gray65", "gray35"),
            hover_color=("gray50", "gray45"),
            state="disabled", command=self._stop)
        self._stop_btn.pack(side="left")
        # History button — only meaningful when a data_store is wired in.
        # Mirrors IcmpDiagWindow: hide rather than disable to avoid an
        # inert control on ad-hoc / test instances.
        if self._data_store is not None:
            self._history_btn = ctk.CTkButton(
                btn_frm, text="📜 历史", width=90, height=32, font=F(12),
                text_color=("gray15", "gray90"),
                fg_color=("gray70", "gray30"),
                hover_color=("gray55", "gray40"),
                command=self._open_history)
            self._history_btn.pack(side="left", padx=(8, 0))
        self._status_lbl = ctk.CTkLabel(
            btn_frm, text="", font=F(11), text_color="gray50")
        self._status_lbl.pack(side="left", padx=16)

        # Phase 3C-1: results area is now a "view container" that holds
        # exactly one of two children at a time:
        #   • _single_view  — original Phase 1/3B layout (summary line,
        #                     chain box, scrollable answer rows, conclusion)
        #   • _compare_view — Phase 3C-1 dual-panel layout (verdict bar
        #                     + side-by-side system / custom panels)
        # Both children grid into row=0,col=0 of the container; toggle
        # via grid()/grid_remove() in _switch_view().  Single is shown
        # by default so a freshly opened window looks identical to 3B.
        self._view_container = ctk.CTkFrame(self, fg_color="transparent")
        self._view_container.grid(row=3, column=0, sticky="nsew",
                                   padx=0, pady=0)
        self._view_container.grid_columnconfigure(0, weight=1)
        self._view_container.grid_rowconfigure(0, weight=1)

        self._single_view = self._build_single_view(self._view_container)
        self._single_view.grid(row=0, column=0, sticky="nsew")

        # Phase 3C-5 polish — kick off the autohide retry chain for the
        # initial single-view _results bar.  _build_single_view already
        # hides it synchronously, but Tk's first layout pass after the
        # window is realised can briefly grow the canvas in stages
        # (visible_h ≈ 100 → 400) and naïve measurements during that
        # window may re-show the bar.  Scheduling autohide here gives
        # the helper its full 0/50/120/280 ms retry budget on first
        # open, so an empty single view never carries a phantom bar.
        try:
            self.after_idle(self._update_results_scrollbar)
        except Exception:
            pass

        # Compare view is built lazily on the first compare run to keep
        # window-open cost identical to 3B for users who never use it.
        # _switch_view() handles the lazy creation.
        self._compare_view = None
        # Phase 3C-4: auth (trace_auth) view is similarly lazy.  Holds
        # its own tree + answer table + conclusion; never shares state
        # with single or compare.  Built on first switch to "auth".
        self._auth_view = None
        # Phase 3C-5: dnssec view — fourth top-level result panel.
        # Carries a verdict bar + verification chain TABLE + answer
        # table + AD/RRSIG metadata strip.  Lazy build on first
        # switch to "dnssec" (history replay, mode flip, or run).
        self._dnssec_view = None

    # ------------------------------------------------------------------
    # Phase 3C-1: view container — single / compare swap
    # ------------------------------------------------------------------

    def _build_single_view(self, parent):
        """Construct the Phase 1/3B single-resolver result panel.

        Mirrors the original top-level layout exactly so the visual
        behaviour is byte-identical; only the parent widget changed.
        Returns the container frame so the caller can grid() it.
        """
        view = ctk.CTkFrame(parent, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)
        # row weights match the original window-level weights so the
        # answer-rows scrollable frame still gets all the vertical
        # stretch.
        view.grid_rowconfigure(2, weight=1)

        # ── Summary line (resolver / rcode / elapsed) ────────────────
        self._summary_lbl = ctk.CTkLabel(
            view, text="", font=F(11), text_color=("gray30", "gray70"),
            anchor="w", justify="left")
        self._summary_lbl.grid(row=0, column=0, sticky="ew",
                                padx=14, pady=(6, 0))

        # ── CNAME chain box ─────────────────────────────────────────
        # height starts at the "no chain" minimum (1 line of placeholder
        # text); _render_result resizes dynamically per chain depth so
        # a 4-step chain shows all 4 lines without an internal scroll.
        # Phase 3C-5 polish v2 — "card on background" delta tuning.
        # Goal (per operator feedback): BOTH themes should show a
        # subtle but visible card outline so the user perceives each
        # info area as a distinct display region.  Previous defaults
        # had:
        #   light  gray92 on gray95 → RGB delta 7  (too subtle —
        #                              user reported "no visible card")
        #   dark   gray19 on gray10 → RGB delta 22 (too bold — user
        #                              reported "obvious framed box")
        # Target: ~delta 10-15 in BOTH modes for the chain/result
        # areas, with the conclusion box getting a slightly stronger
        # delta to emphasise the bottom-of-panel summary.  Values
        # picked so dark/light visually match each other at a glance.
        #   chain_box       light gray90 / dark gray15 → delta 12 / 12
        #   _results        light gray91 / dark gray14 → delta 11 / 10
        #   _conclusion     light gray87 / dark gray17 → delta 16 / 17
        self._chain_box = ctk.CTkTextbox(
            view, height=_CHAIN_MIN_H, font=F(12), wrap="word",
            state="disabled", fg_color=("gray90", "gray15"))
        self._chain_box.grid(row=1, column=0, sticky="ew",
                              padx=12, pady=(4, 6))

        # ── Scrollable results frame (one row per answer) ────────────
        # Use CTkScrollableFrame because each row needs a real button
        # widget ("追踪此 IP"), and a Text widget can't host those.
        self._results = ctk.CTkScrollableFrame(
            view, fg_color=("gray91", "gray14"))
        self._results.grid(row=2, column=0, sticky="nsew",
                            padx=12, pady=(0, 6))
        self._results.grid_columnconfigure(0, weight=1)

        # ── Conclusion box ───────────────────────────────────────────
        self._conclusion = ctk.CTkTextbox(
            view, height=70, font=F(12), wrap="word", state="disabled",
            fg_color=("gray87", "gray17"))
        self._conclusion.grid(row=3, column=0, sticky="ew",
                               padx=12, pady=(2, 10))
        # Phase 3C-5 polish — hide the empty _results scrollbar
        # immediately so the initial single-mode view doesn't show a
        # phantom bar before the first query runs.  Autohide will
        # bring it back when an answer table overflows.
        self._hide_scrollbar_now(self._results)
        return view

    def _build_compare_view(self, parent):
        """Construct the Phase 3C-1.5 / 3C-3 diff-first compare layout.

        Layout (top → bottom, inside an outer ScrollableFrame):
          row 0 — verdict bar (colour-coded ✓/✗ + conclusion + total ms)
          row 1 — full-width DIFF MATRIX (own scrollbar for huge sets)
          row 2 — N collapsible per-resolver detail panels, REBUILT on
                  every render (3C-3: number of sides varies between
                  runs, so a fixed two-panel grid would silently drop
                  sides 2..3).  Each panel pair (button + body) lives
                  inside `_details_container`.
          row 3 — secondary conclusion textbox.

        ── Why the WHOLE view scrolls, not just sub-sections ──
        Total vertical budget when ALL detail panels are expanded
        easily exceeds 900 px in a 4-side compare run.  Giving the
        OUTER container scrollbars (one place, predictable behaviour)
        is the only way this scales — per-section fixed heights with
        internal scrolls produced the truncation seen in 3C-1.5 v1.

        Inner scrolls are kept only for the diff matrix card — bounded
        so it stays a "block" at the top and doesn't push the details
        off-screen even when an answer set has 20+ entries.
        """
        view = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)

        # ── row 0: verdict bar ────────────────────────────────────────
        # Outer frame gives us a coloured background pill — the label
        # alone can't carry both text-color and fg-color cleanly across
        # both themes, so we wrap.
        self._verdict_frame = ctk.CTkFrame(
            view, corner_radius=8,
            fg_color=("gray92", "gray22"),
            border_width=1, border_color=("gray80", "gray30"))
        self._verdict_frame.grid(row=0, column=0, sticky="ew",
                                  padx=12, pady=(10, 6))
        self._verdict_frame.grid_columnconfigure(0, weight=1)
        self._verdict_lbl = ctk.CTkLabel(
            self._verdict_frame, text="", font=F(13, "bold"),
            anchor="w", justify="left",
            text_color=("gray15", "gray90"))
        self._verdict_lbl.grid(row=0, column=0, sticky="ew",
                                padx=14, pady=10)

        # ── row 1: diff matrix (fixed-height scrollable) ──────────────
        # height=180 fits ~5 rows comfortably (slightly taller than the
        # 3C-1.5 default of 150 because 3/4-column rows take ~2 px more
        # vertical per row in the wider modal).  Longer answer sets get
        # a vertical scrollbar inside the matrix card rather than
        # pushing the detail panels off-screen.
        #
        # Phase 3C-5 polish v3 — border lives on a WRAPPER frame, NOT
        # on the CTkScrollableFrame.  CTkScrollableFrame draws its
        # scrollbar in the same widget that carries border_width /
        # corner_radius, so the right rounded corner gets clipped or
        # covered even when the bar is grid_remove()'d (the track
        # column still participates in layout).  Putting the border on
        # an outer CTkFrame and keeping the scrollable borderless
        # inside guarantees a complete rectangle in both themes.
        self._compare_diff_outer = ctk.CTkFrame(
            view, fg_color="transparent",
            corner_radius=8, border_width=1,
            border_color=("gray82", "gray26"))
        self._compare_diff_outer.grid(row=1, column=0, sticky="ew",
                                       padx=12, pady=(0, 8))
        self._compare_diff_outer.grid_columnconfigure(0, weight=1)
        self._compare_diff_outer.grid_rowconfigure(0, weight=1)
        self._compare_diff_frame = ctk.CTkScrollableFrame(
            self._compare_diff_outer,
            fg_color=("gray91", "gray14"),
            corner_radius=0, height=178,
            border_width=0)
        self._compare_diff_frame.grid(row=0, column=0, sticky="nsew",
                                       padx=1, pady=1)
        self._compare_diff_frame.grid_columnconfigure(0, weight=1)

        # ── row 2: details container — populated lazily ───────────────
        # Phase 3C-3: panel count varies per run, so we build them in
        # _rebuild_compare_detail_panels and just maintain an empty
        # holder frame here.  The container's row weights are also set
        # dynamically (one row per panel body needs weight=1 for the
        # answer table to stretch).
        self._details_container = ctk.CTkFrame(
            view, fg_color="transparent")
        self._details_container.grid(row=2, column=0, sticky="nsew",
                                      padx=12, pady=0)
        self._details_container.grid_columnconfigure(0, weight=1)
        # key -> {"btn": CTkButton, "body": CTkFrame, "open": bool,
        #         "label": str, "accent": tuple}
        # Populated by _rebuild_compare_detail_panels; cleared by
        # _clear_results and on each fresh compare render.
        self._compare_detail_panels: dict = {}

        # ── row 3: secondary conclusion box (compact) ─────────────────
        # Verdict bar already shows the conclusion; this duplicate is
        # for users who scroll long matrices and want the wording
        # without scrolling back up.  Heights kept tight (56 px) so it
        # doesn't compete with the matrix for vertical space.
        # Border wrapper — same rationale as _compare_diff_outer.
        self._compare_conclusion_outer = ctk.CTkFrame(
            view, fg_color="transparent",
            corner_radius=8, border_width=1,
            border_color=("gray82", "gray26"))
        self._compare_conclusion_outer.grid(row=3, column=0, sticky="ew",
                                             padx=12, pady=(2, 10))
        self._compare_conclusion_outer.grid_columnconfigure(0, weight=1)
        self._compare_conclusion = ctk.CTkTextbox(
            self._compare_conclusion_outer, height=54, font=F(12),
            wrap="word", state="disabled",
            fg_color=("gray87", "gray17"),
            border_width=0, corner_radius=0)
        self._compare_conclusion.grid(row=0, column=0, sticky="ew",
                                       padx=1, pady=1)
        # Phase 3C-5 polish — hide the empty outer + diff-card
        # scrollbars immediately.  Without this, the diff card's
        # rounded right border looks "broken" because the visible
        # scrollbar overlaps the corner (see issue ②).  Autohide
        # brings them back on real overflow.
        self._hide_scrollbar_now(view)
        self._hide_scrollbar_now(self._compare_diff_frame)
        return view

    # ------------------------------------------------------------------
    # Phase 3C-4: authority-trace view (dedicated, NOT a compare reuse)
    # ------------------------------------------------------------------

    def _build_auth_view(self, parent):
        """Construct the authority-trace result panel.

        Layout (top → bottom, inside an outer ScrollableFrame so a
        long hop list never pushes the conclusion off-screen):
          row 0 — verdict bar (colour-coded, mirrors compare palette
                  for visual consistency across all three modes)
          row 1 — metadata strip (target / qtype / hops / CNAME chain)
          row 2 — monospace TREE textbox (one hop per visual block;
                  zone label + arrow + (host, ip) + rtt on the main
                  line; indented sub-lines for NS list / glue / msg /
                  errors).  This is the primary visual artefact of
                  trace_auth — operators read it top-to-bottom like a
                  recursive resolver log.
          row 3 — final answer rows (only populated on success;
                  reuses _render_answer_rows_into for consistency
                  with the single/compare detail tables)
          row 4 — conclusion textbox (echoes verdict so it's visible
                  without scrolling back to the top after a long tree)

        Why outer ScrollableFrame rather than nested fixed-height
        sections: identical rationale to compare view (3C-1.5) — a
        15-hop trace can exceed 700 px and we want ONE predictable
        scrollbar, not three sub-scrollbars competing.
        """
        view = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)

        # row 0 — verdict bar (same widget layout as compare's verdict
        # frame; colour palette is identical too so the operator's
        # eye doesn't have to relearn the visual grammar).
        self._auth_verdict_frame = ctk.CTkFrame(
            view, corner_radius=8,
            fg_color=("gray92", "gray22"),
            border_width=1, border_color=("gray80", "gray30"))
        self._auth_verdict_frame.grid(row=0, column=0, sticky="ew",
                                       padx=12, pady=(10, 6))
        self._auth_verdict_frame.grid_columnconfigure(0, weight=1)
        self._auth_verdict_lbl = ctk.CTkLabel(
            self._auth_verdict_frame, text="", font=F(13, "bold"),
            anchor="w", justify="left",
            text_color=("gray15", "gray90"))
        self._auth_verdict_lbl.grid(row=0, column=0, sticky="ew",
                                     padx=14, pady=10)

        # row 1 — metadata strip.  Compact monospace line summarising
        # the request + key counts.  Keeps the operator oriented when
        # scrolling a deep tree.
        self._auth_meta_lbl = ctk.CTkLabel(
            view, text="", font=F(11),
            text_color=("gray30", "gray70"),
            anchor="w", justify="left")
        self._auth_meta_lbl.grid(row=1, column=0, sticky="ew",
                                  padx=14, pady=(0, 6))

        # row 2 — TREE textbox.  Monospace font + wrap="word" so a
        # single very long NS / glue line wraps gracefully inside the
        # box rather than introducing horizontal scroll.  Starts at
        # 12 lines tall; we resize dynamically in _render_auth_result.
        self._auth_tree_box = ctk.CTkTextbox(
            view, height=12 * 20 + 12, font=F(11), wrap="word",
            state="disabled",
            fg_color=("gray90", "gray15"))
        self._auth_tree_box.grid(row=2, column=0, sticky="nsew",
                                  padx=12, pady=(0, 6))
        # Phase 3C-4 polish — register colour tags up-front so the
        # render path can just call tag_add per segment.  The dnspython
        # walk is fast (sub-second on the common path) and we don't
        # want the per-tag-configure cost to land on the UI thread
        # alongside the result.  CTkTextbox delegates tag_configure
        # straight to the underlying tk.Text via __getattr__.
        self._setup_auth_tree_tags(self._auth_tree_box)

        # row 3 — final answer table (reuses the single-mode helper
        # via _render_answer_rows_into).  Lives inside its own frame
        # so the helper has a fresh parent to clear / populate.
        self._auth_answers_frame = ctk.CTkFrame(
            view, fg_color=("gray91", "gray14"), corner_radius=6)
        self._auth_answers_frame.grid(row=3, column=0, sticky="ew",
                                       padx=12, pady=(0, 6))
        self._auth_answers_frame.grid_columnconfigure(0, weight=1)

        # row 4 — conclusion echo.  Same height as compare's
        # secondary conclusion for visual consistency.
        self._auth_conclusion = ctk.CTkTextbox(
            view, height=56, font=F(12), wrap="word", state="disabled",
            fg_color=("gray87", "gray17"))
        self._auth_conclusion.grid(row=4, column=0, sticky="ew",
                                    padx=12, pady=(2, 10))
        # Phase 3C-5 polish — hide outer scrollbar on empty auth view.
        self._hide_scrollbar_now(view)
        return view

    # ------------------------------------------------------------------
    # Phase 3C-5: DNSSEC validation view (dedicated)
    # ------------------------------------------------------------------

    def _build_dnssec_view(self, parent):
        """Construct the DNSSEC validation result panel.

        Layout (top → bottom, inside an outer ScrollableFrame so a
        long verification chain never pushes the conclusion offscreen):
          row 0 — verdict bar (FOUR-state palette — see
                  _DNSSEC_VERDICT_PALETTE; the visual language
                  intentionally treats INSECURE as a grey informational
                  state rather than a red ✗ so an operator running CN
                  domains daily doesn't read "未签名" as "故障").
          row 1 — metadata strip (resolver / target / qtype / CNAME
                  chain summary)
          row 2 — verification chain TABLE (one row per zone, root →
                  leaf; ✓/○/✗ mark + zone + DS/DNSKEY status pills +
                  algorithm + note).  This is the primary visual
                  artefact of dnssec mode; it answers the operator's
                  inevitable "where did the trust break?" at a glance.
          row 3 — AD / RRSIG metadata strip (informational; the AD bit
                  in particular is explicitly labelled as "(仅参考)" so
                  there's no doubt the verdict didn't depend on it).
          row 4 — answer table (reuses _render_answer_rows_into).
                  Populated even on INSECURE / BOGUS so the operator
                  sees what the resolver returned; the verdict bar
                  carries the security caveat.
          row 5 — conclusion textbox (echoes verdict, identical to
                  the auth view's conclusion row for visual parity).

        Why ScrollableFrame: same reasoning as the auth view — a chain
        TABLE that grows beyond 700 px combined with a long answer
        list needs ONE predictable scrollbar, not multiple sub-scrolls.
        """
        view = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        view.grid_columnconfigure(0, weight=1)

        # row 0 — verdict bar.  Container + label split same as auth
        # view so background colour and text colour can be set
        # independently (Tk widgets don't support a single colour-
        # plus-border on a CTkLabel cleanly).
        self._dnssec_verdict_frame = ctk.CTkFrame(
            view, corner_radius=8,
            fg_color=("gray92", "gray22"),
            border_width=1, border_color=("gray80", "gray30"))
        self._dnssec_verdict_frame.grid(row=0, column=0, sticky="ew",
                                         padx=12, pady=(10, 6))
        self._dnssec_verdict_frame.grid_columnconfigure(0, weight=1)
        self._dnssec_verdict_lbl = ctk.CTkLabel(
            self._dnssec_verdict_frame, text="", font=F(13, "bold"),
            anchor="w", justify="left",
            text_color=("gray15", "gray90"))
        self._dnssec_verdict_lbl.grid(row=0, column=0, sticky="ew",
                                       padx=14, pady=10)

        # row 1 — metadata strip.  Compact monospace line summarising
        # the request.
        self._dnssec_meta_lbl = ctk.CTkLabel(
            view, text="", font=F(11),
            text_color=("gray30", "gray70"),
            anchor="w", justify="left")
        self._dnssec_meta_lbl.grid(row=1, column=0, sticky="ew",
                                    padx=14, pady=(0, 6))

        # row 2 — verification chain TABLE.  We render this as a
        # textbox of tagged columns rather than a grid of widgets:
        #   • The chain is short (≤ 6 rows in practice — root + TLD +
        #     SLD + 1-3 sub-labels), so widget overhead is negligible
        #     either way, but the textbox path lets us use the same
        #     tag-based colouring discipline as the auth tree.
        #   • A textbox stays selectable / copyable for diagnostics —
        #     an operator pasting a verification chain into a ticket
        #     gets monospace-aligned plain text instead of widget noise.
        # Height starts at 6 lines × _CHAIN_LINE_PX; the renderer
        # re-clamps after we know the chain length.
        self._dnssec_chain_box = ctk.CTkTextbox(
            view,
            height=6 * _CHAIN_LINE_PX + _CHAIN_PAD_PX,
            font=F(11), wrap="word", state="disabled",
            fg_color=("gray90", "gray15"))
        self._dnssec_chain_box.grid(row=2, column=0, sticky="nsew",
                                     padx=12, pady=(0, 6))
        self._setup_dnssec_chain_tags(self._dnssec_chain_box)

        # row 3 — AD / RRSIG metadata strip.  Small dim text; matters
        # for operators comparing "what does the resolver claim"
        # against "what does my own validator say".
        self._dnssec_extra_lbl = ctk.CTkLabel(
            view, text="", font=F(10),
            text_color=("gray40", "gray60"),
            anchor="w", justify="left")
        self._dnssec_extra_lbl.grid(row=3, column=0, sticky="ew",
                                     padx=14, pady=(0, 6))

        # row 4 — answer table.  Reuses _render_answer_rows_into so
        # the table identical to single / auth modes.
        self._dnssec_answers_frame = ctk.CTkFrame(
            view, fg_color=("gray91", "gray14"), corner_radius=6)
        self._dnssec_answers_frame.grid(row=4, column=0, sticky="ew",
                                         padx=12, pady=(0, 6))
        self._dnssec_answers_frame.grid_columnconfigure(0, weight=1)

        # row 5 — conclusion echo.
        self._dnssec_conclusion = ctk.CTkTextbox(
            view, height=56, font=F(12), wrap="word", state="disabled",
            fg_color=("gray87", "gray17"))
        self._dnssec_conclusion.grid(row=5, column=0, sticky="ew",
                                      padx=12, pady=(2, 10))
        # Phase 3C-5 polish — hide outer scrollbar on empty dnssec view.
        self._hide_scrollbar_now(view)
        return view

    def _setup_dnssec_chain_tags(self, textbox) -> None:
        """Register colour tags for the dnssec verification chain.

        Palette mirrors the Web .dns-sec-chain colours so an operator
        switching between C / Web sees the same semantic colouring:
          • secure_ok  — green check / DNSKEY ✓ pill text
          • insecure   — grey ○ / "未签名" pill text
          • bogus      — red ✗ / DS ✗ pill text
          • indet      — orange ⚠ / unresolved
          • zone       — bold zone name
          • dim        — algorithm column + low-weight separators
          • note       — default text colour for the note column
        """
        try:
            theme_pairs = {
                "secure_ok":  ("#15803d", "#86efac"),
                "insecure":   ("#6b7280", "#9ca3af"),
                "bogus":      ("#b91c1c", "#f87171"),
                "indet":      ("#c2410c", "#fb923c"),
                "zone":       ("#1d4ed8", "#60a5fa"),
                "dim":        ("#6b7280", "#9ca3af"),
                "note":       ("#111827", "#e5e7eb"),
            }
            for name, pair in theme_pairs.items():
                textbox.tag_configure(name,
                                       foreground=_resolve_theme_color(pair))
            textbox.tag_configure("zone",      font=F(11, "bold"))
            textbox.tag_configure("mark",      font=F(12, "bold"))
            textbox.tag_configure("header",
                                   font=F(10, "bold"),
                                   foreground=_resolve_theme_color(
                                       ("#374151", "#d1d5db")))
        except Exception:
            pass

    def _dnssec_verdict_visuals(self, status: str) -> dict:
        """Return colour + glyph trio for a four-state DNSSEC status.

        Centralised so list-row badge, verdict bar, and conclusion
        echo can all pull the same palette.  Light/dark pairs follow
        the same convention as _AUTH_TREE_COLORS.  Greens, greys, reds,
        oranges are tuned to be visually distinct against both light
        and dark CTk themes (tested against the bundled "dark-blue"
        appearance and the system "light" default).
        """
        st = (status or "indeterminate").lower()
        if st == "secure":
            return {
                "mark":      "✓",
                "tag":       "SECURE",
                "text_color": ("#15803d", "#86efac"),
                "bar_bg":     ("#dcfce7", "#14532d"),
                "bar_border": ("#86efac", "#16a34a"),
                "row_tag":    "secure_ok",
            }
        if st == "insecure":
            return {
                "mark":      "○",
                "tag":       "INSECURE",
                "text_color": ("#4b5563", "#d1d5db"),
                "bar_bg":     ("#f3f4f6", "#1f2937"),
                "bar_border": ("#d1d5db", "#4b5563"),
                "row_tag":    "insecure",
            }
        if st == "bogus":
            return {
                "mark":      "✗",
                "tag":       "BOGUS",
                "text_color": ("#b91c1c", "#fca5a5"),
                "bar_bg":     ("#fee2e2", "#7f1d1d"),
                "bar_border": ("#fca5a5", "#dc2626"),
                "row_tag":    "bogus",
            }
        # indeterminate (default).
        return {
            "mark":      "⚠",
            "tag":       "INDETERMINATE",
            "text_color": ("#9a3412", "#fdba74"),
            "bar_bg":     ("#ffedd5", "#7c2d12"),
            "bar_border": ("#fdba74", "#ea580c"),
            "row_tag":    "indet",
        }

    def _render_dnssec_result(self, result: DnsSecResult):
        """Paint the dnssec view from a DnsSecResult.

        Steps in order:
          1.  Flip buttons (Stop → Start).
          2.  Status bar text — "DNSSEC 已签名 / 未签名 / 签名错误 /
              未能判定" depending on status.  Mirrors the four-state
              colouring used by the verdict bar.
          3.  Verdict bar — large coloured strip with mark + tag +
              message + elapsed.
          4.  Metadata strip — resolver / target / qtype / CNAME chain.
          5.  Verification chain — tagged textbox rendering one row
              per zone with ✓/○/✗ + zone label + DS/DNSKEY status +
              algorithm + note.  Empty-chain (rare INDETERMINATE)
              shows a placeholder line.
          6.  AD / RRSIG metadata strip — informational; AD is
              explicitly labelled "(仅参考)".
          7.  Answer table — reuses _render_answer_rows_into.  Even on
              INSECURE / BOGUS we display the records.
          8.  Conclusion echo at bottom.

        No interaction with single/compare/auth state — this method is
        a pure painter on the four widgets in _build_dnssec_view.
        """
        self._set_buttons(running=False)

        v = self._dnssec_verdict_visuals(result.status)
        # Status pill — same four-state mapping; INSECURE specifically
        # is NOT raised as an error (set_status with error=True paints
        # the status bar red which would scream incident).
        if result.status == "secure":
            self._set_status(f"DNSSEC 验证通过（SECURE）")
        elif result.status == "insecure":
            self._set_status("DNSSEC 未部署（INSECURE）")
        elif result.status == "bogus":
            self._set_status("DNSSEC 签名错误（BOGUS）", error=True)
        else:
            self._set_status("DNSSEC 未能判定（INDETERMINATE）",
                             error=True)

        # 3) Verdict bar.
        verdict_txt = (f"{v['mark']}  [{v['tag']}]  "
                       f"{result.message or ''}    "
                       f"耗时 {result.elapsed_ms:.1f} ms")
        try:
            self._dnssec_verdict_lbl.configure(
                text=verdict_txt, text_color=v["text_color"])
            self._dnssec_verdict_frame.configure(
                fg_color=v["bar_bg"], border_color=v["bar_border"])
        except Exception:
            pass

        # 4) Metadata strip.
        meta_parts = [
            f"传输解析器: {result.resolver or '系统默认'}",
            f"目标: {result.target}",
            f"类型: {result.qtype}",
        ]
        if result.cname_chain and len(result.cname_chain) >= 2:
            meta_parts.append("CNAME 链: " + " → ".join(result.cname_chain))
        try:
            self._dnssec_meta_lbl.configure(
                text="    ".join(meta_parts))
        except Exception:
            pass

        # 5) Verification chain — tagged textbox.
        self._render_dnssec_chain_into(
            self._dnssec_chain_box, result.chain or [])

        # 6) AD / RRSIG strip.
        if result.ad_flag is None:
            ad_txt = "解析器返回 AD 位: 未收到"
        else:
            ad_txt = ("解析器返回 AD 位: AD=1 (仅参考)"
                      if result.ad_flag
                      else "解析器返回 AD 位: AD=0 (仅参考)")
        rrsig_txt = ("本机 RRSIG 校验: ✓ 通过" if result.rrsig_ok
                     else "本机 RRSIG 校验: ✗ 未通过")
        ans_txt = f"答案条数: {len(result.answers or [])}"
        try:
            self._dnssec_extra_lbl.configure(
                text=f"{ad_txt}    {rrsig_txt}    {ans_txt}")
        except Exception:
            pass

        # 7) Answer table — clear unconditionally first.
        try:
            for child in self._dnssec_answers_frame.winfo_children():
                try: child.destroy()
                except Exception: pass
        except Exception:
            pass
        if result.answers:
            self._render_answer_rows_into(
                self._dnssec_answers_frame, result.answers,
                compact=False)
            try:
                self._dnssec_answers_frame.grid()
            except Exception: pass
        else:
            try:
                self._dnssec_answers_frame.grid_remove()
            except Exception: pass

        # 8) Conclusion echo.
        try:
            self._dnssec_conclusion.configure(state="normal")
            self._dnssec_conclusion.delete("1.0", "end")
            self._dnssec_conclusion.insert(
                "end", f"{v['mark']} {result.message or ''}")
            self._dnssec_conclusion.configure(
                state="disabled",
                text_color=v["text_color"],
                fg_color=v["bar_bg"])
        except Exception:
            pass

        # ScrollableFrame autohide refresh.
        try:
            self.after_idle(self._autohide_scrollbar, self._dnssec_view)
        except Exception:
            pass

    def _render_dnssec_chain_into(self, textbox, chain: list) -> int:
        """Render the verification chain as a tagged monospace table.

        Returns the number of LINES emitted (so the caller can resize
        the textbox).  Each chain link occupies ONE line:

          ✓ example.com.    DS ✓  DNSKEY ✓    SHA-256    DS → DNSKEY ✓

        Column widths:
          mark   2 chars
          zone   variable, padded to 26
          status 22  ("DS ✓  DNSKEY ✓")
          algo   12
          note   tail

        We use space-padding for monospace alignment rather than Tk
        grid columns — the chain is short enough (<6 lines) and the
        textbox path keeps copy-paste plain-text-friendly.
        """
        try:
            textbox.configure(state="normal")
            textbox.delete("1.0", "end")
        except Exception:
            return 0

        if not chain:
            try:
                textbox.insert("end", "（无验证链——验证未启动或在传输层失败）",
                                ("insecure",))
                textbox.configure(state="disabled", height=_CHAIN_MIN_H)
            except Exception:
                pass
            return 1

        # Header row.
        try:
            header = "  Zone".ljust(28) + "DS/DNSKEY".ljust(24) \
                      + "摘要算法".ljust(14) + "说明\n"
            textbox.insert("end", header, ("header",))
        except Exception:
            pass

        lines = 1
        for i, link in enumerate(chain):
            mark, mark_tag = self._dnssec_link_mark(link, is_root=(i == 0))
            ds_txt, ds_tag = self._dnssec_ds_cell(link, is_root=(i == 0))
            key_txt, key_tag = self._dnssec_key_cell(link)
            try:
                textbox.insert("end", f"{mark} ", (mark_tag, "mark"))
                textbox.insert("end",
                                (link.zone or "").ljust(26), ("zone",))
                # DS / DNSKEY cell — two coloured sub-tokens on the
                # same line.  Width budget 22 chars total.
                textbox.insert("end", ds_txt.ljust(10), (ds_tag,))
                textbox.insert("end", " ", ())
                textbox.insert("end", key_txt.ljust(12), (key_tag,))
                textbox.insert("end",
                                (link.algorithm or "").ljust(14),
                                ("dim",))
                textbox.insert("end",
                                (link.note or "") + "\n", ("note",))
                lines += 1
            except Exception:
                # Best-effort — keep going so a partial render still
                # surfaces something.
                pass

        try:
            textbox.configure(state="disabled")
            # Resize: header + N chain rows, clamped 6..14.
            h_lines = max(6, min(14, lines))
            textbox.configure(
                height=h_lines * _CHAIN_LINE_PX + _CHAIN_PAD_PX)
        except Exception:
            pass
        return lines

    def _dnssec_link_mark(self, link: DnsSecLink, *, is_root: bool):
        """Pick the mark glyph + tag for a single chain row.

        Precedence (same as the Web renderer):
          • dnskey_ok && (root OR ds_ok)            → ✓ secure_ok
          • !has_ds && !is_root                     → ○ insecure
          • has_ds && !ds_ok                        → ✗ bogus
          • has_ds && (!has_dnskey || !dnskey_ok)   → ✗ bogus
          • otherwise (rare INDET)                  → ⚠ indet
        """
        if link.dnskey_ok and (is_root or link.ds_ok):
            return "✓", "secure_ok"
        if (not is_root) and (not link.has_ds):
            return "○", "insecure"
        if link.has_ds and (not link.ds_ok):
            return "✗", "bogus"
        if link.has_ds and (not link.has_dnskey or not link.dnskey_ok):
            return "✗", "bogus"
        return "⚠", "indet"

    def _dnssec_ds_cell(self, link: DnsSecLink, *, is_root: bool):
        """Text + tag for the DS sub-cell of a chain row."""
        if is_root:
            return "— (根)", "dim"
        if not link.has_ds:
            return "无 DS", "insecure"
        return ("DS ✓", "secure_ok") if link.ds_ok else ("DS ✗", "bogus")

    def _dnssec_key_cell(self, link: DnsSecLink):
        """Text + tag for the DNSKEY sub-cell of a chain row."""
        if not link.has_dnskey:
            return "无 DNSKEY", "dim"
        return ("DNSKEY ✓", "secure_ok") if link.dnskey_ok \
                else ("DNSKEY ✗", "bogus")

    def _setup_auth_tree_tags(self, textbox) -> None:
        """Register all the colour / weight tags used by the tagged
        tree renderer.  Idempotent — safe to call again after a
        theme switch to re-resolve light/dark hex values.

        Tag → visual mapping is documented inline alongside the
        _AUTH_TREE_COLORS table at module top; here we just convert
        the (light, dark) tuples into concrete foregrounds for the
        current appearance mode and attach the small set of
        font-modifier tags ("bold", "italic", "bold_err", …).
        """
        try:
            for name, pair in _AUTH_TREE_COLORS.items():
                textbox.tag_configure(name,
                                      foreground=_resolve_theme_color(pair))
            # Font modifiers — re-use the project's font factory so
            # weight/slant matches the rest of the window.  CTkFont
            # objects are happy to be assigned to tk.Text tags via
            # the `font` option since they expose a Tk-compatible
            # font spec.
            textbox.tag_configure("bold",      font=F(11, "bold"))
            textbox.tag_configure("italic",    font=F(11, "italic"))
            textbox.tag_configure("bold_zone", font=F(11, "bold"))
            textbox.tag_configure("bold_host", font=F(11, "bold"))
        except Exception:
            # Theme not ready / textbox was just torn down — render
            # path will still work (uncoloured) so we don't propagate.
            pass

    def _auth_hop_visual_class(self, hop: DnsAuthHop) -> str:
        """Map a hop to one of {"ok", "bad", "warn"} for colour use.

        Same heuristic as the Web's _dnsAuthHopCls so both UIs paint
        the same hop the same colour — a glue-borrow event lands as
        "warn" (orange) on both sides because the engine carries the
        same '"glue 缺失"' substring in hop.message.
        """
        if hop is None or not hop.success:
            return "bad"
        if "glue 缺失" in (hop.message or ""):
            return "warn"
        return "ok"

    def _render_auth_tree_colored(self, textbox,
                                  result: DnsAuthResult) -> int:
        """Paint the trace tree into `textbox` with per-segment colour
        tags.  Returns the line count so the caller can size the
        textbox.

        Layout (per hop):
            ├─ <zone>  → <host> (<ip>)   <rtt> · <rcode>
               <answer_summary or apex note>
               NS:   ns1, ns2, ns3
               glue: ns1 → 1.2.3.4
               glue: ns2 → 5.6.7.8
               <engine message>      (only if it adds info)

        We deliberately drop the rev1 depth-indent staircase (which
        pushed deep hops to the right and made 8+ hop traces hard to
        scan); matches the Web rev2 layout.
        """
        # ── Insertion helper.  Captures the textbox + line counter ──
        # in a closure so the per-hop code reads top-to-bottom without
        # threading state through every call.
        line_count = [1]
        def _w(s: str, *tags: str) -> None:
            if not s:
                return
            try:
                if tags:
                    textbox.insert("end", s, tags)
                else:
                    textbox.insert("end", s)
            except Exception:
                pass
            line_count[0] += s.count("\n")

        try:
            textbox.configure(state="normal")
            textbox.delete("1.0", "end")
        except Exception:
            return 1

        hops = list(result.hops or [])
        if not hops:
            _w("（未生成任何追踪步骤）", "info", "italic")
            try: textbox.configure(state="disabled")
            except Exception: pass
            return 1

        for i, hop in enumerate(hops):
            is_last = (i == len(hops) - 1)
            cls     = self._auth_hop_visual_class(hop)
            zone_tag = ("zone_bad" if cls == "bad"
                        else "zone_warn" if cls == "warn"
                        else "zone_ok")

            # Blank line between hops (cheap visual breathing room
            # without the dashed-border noise we tried in web rev1).
            if i > 0:
                _w("\n")

            # ── Header line ─────────────────────────────────────────
            prefix = "└─" if is_last else "├─"
            _w(prefix, "prefix")
            _w(" ")
            if not hop.success and hop.rcode in ("NXDOMAIN",
                                                  "SERVFAIL",
                                                  "REFUSED"):
                _w("✗ ", "bad_mark", "bold")
            zone_disp = ". (root)" if hop.zone == "." else (hop.zone or "")
            _w(zone_disp, zone_tag, "bold_zone")
            _w("  ")
            _w("→", "arrow")
            _w(" ")
            host = hop.server_host or ""
            ip   = hop.server_ip   or ""
            if host:
                _w(host, "dest_host", "bold_host")
                if ip:
                    _w(" (", "dest_ip")
                    _w(ip, "dest_ip")
                    _w(")", "dest_ip")
            elif ip:
                _w(ip, "dest_ip")
            else:
                _w("—", "dest_ip")
            _w("   ")
            if hop.rtt_ms is not None and hop.rtt_ms >= 0:
                _w(f"{hop.rtt_ms:.1f} ms", "rtt")
            else:
                _w("—", "rtt")
            if hop.rcode:
                _w(" · ", "rtt")
                rc_tag = ("rcode_bad"
                          if (not hop.success and hop.rcode
                              in ("NXDOMAIN", "SERVFAIL", "REFUSED"))
                          else "rtt")
                _w(hop.rcode, rc_tag)

            # ── Body lines (each indented under the header) ─────────
            body_indent = "   "

            if hop.answer_summary:
                _w("\n")
                _w(body_indent)
                # Apex pivot summary deserves a green hint colour to
                # signal "this is intentional, not an error".
                if "已到权威 zone" in hop.answer_summary:
                    _w(hop.answer_summary, "apex_note", "italic")
                else:
                    _w(hop.answer_summary, "info", "italic")

            ref = list(hop.referral_ns or [])
            if len(ref) > 2:
                _w("\n")
                _w(body_indent)
                _w("NS:   ", "label")
                for j, n in enumerate(ref):
                    if j > 0:
                        _w(", ", "label")
                    _w(n.rstrip("."), "ns_name")

            for g in (hop.glue or []):
                _w("\n")
                _w(body_indent)
                _w("glue: ", "label")
                # Glue strings come from the engine as
                # "ns1.example.com → 1.2.3.4".  Split so we can
                # green-tag just the IP — that's the operationally
                # interesting bit (the hostname is already in the
                # NS line above).
                if " → " in g:
                    name_part, ip_part = g.split(" → ", 1)
                    _w(name_part.strip(), "glue_name")
                    _w(" → ", "glue_arrow")
                    _w(ip_part.strip(), "glue_ip", "bold")
                else:
                    _w(g, "info")

            if hop.message and hop.message != hop.answer_summary:
                _w("\n")
                _w(body_indent)
                if cls == "bad":
                    _w(hop.message, "err", "bold")
                elif cls == "warn":
                    _w(hop.message, "warn")
                elif "已到权威 zone" in hop.message:
                    _w(hop.message, "apex_note", "italic")
                else:
                    _w(hop.message, "info", "italic")

        try:
            textbox.configure(state="disabled")
        except Exception:
            pass
        return line_count[0]

    def _format_auth_tree_text(self, result: DnsAuthResult) -> str:
        """Compose the monospace tree string for a DnsAuthResult.

        Returns a multi-line string where each hop owns:
          • one HEADER line: indent + arrow + zone + → host (ip) + rtt + rcode
          • optional SUB lines (each indent-aligned with the header):
              - answer_summary (the engine's pre-formatted short text)
              - "NS:  ns1.x, ns2.x, ns3.x"  (when referral_ns has > 2 entries)
              - "glue: ns1 → 1.2.3.4; …"   (when ADDITIONAL had glue)
              - the engine's message (when distinct from answer_summary —
                this is where glue-borrow / CNAME-follow notes land)
              - "✗ <error_label>"          (only on failed hops)

        The tree is the same conceptual artefact rendered by the Web
        side's `_renderDnsAuthBlock`; we keep the indent / arrow glyphs
        identical so an operator switching between the two UIs sees
        the same structure.
        """
        hops = list(result.hops or [])
        if not hops:
            return "（未生成任何追踪步骤）"
        lines: list = []
        for i, hop in enumerate(hops):
            is_last = (i == len(hops) - 1)
            indent  = "   " * i
            arrow   = "└─" if is_last else "├─"
            sub_indent = indent + "   "
            zone_disp = "." if hop.zone == "." else hop.zone
            if hop.zone == ".":
                zone_disp = ". (root)"
            host = hop.server_host or ""
            ip   = hop.server_ip   or ""
            dst  = f"{host} ({ip})" if host else (ip or "—")
            rtt  = (f"{hop.rtt_ms:.1f} ms"
                    if (hop.rtt_ms is not None and hop.rtt_ms >= 0)
                    else "—")
            mark = "✗ " if not hop.success else ""
            rcode_bit = f" · {hop.rcode}" if hop.rcode else ""
            lines.append(
                f"{indent}{arrow} {mark}{zone_disp}  → {dst}  {rtt}{rcode_bit}"
            )
            if hop.answer_summary:
                lines.append(f"{sub_indent}{hop.answer_summary}")
            ref = list(hop.referral_ns or [])
            if len(ref) > 2:
                ns_disp = ", ".join(n.rstrip(".") for n in ref)
                lines.append(f"{sub_indent}NS:   {ns_disp}")
            for g in (hop.glue or []):
                lines.append(f"{sub_indent}glue: {g}")
            # Engine message — only when it adds info beyond the
            # answer_summary (glue-borrow / CNAME continuation / error).
            if hop.message and hop.message != hop.answer_summary:
                tag = "✗ " if (not hop.success and hop.error_code) else "  "
                lines.append(f"{sub_indent}{tag}{hop.message}")
        return "\n".join(lines)

    def _render_auth_result(self, result: DnsAuthResult):
        """Populate the auth view from a DnsAuthResult.

        Mirrors _render_compare_result's structure: flip buttons,
        update the verdict bar (colour + text), paint the tree, fill
        the optional answer table, drop the conclusion echo.
        """
        self._set_buttons(running=False)

        if result.success:
            self._set_status("权威追踪完成")
        else:
            self._set_status("权威追踪失败", error=True)

        # Verdict bar — same colour palette as compare.
        ok_mark = "✓" if result.success else "✗"
        if result.success:
            verdict_color = ("#15803d", "#86efac")
            bar_bg        = ("#dcfce7", "#14532d")
            bar_border    = ("#86efac", "#16a34a")
        else:
            verdict_color = ("#b91c1c", "#fca5a5")
            bar_bg        = ("#fee2e2", "#7f1d1d")
            bar_border    = ("#fca5a5", "#dc2626")
        verdict_txt = (f"{ok_mark}  {result.message or ''}    "
                       f"总耗时 {result.elapsed_ms:.1f} ms")
        try:
            self._auth_verdict_lbl.configure(
                text=verdict_txt, text_color=verdict_color)
            self._auth_verdict_frame.configure(
                fg_color=bar_bg, border_color=bar_border)
        except Exception:
            pass

        # Metadata strip.
        meta_parts = [
            f"目标: {result.target}",
            f"类型: {result.qtype}",
            f"跳数: {len(result.hops or [])}",
        ]
        if result.cname_chain and len(result.cname_chain) >= 2:
            meta_parts.append(
                "CNAME 链: " + " → ".join(result.cname_chain))
        try:
            self._auth_meta_lbl.configure(text="    ".join(meta_parts))
        except Exception:
            pass

        # Tree.  Phase 3C-4 polish: re-apply tag palette before each
        # render so a runtime theme switch (light↔dark via the system
        # menu) immediately picks up new foregrounds; then defer the
        # painting to the tagged renderer.  Falls back to plain-text
        # rendering if the tagged path raises — better an uncoloured
        # tree than no tree at all.
        try:
            self._setup_auth_tree_tags(self._auth_tree_box)
            n = self._render_auth_tree_colored(self._auth_tree_box, result)
        except Exception:
            tree_text = self._format_auth_tree_text(result)
            try:
                self._auth_tree_box.configure(state="normal")
                self._auth_tree_box.delete("1.0", "end")
                self._auth_tree_box.insert("end", tree_text)
                self._auth_tree_box.configure(state="disabled")
            except Exception:
                pass
            n = max(1, tree_text.count("\n") + 1)
        try:
            # Resize the tree box to fit content, clamping between
            # 6 and 18 lines.  Past 18 lines the textbox's own
            # scrollbar takes over.
            h = max(6 * _CHAIN_LINE_PX + _CHAIN_PAD_PX,
                    min(18 * _CHAIN_LINE_PX + _CHAIN_PAD_PX,
                        n * _CHAIN_LINE_PX + _CHAIN_PAD_PX))
            self._auth_tree_box.configure(height=h)
        except Exception:
            pass

        # Answer rows — only populated on success with non-empty
        # final_answers.  Clear unconditionally first so a previous
        # success → failure flip doesn't leave stale rows behind.
        try:
            for child in self._auth_answers_frame.winfo_children():
                try: child.destroy()
                except Exception: pass
        except Exception:
            pass
        if result.success and result.final_answers:
            self._render_answer_rows_into(
                self._auth_answers_frame, result.final_answers,
                compact=False)
            try:
                self._auth_answers_frame.grid()
            except Exception: pass
        else:
            # Hide the answer frame entirely on failure / empty so a
            # tall empty card doesn't dilute the tree's prominence.
            try:
                self._auth_answers_frame.grid_remove()
            except Exception: pass

        # Conclusion echo — coloured to match the verdict bar so a
        # quick glance at the bottom of a long trace still conveys
        # the outcome without scrolling back to the top.  Background
        # echoes the verdict bar's bar_bg with a softer tone so it
        # reads as "related summary" rather than competing with the
        # verdict bar itself.
        try:
            self._auth_conclusion.configure(state="normal")
            self._auth_conclusion.delete("1.0", "end")
            prefix = "✓ " if result.success else "✗ "
            self._auth_conclusion.insert(
                "end", prefix + (result.message or ""))
            self._auth_conclusion.configure(
                state="disabled",
                text_color=verdict_color,
                fg_color=(
                    ("#f0fdf4", "#052e16") if result.success
                    else ("#fef2f2", "#450a0a")))
        except Exception:
            pass

        # Outer view is a ScrollableFrame — refresh its autohide bar.
        try:
            view = self._auth_view
            if view is not None:
                self.after_idle(self._autohide_scrollbar, view)
        except Exception:
            pass

    def _switch_view(self, mode: str):
        """Show the requested result view; hide the others.

        mode ∈ {"single", "compare", "auth", "dnssec"}.  Compare, auth,
        and dnssec views are built lazily on first request so the
        window-open cost for users who never touch those modes stays
        unchanged from 3B.  Each is a top-level container with its own
        widget tree and state; switching never leaks data between
        views (e.g. a compare chip list won't appear in a dnssec render).
        """
        # Always hide the inactive views first so a stale frame from
        # a previous mode doesn't bleed through during the swap.
        if self._single_view is not None:
            try: self._single_view.grid_remove()
            except Exception: pass
        if self._compare_view is not None:
            try: self._compare_view.grid_remove()
            except Exception: pass
        if self._auth_view is not None:
            try: self._auth_view.grid_remove()
            except Exception: pass
        if getattr(self, "_dnssec_view", None) is not None:
            try: self._dnssec_view.grid_remove()
            except Exception: pass

        # Phase 3C-5 polish — every view that wraps content in a
        # CTkScrollableFrame (compare, auth, dnssec) has its scrollbar
        # forcibly shown by default until _autohide_scrollbar measures
        # the bbox.  Without the after_idle trigger below, switching
        # into an EMPTY view (e.g. user clicks 多解析器对比 before
        # running anything) leaves a lone scrollbar floating to the
        # right of a blank panel — see the bug report attached image 5.
        # We call autohide on every switch, not just on result-render,
        # so the empty initial state is also clean.
        if mode == "compare":
            if self._compare_view is None:
                self._compare_view = self._build_compare_view(
                    self._view_container)
            try:
                self._compare_view.grid(row=0, column=0, sticky="nsew")
            except Exception: pass
            try:
                # Hide first, then let autohide re-show only on real
                # overflow — prevents the outer compare bar from
                # sticking visible through a transient layout pass.
                self._hide_scrollbar_now(self._compare_view)
                diff = getattr(self, "_compare_diff_frame", None)
                if diff is not None:
                    self._hide_scrollbar_now(diff)
                self._refresh_compare_scrollbars()
            except Exception: pass
        elif mode == "auth":
            if self._auth_view is None:
                self._auth_view = self._build_auth_view(
                    self._view_container)
            try:
                self._auth_view.grid(row=0, column=0, sticky="nsew")
            except Exception: pass
            try:
                self.after_idle(self._autohide_scrollbar, self._auth_view)
            except Exception: pass
        elif mode == "dnssec":
            if getattr(self, "_dnssec_view", None) is None:
                self._dnssec_view = self._build_dnssec_view(
                    self._view_container)
            try:
                self._dnssec_view.grid(row=0, column=0, sticky="nsew")
            except Exception: pass
            try:
                self.after_idle(self._autohide_scrollbar, self._dnssec_view)
            except Exception: pass
        else:
            try:
                self._single_view.grid(row=0, column=0, sticky="nsew")
            except Exception: pass
            # Single view doesn't wrap content in an outer ScrollableFrame,
            # but its inner _results scrollable list could also be sitting
            # on a stale "needs-bar" state from a previous run.
            try:
                self.after_idle(self._update_results_scrollbar)
            except Exception: pass

    def _on_resolver_mode_change(self):
        """Enable / disable the custom-IP entry to reflect mode.

        We don't clear the entry's content when switching back to
        system-default — operators often flip modes while comparing,
        and forcing them to re-type 1.1.1.1 every time would be hostile.
        The value just becomes inert (state=disabled) until they flip
        back to 自定义.

        No-op when in compare mode: the entry is unconditionally enabled
        there (it's the mandatory 对照解析器 input), so toggling the
        single-mode segmented control underneath would only confuse the
        Tk state machine.  Compare mode hides this segmented button, so
        in practice the user never reaches this codepath while compare
        is selected, but the gate makes the intent explicit.
        """
        if self._is_compare_mode():
            return
        is_custom = (self._resolver_mode.get() == "自定义")
        try:
            self._ns_entry.configure(
                state="normal" if is_custom else "disabled")
        except Exception:
            pass
        if is_custom:
            try:
                self._ns_entry.focus_set()
            except Exception:
                pass

    def _is_compare_mode(self) -> bool:
        """True iff 查询模式 == 多解析器对比.

        Tiny helper so every gate site reads the same way and we don't
        sprinkle the Chinese literal everywhere.  Used by the start
        path (sends mode=compare), the resolver-row state machine
        (disables single-mode pills), and the result rendering branch.
        """
        try:
            return self._query_mode.get() == "多解析器对比"
        except Exception:
            return False

    def _is_auth_mode(self) -> bool:
        """Phase 3C-4 — True iff 查询模式 == 权威追踪.

        Auth mode is fully exclusive from the other two: it hides both
        resolver rows, disables the CNAME-chain checkbox, and renders
        into a third top-level view (_auth_view) instead of either
        _single_view or _compare_view.
        """
        try:
            return self._query_mode.get() == "权威追踪"
        except Exception:
            return False

    def _is_dnssec_mode(self) -> bool:
        """Phase 3C-5 — True iff 查询模式 == DNSSEC 验证.

        Behaviourally close to single mode: the same single-mode resolver
        row is shown (the resolver IS used, as a DO=1 + CD=1 transport),
        but the CNAME-chain checkbox is force-disabled (the engine
        chases CNAMEs internally to find the leaf zone) and the result
        renders into a dedicated _dnssec_view container with its own
        verification chain table, four-state verdict bar, and answer
        table — none of which exist on the single view.
        """
        try:
            return self._query_mode.get() == "DNSSEC 验证"
        except Exception:
            return False

    def _on_query_mode_change(self):
        """React to a 查询模式 flip.

        Compare mode (3C-3):
          • Hide `_single_resolver_row`; show `_compare_resolver_row`.
          • Relabel "解析器:" → "对照解析器:" so the chip list's purpose
            reads naturally.
          • Hint text picks up the compare-specific note.

        Trace_auth mode (3C-4):
          • Hide BOTH resolver rows — the engine walks from root and
            ignores any operator-supplied resolver IP.
          • Relabel "解析器:" → "权威追踪:" so the label slot still
            anchors the row visually but makes its current purpose
            (just a label, no input) self-explanatory.
          • Disable CNAME-chain checkbox — chasing is built into the
            engine (one-step end-segment follow) and the toggle would
            mislead operators into thinking they control it.

        Single mode:
          • Reverse the above; restore the 3B entry's enabled state
            from the current resolver_mode value.  Chip list state is
            preserved across the flip so a user who builds a 3-IP
            compare set, switches to single, then back to compare
            sees their chips intact (mirrors Web behaviour).
        """
        is_compare = self._is_compare_mode()
        is_auth    = self._is_auth_mode()
        is_dnssec  = self._is_dnssec_mode()

        # Phase 3C-5 — single-mode resolver row is shown for BOTH
        # single and dnssec; hidden for compare and auth.  Dnssec uses
        # the same row because the resolver is the transport for
        # fetching DNSKEY / DS / target rrsets.
        try:
            if is_compare or is_auth: self._single_resolver_row.grid_remove()
            else:                     self._single_resolver_row.grid()
        except Exception: pass
        try:
            if is_compare:            self._compare_resolver_row.grid()
            else:                     self._compare_resolver_row.grid_remove()
        except Exception: pass

        if is_auth:
            try: self._resolver_lbl.configure(text="权威追踪:")
            except Exception: pass
        elif is_compare:
            try: self._resolver_lbl.configure(text="对照解析器:")
            except Exception: pass
            try: self._compare_input_entry.focus_set()
            except Exception: pass
            # Refresh chip strip + counter + add-button enabledness in
            # case _compare_ns_list changed while we were away (rare
            # but possible via _replay_history → re-render path).
            self._render_compare_chips()
        elif is_dnssec:
            # Same row as single — label is "传输解析器:" to make it
            # obvious the IP is a transport carrier, not the validator
            # (the validator IS the local trust anchor + this code).
            try: self._resolver_lbl.configure(text="传输解析器:")
            except Exception: pass
            self._on_resolver_mode_change()
        else:
            try: self._resolver_lbl.configure(text="解析器:")
            except Exception: pass
            self._on_resolver_mode_change()

        # Hint text changes mention compare / auth / dnssec modes
        # explicitly, so refresh whenever query mode flips (also re-
        # evaluates the CNAME-chain checkbox enabledness via
        # _update_chain_hint).
        self._update_chain_hint()

        # Phase 3C-4 / 3C-5: switch the active view eagerly so an
        # operator flipping mode BEFORE running anything sees the
        # right empty skeleton instead of a stale panel.
        # _render_any_result still re-asserts on result arrival, so
        # this is purely a UX nicety.
        if is_dnssec:
            self._switch_view("dnssec")
        elif is_auth:
            self._switch_view("auth")
        elif is_compare:
            self._switch_view("compare")
        else:
            self._switch_view("single")

    def _apply_preset_ns(self, ip: str):
        """Single-mode preset: fill the entry and flip mode to 自定义.

        Why flip the mode: a preset click only makes sense as "I want
        this IP" — leaving mode at 系统默认 with a populated entry would
        look broken because the value would still be ignored at start.
        """
        try:
            self._resolver_mode.set("自定义")
            self._ns_var.set(ip)
            self._on_resolver_mode_change()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Phase 3C-3: compare-mode chip list helpers
    # ------------------------------------------------------------------

    def _render_compare_chips(self):
        """Rebuild the chip strip + counter + add/preset enabledness.

        Called whenever `_compare_ns_list` mutates AND whenever the
        compare row is about to become visible.  Cheap: at most 3
        chip widgets + 3 preset buttons get touched per render.
        """
        # Destroy old chips.  We don't reuse them because chip count
        # is bounded (≤ 3) and the per-chip command needs to bind the
        # CURRENT index, which changes on every removal.
        try:
            for child in self._compare_chip_row.winfo_children():
                try: child.destroy()
                except Exception: pass
        except Exception:
            return

        n = len(self._compare_ns_list)
        if n == 0:
            ctk.CTkLabel(
                self._compare_chip_row,
                text="尚未选择对照解析器",
                font=F(10), text_color="gray50",
                anchor="w").pack(side="left", padx=10, pady=5)
        else:
            for idx, ip in enumerate(self._compare_ns_list):
                # Each chip is a small frame holding the IP label and
                # an × close button.  Purple accent matches the Web
                # `.dns-cmp-ns-chip` palette so the two UIs feel related.
                chip = ctk.CTkFrame(
                    self._compare_chip_row,
                    fg_color=("#ede9fe", "#3b2f6b"),
                    corner_radius=12, height=24,
                    border_width=1,
                    border_color=("#c4b5fd", "#7c3aed"))
                chip.pack(side="left", padx=(6, 0), pady=4)
                ctk.CTkLabel(
                    chip, text=ip, font=F(10),
                    text_color=("#5b21b6", "#c4b5fd"),
                ).pack(side="left", padx=(10, 2), pady=1)
                ctk.CTkButton(
                    chip, text="×", width=22, height=20, font=F(11, "bold"),
                    fg_color="transparent",
                    hover_color=("#c4b5fd", "#5b21b6"),
                    text_color=("#5b21b6", "#c4b5fd"),
                    command=lambda i=idx: self._remove_compare_ns(i),
                ).pack(side="left", padx=(0, 2), pady=0)

        # Counter colour + add-button / preset-button enabledness.
        full = (n >= _MAX_COMPARE_CUSTOM_NS)
        try:
            self._compare_count_lbl.configure(
                text=f"已选 {n}/{_MAX_COMPARE_CUSTOM_NS}",
                text_color=("#dc2626" if full else "gray50"))
        except Exception:
            pass
        try:
            self._compare_add_btn.configure(
                state="disabled" if full else "normal")
        except Exception:
            pass
        # Preset buttons: disabled when the list is full, OR (subtler)
        # when this specific IP is already in the list — clicking
        # would just bounce off the dedup check.
        for ip, b in zip(_DNS_PRESETS, self._compare_preset_btns):
            try:
                if full or ip in self._compare_ns_list:
                    b.configure(state="disabled")
                else:
                    b.configure(state="normal")
            except Exception:
                pass

    def _add_compare_ns(self, ip: str):
        """Append an IP to the chip list (de-dup, validate, cap).

        Surfaces validation errors via _set_status so the operator
        sees them in the status line under the action buttons.
        """
        ip = (ip or "").strip()
        if not ip:
            self._set_status("请输入有效的 IP", error=True)
            return
        err = _validate_nameserver(ip)
        if err is not None:
            self._set_status(err, error=True)
            return
        if ip in self._compare_ns_list:
            self._set_status(f"已添加该解析器：{ip}", error=True)
            return
        if len(self._compare_ns_list) >= _MAX_COMPARE_CUSTOM_NS:
            self._set_status(
                f"最多支持 {_MAX_COMPARE_CUSTOM_NS} 个对照解析器",
                error=True)
            return
        self._compare_ns_list.append(ip)
        self._render_compare_chips()
        self._set_status("")

    def _add_compare_ns_from_input(self):
        """Pull the current input value and add it; clear on success.

        Keeps focus on the entry so the operator can keep typing IPs
        without re-clicking the box — matches the Web Enter-to-add flow.
        """
        ip = (self._compare_input_var.get() or "").strip()
        before = len(self._compare_ns_list)
        self._add_compare_ns(ip)
        if len(self._compare_ns_list) > before:
            # Added successfully — clear input and refocus.
            try:
                self._compare_input_var.set("")
                self._compare_input_entry.focus_set()
            except Exception:
                pass

    def _remove_compare_ns(self, idx: int):
        """Pop chip at `idx` (called from chip's × button)."""
        if 0 <= idx < len(self._compare_ns_list):
            self._compare_ns_list.pop(idx)
            self._render_compare_chips()
            self._set_status("")

    def _update_chain_hint(self):
        """Hint text + checkbox enabledness reflect qtype/mode.

        Why this matters: users selecting MX/NS but expecting CNAME
        expansion to follow is a common misunderstanding.  We surface
        the rule explicitly (hint text) AND physically disable the
        checkbox outside A/AAAA — the server-side ignores trace_chain
        for those qtypes anyway, so an enabled but inert toggle is just
        misleading.

        In compare mode we add a sentence about the verdict policy so
        a green "一致" badge isn't misread as "the resolvers agree on
        every byte" (TTL drift is normal and gets a sidenote, not a
        red flag).

        Phase 3C-4: trace_auth uses its OWN hint (the engine walks
        delegation, ignores custom resolvers, may take longer due to
        cross-continent UDP round-trips) AND unconditionally disables
        the trace_chain checkbox — CNAME chasing is performed by the
        engine internally, the toggle would be misleading.
        """
        qt = self._qtype_var.get()
        is_aaaa = qt in ("A", "AAAA")
        is_auth   = self._is_auth_mode()
        is_dnssec = self._is_dnssec_mode()
        if is_auth:
            base = ("权威追踪从 IPv4 根服务器迭代查询 delegation 链至权威 "
                    "NS，再查目标 qtype。本模式不使用系统或自定义解析器，"
                    "不验证 DNSSEC。\n需本机可访问公网 UDP/53；专网封外网"
                    "时第一跳即超时。")
            if qt in ("A", "AAAA"):
                base += ("\n若权威返回 CNAME，引擎会对 CNAME 目标自动再做"
                         "一次完整追踪（共享 12 跳上限）。")
        elif is_dnssec:
            base = ("DNSSEC 验证：本机独立验证签名链（root → TLD → leaf），"
                    "DO=1 + CD=1 抓取 DNSKEY / DS / RRSIG 后在客户端校验，"
                    "不信任解析器的 AD 位。\n"
                    "四态结果：SECURE（已签名通过）/ INSECURE（zone 未签名，"
                    "常见且非故障）/ BOGUS（签名错误）/ INDETERMINATE（未能判定）。"
                    "\n建议选用 1.1.1.1 / 8.8.8.8 等公共解析器作为传输，"
                    "以避免运营商递归剥离 RRSIG 记录。")
        else:
            if is_aaaa:
                base = ("DNS 诊断为高级工具，请按需手动执行。\n"
                        "A / AAAA 查询会按所选项自动展开 CNAME 链至终端 IP。")
            else:
                base = ("DNS 诊断为高级工具，请按需手动执行。\n"
                        f"已选 {qt}：仅查询该类型，不自动跟随 CNAME。"
                        "如需 IP 解析请改用 A / AAAA。")
            if self._is_compare_mode():
                base += ("\n对比仅比较答案值集合；CNAME 链 / TTL 差异"
                         "会作为提示附加，不影响一致判定。")
        try:
            self._hint_lbl.configure(text=base)
        except Exception:
            pass
        try:
            # Trace_auth + dnssec both lock the checkbox regardless of
            # qtype — both engines handle CNAME chasing internally.
            # Other modes honour the existing A/AAAA-only gate.
            allow = (is_aaaa and not is_auth and not is_dnssec)
            self._trace_chk.configure(
                state="normal" if allow else "disabled")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _start(self):
        domain  = (self._domain_var.get() or "").strip()
        qtype   = self._qtype_var.get()
        try:
            timeout = float(self._timeout_var.get())
        except ValueError:
            self._set_status("超时格式不正确", error=True)
            return

        # Phase 3C-1 / 3C-3 / 3C-4 / 3C-5: dispatch on the 查询模式 toggle.
        #   • single     → single optional custom NS via _ns_var
        #   • compare    → list of 1..3 chips in _compare_ns_list
        #   • trace_auth → no resolver input; engine walks from root
        #   • dnssec     → single optional custom NS via _ns_var
        #                  (transport for DO+CD fetches; engine still
        #                  validates client-side against embedded anchor)
        is_compare = self._is_compare_mode()
        is_auth    = self._is_auth_mode()
        is_dnssec  = self._is_dnssec_mode()
        ns: Optional[str] = None
        nss: Optional[list] = None
        if is_auth:
            # Trace_auth: engine ignores both single NS and chip list.
            # We don't try to be clever about preserving them either —
            # the operator sees the resolver row hidden so there's no
            # surprise.  trace_chain is irrelevant (engine handles
            # CNAME chasing); pass False to keep the engine quiet.
            mode = "trace_auth"
        elif is_dnssec:
            # Phase 3C-5: dnssec — same resolver-row UX as single mode.
            # 系统默认 → ns=None (engine builds a default resolver and
            # asks the OS for nameservers); 自定义 → operator IP.
            if self._resolver_mode.get() == "自定义":
                ns = (self._ns_var.get() or "").strip()
                if not ns:
                    self._set_status("请输入解析器 IP", error=True)
                    return
            mode = "dnssec"
        elif is_compare:
            # As a courtesy, also slurp any pending text the operator
            # typed but didn't click "+ 添加" — saves a click on the
            # common "I typed an IP then hit Start" path.
            pending = (self._compare_input_var.get() or "").strip()
            if pending:
                before = len(self._compare_ns_list)
                self._add_compare_ns(pending)
                # _add_compare_ns may have surfaced an error and
                # rejected — only clear the input if it actually landed.
                if len(self._compare_ns_list) > before:
                    try: self._compare_input_var.set("")
                    except Exception: pass
            if not self._compare_ns_list:
                self._set_status("请至少添加 1 个对照解析器 IP", error=True)
                return
            nss = list(self._compare_ns_list)
            mode = "compare"
        elif self._resolver_mode.get() == "自定义":
            # Phase 3B path — entry must be non-empty if custom mode.
            ns = (self._ns_var.get() or "").strip()
            if not ns:
                self._set_status("请输入解析器 IP", error=True)
                return
            mode = "single"
        else:
            ns = None
            mode = "single"

        req = DnsDiagRequest(
            target      = domain,
            qtype       = qtype,
            timeout_s   = timeout,
            trace_chain = bool(self._trace_var.get()),
            nameserver  = ns,
            nameservers = nss,
            mode        = mode,
        )

        # Sync validation so user gets immediate feedback for empty /
        # malformed input without spinning up a thread.
        from src.dns_diag import validate_dns_request
        err = validate_dns_request(req)
        if err:
            self._set_status(err, error=True)
            return

        self._clear_results()
        self._set_buttons(running=True)
        # Phase 3C-4: eagerly switch to the right view BEFORE the
        # async runner starts so the operator sees the correct empty
        # skeleton instead of whichever view was last visible.  The
        # result-arrival path (_render_any_result) re-asserts, but
        # that fires after the first ~tens-of-ms of UDP, during which
        # a stale single-view "summary line" would look misleading.
        if is_auth:
            self._switch_view("auth")
            self._set_status(
                f"正在从根追踪 {domain} ({qtype}) 的权威 NS …")
        elif is_dnssec:
            # Phase 3C-5: dnssec spinner — mention the resolver only
            # when explicit (system default is implied otherwise).
            self._switch_view("dnssec")
            ns_disp = f"（经由 {ns}）" if ns else ""
            self._set_status(
                f"正在验证 {domain} ({qtype}) 的 DNSSEC 签名链{ns_disp} …")
        elif is_compare:
            self._switch_view("compare")
            # Build a short summary string for the spinner.  Same
            # truncation rule as the Web /status text — first IP plus
            # "+N" tail so a 3-IP set doesn't blow out the status line.
            if len(nss) == 1:
                ns_disp = nss[0]
            else:
                ns_disp = f"{nss[0]}, +{len(nss) - 1}"
            self._set_status(f"正在对比解析（系统 → {ns_disp}）…")
        else:
            self._switch_view("single")
            self._set_status(f"正在解析 {domain} ({qtype}) …")

        self._task = run_dns_diag_async(
            req,
            on_done    = self._on_done,
            on_error   = self._on_error,
            data_store = self._data_store,
            target_id  = self._target_id,
        )

    def _stop(self):
        if self._task:
            self._task.cancel()
        self._set_status("已停止")
        self._set_buttons(running=False)

    # ------------------------------------------------------------------
    # Async callbacks — must marshal to Tk thread via after()
    # ------------------------------------------------------------------

    def _on_done(self, result):
        """Receive either a DnsDiagResult (single) or DnsCompareResult.

        The async runner picks the result type based on req.mode; we
        dispatch off isinstance rather than self._is_compare_mode()
        because the user may have flipped the mode toggle while the
        run was in flight, and the rendered result must always match
        what was actually queried.
        """
        try:
            self.after(0, lambda r=result: self._render_any_result(r))
        except Exception:
            pass

    def _on_error(self, msg: str):
        try:
            self.after(0, lambda m=msg: (
                self._set_status(m, error=True),
                self._set_buttons(running=False),
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Result rendering
    # ------------------------------------------------------------------

    def _clear_results(self):
        """Wipe both single AND compare views' contents.

        We clear unconditionally (regardless of which is currently
        visible) because the user may toggle 查询模式 between
        consecutive runs, and leftover state in the inactive view
        would confuse a later switch.  Cheap — both clears are
        no-ops on already-empty widgets.
        """
        # --- single view ---
        for child in self._results.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass
        for box in (self._chain_box, self._conclusion):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")
        self._summary_lbl.configure(text="")
        # Reset chain box to its minimum height + hide the results
        # scrollbar so re-running on a different domain doesn't leave a
        # tall chain box / lingering scrollbar from the previous query.
        try:
            self._chain_box.configure(height=_CHAIN_MIN_H)
        except Exception:
            pass
        self.after_idle(self._update_results_scrollbar)
        # --- auth view (only if it's been built) — 3C-4 ---
        if self._auth_view is not None:
            try:
                self._auth_verdict_lbl.configure(text="")
                self._auth_verdict_frame.configure(
                    fg_color=("gray92", "gray22"),
                    border_color=("gray80", "gray30"))
                self._auth_meta_lbl.configure(text="")
            except Exception:
                pass
            try:
                self._auth_tree_box.configure(state="normal")
                self._auth_tree_box.delete("1.0", "end")
                self._auth_tree_box.configure(state="disabled")
            except Exception:
                pass
            try:
                for child in self._auth_answers_frame.winfo_children():
                    try: child.destroy()
                    except Exception: pass
                self._auth_answers_frame.grid_remove()
            except Exception:
                pass
            try:
                self._auth_conclusion.configure(state="normal")
                self._auth_conclusion.delete("1.0", "end")
                self._auth_conclusion.configure(state="disabled")
            except Exception:
                pass
            try:
                view = self._auth_view
                if view is not None:
                    self.after_idle(self._autohide_scrollbar, view)
            except Exception:
                pass
        # --- dnssec view (only if it's been built) — 3C-5 ---
        if getattr(self, "_dnssec_view", None) is not None:
            try:
                self._dnssec_verdict_lbl.configure(text="")
                self._dnssec_verdict_frame.configure(
                    fg_color=("gray92", "gray22"),
                    border_color=("gray80", "gray30"))
                self._dnssec_meta_lbl.configure(text="")
                self._dnssec_extra_lbl.configure(text="")
            except Exception:
                pass
            try:
                self._dnssec_chain_box.configure(state="normal")
                self._dnssec_chain_box.delete("1.0", "end")
                self._dnssec_chain_box.configure(state="disabled")
            except Exception:
                pass
            try:
                for child in self._dnssec_answers_frame.winfo_children():
                    try: child.destroy()
                    except Exception: pass
                self._dnssec_answers_frame.grid_remove()
            except Exception:
                pass
            try:
                self._dnssec_conclusion.configure(state="normal")
                self._dnssec_conclusion.delete("1.0", "end")
                self._dnssec_conclusion.configure(state="disabled")
            except Exception:
                pass
            try:
                self.after_idle(self._autohide_scrollbar, self._dnssec_view)
            except Exception:
                pass
        # --- compare view (only if it's been built) — 3C-1.5 / 3C-3 ---
        if self._compare_view is not None:
            try:
                self._verdict_lbl.configure(text="")
                # Reset the verdict pill to neutral colours so a stale
                # green/red background doesn't linger while the next run
                # is in flight.
                self._verdict_frame.configure(
                    fg_color=("gray92", "gray22"),
                    border_color=("gray80", "gray30"))
            except Exception:
                pass
            # Clear the diff matrix card.
            try:
                for child in self._compare_diff_frame.winfo_children():
                    try: child.destroy()
                    except Exception: pass
            except Exception:
                pass
            # Phase 3C-3: destroy every detail panel (their widgets are
            # rebuilt fresh each render via _rebuild_compare_detail_panels).
            try:
                for child in self._details_container.winfo_children():
                    try: child.destroy()
                    except Exception: pass
            except Exception:
                pass
            self._compare_detail_panels = {}
            try:
                self._compare_conclusion.configure(state="normal")
                self._compare_conclusion.delete("1.0", "end")
                self._compare_conclusion.configure(state="disabled")
            except Exception:
                pass
            # Re-evaluate both compare-view scrollbars now that content
            # is wiped — otherwise a previous run's "needed" bar lingers
            # over an empty frame until the next render fires.
            self._refresh_compare_scrollbars()

    def _render_any_result(self, result):
        """Dispatch on result type — single / compare / trace_auth.

        Picks the correct view AND triggers a view swap so the layout
        always matches the result kind, even if the user flipped the
        mode toggle mid-run.  Phase 3C-4 adds the DnsAuthResult branch;
        the cancelled sentinel reuses DnsDiagResult shape (decision A
        in the 3C-4 plan) so it falls through to the single branch
        regardless of which mode actually issued the request — which
        is fine because cancelled rendering doesn't care about the
        original mode beyond status-text wording.
        """
        if isinstance(result, DnsCompareResult):
            self._switch_view("compare")
            self._render_compare_result(result)
        elif isinstance(result, DnsAuthResult):
            self._switch_view("auth")
            self._render_auth_result(result)
        elif isinstance(result, DnsSecResult):
            # Phase 3C-5: dedicated dnssec render path.  DnsSecResult
            # NEVER carries a rcode == ERROR_CANCELLED because cancel
            # is detected upstream and substituted with the canonical
            # DnsDiagResult sentinel (see run_dns_diag_async).
            self._switch_view("dnssec")
            self._render_dnssec_result(result)
        else:
            # Single mode OR cancelled sentinel from
            # compare/trace_auth/dnssec.  In each case the single-view
            # rendering branch is the right home — _render_result
            # already handles the cancelled ERROR_CANCELLED rcode path
            # explicitly.  Don't force a switch back to single if the
            # user was running trace_auth / dnssec and just cancelled —
            # keep the active view visible so any partial state stays
            # on screen alongside the "■ 查询已取消" wording.
            if (getattr(result, "rcode", "") == ERROR_CANCELLED
                    and self._is_auth_mode()):
                self._set_buttons(running=False)
                self._set_status("已停止")
                try:
                    self._auth_conclusion.configure(state="normal")
                    self._auth_conclusion.delete("1.0", "end")
                    self._auth_conclusion.insert("end", "■ 权威追踪已取消")
                    self._auth_conclusion.configure(state="disabled")
                except Exception:
                    pass
                return
            if (getattr(result, "rcode", "") == ERROR_CANCELLED
                    and self._is_dnssec_mode()):
                # Phase 3C-5 — same cancellation polish for dnssec.
                # Persistence layer skipped the partial chain so the
                # history list will NOT show the cancelled run; we
                # just paint a clear cancellation marker on the
                # current view and stay where we are.
                self._set_buttons(running=False)
                self._set_status("已停止")
                try:
                    self._dnssec_conclusion.configure(state="normal")
                    self._dnssec_conclusion.delete("1.0", "end")
                    self._dnssec_conclusion.insert(
                        "end", "■ DNSSEC 验证已取消")
                    self._dnssec_conclusion.configure(state="disabled")
                except Exception:
                    pass
                return
            self._switch_view("single")
            self._render_result(result)

    def _render_result(self, result: DnsDiagResult):
        self._set_buttons(running=False)
        cancelled = (result.rcode == ERROR_CANCELLED)
        if cancelled:
            # Synthetic result built by run_dns_diag_async when the user
            # clicked Stop mid-query.  Keep UI minimal — no chain / no
            # answer rows — and surface a clear "已取消" conclusion.
            self._set_status("已停止")
            self._summary_lbl.configure(text="")
            self._chain_box.configure(state="normal")
            self._chain_box.delete("1.0", "end")
            self._chain_box.configure(state="disabled")
            try:
                self._chain_box.configure(height=_CHAIN_MIN_H)
            except Exception:
                pass
            self._conclusion.configure(state="normal")
            self._conclusion.delete("1.0", "end")
            self._conclusion.insert("end", "■ 查询已取消")
            self._conclusion.configure(state="disabled")
            self.after_idle(self._update_results_scrollbar)
            return
        if result.success:
            self._set_status("查询完成")
        else:
            label = ERROR_LABELS.get(
                first_failing_step_code(result) or "", "")
            self._set_status(f"查询失败：{label or result.message}",
                             error=True)

        # Summary line — resolver / rcode / elapsed always shown.
        summary = (f"解析器: {result.resolver}    "
                   f"RCODE: {result.rcode or '—'}    "
                   f"耗时: {result.elapsed_ms:.1f} ms")
        self._summary_lbl.configure(text=summary)

        # ── CNAME chain box ──
        chain_text = self._format_chain_text(result)
        self._chain_box.configure(state="normal")
        self._chain_box.delete("1.0", "end")
        self._chain_box.insert("end", chain_text)
        self._chain_box.configure(state="disabled")
        self._fit_chain_box(chain_text)

        # ── Answer rows ──
        self._render_answer_rows(result.answers)
        # After rows are gridded, hide the scrollable-frame scrollbar
        # when the content fits the visible canvas — defer to after_idle
        # so Tk has actually laid the rows out before we measure.
        self.after_idle(self._update_results_scrollbar)

        # ── Conclusion ──
        msg = result.message or ""
        if not result.success and not msg:
            msg = "查询失败，详见上方日志。"
        self._conclusion.configure(state="normal")
        self._conclusion.delete("1.0", "end")
        self._conclusion.insert("end", msg)
        self._conclusion.configure(state="disabled")

    def _format_chain_text(self, result: DnsDiagResult) -> str:
        """Build the monospace tree string for a DnsDiagResult's chain.

        Shared between the single-mode rendering and the compare
        side-panels so the chain looks IDENTICAL in either view —
        differences between layouts would make compare visually
        misleading.  Returns "(无 CNAME 链)" placeholder when the
        chain is empty.
        """
        chain = result.cname_chain or []
        if not chain:
            return "(无 CNAME 链)"
        text = ""
        for i, name in enumerate(chain):
            if i == 0:
                text += name + "\n"
            else:
                indent = "  " * i
                text += f"{indent}└─ CNAME {name}\n"
        if result.qtype in ("A", "AAAA"):
            indent = "  " * len(chain)
            for ans in result.answers:
                text += f"{indent}└─ {ans.qtype} {ans.value}\n"
        return text

    # ------------------------------------------------------------------
    # Phase 3C-1.5 — diff-first compare result rendering
    # ------------------------------------------------------------------

    def _render_compare_result(self, compare: DnsCompareResult):
        """Render verdict bar, diff matrix, and N detail panels.

        Cancelled-state handling is unified with single mode: a
        cancelled compare run arrives as a synthetic DnsDiagResult
        with rcode == ERROR_CANCELLED (see run_dns_diag_async's
        _build_cancelled), so it never reaches THIS function.  This
        function is always invoked with a real DnsCompareResult.

        Detail-panel default state (3C-3 generalisation of 3C-1.5):
        expanded when there's something worth looking at — any verdict
        failure OR any side's CNAME chain signature differs from side 0's.
        Otherwise all panels stay collapsed so the user sees just the
        matrix + verdict.
        """
        self._set_buttons(running=False)

        if compare.success:
            self._set_status("对比完成 — 答案一致")
        else:
            self._set_status("对比完成 — 结果不一致", error=True)

        # Verdict bar — text + colour together; pill background is set
        # on _verdict_frame so success/failure is immediately readable.
        ok_mark = "✓" if compare.success else "✗"
        if compare.success:
            verdict_color = ("#15803d", "#86efac")
            bar_bg        = ("#dcfce7", "#14532d")
            bar_border    = ("#86efac", "#16a34a")
        else:
            verdict_color = ("#b91c1c", "#fca5a5")
            bar_bg        = ("#fee2e2", "#7f1d1d")
            bar_border    = ("#fca5a5", "#dc2626")
        verdict_txt = (f"{ok_mark}  {compare.conclusion or ''}    "
                       f"总耗时 {compare.elapsed_ms:.1f} ms")
        try:
            self._verdict_lbl.configure(
                text=verdict_txt, text_color=verdict_color)
            self._verdict_frame.configure(
                fg_color=bar_bg, border_color=bar_border)
        except Exception:
            pass

        # ── Diff matrix (main view) ──
        # Phase 3C-3: build_compare_diff_matrix takes the side list
        # directly (sides[] is the canonical container).  Empty sides
        # would be a bug — render an empty matrix so the user sees
        # the verdict text rather than a crash.
        sides = list(compare.sides or [])
        diff = build_compare_diff_matrix(sides)
        self._render_compare_diff_table(diff)

        # ── Rebuild detail panels (one per side, in order) ──
        self._rebuild_compare_detail_panels(sides)

        # ── Auto-expand decision ──
        # Any chain divergence triggers expand for ALL panels so the
        # operator can scan every side's chain side-by-side without
        # clicking each panel open.
        base_sig = (_chain_signature_for_ui(sides[0].result)
                    if sides else tuple())
        chain_div = any(
            _chain_signature_for_ui(s.result) != base_sig
            for s in sides[1:]
        )
        expand = (not compare.success) or chain_div
        for key in list(self._compare_detail_panels.keys()):
            self._compare_detail_panels[key]["open"] = expand
            self._apply_compare_detail_state(key)

        # ── Secondary conclusion box ──
        try:
            self._compare_conclusion.configure(state="normal")
            self._compare_conclusion.delete("1.0", "end")
            self._compare_conclusion.insert("end",
                                             compare.conclusion or "")
            self._compare_conclusion.configure(state="disabled")
        except Exception:
            pass

        # ── Auto-hide scrollbars when content fits ──
        # Deferred so Tk has finished laying out the new widgets before
        # we ask the canvas for its bbox.  Without this the bars would
        # flash visible on every fresh render even if content fits.
        self._refresh_compare_scrollbars()

    def _rebuild_compare_detail_panels(self, sides: list):
        """Phase 3C-3 — destroy old panels and build one per side.

        Why rebuild on every render rather than reuse widgets: the
        panel COUNT varies between runs (a 2-side history row replayed
        right after a 4-side live run, or vice-versa), and the panel
        labels carry side.label which can also change.  Building fresh
        is cheaper than reconciling, and each panel's child widgets
        (chain box, answer table, "追踪此 IP" buttons) are themselves
        rebuilt unconditionally inside _render_compare_detail_panel.
        """
        # Destroy any leftovers.
        try:
            for child in self._details_container.winfo_children():
                try: child.destroy()
                except Exception: pass
        except Exception:
            pass
        self._compare_detail_panels = {}

        if not sides:
            return

        # Reset row weights to all-0 so a leftover weight from a longer
        # previous run doesn't pad empty space.  We then explicitly set
        # weight=1 on EACH body row so the table inside the panel can
        # stretch.
        # CTk doesn't expose grid_size().resetWeights, so we just
        # over-set up to the current panel count.
        for i in range(2 * len(sides)):
            try:
                self._details_container.grid_rowconfigure(
                    i, weight=(1 if i % 2 else 0))
            except Exception:
                pass

        for i, side in enumerate(sides):
            accent = (("#1d4ed8", "#93c5fd") if i == 0
                      else ("#7e22ce", "#d8b4fe"))
            label = (side.label or "").strip() or (
                "系统默认" if i == 0 else f"解析器 {i}"
            )
            btn = ctk.CTkButton(
                self._details_container,
                text=f"▶ {label} — 详情", anchor="w",
                font=F(11, "bold"), height=30, corner_radius=6,
                fg_color=("gray86", "gray22"),
                hover_color=("gray78", "gray28"),
                text_color=accent,
                command=lambda k=side.key: self._toggle_compare_detail(k))
            btn.grid(row=2 * i, column=0, sticky="ew", pady=(2, 0))
            body = ctk.CTkFrame(
                self._details_container,
                fg_color=("gray94", "gray19"), corner_radius=8,
                border_width=1, border_color=("gray82", "gray26"))
            body.grid(row=2 * i + 1, column=0, sticky="nsew", pady=(2, 6))
            body.grid_remove()
            # Populate body contents (chain box + answer table + msg).
            self._render_compare_detail_panel(
                body, side.result, accent=accent)
            self._compare_detail_panels[side.key] = {
                "btn": btn, "body": body, "open": False,
                "label": label, "accent": accent,
            }

    def _render_compare_diff_table(self, diff: dict):
        """Render the diff matrix dynamically for N sides.

        D3: value column gets uniform weight=3, each side column
        weight=2 — at 4 columns this gives roughly 33% value /
        ~22% per side, mirroring the Web layout.  uniform="diffcol"
        keeps the header row and each data row in lockstep so column
        edges line up visually.
        """
        frm = self._compare_diff_frame
        for child in frm.winfo_children():
            try: child.destroy()
            except Exception: pass

        # Phase 3C-3 — `side_labels` may arrive as a list (v2 canonical),
        # a dict (legacy 3C-1.5), or empty.  Normalise to a list of
        # {key,label} so the rest of this function only handles one shape.
        raw = diff.get("side_labels") or []
        if isinstance(raw, dict):
            sides_info = [{"key": k, "label": v} for k, v in raw.items()]
        elif isinstance(raw, list):
            sides_info = [
                {"key": s.get("key", ""), "label": s.get("label", "")}
                for s in raw
            ]
        else:
            sides_info = []
        N = len(sides_info)
        rows = diff.get("rows") or []

        def _configure_cols(container):
            # Value column has more weight so long IP / TXT values
            # don't crowd the side columns.  uniform="diffcol" forces
            # header row and data rows to align column edges exactly.
            container.grid_columnconfigure(0, weight=3, uniform="diffcol")
            for i in range(N):
                container.grid_columnconfigure(
                    i + 1, weight=2, uniform="diffcol")

        # Header row.
        hdr = ctk.CTkFrame(frm, fg_color=("gray88", "gray23"),
                           corner_radius=4)
        hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 2))
        _configure_cols(hdr)
        ctk.CTkLabel(hdr, text="值", font=F(10, "bold"),
                     text_color=("gray30", "gray70"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=10, pady=4)
        for i, s in enumerate(sides_info):
            # Side 0 (always system) gets the blue tone; sides 1..N
            # share the purple tone — same eye-grouping rationale as
            # the Web side (see CSS comment in web_server.py).
            color = (("#1d4ed8", "#93c5fd") if i == 0
                     else ("#7e22ce", "#d8b4fe"))
            ctk.CTkLabel(hdr, text=(s["label"] or "—"),
                         font=F(10, "bold"), text_color=color,
                         anchor="w").grid(
                row=0, column=i + 1, sticky="w", padx=10, pady=4)

        if not rows:
            ctk.CTkLabel(frm, text="(无对比数据)",
                         font=F(11), text_color="gray50").grid(
                row=1, column=0, pady=18, padx=12, sticky="w")
            return

        # Wraplength shrinks slightly at 4-column layouts so a long
        # IPv6 / TXT value doesn't push the side columns off-screen.
        wrap_v = 340 if N <= 2 else 260

        for ri, row in enumerate(rows, start=1):
            rf = ctk.CTkFrame(frm, fg_color=("gray93", "gray20"),
                               corner_radius=6)
            rf.grid(row=ri, column=0, sticky="ew", padx=4, pady=2)
            _configure_cols(rf)

            disp = row.get("display", "") or ""
            qt   = row.get("qtype", "") or ""

            val_box = ctk.CTkFrame(rf, fg_color="transparent")
            val_box.grid(row=0, column=0, sticky="ew", padx=8, pady=7)
            ctk.CTkLabel(
                val_box, text=disp, font=F(11),
                anchor="w", justify="left",
                wraplength=wrap_v,
                text_color=("gray12", "gray92")
            ).pack(side="left", anchor="w")
            if qt:
                ctk.CTkLabel(
                    val_box, text=qt, font=F(9, "bold"),
                    text_color=("gray45", "gray65"),
                    fg_color=("gray82", "gray28"),
                    corner_radius=4, width=42, height=18,
                ).pack(side="left", padx=(8, 0), anchor="w")

            cells = row.get("cells") or {}
            for i, s in enumerate(sides_info):
                key = s["key"]
                # Prefer cells[key] (v2); fall back to row[key] for
                # legacy 2-side rows that carry system/custom directly.
                cell = cells.get(key)
                if cell is None:
                    cell = row.get(key) or {}
                txt = cell.get("text", "—") or "—"
                ok = bool(cell.get("ok"))
                color = ("#15803d", "#86efac") if ok \
                        else ("#b91c1c", "#fca5a5")
                ctk.CTkLabel(rf, text=txt, font=F(11, "bold"),
                             text_color=color, anchor="w").grid(
                    row=0, column=i + 1, sticky="w", padx=10, pady=7)

    def _toggle_compare_detail(self, key: str):
        """Flip open/closed state for a detail panel and reflect it."""
        p = self._compare_detail_panels.get(key)
        if not p:
            return
        p["open"] = not p["open"]
        self._apply_compare_detail_state(key)

    def _apply_compare_detail_state(self, key: str):
        """Sync widget visibility / button glyph from `open` flag."""
        p = self._compare_detail_panels.get(key)
        if not p:
            return
        try:
            if p["open"]:
                p["body"].grid()
                p["btn"].configure(text=f"▼ {p['label']} — 详情")
            else:
                p["body"].grid_remove()
                p["btn"].configure(text=f"▶ {p['label']} — 详情")
        except Exception:
            pass
        # Expand / collapse changes the outer view's content height,
        # so the outer scrollbar's "needed?" verdict can flip; refresh.
        self._refresh_compare_scrollbars()

    def _render_compare_detail_panel(self, parent,
                                      result: Optional[DnsDiagResult],
                                      accent: tuple):
        """Populate one collapsible detail panel.

        Layout inside the panel (top to bottom):
          • summary line — RCODE / elapsed / 成功/失败 (mirrors the Web
            detail header so the user sees the same trio in both UIs)
          • CNAME chain monospace box (always present — shows
            "(无 CNAME 链)" placeholder for parity)
          • full answer table — compact=False, wider columns; A/AAAA
            rows get the same 「追踪此 IP」 button as single mode
          • inline message line (failures land here)

        Width assumption: the panel is full-width (~830 px in the 880
        default window), so we use non-compact table column widths.
        """
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)   # answer rows expand

        # Summary line — no separate title bar; the resolver name is
        # already on the detail toggle button right above this panel.
        if result is None:
            summary = "（无数据）"
            sum_col = ("gray45", "gray60")
        elif result.rcode == ERROR_CANCELLED:
            # Defensive — shouldn't happen for compare (cancelled
            # compares short-circuit before _render_compare_result),
            # but render gracefully if a stray cancelled result is
            # surfaced via history replay.
            summary = "已取消"
            sum_col = ("gray45", "gray60")
        else:
            rc  = result.rcode or "—"
            ems = f"{result.elapsed_ms:.1f} ms" \
                  if isinstance(result.elapsed_ms, (int, float)) else "—"
            ok_mark = "✓ 成功" if result.success else "✗ 失败"
            summary = f"{ok_mark}    RCODE: {rc}    耗时: {ems}"
            sum_col = (("#15803d", "#86efac") if result.success
                       else ("#b91c1c", "#fca5a5"))
        ctk.CTkLabel(parent, text=summary, font=F(11, "bold"),
                     text_color=sum_col, anchor="w").grid(
            row=0, column=0, sticky="ew", padx=14, pady=(10, 2))

        # CNAME chain — compact textbox; we don't dynamically resize
        # here because both sides need the same height, and the
        # natural cap (8 lines max) is already enforced by
        # _CHAIN_MAX_H.  Show "(无 CNAME 链)" placeholder for parity.
        chain_text = self._format_chain_text(result) \
                     if result is not None else "(无数据)"
        chain_box = ctk.CTkTextbox(
            parent, height=_CHAIN_MIN_H, font=F(11), wrap="none",
            state="disabled", fg_color=("gray92", "gray19"))
        chain_box.grid(row=2, column=0, sticky="ew",
                        padx=10, pady=(2, 4))
        chain_box.configure(state="normal")
        chain_box.insert("end", chain_text)
        chain_box.configure(state="disabled")
        # Manual fit using the same line-count math as _fit_chain_box.
        n = max(1, chain_text.count("\n") +
                   (0 if chain_text.endswith("\n") else 1))
        h = max(_CHAIN_MIN_H, min(_CHAIN_MAX_H,
                                   n * _CHAIN_LINE_PX + _CHAIN_PAD_PX))
        try: chain_box.configure(height=h)
        except Exception: pass

        # Answer rows — natural-height frame (no inner scroll).
        # 3C-1.5 v2: the OUTER compare view is now a ScrollableFrame,
        # so an inner CTkScrollableFrame here would (a) double-scroll
        # the mouse wheel and (b) cap the visible row count to whatever
        # height we picked, which is exactly the truncation the user
        # reported in v1.  Letting the table grow naturally + outer
        # scrolling is the layout that actually fits N resolvers.
        # compact=False because the detail panel is full-width (no
        # longer competing with a side-by-side sibling for the modal's
        # 680 / 880 px).
        ans_frm = ctk.CTkFrame(
            parent, fg_color=("gray97", "gray15"), corner_radius=6)
        ans_frm.grid(row=3, column=0, sticky="nsew",
                      padx=12, pady=(2, 6))
        ans_frm.grid_columnconfigure(0, weight=1)
        answers = (result.answers if result is not None else []) or []
        self._render_answer_rows_into(ans_frm, answers, compact=False)

        # Per-side message — surface the side's specific failure mode
        # (NXDOMAIN, TIMEOUT, …) so the operator doesn't need to
        # mentally cross-reference the verdict bar with each panel.
        # wraplength matches the panel inner width minus padding.
        msg = ""
        if result is not None and result.message:
            msg = result.message
        elif result is None:
            msg = "（无结果）"
        if msg:
            ctk.CTkLabel(parent, text=msg, font=F(10),
                         text_color=("gray30", "gray70"), anchor="w",
                         wraplength=780, justify="left").grid(
                row=4, column=0, sticky="ew", padx=14, pady=(0, 10))

    def _render_answer_rows_into(self, parent, answers, compact: bool):
        """Render answer rows into an arbitrary parent frame.

        `compact=True` shrinks the column widths so the table fits in
        a narrow container — historically used by 3C-1's side-by-side
        panels.  After 3C-1.5 made compare-mode detail panels
        full-width, compact mode is unused by compare; we keep the
        flag for future callers (e.g. a future "preview" widget) and
        for any in-flight migration of older builds.

        Trace buttons are produced for A/AAAA rows just like the
        single-mode renderer; they reuse the same _open_tracert
        callback so the diagnostic flow stays consistent across modes.
        """
        if not answers:
            ctk.CTkLabel(parent, text="(无返回记录)",
                         font=F(11), text_color="gray50").grid(
                row=0, column=0, pady=14, sticky="w", padx=12)
            return

        if compact:
            cols = ((0, "名称", 110),
                    (1, "类型",  50),
                    (2, "值",   140),
                    (3, "TTL",   46),
                    (4, "操作",  84))
            name_w, qt_w, ttl_w, btn_w = 110, 50, 46, 70
            wrap_v = 130
        else:
            cols = ((0, "名称", 220),
                    (1, "类型",  70),
                    (2, "值",   320),
                    (3, "TTL",   60),
                    (4, "操作", 110))
            name_w, qt_w, ttl_w, btn_w = 220, 70, 60, 98
            wrap_v = 380

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(2, 4))
        hdr.grid_columnconfigure(2, weight=1)
        for col, txt, w in cols:
            ctk.CTkLabel(hdr, text=txt, font=F(10, "bold"),
                         text_color="gray50", anchor="w",
                         width=w).grid(row=0, column=col,
                                       sticky="w", padx=4)

        for i, ans in enumerate(answers, start=1):
            row = ctk.CTkFrame(parent,
                                fg_color=("gray92", "gray19"),
                                corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", padx=4, pady=2)
            row.grid_columnconfigure(2, weight=1)
            ctk.CTkLabel(row, text=ans.name, font=F(11), anchor="w",
                         width=name_w).grid(row=0, column=0,
                                            sticky="w", padx=4, pady=4)
            ctk.CTkLabel(row, text=ans.qtype, font=F(11, "bold"),
                         anchor="w", width=qt_w,
                         text_color=("#1e40af", "#93c5fd")
                         ).grid(row=0, column=1, sticky="w", padx=4)
            ctk.CTkLabel(row, text=ans.value, font=F(11), anchor="w",
                         wraplength=wrap_v, justify="left"
                         ).grid(row=0, column=2, sticky="w", padx=4)
            ttl_txt = str(ans.ttl) if ans.ttl is not None else "—"
            ctk.CTkLabel(row, text=ttl_txt, font=F(11),
                         text_color="gray50", anchor="w", width=ttl_w
                         ).grid(row=0, column=3, sticky="w", padx=4)
            if ans.qtype in ("A", "AAAA"):
                ctk.CTkButton(
                    row, text="追踪此 IP", width=btn_w, height=24,
                    font=F(10),
                    fg_color=("#5B7FA6", "gray25"),
                    hover_color=("#4A6E94", "gray35"),
                    command=lambda ip=ans.value: self._open_tracert(ip),
                ).grid(row=0, column=4, padx=4, pady=2)

    def _render_answer_rows(self, answers: list[DnsAnswer]):
        """Backwards-compatible alias — single-view rendering path.

        Kept as a thin wrapper around _render_answer_rows_into so the
        existing call site in _render_result doesn't need to change
        and any future single-mode-only tweaks have an obvious home.
        """
        self._render_answer_rows_into(self._results, answers,
                                       compact=False)

    def _fit_chain_box(self, chain_text: str):
        """Resize the chain textbox vertically to fit its content.

        Why: a fixed 72 px height showed only ~3 lines, so a 4-step
        CNAME chain (typical for CDN-fronted sites like baidu) was
        clipped.  We count actual visual lines (no wrapping since the
        text is monospace + short) and clamp between _CHAIN_MIN_H /
        _CHAIN_MAX_H — past 8 lines the textbox's own scrollbar takes
        over so the answer table below isn't pushed off-screen.
        """
        if not chain_text:
            n = 1
        else:
            # Trailing "\n" is the cosmetic line-ending after the last
            # entry — don't double-count it.
            n = max(1, chain_text.count("\n") + (0 if chain_text.endswith("\n") else 1))
        h = max(_CHAIN_MIN_H, min(_CHAIN_MAX_H,
                                   n * _CHAIN_LINE_PX + _CHAIN_PAD_PX))
        try:
            self._chain_box.configure(height=h)
        except Exception:
            pass

    def _hide_scrollbar_now(self, scroll) -> None:
        """Immediately remove a CTkScrollableFrame's scrollbar from the
        grid, bypassing the bbox-based autohide measurement.

        Why this exists: `_autohide_scrollbar` measures the canvas
        AFTER Tk has laid out the widget.  On initial widget
        construction the canvas is briefly realised at a small height
        (e.g. 100 px) before geometry propagation finishes settling
        at its real size (e.g. 400 px).  During that interim window
        the autohide may see `content_h > visible_h` and mistakenly
        grid() the scrollbar, where it then stays until something
        re-triggers autohide.

        We sidestep the whole timing dance by HIDING the scrollbar at
        widget-build time — empty content has no overflow anyway —
        and rely on `_autohide_scrollbar` to RE-show it the moment
        real content overflows the visible area.  This makes the
        empty-state UX strictly "no scrollbar visible" without
        depending on layout completion order.
        """
        try:
            bar = getattr(scroll, "_scrollbar", None)
            if bar is not None:
                bar.grid_remove()
        except Exception:
            pass

    def _autohide_scrollbar(self, scroll, _retries: int = 3):
        """Show / hide a CTkScrollableFrame's scrollbar based on overflow.

        Why: CTkScrollableFrame shows its scrollbar unconditionally,
        which looks like UI noise when (as is typical) the content
        fits comfortably in the frame.  We measure the underlying
        canvas's content bbox against its visible height; if content
        fits, grid_remove() the scrollbar; otherwise grid() it back.

        Uses `._parent_canvas` and `._scrollbar` — private attrs, but
        stable across customtkinter 5.x (verified on the version this
        project ships against).  Wrapped in try/except so a future CTk
        rename can't break the diagnostic window — at worst the bar
        stays visible, which is the pre-helper default.

        Phase 3C-5 polish v2: when called from `_switch_view` on a
        freshly-gridded view the canvas may not have completed its
        layout pass yet.  Previously we only retried on the obvious
        "winfo_height() == 1" placeholder, but Tk's geometry manager
        can also expose intermediate "small-but-realistic" values
        mid-relayout (e.g. visible_h ≈ 100 px before settling at
        400 px).  Measuring at that moment with a real content_h of
        300 px wrongly grids the scrollbar back in, which then sticks.

        Fix: schedule an UNCONDITIONAL chain of re-measurements
        (50 / 120 / 280 ms) regardless of the initial outcome.  Each
        pass adjusts the bar based on the latest measurement, so a
        bad early call self-corrects once Tk settles.  This trades a
        few extra idle-callback evaluations for guaranteed convergence
        without any visible bar flicker (grid_remove / grid is cheap
        and doesn't redraw the rounded corners of CTkScrollableFrame
        between calls).
        """
        try:
            scroll.update_idletasks()
            canvas = getattr(scroll, "_parent_canvas", None)
            bar    = getattr(scroll, "_scrollbar",     None)
            if canvas is None or bar is None:
                return
            canvas.update_idletasks()
            bbox = canvas.bbox("all")
            visible_h = canvas.winfo_height()
            # Only act on a measurement when the canvas is realistically
            # sized — otherwise let the retry chain re-evaluate later.
            if visible_h > 1:
                content_h = (bbox[3] - bbox[1]) if bbox else 0
                # +2 px slack absorbs sub-pixel rounding so a perfectly-
                # fit frame doesn't oscillate between showing/hiding.
                if content_h > visible_h + 2:
                    bar.grid()
                else:
                    bar.grid_remove()
            # Always schedule another pass while we still have retry
            # budget — Tk's layout often settles only after multiple
            # idle cycles, especially right after a grid()/grid_remove()
            # of a sibling view, and the first measurement can land at
            # a transient height where content APPEARS to overflow.
            if _retries > 0:
                delay_ms = (50, 120, 280)[3 - _retries]
                self.after(
                    delay_ms,
                    lambda: self._autohide_scrollbar(
                        scroll, _retries - 1))
        except Exception:
            pass

    def _update_results_scrollbar(self):
        """Back-compat wrapper — auto-hide the single-view results bar."""
        self._autohide_scrollbar(self._results)

    def _refresh_compare_scrollbars(self):
        """Re-evaluate both compare-view scrollbars (outer + diff matrix).

        Called after the compare view changes shape — initial render
        and every detail-panel toggle.  Defers via after_idle so the
        bbox math runs once Tk has actually laid out the new content.
        """
        try:
            view = self._compare_view
            if view is not None:
                self.after_idle(self._autohide_scrollbar, view)
            diff = getattr(self, "_compare_diff_frame", None)
            if diff is not None:
                self.after_idle(self._autohide_scrollbar, diff)
        except Exception:
            pass

    def _open_tracert(self, ip: str):
        """Spawn a TracerouteResultWindow for the given IP.

        Multiple windows are allowed (user might trace different IPs in
        sequence), but each instance individually acquires the global
        diag sem — so two parallel runs aren't possible regardless.

        The on_close_callback pops the window out of self._tracert_windows
        so the list does NOT grow unbounded across many traces; the
        cleanup loop in _on_close only runs on parent close and only
        needs to deal with windows still alive at that moment.
        """
        max_hops = 30
        if self._get_max_hops is not None:
            try:
                v = self._get_max_hops()
                if isinstance(v, int) and v > 0:
                    max_hops = v
            except Exception:
                pass

        # NOTE: TracerouteResultWindow calls on_close_callback() with no
        # arguments (see ui/traceroute_result_window.py:243), so we
        # capture the window reference via closure.  The ref is rebound
        # right after construction — bind-by-name via default arg won't
        # work because `win` doesn't exist yet inside the closure body
        # at definition time.
        holder = {}
        def _on_child_close():
            w = holder.get("w")
            if w is None: return
            try:
                self._tracert_windows.remove(w)
            except ValueError:
                pass   # already gone — _on_close cleanup or duplicate fire

        win = TracerouteResultWindow(
            parent=self, ip=ip, max_hops=max_hops,
            on_close_callback=_on_child_close)
        holder["w"] = win
        self._tracert_windows.append(win)

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
        try:
            self.geometry(DnsDiagWindow._saved_geometry)
            self.update_idletasks()
            wx, wy = self.winfo_x(), self.winfo_y()
            ww, wh = self.winfo_width(), self.winfo_height()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            cx = max(-ww + 100, min(wx, sw - 100))
            cy = max(0,         min(wy, sh - 50))
            if cx != wx or cy != wy:
                self.geometry(f"{ww}x{wh}+{cx}+{cy}")
        except Exception:
            self.geometry("720x640")

    def _on_close(self):
        try:
            geo = self.geometry()
            if geo and "x" in geo:
                DnsDiagWindow._saved_geometry = geo
        except Exception:
            pass

        if self._task:
            try:
                self._task.cancel()
            except Exception:
                pass

        # Close any spawned traceroute child windows so they don't linger
        # as orphans pointing at a destroyed parent — same defensive
        # pattern IcmpDiagWindow uses for its history sub-window.
        for w in list(self._tracert_windows):
            try:
                if w.winfo_exists():
                    w.destroy()
            except Exception:
                pass
        self._tracert_windows.clear()

        # Close child history window if open — otherwise it becomes
        # orphaned and clicking its rows would call back into a destroyed
        # parent (mirror of IcmpDiagWindow._on_close).
        hist = getattr(self, "_history_win", None)
        if hist is not None:
            try: hist.destroy()
            except Exception: pass
            self._history_win = None

        if self._on_close_cb:
            try:
                self._on_close_cb()
            except Exception:
                pass
        self.destroy()

    def _sync_history_list_scrollbar(self, listbox):
        self._hide_scrollbar_now(listbox)
        self.after_idle(self._autohide_scrollbar, listbox)

    def _bind_history_scrollbar_sync(self, win, listbox):
        job = [None]

        def _on_configure(_event=None):
            if job[0] is not None:
                try:
                    win.after_cancel(job[0])
                except Exception:
                    pass
            job[0] = win.after(150, lambda: self._sync_history_list_scrollbar(listbox))

        win.bind("<Configure>", _on_configure, add="+")

    # ------------------------------------------------------------------
    # History list (Phase 3A)
    # ------------------------------------------------------------------

    def _open_history(self):
        """Open (or focus) the DNS diagnostic-history list window.

        Filters by target_id when available, otherwise unfiltered.
        Behaviour mirrors IcmpDiagWindow._open_history so users see the
        same UI shape across the two diagnostic tools.
        """
        existing = getattr(self, "_history_win", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift(); existing.focus_force(); return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        win.title(f"DNS 诊断历史 — {self._label}")
        win.geometry("780x460")
        win.minsize(620, 320)
        win.lift(); win.focus_force()
        self._history_win = win

        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(win, fg_color=("gray88", "gray15"),
                            corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text=f"📜 DNS 历史诊断记录  ({self._label})",
                     font=F(12, "bold")).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(hdr, text="🔄 刷新", width=70, height=26, font=F(11),
                      fg_color=("gray70", "gray30"),
                      hover_color=("gray55", "gray40"),
                      command=lambda: self._refresh_history_list(listbox)
                      ).pack(side="right", padx=8, pady=6)

        listbox = ctk.CTkScrollableFrame(win,
                                          fg_color=("gray95", "gray16"))
        listbox.grid(row=1, column=0, sticky="nsew",
                      padx=10, pady=(8, 10))
        listbox.grid_columnconfigure(0, weight=1)
        self._hide_scrollbar_now(listbox)
        self._bind_history_scrollbar_sync(win, listbox)

        self._refresh_history_list(listbox)

        def _on_close():
            self._history_win = None
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", _on_close)

    def _refresh_history_list(self, listbox):
        """Re-query DB and re-render row list (mirror ICMP)."""
        try:
            for child in listbox.winfo_children():
                try:
                    child.destroy()
                except Exception:
                    pass

            if self._data_store is None:
                ctk.CTkLabel(listbox,
                             text="DataStore 未初始化，无法读取历史",
                             font=F(11), text_color="gray50").grid(
                    row=0, column=0, pady=20)
                return

            try:
                rows = self._data_store.get_dns_diag_history(
                    target_id=self._target_id, limit=100)
            except Exception as e:
                ctk.CTkLabel(listbox, text=f"读取失败：{e}",
                             font=F(11), text_color="#ef4444").grid(
                    row=0, column=0, pady=20)
                return

            if not rows:
                ctk.CTkLabel(
                    listbox,
                    text="暂无历史记录。完成一次 DNS 诊断后将在此列出。",
                    font=F(11), text_color="gray50").grid(
                    row=0, column=0, pady=20)
                return

            import datetime

            for i, rec in enumerate(rows):
                ts_str = datetime.datetime.fromtimestamp(
                    rec["created_ts"]).strftime("%Y-%m-%d %H:%M:%S")

                qtype  = rec.get("qtype", "?")
                domain = rec.get("domain", "")
                ok     = bool(rec.get("success"))
                rcode  = rec.get("rcode") or "—"
                n_ans  = rec.get("answer_count", 0) or 0
                ems    = rec.get("elapsed_ms")
                ems_s  = (f"{ems:.1f} ms" if isinstance(ems, (int, float))
                          else "—")

                details = rec.get("details") or {}
                d_mode  = details.get("mode") or ""
                sec_status = ""
                if d_mode == "dnssec":
                    sec_status = (rcode or "").upper()
                if d_mode == "dnssec" and sec_status == "INSECURE":
                    fg = ("gray90", "gray22")
                elif d_mode == "dnssec" and sec_status == "INDETERMINATE":
                    fg = ("#ffedd5", "#7c2d12")
                elif ok:
                    fg = ("gray90", "gray22")
                else:
                    fg = ("#fecaca", "#451a1a")

                row = ctk.CTkFrame(listbox, fg_color=fg, corner_radius=6)
                row.grid(row=i, column=0, sticky="ew", padx=6, pady=3)
                row.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(row, text=ts_str, font=F(10),
                             text_color="gray50", anchor="w").grid(
                    row=0, column=0, sticky="w", padx=10, pady=(6, 0))

                if d_mode == "dnssec":
                    if sec_status == "SECURE":
                        badge_color = "#16a34a"
                    elif sec_status == "INSECURE":
                        badge_color = "#6b7280"
                    elif sec_status == "INDETERMINATE":
                        badge_color = "#ea580c"
                    else:
                        badge_color = "#dc2626"
                else:
                    badge_color = "#16a34a" if ok else "#dc2626"
                if d_mode == "compare":
                    mode_tag = "对比  "
                elif d_mode == "trace_auth":
                    mode_tag = "🌲 权威  "
                elif d_mode == "dnssec":
                    mode_tag = "🔐 DNSSEC  "
                else:
                    mode_tag = ""
                summary = (f"{mode_tag}{qtype}  {domain}    "
                           f"RCODE={rcode}    {n_ans} 条记录    {ems_s}")
                ctk.CTkLabel(row, text=summary, font=F(11, "bold"),
                             anchor="w", text_color=badge_color).grid(
                    row=1, column=0, sticky="w", padx=10, pady=(0, 2))

                msg = (rec.get("message") or "")[:140]
                if msg:
                    ctk.CTkLabel(row, text=msg,
                                 font=F(10),
                                 text_color=("gray30", "gray70"),
                                 anchor="w", wraplength=680,
                                 justify="left").grid(
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
            self._sync_history_list_scrollbar(listbox)

    def _replay_history(self, rec: dict):
        """Re-render a historical record into the parent result panel.

        Three modes (Phase 3C-1 + 3C-4):
          • details.mode == "compare"    → rebuild DnsCompareResult,
                                            render via _render_compare_result.
          • details.mode == "trace_auth" → rebuild DnsAuthResult,
                                            render via _render_auth_result.
          • else → rebuild DnsDiagResult and render via _render_result.
            Pre-3C-1 rows without a mode key fall through to this
            single-result path, which keeps legacy snapshots
            replayable byte-for-byte.

        Does NOT re-run the probe in any branch — pure replay.
        """
        details = rec.get("details") or {}
        d_mode  = details.get("mode") or ""

        self._clear_results()
        if d_mode == "compare":
            cmp = self._compare_from_details(rec, details)
            self._switch_view("compare")
            self._render_compare_result(cmp)
        elif d_mode == "trace_auth":
            auth = self._auth_from_details(rec, details)
            self._switch_view("auth")
            self._render_auth_result(auth)
        elif d_mode == "dnssec":
            # Phase 3C-5: dnssec replay.  The persisted detail carries
            # the full dnssec_to_dict shape (chain + answers + ad_flag
            # + status) so inflation is a near-passthrough.
            sec = self._dnssec_from_details(rec, details)
            self._switch_view("dnssec")
            self._render_dnssec_result(sec)
        else:
            pseudo = self._single_from_details(rec, details)
            self._switch_view("single")
            self._render_result(pseudo)
        import datetime
        ts_str = datetime.datetime.fromtimestamp(
            rec["created_ts"]).strftime("%H:%M:%S")
        self._set_status(f"已回放 {ts_str} 的历史记录")

    def _single_from_details(self, rec: dict, details: dict) -> DnsDiagResult:
        """Build a DnsDiagResult from a single-mode history row.

        Extracted from _replay_history so the compare-replay path can
        also call it to inflate the system / custom sub-results inside
        a compare history row's details.
        """
        answers: list[DnsAnswer] = []
        for a in (details.get("answers") or []):
            answers.append(DnsAnswer(
                name       = a.get("name", ""),
                qtype      = a.get("qtype", ""),
                value      = a.get("value", ""),
                ttl        = a.get("ttl"),
                preference = a.get("preference"),
            ))

        steps: list[DnsTraceStep] = []
        for s in (details.get("trace_steps") or []):
            steps.append(DnsTraceStep(
                query_name     = s.get("query_name", ""),
                query_type     = s.get("query_type", ""),
                status         = s.get("status", ""),
                ttl            = s.get("ttl"),
                answer_summary = s.get("answer_summary", ""),
            ))

        return DnsDiagResult(
            target      = details.get("target") or rec.get("domain", ""),
            qtype       = details.get("qtype")  or rec.get("qtype", "A"),
            resolver    = details.get("resolver") or rec.get("resolver") or "",
            success     = bool(details.get("success", rec.get("success"))),
            rcode       = details.get("rcode") or rec.get("rcode") or "",
            elapsed_ms  = details.get("elapsed_ms")
                          if details.get("elapsed_ms") is not None
                          else (rec.get("elapsed_ms") or 0.0),
            cname_chain = list(details.get("cname_chain") or []),
            answers     = answers,
            trace_steps = steps,
            message     = details.get("message") or rec.get("message") or "",
            # Phase 3B snapshot — pre-3B rows simply have no key here, so
            # .get default ("") restores the legacy "system default" view.
            nameserver  = details.get("nameserver") or "",
        )

    def _compare_from_details(self, rec: dict, details: dict
                              ) -> DnsCompareResult:
        """Build a DnsCompareResult from a compare-mode history row.

        Phase 3C-3: detect v2 details (compare_version >= 2 + sides[])
        and inflate the side list directly; fall back to the legacy
        3C-1 `system` / `custom` pair otherwise.  The inner result
        dicts are dns_result_to_dict() shapes either way, so we
        delegate to _single_from_details for inflation.
        """
        ver = details.get("compare_version") or 1
        sides: list = []

        if ver >= 2 and isinstance(details.get("sides"), list) \
                and details["sides"]:
            for i, s in enumerate(details["sides"]):
                sub_d = s.get("result") or {}
                sub_res = self._single_from_details(rec, sub_d)
                key = s.get("key") or ("system" if i == 0 else f"r{i}")
                label = s.get("label") or (sub_res.resolver or "")
                sides.append(DnsCompareSide(
                    key=str(key), label=str(label), result=sub_res))
        else:
            # 3C-1 fallback — synthesise the canonical 2-side list.
            sys_d = details.get("system") or {}
            cus_d = details.get("custom") or {}
            if sys_d:
                sys_res = self._single_from_details(rec, sys_d)
                sides.append(DnsCompareSide(
                    key="system",
                    label=(sys_res.resolver or "系统默认"),
                    result=sys_res))
            if cus_d:
                cus_res = self._single_from_details(rec, cus_d)
                sides.append(DnsCompareSide(
                    key="custom",
                    label=(cus_res.resolver
                           or details.get("nameserver") or "自定义"),
                    result=cus_res))

        # 3C-3: prefer the canonical list, fall back to the 3C-1 scalar.
        nss = details.get("nameservers")
        if isinstance(nss, list) and nss:
            nameservers = [str(x) for x in nss if x]
        elif details.get("nameserver"):
            nameservers = [str(details.get("nameserver"))]
        else:
            nameservers = []

        return DnsCompareResult(
            target      = details.get("target") or rec.get("domain", ""),
            qtype       = details.get("qtype")  or rec.get("qtype", "A"),
            trace_chain = bool(details.get("trace_chain", True)),
            nameservers = nameservers,
            sides       = sides,
            success     = bool(details.get("success",
                                            rec.get("success"))),
            conclusion  = details.get("conclusion")
                          or rec.get("message") or "",
            elapsed_ms  = details.get("elapsed_ms")
                          if details.get("elapsed_ms") is not None
                          else (rec.get("elapsed_ms") or 0.0),
        )

    def _auth_from_details(self, rec: dict, details: dict
                           ) -> DnsAuthResult:
        """Phase 3C-4 — build a DnsAuthResult from a trace_auth history row.

        Mirror of _compare_from_details for the auth payload.  Walks
        the stored `hops` and `answers` arrays back into typed
        DnsAuthHop / DnsAnswer instances so the renderer code path is
        identical between live runs and history replay.
        """
        hops: list = []
        for h in (details.get("hops") or []):
            hops.append(DnsAuthHop(
                hop_index      = int(h.get("hop_index", 0) or 0),
                zone           = h.get("zone", "") or "",
                qname          = h.get("qname", "") or "",
                qtype          = h.get("qtype", "") or "",
                server_host    = h.get("server_host", "") or "",
                server_ip      = h.get("server_ip", "") or "",
                rcode          = h.get("rcode", "") or "",
                rtt_ms         = float(h.get("rtt_ms", -1.0)
                                       if h.get("rtt_ms") is not None
                                       else -1.0),
                success        = bool(h.get("success", False)),
                answer_summary = h.get("answer_summary", "") or "",
                referral_ns    = list(h.get("referral_ns") or []),
                glue           = list(h.get("glue") or []),
                error_code     = h.get("error_code", "") or "",
                message        = h.get("message", "") or "",
            ))
        answers: list = []
        for a in (details.get("answers") or []):
            answers.append(DnsAnswer(
                name       = a.get("name", ""),
                qtype      = a.get("qtype", ""),
                value      = a.get("value", ""),
                ttl        = a.get("ttl"),
                preference = a.get("preference"),
            ))
        return DnsAuthResult(
            target        = details.get("target") or rec.get("domain", ""),
            qtype         = details.get("qtype")  or rec.get("qtype", "A"),
            hops          = hops,
            final_answers = answers,
            success       = bool(details.get("success",
                                              rec.get("success"))),
            rcode         = details.get("rcode") or rec.get("rcode") or "",
            elapsed_ms    = (details.get("elapsed_ms")
                             if details.get("elapsed_ms") is not None
                             else (rec.get("elapsed_ms") or 0.0)),
            message       = details.get("message")
                            or rec.get("message") or "",
            cname_chain   = list(details.get("cname_chain") or []),
        )

    def _dnssec_from_details(self, rec: dict, details: dict
                              ) -> DnsSecResult:
        """Phase 3C-5 — build a DnsSecResult from a dnssec history row.

        Mirror of _auth_from_details for the dnssec payload.  Walks
        the stored `chain` and `answers` arrays back into typed
        DnsSecLink / DnsAnswer instances so the renderer is identical
        between live runs and replay.

        The persisted rcode column carries the four-state verdict in
        UPPER case ("SECURE"/"INSECURE"/"BOGUS"/"INDETERMINATE");
        DnsSecResult.status is the same value in lower case.  Prefer
        details.status when present (canonical), otherwise lower-case
        the row's rcode for backward-compat with hypothetical future
        rows missing the status key.
        """
        chain: list = []
        for l in (details.get("chain") or []):
            chain.append(DnsSecLink(
                zone       = l.get("zone", "") or "",
                has_ds     = bool(l.get("has_ds", False)),
                ds_ok      = bool(l.get("ds_ok", False)),
                has_dnskey = bool(l.get("has_dnskey", False)),
                dnskey_ok  = bool(l.get("dnskey_ok", False)),
                algorithm  = l.get("algorithm", "") or "",
                note       = l.get("note", "") or "",
            ))
        answers: list = []
        for a in (details.get("answers") or []):
            answers.append(DnsAnswer(
                name       = a.get("name", ""),
                qtype      = a.get("qtype", ""),
                value      = a.get("value", ""),
                ttl        = a.get("ttl"),
                preference = a.get("preference"),
            ))
        # Status fallback: prefer details.status, then lower(rcode).
        raw_status = (details.get("status")
                      or (rec.get("rcode") or "indeterminate"))
        status = str(raw_status).strip().lower() or "indeterminate"
        if status not in ("secure", "insecure", "bogus", "indeterminate"):
            status = "indeterminate"
        ad_flag = details.get("ad_flag", None)
        if ad_flag is not None:
            ad_flag = bool(ad_flag)
        return DnsSecResult(
            target      = details.get("target") or rec.get("domain", ""),
            qtype       = details.get("qtype")  or rec.get("qtype", "A"),
            resolver    = details.get("resolver")
                          or rec.get("resolver") or "",
            nameserver  = details.get("nameserver") or "",
            status      = status,  # type: ignore[arg-type]
            chain       = chain,
            answers     = answers,
            rrsig_ok    = bool(details.get("rrsig_ok", False)),
            ad_flag     = ad_flag,
            elapsed_ms  = (details.get("elapsed_ms")
                           if details.get("elapsed_ms") is not None
                           else (rec.get("elapsed_ms") or 0.0)),
            message     = (details.get("message")
                            or rec.get("message") or ""),
            cname_chain = list(details.get("cname_chain") or []),
        )


def _chain_signature_for_ui(r) -> tuple:
    """Module-level CNAME chain signature for the compare UI's auto-
    expand decision.  Kept here (rather than imported from dns_diag)
    because the engine's _chain_signature is intentionally private and
    we want the UI's expand-vs-collapse rule readable in isolation.

    A `None` side or one without a chain returns an empty tuple, so two
    "no-chain" sides compare equal and the panels stay collapsed.
    """
    if r is None or not getattr(r, "cname_chain", None):
        return tuple()
    return tuple((n or "").rstrip(".").lower() for n in r.cname_chain)
