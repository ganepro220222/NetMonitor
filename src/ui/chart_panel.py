from __future__ import annotations
"""
chart_panel.py
--------------
Self-driven latency trend chart.

Key design decisions in this version:

Hover crosshair (C1)
  We use matplotlib's motion_notify_event to track the cursor. On each
  mouse move we update three lightweight artists (a vertical dashed line,
  a filled circle at the nearest data point, and a text annotation) and
  call canvas.draw_idle(). draw_idle() is cheap when the data artists
  haven't changed — it just marks the canvas dirty and lets tkinter
  repaint on the next idle cycle. The 1-second timer's canvas.draw()
  also picks up the crosshair position, so the crosshair is always in
  sync regardless of which path triggers the redraw.

Performance (C3)
  REFRESH_MS is now 1500 ms instead of 1000 ms. Halving the chart
  redraw frequency halves the CPU spent on canvas.draw() calls.
  Style updates (axis colors, grid) are only applied in apply_theme(),
  never in the per-cycle _render_chart(), eliminating unnecessary
  matplotlib state mutations every second.
"""

import customtkinter as ctk

try:
    import matplotlib
    matplotlib.use("TkAgg")
    matplotlib.rcParams["toolbar"] = "None"
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib.ticker as ticker
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from src.ui.fonts import FONT_FAMILY

if MATPLOTLIB_AVAILABLE:
    matplotlib.rcParams["font.family"] = [FONT_FAMILY, "DejaVu Sans", "sans-serif"]
    matplotlib.rcParams["axes.unicode_minus"] = False

THEMES = {
    "dark": {
        "bg": "#1e1e1e", "line": "#4dd0e1", "fill": "#4dd0e1",
        "warn_line": "#F39C12", "loss": "#E74C3C",
        "grid": "#2d2d2d", "tick": "#5a5a5a", "stats": "#7a7a7a", "spine": "#333333",
        "crosshair": "#888888", "dot": "#ffffff", "tooltip_bg": "#333333",
    },
    "light": {
        "bg": "#f4f4f4", "line": "#0277bd", "fill": "#0277bd",
        "warn_line": "#e65100", "loss": "#b71c1c",
        "grid": "#e0e0e0", "tick": "#777777", "stats": "#999999", "spine": "#cccccc",
        "crosshair": "#999999", "dot": "#333333", "tooltip_bg": "#555555",
    },
}



# ──────────────────────────────────────────────────────────────────────────
# ChartCoordinator — single-timer staggered chart scheduler
# ──────────────────────────────────────────────────────────────────────────
#
# Problem solved:
#   With N charts open, each had its own after(1500ms) loop. Over time they
#   drifted and occasionally piled up: multiple synchronous canvas redraws
#   back-to-back within one event-loop cycle → stuttering & "low refresh"
#   feel. Switching to draw_idle() helps but staggering renders is the real
#   fix — it spreads CPU load evenly so the event loop stays responsive.
#
# How it works:
#   All ChartPanel instances register here. One shared after() loop fires
#   every STEP_MS and renders exactly ONE chart per tick (round-robin).
#   For 9 charts at STEP_MS=200ms each chart gets refreshed every 1800ms —
#   fast enough to look live, slow enough to never overload the CPU.
#
class ChartCoordinator:
    _charts: list = []
    _index:  int  = 0
    _running: bool = False
    STEP_MS:  int  = 400   # ms between individual chart renders
    # With N charts round-robining: each chart refreshes every N×400ms.
    # 1 chart = 400ms,  3 charts = 1200ms,  5 charts = 2000ms.
    # Previous 200ms caused the UI thread to stay busy even with 1 chart open.

    _paused: bool = False   # set True during theme changes to skip renders
    _wheel_bound: bool = False   # bind_all fires on every register(); only bind once

    @classmethod
    def pause(cls):
        """Temporarily suppress renders (e.g. during theme switch)."""
        cls._paused = True

    @classmethod
    def resume(cls):
        """Re-enable renders after a pause."""
        cls._paused = False

    @classmethod
    def register(cls, chart):
        if chart not in cls._charts:
            cls._charts.append(chart)
        if not cls._running:
            cls._running = True
            cls._index   = 0
            try:
                chart.after(cls.STEP_MS, cls._tick)
            except Exception:
                cls._running = False
        # Bind scroll-end flush: after the user scrolls, residual "ghost"
        # pixels from old positions are cleared by flushing all charts.
        # We bind at the top-level (bind_all) so scrolling anywhere triggers
        # the flush; debounce to 80 ms so we only run once per scroll gesture.
        try:
            if not cls._wheel_bound:
                chart.bind_all("<MouseWheel>", cls._on_scroll, add="+")
                chart.bind_all("<Button-4>",   cls._on_scroll, add="+")  # Linux up
                chart.bind_all("<Button-5>",   cls._on_scroll, add="+")  # Linux down
                cls._wheel_bound = True
        except Exception:
            pass

    _scroll_flush_job = None

    @classmethod
    def _on_scroll(cls, event=None):
        """Debounced: flush all visible charts 80ms after scrolling stops."""
        if cls._scroll_flush_job is not None:
            try:
                cls._charts[0].after_cancel(cls._scroll_flush_job)
            except Exception:
                pass
        if not cls._charts:
            return
        try:
            cls._scroll_flush_job = cls._charts[0].after(80, cls._flush_all)
        except Exception:
            pass

    # Spacing between staggered post-scroll redraws.  Small enough that
    # the visible viewport refreshes in well under a second even at 20
    # charts (20 × 50ms = 1s), large enough to let Tkinter's idle loop
    # actually process each draw_idle() before the next one queues — the
    # previous mass-draw_idle() jammed the idle queue and produced a 1-2s
    # main-thread freeze on heavy dashboards.
    FLUSH_SPACING_MS: int = 50

    @classmethod
    def _flush_all(cls):
        """After scroll stops, redraw visible charts STAGGERED via after().

        Calling draw_idle() on every visible chart in a tight loop queues
        them all into Tkinter's next idle slot, where matplotlib then
        runs every backend draw back-to-back on the main thread.  On a
        dashboard with ~20 charts this causes a 1-2s UI freeze right
        after scrolling stops.  Spacing the calls FLUSH_SPACING_MS apart
        lets Tk return to the event loop between draws.
        """
        cls._scroll_flush_job = None
        visible = []
        for c in cls._charts:
            try:
                if not (c.winfo_exists() and c._running):
                    continue
                # Same visibility check as render_if_visible() — skip off-screen charts
                tl = c.winfo_toplevel()
                wy_rel = c.winfo_rooty() - tl.winfo_rooty()
                win_h  = tl.winfo_height()
                if wy_rel + c.winfo_height() < 0 or wy_rel > win_h:
                    continue
                visible.append(c)
            except Exception:
                pass

        def _safe_draw(chart):
            try:
                if chart.winfo_exists() and chart._running:
                    chart._mpl_canvas.draw_idle()
            except Exception:
                pass

        for i, c in enumerate(visible):
            try:
                c.after(i * cls.FLUSH_SPACING_MS, _safe_draw, c)
            except Exception:
                pass

    @classmethod
    def unregister(cls, chart):
        try:
            cls._charts.remove(chart)
        except ValueError:
            pass
        if cls._index >= len(cls._charts):
            cls._index = 0

    @classmethod
    def _tick(cls):
        if not cls._running:
            return
        # Prune destroyed widgets
        cls._charts = [c for c in cls._charts
                       if not cls._is_dead(c)]
        if not cls._charts:
            cls._running = False
            return
        # If paused (e.g. during theme change), skip rendering but
        # MUST still schedule the next tick — a bare return would
        # permanently break the after() chain.
        if not cls._paused:
            cls._index = cls._index % len(cls._charts)
            try:
                cls._charts[cls._index].render_if_visible()
            except Exception:
                pass
            cls._index = (cls._index + 1) % len(cls._charts)
        # Always reschedule — chain must never break
        try:
            cls._charts[0].after(cls.STEP_MS, cls._tick)
        except Exception:
            # Post-sleep Tcl glitch — retry once with backoff instead of
            # permanently stopping the coordinator.
            if cls._charts:
                try:
                    cls._charts[0].after(cls.STEP_MS * 2, cls._tick)
                except Exception:
                    cls._running = False
            else:
                cls._running = False

    @staticmethod
    def _is_dead(widget):
        try:
            return not widget.winfo_exists()
        except Exception:
            return True

class ChartPanel(ctk.CTkFrame):

    # Reduced from 1000ms to 1500ms — halves CPU spend on chart redraws
    # without meaningfully affecting perceived chart freshness
    REFRESH_MS = 1500

    # PERF-3: time-axis fallback redraw interval.
    # Even when no new probe data has arrived, the X axis ("N seconds ago")
    # keeps shifting leftward — so we must redraw periodically to prevent
    # the chart from appearing frozen on long-interval probes (HTTP/DNS).
    # 3 s is a balanced default: frequent enough that the time-axis still
    # feels alive, cheap enough that it doesn't negate the data-change cache.
    # Extracted as a named constant to avoid magic numbers scattered in logic.
    IDLE_REDRAW_S: float = 3.0

    def __init__(self, parent, target_id, get_history, warn_latency=150):
        super().__init__(parent, fg_color="transparent")
        self.target_id    = target_id
        self.get_history  = get_history
        self.warn_latency = warn_latency
        self._running     = False
        self._fill        = None
        self._fill_tick        = 0
        self._last_render_n         = -1    # PERF-3: skip redraw when data unchanged
        self._last_render_lat       = None
        self._last_render_probe_ts  = None  # newest probe wall-clock ts
        self._last_render_mono      = 0.0   # monotonic ts; time-axis fallback (not wall clock)
        if MATPLOTLIB_AVAILABLE:
            self._build_chart()

    def _C(self):
        return THEMES.get(ctk.get_appearance_mode().lower(), THEMES["dark"])

    def _build_chart(self):
        C = self._C()
        self._fig = Figure(figsize=(6, 1.6), dpi=95)
        self._fig.patch.set_facecolor(C["bg"])
        self._fig.subplots_adjust(left=0.055, right=0.99, top=0.83, bottom=0.24)
        self._ax = self._fig.add_subplot(111)
        self._ax.set_facecolor(C["bg"])

        self._line, = self._ax.plot(
            [], [], color=C["line"], linewidth=1.6, zorder=3, solid_capstyle="round")
        self._loss_scatter = self._ax.scatter(
            [0], [0], color=C["loss"], marker="x", s=30, linewidths=1.4,
            zorder=4, visible=False)
        self._warn_line = self._ax.axhline(
            y=self.warn_latency, color=C["warn_line"],
            linewidth=0.8, linestyle="--", alpha=0.5, zorder=2)

        # ── Hover crosshair elements ───────────────────────────────────
        # These three artists are invisible until the user moves the mouse
        # over the chart. We keep them as permanent artists so they get
        # included in every canvas.draw() / draw_idle() call automatically.
        self._hover_vline = self._ax.axvline(
            x=0, color=C["crosshair"], linewidth=0.9, linestyle=":",
            alpha=0.7, visible=False, zorder=5)
        self._hover_dot, = self._ax.plot(
            [], [], "o", color=C["dot"], markersize=5, zorder=6, visible=False)
        self._hover_annot = self._ax.text(
            0, 0, "",
            fontsize=8, color="#ffffff",
            ha="center", va="bottom",
            bbox=dict(boxstyle="round,pad=0.25",
                      facecolor=C["tooltip_bg"], alpha=0.85, edgecolor="none"),
            visible=False, zorder=7, fontfamily=FONT_FAMILY)

        self._style_axes(C)

        self._ax.xaxis.set_major_formatter(
            ticker.FuncFormatter(
                lambda x, _: "now" if abs(x) < 2 else f"{int(abs(x))}s ago"))
        self._ax.xaxis.set_major_locator(ticker.MaxNLocator(nbins=7, integer=True))
        self._ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: f"{int(y)}"))
        self._ax.yaxis.set_major_locator(ticker.MaxNLocator(nbins=4, integer=True))

        self._stats = self._ax.text(
            0.99, 1.06, "waiting...",
            transform=self._ax.transAxes, ha="right", va="bottom",
            fontsize=7.5, color=C["stats"], fontfamily=FONT_FAMILY)

        self._mpl_canvas = FigureCanvasTkAgg(self._fig, master=self)
        self._widget = self._mpl_canvas.get_tk_widget()
        self._widget.configure(bg=C["bg"], highlightthickness=0, relief="flat")
        self._widget.pack(fill="x")

        # Connect mouse events for the crosshair
        self._mpl_canvas.mpl_connect("motion_notify_event", self._on_hover)
        self._mpl_canvas.mpl_connect("axes_leave_event",    self._on_leave)

    def _style_axes(self, C):
        """Apply axis colors. Called only on build or theme change."""
        for spine in self._ax.spines.values():
            spine.set_edgecolor(C["spine"])
            spine.set_linewidth(0.5)
        self._ax.tick_params(
            axis="both", colors=C["tick"], labelsize=7, length=2, width=0.5)
        self._ax.grid(True, color=C["grid"], linewidth=0.5)
        self._ax.set_axisbelow(True)
        self._ax.set_ylabel(
            "ms", color=C["tick"], fontsize=7, rotation=0, labelpad=16, va="center")

    # ------------------------------------------------------------------
    # Hover crosshair
    # ------------------------------------------------------------------

    def _on_hover(self, event):
        """
        Called on every mouse-move over the figure canvas.

        Important subtlety: the matplotlib figure is larger than the axes
        (it includes the title area, padding, and x-axis label region).
        When the cursor moves from inside the axes into one of these
        padding zones, event.inaxes becomes None but motion_notify_event
        still fires. If we just returned here without touching the
        crosshair, it would stay frozen at its last position — that was
        the source of the "sometimes the crosshair lingers" bug.

        The fix: treat "cursor not in our axes" exactly like a leave event.
        Hide the crosshair right away and bail. This makes hover cleanup
        robust regardless of the exact path the cursor takes when exiting.
        """
        if not self._running:
            return
        if event.inaxes != self._ax:
            # Cursor wandered out of our axes — hide crosshair just like
            # _on_leave would. This catches the case where the cursor
            # moves through the figure's padding without triggering
            # axes_leave_event (which can be unreliable on fast motion).
            if self._hover_vline.get_visible():
                self._hover_vline.set_visible(False)
                self._hover_dot.set_visible(False)
                self._hover_annot.set_visible(False)
                self._mpl_canvas.draw_idle()
            return

        history = self.get_history()
        if history is None or history.is_empty():
            return

        times, latencies = history.get_plot_data()
        t_ok = [(t, lat) for t, lat in zip(times, latencies) if lat is not None]
        if not t_ok:
            return

        xdata = event.xdata
        nearest_t, nearest_lat = min(t_ok, key=lambda p: abs(p[0] - xdata))

        # Update crosshair artists in-place (no matplotlib re-layout needed)
        self._hover_vline.set_xdata([nearest_t])
        self._hover_vline.set_visible(True)

        self._hover_dot.set_data([nearest_t], [nearest_lat])
        self._hover_dot.set_visible(True)

        self._hover_annot.set_position((nearest_t, nearest_lat))
        self._hover_annot.set_text(f"{nearest_lat:.1f} ms")
        self._hover_annot.set_visible(True)

        # draw_idle() is very cheap here — only the three crosshair artists
        # have changed; the rest of the figure is already rendered in the
        # canvas's internal buffer.
        self._mpl_canvas.draw_idle()

    def _on_leave(self, event):
        """Hide crosshair when cursor leaves the axes."""
        self._hover_vline.set_visible(False)
        self._hover_dot.set_visible(False)
        self._hover_annot.set_visible(False)
        self._mpl_canvas.draw_idle()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start_updates(self):
        """Register with the global coordinator. The coordinator drives
        all chart renders so they never overlap and burst simultaneously."""
        self._running = True
        self.update_idletasks()
        ChartCoordinator.register(self)

    def stop_updates(self):
        self._running = False
        ChartCoordinator.unregister(self)

    def destroy(self):
        """Override Tkinter destroy to explicitly release Matplotlib resources.

        Why this matters:
          - Figure() instances are not registered in pyplot's Gcf, so they
            are theoretically GC-able.  BUT FigureCanvasTkAgg holds internal
            references that prevent immediate collection after widget.destroy().
          - ChartCoordinator._charts also keeps a reference until the next
            _tick() prune — that 200 ms window is enough to accumulate figures
            if nodes are deleted in rapid succession.
          - fig.clf() + plt.close() releases C-level artists and axes immediately,
            regardless of GC timing.
        """
        # 1. Immediately unregister from coordinator (no waiting for next _tick)
        self.stop_updates()

        # 2. Explicitly free the Matplotlib Figure and its C-level resources
        if hasattr(self, '_fig') and self._fig is not None:
            try:
                self._fig.clf()          # clear all axes and artists
                import matplotlib.pyplot as _plt
                _plt.close(self._fig)    # un-register from any manager, free canvas
            except Exception:
                pass
            self._fig = None

        # 3. Let Tkinter finish widget destruction
        super().destroy()

    def clear_chart(self):
        """Remove all plotted data from the canvas (Bug104).

        Called when in-memory history is cleared (IP/type identity change)
        or when _render_chart() finds no history — avoids stale curves
        from the previous target lingering on an open mini-chart.
        """
        if not MATPLOTLIB_AVAILABLE or not hasattr(self, "_fig"):
            return
        try:
            self._line.set_data([], [])
            self._loss_scatter.set_offsets([[0, 0]])
            self._loss_scatter.set_visible(False)
            if self._fill is not None:
                self._fill.remove()
                self._fill = None
            self._fill_tick = 0
            self._last_render_n = -1
            self._last_render_lat = None
            self._last_render_probe_ts = None
            self._hover_vline.set_visible(False)
            self._hover_dot.set_visible(False)
            self._hover_annot.set_visible(False)
            self._warn_line.set_visible(False)
            self._ax.set_ylim(0, 50)
            from src.history_store import TargetHistory
            self._ax.set_xlim(-TargetHistory.WINDOW_SECONDS, 2)
            self._stats.set_text("waiting...")
            self._mpl_canvas.draw_idle()
        except Exception as e:
            print(f"[Chart {self.target_id}] clear error: {e}")

    def render_if_visible(self):
        """Called by the coordinator each STEP_MS tick.
        Skip if not running, destroyed, or scrolled off-screen."""
        if not self._running:
            return
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        # Skip charts scrolled entirely outside the visible screen.
        try:
            wy = self.winfo_rooty()
            wh = self.winfo_height()
            # Convert absolute screen Y to Y relative to the window top.
            # winfo_rooty() is an absolute screen coordinate; winfo_height()
            # is a size — comparing them directly causes incorrect culling
            # whenever the window is not at the top of the screen.
            # (This was the bug: wy=700, win_h=600 → 700>600 → culled even
            #  though the chart was visible inside the window.)
            toplevel = self.winfo_toplevel()
            wy_rel = wy - toplevel.winfo_rooty()
            win_h  = toplevel.winfo_height()
            if wy_rel + wh < 0 or wy_rel > win_h:
                return
        except Exception:
            pass
        self._render_chart()

    def apply_theme(self):
        if not MATPLOTLIB_AVAILABLE:
            return
        try:
            C = self._C()
            self._fig.patch.set_facecolor(C["bg"])
            self._ax.set_facecolor(C["bg"])
            self._line.set_color(C["line"])
            self._loss_scatter.set_facecolor(C["loss"])
            self._loss_scatter.set_edgecolor(C["loss"])
            self._warn_line.set_color(C["warn_line"])
            self._stats.set_color(C["stats"])
            self._hover_vline.set_color(C["crosshair"])
            self._hover_dot.set_color(C["dot"])
            self._hover_annot.get_bbox_patch().set_facecolor(C["tooltip_bg"])
            self._widget.configure(bg=C["bg"])
            if self._fill is not None:
                self._fill.remove()
                self._fill = None
                history = self.get_history()
                if history and not history.is_empty():
                    times, latencies = history.get_plot_data()
                    t_ok   = [t   for t, lat in zip(times, latencies) if lat is not None]
                    lat_ok = [lat for lat     in latencies             if lat is not None]
                    if len(t_ok) >= 2:
                        self._fill = self._ax.fill_between(
                            t_ok, lat_ok, 0, color=C["fill"], alpha=0.15, zorder=1)
            self._style_axes(C)
            self._mpl_canvas.draw_idle()
        except Exception:
            pass

    # _loop() is now handled by ChartCoordinator (see module level).
    # Kept as a no-op stub so any lingering references don't crash.
    def _loop(self):
        pass

    def _render_chart(self):
        try:
            history = self.get_history()
            if history is None or history.is_empty():
                self.clear_chart()
                return
            C = self._C()
            times, latencies = history.get_plot_data()

            # ── PERF-3: data-change cache + time-axis fallback ────────────
            # Purpose 1 – data-change cache:
            #   Skip the full artist update when neither the number of points
            #   nor the most-recent latency value has changed.  This avoids
            #   continuous UI thread work while the node is quiet.
            #
            # Purpose 2 – time-axis fallback (IDLE_REDRAW_S):
            #   X values are "seconds ago" (negative floats that shift left
            #   every second).  Even with no new probe data the axis must keep
            #   moving, or long-interval nodes (HTTP 30 s, DNS) appear frozen.
            #   time.monotonic() is used here — not time.time() — because this
            #   is a timer/elapsed-time check; wall-clock jumps (NTP, manual
            #   adjustment) must not corrupt the fallback interval.
            #
            # NOTE: _last_render_mono is updated AFTER the draw decision is
            # confirmed, not at entry.  Updating it early would "use up" the
            # idle budget on paths that never actually draw, defeating the
            # purpose of the fallback.
            import time as _time
            mono_now  = _time.monotonic()
            n            = len(times)
            last_lat     = latencies[-1] if latencies else None
            last_probe_ts = history.get_latest_timestamp()
            data_changed  = (n != self._last_render_n
                             or last_lat != self._last_render_lat
                             or last_probe_ts != self._last_render_probe_ts)
            time_stale    = (mono_now - self._last_render_mono >= self.IDLE_REDRAW_S)
            should_render = data_changed or time_stale or (self._fill_tick >= 5)
            if not should_render:
                return
            # ── Draw decision confirmed — update caches now ───────────────
            self._last_render_n         = n
            self._last_render_lat       = last_lat
            self._last_render_probe_ts  = last_probe_ts
            self._last_render_mono      = mono_now   # monotonic timestamp

            t_ok, lat_ok, t_loss = [], [], []
            for t, lat in zip(times, latencies):
                if lat is not None:
                    t_ok.append(t); lat_ok.append(lat)
                else:
                    t_loss.append(t)

            self._line.set_data(t_ok, lat_ok)

            # Throttle fill_between rebuilds.
            # _fill_tick counts *actual renders* (not poll cycles) because it
            # is incremented here — after the should_render early-return — so
            # skipped frames never advance the counter.
            #
            # fill_between rebuild frequency is therefore self-adaptive:
            # it tracks how often *this specific chart* actually renders,
            # not the global scheduler tick rate.  A chart that renders
            # frequently (ICMP, few charts open) rebuilds fill sooner;
            # a chart that renders rarely (HTTP, many charts open, or
            # long idle periods) rebuilds fill less often — which is
            # exactly the right behaviour since fill_between is relatively
            # expensive and should be tied to real rendering pressure.
            self._fill_tick += 1
            if self._fill_tick >= 5:
                self._fill_tick = 0
                if self._fill is not None:
                    self._fill.remove()
                    self._fill = None
                if len(t_ok) >= 2:
                    self._fill = self._ax.fill_between(
                        t_ok, lat_ok, 0, color=C["fill"], alpha=0.15, zorder=1)

            if t_loss:
                self._loss_scatter.set_offsets([[t, 0] for t in t_loss])
                self._loss_scatter.set_visible(True)
            else:
                self._loss_scatter.set_visible(False)

            if lat_ok:
                y_max = max(max(lat_ok) * 1.5, 20)
                self._ax.set_ylim(0, y_max)
                self._warn_line.set_visible(self.warn_latency < y_max)
            else:
                self._ax.set_ylim(0, 50)
                self._warn_line.set_visible(False)

            # Fixed time window: all charts show the same X span regardless
            # of probe interval. Import the constant lazily to avoid a
            # circular import at module load time.
            from src.history_store import TargetHistory
            self._ax.set_xlim(-TargetHistory.WINDOW_SECONDS, 2)

            if lat_ok:
                avg = sum(lat_ok) / len(lat_ok)
                txt = f"cur {lat_ok[-1]:.0f}ms  avg {avg:.0f}ms  max {max(lat_ok):.0f}ms"
                if t_loss:
                    txt += f"  timeout {len(t_loss)}"
            else:
                txt = "all timeout"
            self._stats.set_text(txt)

            self._mpl_canvas.draw_idle()

        except Exception as e:
            print(f"[Chart {self.target_id}] render error: {e}")
