from __future__ import annotations
"""
ping_engine.py — Network probe engine with dual-dimension alerting
====================================================================

ARCHITECTURE: Availability vs Performance
====================================================================
Inspired by Pingdom / UptimeRobot / Datadog Synthetics, this engine
classifies probe outcomes along two INDEPENDENT dimensions:

  AVAILABILITY  (binary per-probe: "did we get the expected response within
                 the timeout window?")
    failure cases — count toward _consecutive_loss:
      • ICMP: no echo reply
      • TCP : connect failed or timed out
      • HTTP: timeout, DNS error, TCP error, TLS error, unmatched status code
    These can escalate to RED status (alert_category = "availability").

  PERFORMANCE   (continuous: "how fast was the response?")
    measured by latency_ms when probe succeeded.
    Counts toward _consecutive_high_lat. By the industry-standard rule,
    PERFORMANCE NEVER ESCALATES TO RED — it caps at ORANGE.

    Rationale: if we got a successful response, the service IS available.
    A slow response degrades user experience but does NOT mean "down."

Consequences for the user's HTTPS sites typically running at 2000-3000ms:
  • Old behaviour: status flipped to RED after a few high-latency probes
    even though every request succeeded. This was wrong.
  • New behaviour: status caps at ORANGE (performance warning). Only a real
    failure (timeout, 4xx/5xx, connection error) triggers RED.

HTTP TIMING BREAKDOWN
====================================================================
HTTPMonitor uses raw socket + ssl instead of urllib.urlopen, which lets
us measure each phase separately:

  • dns_ms    — name resolution
  • tcp_ms    — TCP three-way handshake
  • tls_ms    — TLS handshake (HTTPS only)
  • ttfb_ms   — request sent → first response byte
                (≈ server-side processing time)
  • total_ms  — overall request duration

The diagnosis modal shows these so operators can localize bottlenecks:
high tcp_ms = network issue; high ttfb_ms = slow server.

RECOVERY HYSTERESIS
====================================================================
Transitions INTO alarm states (green → orange/red) are immediate.
Transitions OUT of alarm states (orange/red → green) require
recovery_count consecutive "naturally green" observations. This kills
flapping at the boundary AND guarantees alerts clear once conditions
normalize for a sustained period.

HTTP-SPECIFIC DEFAULTS
====================================================================
HTTPMonitor overrides DEFAULT_WARN_LAT = 2000ms (vs ICMP's 150ms) so
typical HTTPS sites don't trigger constant performance warnings.
Users can override via per-target thresholds.
"""

import re
import errno
import socket
import ssl
import subprocess
import threading
import time
import platform
import urllib.parse
import urllib.request
import uuid
import urllib.error
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


# ======================================================================
# Data classes
# ======================================================================

@dataclass
class PingResult:
    """Outcome of one probe attempt."""
    success: bool
    latency_ms: Optional[float]
    timestamp: float = field(default_factory=time.time)
    # Extended (mostly HTTP) — defaults keep older code working
    status_code:    Optional[int]  = None
    failure_reason: Optional[str]  = None
    timings:        Optional[dict] = None
    cert_days_left: Optional[int]  = None   # SSL cert days remaining (HTTPS, verify_ssl=True)
    keyword_ok:     Optional[bool] = None   # None = no check; True/False = match result


@dataclass
class TargetState:
    """What the UI sees — aggregated state of a target."""
    target_id: str
    status: str                                  # "gray" | "green" | "orange" | "red"
    latency_ms:    Optional[float]
    jitter_ms:     Optional[float]
    loss_rate:     float
    consecutive_loss: int
    # Extended
    alert_category: str = "ok"
    status_code:    Optional[int]  = None
    failure_reason: Optional[str]  = None
    timings:        Optional[dict] = None
    cert_days_left: Optional[int]  = None   # days until SSL cert expires; None = N/A or unknown
    keyword_ok:     Optional[bool] = None   # keyword match result; None = not configured
    # Identity snapshot captured at probe start.  Carried through to
    # the commit-side _on_state_update so a concurrent identity-
    # boundary edit (IP change, type change, wipe, delete) landing
    # AFTER _run_loop passed all its gates but BEFORE the callback
    # actually commits can be detected and the row dropped.  Pre-2025
    # the version-gate / callback / DataStore-write sequence was not
    # atomic: a probe could pass all gates, get context-switched out,
    # and resume executing the callback after the operator had
    # finished editing -- _on_state_update then read the FRESHLY
    # rewritten MainWindow caches and recorded the old probe's data
    # under the new identity.  None means "no probe-time capture"
    # (e.g. initial gray seed) and disables the commit-side recheck.
    probe_ip_version:       Optional[int] = None
    probe_settings_version: Optional[int] = None
    # Monitor instance token captured at probe start.  Needed because
    # a type-change destroys the OLD monitor and creates a NEW one
    # under the same target_id, with both monitors' _ip_version and
    # _settings_version reset to 0.  An old delayed callback carrying
    # (0, 0) would otherwise falsely pass commit-side version checks
    # against the new monitor.  The token is a per-monitor UUID so
    # the comparison is reused-target-id safe.
    probe_monitor_token:    Optional[str] = None
    # DataStore target generation captured at probe start.  Forwarded
    # to record_ping as captured_generation so the DataStore writer
    # thread can drop a ping whose target was wiped / removed between
    # this probe's start and the actual INSERT.  Same shape as the
    # existing record_traceroute / record_diag_result captured_gen
    # protection; None disables the check (e.g. when the engine
    # wasn't wired to a DataStore for synthetic tests).
    probe_data_store_generation: Optional[int] = None


# ======================================================================
# Base monitor (ICMP)
# ======================================================================

class TargetMonitor:
    """
    One thread per target. State machine described in the module docstring.

    Subclass overrides _do_ping() and optionally DEFAULT_WARN_LAT.
    """

    # Default warn-latency threshold if not configured per-target / globally.
    # ICMP uses 150 ms; subclasses override.
    DEFAULT_WARN_LAT = 150

    # Settings keys whose change must invalidate any in-flight probe via
    # _settings_version bump.  Two rules of thumb:
    #   * Anything that changes WHAT _do_ping() measures (host, port,
    #     URL, query domain) belongs here -- otherwise an in-flight
    #     probe under the OLD config can return AFTER the edit and be
    #     attributed to the new config.
    #   * Anything that changes the SUCCESS / FAILURE BOUNDARY (timeout,
    #     accepted status codes, expected DNS answer, follow_redirects,
    #     verify_ssl, ipv6_only address-family selection) also belongs
    #     here, because a result that was "success" under the old rule
    #     can become "failure" under the new one.
    # Threshold-only fields (latency_warn_ms, consecutive_loss_*, etc.)
    # change post-classification behaviour and are intentionally excluded
    # -- their results are still valid measurements under either rule
    # set.  Per-target display knobs (tcp_probe_ports for the diag pill)
    # are also excluded because they don't drive _do_ping().
    PROBE_SEMANTIC_KEYS = (
        "tcp_port",
        "timeout",
        "ipv6_only",
        "http_url",
        "http_timeout",
        "http_verify_ssl",
        "http_follow_redirects",
        "http_success_codes",
        "http_expected_status",
        "http_keyword",
        "http_keyword_mode",
        "dns_domain",
        "dns_expected",
    )

    def __init__(self, target_id, ip, settings, on_state_change,
                 initial_status: str = "gray"):
        self.target_id = target_id
        self.ip = ip
        self.settings = settings
        self.on_state_change = on_state_change
        # Per-instance immutable identifier.  Used by the commit-side
        # callbacks (_on_state_update, _apply_state_update) to detect
        # Monitor ABA: a type-change destroys the OLD monitor and
        # creates a NEW one under the same target_id, with both
        # monitors' _ip_version / _settings_version reset to 0.  An
        # old delayed callback carrying (0, 0) would otherwise falsely
        # pass version-only equality checks against the new monitor.
        # UUID4 keeps the token globally unique even if create + destroy
        # cycles happen in rapid succession.
        self._instance_token = uuid.uuid4().hex
        # Per-monitor commit lock that serialises the _run_loop result-
        # commit sequence (version check + _window.append + _compute_state
        # + state stamping) with config-edit paths that mutate the same
        # state (update_ip, invalidate_stale_extended_caches, and the
        # settings-swap inside PingEngine.update_target_thresholds).
        # Replaces the previous snapshot+rollback hack which restored
        # PRE-edit cache values -- thereby UNDOING the edit's
        # invalidate_stale_extended_caches cleanup whenever a probe
        # finished mid-edit.  RLock so update_target_thresholds can
        # hold the lock across `m.settings = merged` and then call
        # m.invalidate_stale_extended_caches (which re-acquires).
        self._commit_lock = threading.RLock()

        self._window: deque[PingResult] = deque(maxlen=settings.get("window_size", 10))

        # Initialise from last known DB status so that after a restart the
        # state machine continues from where it left off.  Without this, a
        # node that was RED before restart would reset to gray, causing a
        # spurious gap in SLA data instead of keeping the outage open.
        self._status                = initial_status
        self._last_category         = "availability" if initial_status == "red" else "ok"
        self._consecutive_loss      = 0
        self._consecutive_high_lat  = 0
        self._recovery_counter      = 0
        # Natural state currently being counted toward de-escalation; reset
        # whenever the lower-severity natural flips, so a flapping link
        # cannot satisfy `recovery_need` with non-contiguous observations
        # (e.g. green/orange/green/orange/green would otherwise hit 5).
        self._pending_natural       = None

        # Last-seen extended attributes (for UI display when current
        # probe doesn't include them, e.g. a timeout for HTTP)
        self._last_status_code      = None
        self._last_failure_reason   = None
        self._last_timings          = None
        self._last_cert_days_left   = None
        self._last_keyword_ok       = None

        self._stop_event  = threading.Event()
        self._pause_event = threading.Event()
        # Monotonic counter bumped by update_ip() so a probe whose
        # _do_ping() was already in flight when the user changed the
        # node's IP can detect the change on return and discard its
        # now-stale result.  Without this guard, a 10 s HTTP probe
        # that started on the old IP and finished after the edit
        # would still bubble up through on_state_change to
        # DataStore.record_ping under the NEW target_id -- old IP's
        # failure poisons the new server's history, waveform, SLA,
        # and alarm state.
        self._ip_version  = 0
        # Monotonic counter for SETTINGS identity (separate from
        # _ip_version which tracks the ip field).  Bumped by
        # invalidate_stale_extended_caches() when probe-semantics
        # config changed: http_keyword / http_keyword_mode / http_url
        # / http_verify_ssl (and any future field that changes what
        # the next probe will measure).  _run_loop captures the
        # version it observed before _do_ping() and discards the
        # result on return when it doesn't match -- so an HTTP
        # request started against the OLD config can't sneak its
        # post-edit result into the freshly-cleared
        # _last_keyword_ok / _last_cert_days_left caches (which
        # would otherwise resurrect the very badge the cache
        # invalidation just removed).
        self._settings_version  = 0
        self._thread = threading.Thread(target=self._run_loop,
                                         name=f"ping-{ip}", daemon=True)

    # ── thread control ──────────────────────────────────────────────
    def start(self):  self._thread.start()
    def stop(self):   self._stop_event.set()
    def pause(self):  self._pause_event.set()

    def join(self, timeout: float | None = None):
        """Wait for the monitor thread to terminate (caller must call stop()
        first).  Returns whether the thread actually exited; callers can
        check is_alive() afterwards for the same answer."""
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def resume(self):
        self._consecutive_loss = 0
        self._consecutive_high_lat = 0
        self._recovery_counter = 0
        self._pending_natural = None
        self._status = "gray"
        self._last_category = "ok"
        self._last_failure_reason = None
        self._window.clear()
        self._pause_event.clear()

    @property
    def is_paused(self): return self._pause_event.is_set()

    def update_ip(self, new_ip):
        # Same-value updates are no-ops: callers (notably
        # main_window._on_edit) used to fire update_target_ip on every
        # save -- including label-only edits where the IP didn't move
        # -- and the unconditional state reset below would yank the
        # monitor back to gray, clearing the recovery debounce counter
        # in mid-flight.  Net effect: a node still legitimately red
        # would jump straight to green on its next successful probe
        # because the state machine treated `gray` as severity -1 and
        # any natural value as an escalation.  Bail out before any
        # state mutation when the address hasn't actually changed.
        if new_ip == self.ip:
            return
        # Hold the commit lock for the entire identity reset.  A probe
        # whose _run_loop is also inside the commit lock blocks until
        # we finish; on its turn the version check fires and the
        # result is dropped.  Without the lock, a probe could compute
        # state mid-reset and observe a partially-cleared monitor.
        with self._commit_lock:
            self.ip = new_ip
            # Bump version so any probe currently inside _do_ping() (HTTP
            # request, TCP connect, blocking subprocess ping, ...) sees a
            # mismatch on return and discards its result instead of pushing
            # it through on_state_change.  See __init__ for the rationale.
            self._ip_version += 1
            self._window.clear()
            self._consecutive_loss = 0
            self._consecutive_high_lat = 0
            self._recovery_counter = 0
            self._pending_natural = None
            self._status = "gray"
            self._last_category = "ok"
            # Drop every extended-field cache that belonged to the OLD
            # identity.  See the comment in __init__ for the full
            # rationale; the lock above prevents a concurrent
            # _compute_state from racing the clears.
            self._last_status_code     = None
            self._last_failure_reason  = None
            self._last_timings         = None
            self._last_cert_days_left  = None
            self._last_keyword_ok      = None

    def invalidate_stale_extended_caches(self, old_settings: dict,
                                          new_settings: dict) -> None:
        """Cache invalidation + in-flight probe invalidation for a
        settings edit.

        Two intentionally independent jobs:

        (1) Drop the _last_* extended-display caches whose backing
            config changed:
              * http_keyword / http_keyword_mode -> _last_keyword_ok
              * http_url / http_verify_ssl       -> _last_cert_days_left
            _compute_state() reuses these caches whenever the current
            probe doesn't supply the value (HTTP timeout still shows
            the last keyword / cert badge) -- that's correct for a
            transient probe gap but wrong when the operator changed
            the config so the field no longer applies (cleared
            keyword, switched https->http).  Without the cache drop
            the dashboard renders a permanent ⚠ 关键字未匹配 /
            🔒 证书7天 badge that no future probe can erase.

        (2) Bump _settings_version when ANY field in
            PROBE_SEMANTIC_KEYS actually changed.  _run_loop captures
            the version before _do_ping() and discards the result on
            mismatch, so an in-flight probe started under the OLD
            config (e.g. TCP 80 in flight while the user edits to
            TCP 443) can't get its result attributed to the new
            config.  Pre-2025 the bump was tied to (1) and only the
            four HTTP cache-driving fields qualified; that left
            tcp_port / dns_domain / http_timeout / http_success_codes
            etc. without an in-flight gate, so an old-port success
            could be recorded under the new port's row.  Splitting
            the two responsibilities -- with PROBE_SEMANTIC_KEYS as
            the authoritative list -- closes the gap.

        We leave _last_status_code / _last_failure_reason /
        _last_timings alone in (1) -- those reflect transport
        behaviour, not config state, and the next successful probe
        rewrites them naturally.

        Acquires the per-monitor commit lock (RLock) for the entire
        method so a probe currently inside _run_loop's commit
        sequence finishes (or blocks at the lock until we return).
        This replaces the previous snapshot+rollback workaround
        which restored PRE-edit cache values -- thereby undoing the
        very cleanup this method just performed.  RLock so
        PingEngine.update_target_thresholds can hold the lock around
        the settings swap AND this method without nested-acquire
        deadlock.
        """
        with self._commit_lock:
            self._do_invalidate_stale_extended_caches(
                old_settings, new_settings)

    def _do_invalidate_stale_extended_caches(self, old_settings: dict,
                                              new_settings: dict) -> None:
        # Caller MUST hold self._commit_lock.
        def _kw(d):    return (d.get("http_keyword") or "")
        def _kmode(d): return (d.get("http_keyword_mode") or "contains")
        def _url(d):   return (d.get("http_url") or "")
        def _vssl(d):  return bool(d.get("http_verify_ssl", True))
        url_changed  = _url(old_settings)   != _url(new_settings)
        vssl_changed = _vssl(old_settings)  != _vssl(new_settings)
        kw_changed   = (_kw(old_settings)    != _kw(new_settings)
                        or _kmode(old_settings) != _kmode(new_settings))
        # ── (1) cache invalidation ─────────────────────────────────
        # Symmetry with TargetMonitor.update_ip(): a URL change is the
        # HTTP monitor's identity boundary.  Everything tied to the
        # previous URL -- status code, failure reason, response
        # timings, cert expiry, keyword match -- is stale and would
        # otherwise leak through _compute_state's "reuse last value
        # on probe-side None" rule onto the new URL's card.  Pre-2025
        # we only nulled _last_cert_days_left here; a new URL that
        # timed out kept showing the previous URL's HTTP 200 / DNS
        # timing / etc.  Treat URL changes the same way update_ip
        # treats IP changes.
        if url_changed:
            self._last_status_code     = None
            self._last_failure_reason  = None
            self._last_timings         = None
            self._last_cert_days_left  = None
            self._last_keyword_ok      = None
            # HTTPMonitor caches a HEAD-vs-GET method preference that
            # auto-downgrades on 405/501.  The previous URL's server
            # may have refused HEAD; the new URL must get a fresh
            # chance to use the lightweight method.  hasattr keeps
            # this base-class hook safe for non-HTTP monitors which
            # don't define _preferred_method.
            if hasattr(self, "_preferred_method"):
                self._preferred_method = "HEAD"
        else:
            # No URL change: narrow invalidation only.
            if vssl_changed:
                self._last_cert_days_left = None
            if kw_changed:
                self._last_keyword_ok = None
        # ── (2) in-flight probe invalidation ───────────────────────
        # Sentinel `_MISSING` distinguishes "key absent" from
        # "key set to None" so a clear-vs-explicit-None edit also
        # counts as a change.  Compare every PROBE_SEMANTIC_KEYS
        # field, stop at the first delta.
        _MISSING = object()
        for k in self.PROBE_SEMANTIC_KEYS:
            if old_settings.get(k, _MISSING) != new_settings.get(k, _MISSING):
                self._settings_version += 1
                break

    # ── main loop ───────────────────────────────────────────────────
    def _run_loop(self):
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                self._stop_event.wait(0.5); continue
            interval = self.settings.get("ping_interval", 1.0)
            t0 = time.time()
            try:
                # Capture the IP version we're about to probe.  If
                # update_ip() runs while _do_ping() is blocked, the
                # version on return won't match -- discard the result
                # so the OLD ip's outcome doesn't get attributed to
                # the NEW ip in DataStore / UI.  Same pattern as the
                # stop/pause re-checks below.
                probe_version = self._ip_version
                # Capture the settings version too.  Without this an
                # HTTP probe that started under e.g. http_keyword="X"
                # could return AFTER the operator cleared the keyword
                # config, slip past the cache invalidation that ran
                # at edit time (which only touched _last_keyword_ok),
                # and have its keyword_ok=False/True written back
                # into the freshly-cleared cache by _compute_state.
                # Mirror the ip-version pattern.
                probe_settings_version = self._settings_version
                result = self._do_ping()
                # _do_ping may block for the full HTTP timeout (10s+).
                # During that window the caller can have stopped this
                # monitor and re-added a NEW monitor with the same
                # target_id (the rename / repurpose flow in
                # main_window._on_edit).  Without this check, this
                # zombie thread would wake from the long blocking call
                # and push its now-stale state into the shared
                # on_state_change callback -- the new monitor's UI
                # card / DB row would briefly flicker the old node's
                # status before its own first probe lands.
                if self._stop_event.is_set():
                    break
                # Same defensive re-check for the pause path: if the
                # user paused the node WHILE _do_ping() was in flight,
                # the top-of-loop pause guard already passed (we were
                # mid-probe).  Without this second check, the result
                # would still bubble through on_state_change ->
                # _on_state_update -> record_ping, polluting the SLA /
                # waveform with a tick that arrived AFTER the user
                # explicitly said "stop counting this node".
                if self._pause_event.is_set():
                    self._stop_event.wait(0.5); continue
                # Atomic commit section.  The per-monitor commit lock
                # serialises us with every config-edit path that
                # mutates the same fields (update_ip,
                # invalidate_stale_extended_caches, and the settings
                # swap inside PingEngine.update_target_thresholds),
                # so within the `with` block:
                #   * a probe that passed version checks here CANNOT
                #     have its _window.append / _compute_state writes
                #     undone or re-poisoned by a concurrent edit;
                #   * an edit that runs concurrently waits at the
                #     lock, then bumps versions; on its turn the
                #     probe's outer "next iteration" sees the bumped
                #     versions and the probe-time capture mismatches.
                # Replaces the previous snapshot+rollback workaround
                # whose rollback restored PRE-edit cache values --
                # overwriting the very cleanup the concurrent edit
                # had just done in invalidate_stale_extended_caches.
                with self._commit_lock:
                    # IP changed mid-probe (update_ip bumped _ip_version).
                    if probe_version != self._ip_version:
                        committed = False
                    # Probe-semantics config changed mid-probe.
                    elif probe_settings_version != self._settings_version:
                        committed = False
                    else:
                        self._window.append(result)
                        state = self._compute_state(result)
                        committed = True
                if not committed:
                    self._stop_event.wait(0.5); continue
                # Stamp the probe-time identity snapshot onto the state
                # so _on_state_update can re-validate at COMMIT time --
                # a wipe / IP edit / type change / delete landing in the
                # gap between this assignment and DataStore.record_ping
                # would otherwise have its old-probe result attributed
                # to the new identity (or, post-delete, written as a
                # ghost row with empty label/ip).  See _on_state_update
                # for the commit-side check.
                state.probe_ip_version       = probe_version
                state.probe_settings_version = probe_settings_version
                # Per-instance UUID closes the type-change ABA hole --
                # the new monitor's versions start at (0,0) just like
                # this OLD monitor's, but its token is different.
                state.probe_monitor_token    = self._instance_token
                # DataStore generation snapshot for the record_ping
                # writer-thread guard.  None when the engine isn't
                # wired to a DataStore (synthetic / test setups).
                try:
                    _ds = getattr(self, "_data_store", None)
                    if _ds is not None:
                        state.probe_data_store_generation = \
                            _ds.current_target_generation(self.target_id)
                except Exception:
                    # Never crash the probe thread over the snapshot.
                    pass
                self.on_state_change(state)
            except Exception as e:
                # Unexpected error (OS stack issue, callback exception, etc.)
                # Log and continue — thread must NEVER die silently.
                print(f"[{self.__class__.__name__}:{self.target_id}] "
                      f"unexpected error, retrying in {interval}s: {e}")
            self._stop_event.wait(max(0.0, interval - (time.time() - t0)))

    # ── probe (override in subclasses) ──────────────────────────────
    def _do_ping(self) -> PingResult:
        is_win = platform.system().lower() == "windows"
        ipv6 = self.settings.get("ipv6_only", False) or ":" in self.ip
        # Honour the per-target "timeout" setting (defaults to 1 s for
        # ICMP to match the historical hard-coded values).  TCP / DNS /
        # HTTP probes already respect their own timeout knobs; without
        # this, a user who bumped a cross-region or satellite-link
        # target's threshold to 2500 ms still had every probe killed
        # at 1 s by the underlying ping binary -- the UI setting was
        # silently ignored and the node thrashed between green and
        # "100% loss" on legitimate >1 s round-trips.
        timeout_s = float(self.settings.get("timeout", 1.0))
        if is_win:
            # Windows ping -w is in MILLISECONDS, integer.
            timeout_ms = str(max(1, int(timeout_s * 1000)))
            cmd = ["ping", "-n", "1", "-w", timeout_ms]
            if ipv6: cmd.append("-6")
            cmd.append(self.ip)
        else:
            # Linux ping -W is in SECONDS, integer; sub-second precision
            # is not available on this platform.  max(1, ...) preserves
            # the historical 1 s floor for sub-second user settings.
            timeout_int = str(max(1, int(timeout_s)))
            cmd = ["ping", "-c", "1", "-W", timeout_int]
            if ipv6: cmd.append("-6")
            cmd.append(self.ip)
        try:
            # On Windows, hide the subprocess console window.
            # Without this, every ping spawns a visible black cmd window —
            # especially noticeable when the app is built with console=False.
            run_kwargs: dict = {}
            if is_win:
                si = subprocess.STARTUPINFO()
                si.dwFlags  |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                run_kwargs["startupinfo"] = si
                run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            # subprocess wrapper deadline = ping's own deadline + 1 s
            # grace.  Without this margin a user-set 5 s timeout would
            # be cut short by the previously-hard-coded 3 s subprocess
            # timeout, reintroducing the same "ignored setting" bug.
            r = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=max(2.0, timeout_s + 1.0),
                                encoding="utf-8", errors="ignore",
                                **run_kwargs)
            latency = self._parse_latency(r.stdout + r.stderr, is_win)
            return PingResult(
                success=(latency is not None),
                latency_ms=latency,
                failure_reason=None if latency is not None else "no_reply",
            )
        except subprocess.TimeoutExpired:
            return PingResult(success=False, latency_ms=None, failure_reason="timeout")
        except Exception as e:
            return PingResult(success=False, latency_ms=None,
                               failure_reason=f"error:{type(e).__name__}")

    @staticmethod
    def _parse_latency(out, is_win):
        if is_win:
            # Match "time=2ms" / "时间=2ms" — exclude '<' here so that
            # "time<1ms" falls through to the special-case handler below.
            m = re.search(r"[时间=time]+\s*(\d+(?:\.\d+)?)\s*ms", out, re.IGNORECASE)
            if m: return float(m.group(1))
            # Sub-millisecond: just look for "<1ms" without a language-
            # specific prefix.  The previous "[时间time]+" character class
            # required one of {时, 间, t, i, m, e} immediately before the
            # "<", which silently fails on Traditional Chinese ("時間"
            # — neither character is in the class), Spanish ("tiempo<"
            # — "o" not in class), French ("temps<" — "s" not in class)
            # and other localised Windows ping outputs.  The bare "<1ms"
            # token is distinctive enough on its own.
            if re.search(r"<\s*1\s*ms", out, re.IGNORECASE): return 0.5
        else:
            m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out, re.IGNORECASE)
            if m: return float(m.group(1))
        return None

    # ── state machine (dual-dimension model) ────────────────────────
    def _compute_state(self, latest: PingResult) -> TargetState:
        cfg            = self.settings
        loss_orange    = cfg.get("consecutive_loss_orange", 3)
        loss_red       = cfg.get("consecutive_loss_red",    5)
        lat_orange     = cfg.get("consecutive_lat_orange",  3)
        warn_lat       = cfg.get("latency_warn_ms",         self.DEFAULT_WARN_LAT)
        recovery_need  = cfg.get("recovery_count",          5)

        # ── 1. Update counters ──────────────────────────────────────
        if latest.success:
            self._consecutive_loss = 0
            if latest.latency_ms is not None and latest.latency_ms >= warn_lat:
                self._consecutive_high_lat += 1
            else:
                self._consecutive_high_lat = 0
        else:
            self._consecutive_loss += 1
            # Probe failure has no latency sample — it must not bridge two
            # high-latency streaks (see consecutive_lat_orange semantics).
            self._consecutive_high_lat = 0
            # Recovery requires consecutive successes (recovery_count); a
            # failed probe must restart the debounce window.
            self._recovery_counter = 0
            self._pending_natural  = None

        # Remember extended attributes for UI persistence
        if latest.status_code is not None:    self._last_status_code   = latest.status_code
        if latest.failure_reason is not None: self._last_failure_reason = latest.failure_reason
        else:
            if latest.success: self._last_failure_reason = None
        if latest.timings is not None and latest.success:
            self._last_timings = latest.timings
        if latest.cert_days_left is not None:
            self._last_cert_days_left = latest.cert_days_left
        if latest.keyword_ok is not None:
            self._last_keyword_ok = latest.keyword_ok

        # ── 2. Derive "natural" state from counters ─────────────────
        #     AVAILABILITY can escalate to RED.
        #     PERFORMANCE caps at ORANGE — never RED.
        natural, category = "green", "ok"
        if self._consecutive_loss >= loss_red:
            natural, category = "red", "availability"
        elif self._consecutive_loss >= loss_orange:
            natural, category = "orange", "availability"
        elif self._consecutive_high_lat >= lat_orange:
            natural, category = "orange", "performance"

        # ── 3. Apply recovery hysteresis ────────────────────────────
        #     Severity-based, not just green-vs-non-green:
        #       • escalation (severity ↑) -- instant: alerts MUST fire now.
        #       • de-escalation (severity ↓) -- debounced through
        #         `recovery_need` consecutive observations at the lower
        #         severity.  Previously only red→green / orange→green were
        #         debounced; red→orange (partial recovery during a deep
        #         outage) hit the else-branch and flipped status instantly,
        #         shredding one long red outage into many short red/orange
        #         fragments in the SLA stats whenever the link flapped near
        #         the loss thresholds.
        #       • same severity -- keep status, refresh category info,
        #         reset the debounce counter.
        #
        # Defensive .get on self._status: it can be "gray" (paused) or the
        # caller's `initial_status` which is not constrained to {green,
        # orange, red}.  Treating unknown as severity -1 means any natural
        # value is an escalation from gray → fires instantly (matches the
        # old behaviour where coming out of gray went straight to natural).
        severity = {"green": 0, "orange": 1, "red": 2}
        nat_sev = severity[natural]                # natural ∈ {green,orange,red}
        cur_sev = severity.get(self._status, -1)   # gray / unknown → -1

        if nat_sev > cur_sev:
            # Escalation: surface the alarm without delay.
            self._status          = natural
            self._last_category   = category
            self._recovery_counter = 0
            self._pending_natural  = None
        elif nat_sev < cur_sev:
            # De-escalation: `recovery_count` means consecutive successful
            # probes, not merely consecutive "green natural" ticks — a
            # single loss can leave natural=green while cur is still red.
            if latest.success:
                # Must see `recovery_need` consecutive successes at the
                # same lower-severity natural state before status updates.
                if self._pending_natural != natural:
                    self._pending_natural  = natural
                    self._recovery_counter = 1
                else:
                    self._recovery_counter += 1
                if self._recovery_counter >= recovery_need:
                    self._status          = natural
                    self._last_category   = category
                    self._recovery_counter = 0
                    self._pending_natural  = None
        else:
            # Same severity: keep _status as-is.  Update category so a
            # swap between e.g. orange/performance ↔ orange/availability
            # still surfaces correctly downstream.  Reset the debounce
            # counter so a brief excursion to a lower severity does not
            # accumulate across non-contiguous occurrences.
            self._last_category   = category
            self._recovery_counter = 0
            self._pending_natural  = None

        # ── 4. Window-based stats for the UI ────────────────────────
        lats = [r.latency_ms for r in self._window
                if r.success and r.latency_ms is not None]
        jitter = (sum(abs(lats[i] - lats[i-1]) for i in range(1, len(lats)))
                  / (len(lats) - 1)) if len(lats) >= 2 else None
        loss_rate = (sum(1 for r in self._window if not r.success) / len(self._window)
                     if self._window else 0.0)

        return TargetState(
            target_id        = self.target_id,
            status           = self._status,
            alert_category   = self._last_category,
            latency_ms       = latest.latency_ms if latest.success else None,
            jitter_ms        = round(jitter, 1) if jitter is not None else None,
            loss_rate        = loss_rate,
            consecutive_loss = self._consecutive_loss,
            status_code      = self._last_status_code,
            failure_reason   = latest.failure_reason if not latest.success else None,
            timings          = self._last_timings,
            cert_days_left   = self._last_cert_days_left,
            keyword_ok       = self._last_keyword_ok,
        )


# ======================================================================
# TCP monitor
# ======================================================================

class TCPMonitor(TargetMonitor):
    DEFAULT_WARN_LAT = 200

    def _do_ping(self) -> PingResult:
        port    = int(self.settings.get("tcp_port", 80))
        timeout = float(self.settings.get("timeout", 3.0))
        start   = time.time()
        sock    = None
        try:
            if self.settings.get("ipv6_only", False):
                # create_connection() only accepts (host, port) — use connect()
                # with the full sockaddr for IPv6 4-tuples from getaddrinfo.
                infos = socket.getaddrinfo(
                    self.ip, port, socket.AF_INET6, socket.SOCK_STREAM)
                if not infos:
                    raise socket.gaierror("no address")
                last_err = None
                for res in infos:
                    candidate = None
                    try:
                        candidate = socket.socket(res[0], res[1], res[2])
                        candidate.settimeout(timeout)
                        candidate.connect(res[4])
                        sock = candidate
                        break
                    except socket.timeout as e:
                        last_err = e
                    except OSError as e:
                        last_err = e
                    finally:
                        if candidate is not sock:
                            try:
                                candidate.close()
                            except Exception:
                                pass
                if sock is None:
                    raise last_err or OSError("connect failed")
            else:
                sock = socket.create_connection((self.ip, port), timeout=timeout)
            elapsed = (time.time() - start) * 1000
            return PingResult(success=True, latency_ms=elapsed)
        except socket.timeout:
            return PingResult(success=False, latency_ms=None,
                              failure_reason="tcp_timeout")
        except socket.gaierror as e:
            return PingResult(success=False, latency_ms=None,
                              failure_reason=f"dns_failed:{e.strerror or e}")
        except OSError as e:
            if e.errno == errno.ECONNREFUSED:
                return PingResult(success=False, latency_ms=None,
                                  failure_reason="connection_refused")
            return PingResult(
                success=False, latency_ms=None,
                failure_reason=f"tcp_failed:{e.strerror or e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


# ======================================================================
# HTTP monitor — raw socket + ssl for full timing breakdown
# ======================================================================

class HTTPMonitor(TargetMonitor):
    """
    HTTP/HTTPS availability monitor with timing breakdown.

    Default latency-warn threshold is 2000ms (vs 150ms for ICMP), because
    HTTPS naturally takes 200-3000ms (DNS+TCP+TLS+server+network).
    Per-target overrides via custom_settings.latency_warn_ms / .latency_error_ms.
    """

    DEFAULT_WARN_LAT = 2000   # HTTPS sites typically take 1-3 s

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Per-target method preference: starts as HEAD (lightweight), auto-
        # switches to GET if the server returns 405 / 501, then stays on GET
        # for all subsequent probes to avoid the redundant HEAD→retry cycle.
        # Resets to HEAD if the target is edited (new instance created).
        self._preferred_method = "HEAD"

    # Status codes that we treat as redirects to follow.
    # 301 (Moved Permanently), 302 (Found), 303 (See Other),
    # 307 (Temporary Redirect), 308 (Permanent Redirect).
    # Note: 304 (Not Modified) is NOT a redirect — it just means
    # "your cached copy is still fresh".
    REDIRECT_CODES = (301, 302, 303, 307, 308)
    MAX_REDIRECTS  = 5

    def _do_ping(self) -> PingResult:
        """
        Top-level HTTP probe:
          1. Method selection — HEAD if lightweight is fine, GET if keyword
             matching is configured (needs body).
          2. Redirect following — up to MAX_REDIRECTS hops; per-hop timings
             are merged, final status code is what the user sees.
          3. HEAD → GET auto-downgrade — if the server refuses HEAD (405/501)
             we switch to GET, remember the preference, and retry the whole
             redirect chain from the original URL.
          4. Keyword matching — performed on the GET response body after
             status-code check passes.
          5. Certificate expiry extraction — pulled from the TLS socket
             after a successful handshake; only when verify_ssl=True.
        """
        url          = self.settings.get("http_url") or f"http://{self.ip}"
        timeout      = float(self.settings.get("http_timeout", 10.0))
        success_spec = str(self.settings.get("http_success_codes", "2xx,3xx"))
        verify_ssl   = bool(self.settings.get("http_verify_ssl", True))
        follow       = bool(self.settings.get("http_follow_redirects", True))
        keyword      = str(self.settings.get("http_keyword", "")).strip()
        kw_mode      = str(self.settings.get("http_keyword_mode", "contains"))
        body_limit   = int(self.settings.get("http_body_limit_kb", 64)) * 1024

        # Keyword matching requires response body → must use GET.
        # Otherwise start with the cached preferred method (usually HEAD,
        # auto-promotes to GET if server returned 405 on a previous probe).
        method = "GET" if keyword else self._preferred_method
        # Capture the settings version we're probing under so the
        # HEAD->GET auto-downgrade below can refuse to persist when
        # the URL changed mid-probe.  _run_loop also re-checks
        # settings_version on return and drops the RESULT, but
        # _preferred_method is a side-effect on the monitor itself --
        # without this guard an in-flight 405 reply against an OLD
        # URL would overwrite the HEAD reset that update_target_thresholds
        # just performed, and the NEW URL would never get to try the
        # lightweight HEAD path.
        probe_settings_version = self._settings_version

        overall_start = time.time()
        cert_days     = None   # filled in on first successful TLS leg

        def _try_chain(m: str):
            """Run the full redirect chain using HTTP method `m`."""
            nonlocal cert_days
            timings = {}
            current_url = url

            for hop in range(self.MAX_REDIRECTS + 1):
                single = self._do_single_request(
                    current_url, timeout, verify_ssl, method=m,
                    body_limit=body_limit if m == "GET" else 0,
                    connect_target=self.ip if hop == 0 else None)
                # Absorb first-hop phase timings (DNS/TCP/TLS are most
                # informative on the initial connection).
                for k, v in (single.timings or {}).items():
                    if k not in timings:
                        timings[k] = v
                # Propagate cert info from the first HTTPS leg
                if single.cert_days_left is not None and cert_days is None:
                    cert_days = single.cert_days_left

                # Hard network error — propagate immediately
                if single.failure_reason and single.status_code is None:
                    timings["total_ms"] = round((time.time()-overall_start)*1000, 1)
                    return PingResult(success=False, latency_ms=None,
                                      status_code=None,
                                      failure_reason=single.failure_reason,
                                      timings=timings, cert_days_left=cert_days)

                # Follow redirect?
                if (follow and single.status_code in self.REDIRECT_CODES
                        and single._redirect_to):
                    if hop >= self.MAX_REDIRECTS:
                        total_ms = round((time.time()-overall_start)*1000, 1)
                        return PingResult(success=False, latency_ms=total_ms,
                                          failure_reason="too_many_redirects",
                                          cert_days_left=cert_days)
                    current_url = urllib.parse.urljoin(current_url, single._redirect_to)
                    continue

                # Final response
                total_ms = round((time.time()-overall_start)*1000, 1)
                timings["total_ms"] = total_ms

                # Status code check
                ok = self._is_success(single.status_code, success_spec)
                if not ok:
                    return PingResult(success=False, latency_ms=total_ms,
                                      status_code=single.status_code,
                                      failure_reason=f"status_{single.status_code}",
                                      timings=timings, cert_days_left=cert_days)

                # Content-Length framing: truncated body must not pass
                # absent-keyword checks; contains may succeed if the
                # keyword is already in the bytes we received.
                cl = getattr(single, "_content_length", None)
                framing_ok = getattr(single, "_body_framing_complete", True)
                if (m == "GET" and single._body is not None
                        and cl is not None and not framing_ok):
                    required = min(cl, body_limit)
                    if len(single._body) < required:
                        if keyword:
                            if kw_mode == "contains":
                                kw_ok = HTTPMonitor._keyword_match(
                                    single._body,
                                    single._content_type or "",
                                    keyword, kw_mode)
                                if not kw_ok:
                                    return PingResult(
                                        success=False, latency_ms=total_ms,
                                        status_code=single.status_code,
                                        failure_reason="body_incomplete",
                                        timings=timings,
                                        cert_days_left=cert_days,
                                        keyword_ok=False)
                            else:
                                return PingResult(
                                    success=False, latency_ms=total_ms,
                                    status_code=single.status_code,
                                    failure_reason="body_incomplete",
                                    timings=timings,
                                    cert_days_left=cert_days,
                                    keyword_ok=False)
                        # No keyword: status-code-only probes may treat a
                        # partial body as available once headers + code OK.

                # Keyword check (only when GET returned a body)
                kw_ok = None
                if keyword and m == "GET" and single._body is not None:
                    kw_ok = HTTPMonitor._keyword_match(
                        single._body,
                        single._content_type or "",
                        keyword, kw_mode)
                    if not kw_ok:
                        reason = ("keyword_found" if kw_mode == "absent"
                                  else "keyword_not_found")
                        return PingResult(success=False, latency_ms=total_ms,
                                          status_code=single.status_code,
                                          failure_reason=reason, timings=timings,
                                          cert_days_left=cert_days,
                                          keyword_ok=False)

                return PingResult(success=True, latency_ms=total_ms,
                                  status_code=single.status_code,
                                  timings=timings, cert_days_left=cert_days,
                                  keyword_ok=kw_ok)

        result = _try_chain(method)

        # HEAD → GET auto-downgrade: server refused HEAD (405 Method Not
        # Allowed or 501 Not Implemented).  Switch method for this probe
        # and persist the preference so future probes start with GET.
        if (method == "HEAD" and result.status_code in (405, 501)
                and not keyword):   # keyword probes already use GET
            # Only persist the downgrade when this probe is still
            # under the same settings as when it captured the version.
            # A mid-probe URL edit bumps _settings_version and resets
            # _preferred_method back to HEAD; the OLD URL's 405 reply
            # must not stomp that reset.  The result itself is also
            # discarded by _run_loop's version check, so the local
            # GET retry below is only worth attempting under the
            # current settings.
            if probe_settings_version == self._settings_version:
                self._preferred_method = "GET"
                overall_start = time.time()   # reset timer for the GET chain
                cert_days = None
                result = _try_chain("GET")
            # else: settings changed mid-probe; return the original
            # 405 result and let _run_loop drop it.  The next probe
            # will start fresh against the new URL with HEAD.

        return result


    def _do_single_request(self, url: str, timeout: float, verify_ssl: bool,
                             method: str = "HEAD", body_limit: int = 0,
                             connect_target: Optional[str] = None):
        """
        Single HTTP request with full phase timing.

        Parameters
        ----------
        method     : "HEAD" (fast, no body) or "GET" (needed for keyword matching)
        body_limit : if > 0 and method=="GET", read up to this many body bytes
        connect_target : physical connect/DNS target; defaults to URL hostname.
                         Set to self.ip on the first hop so CDN edge-IP tests
                         connect to the configured address while Host/SNI stay
                         on the URL hostname.

        Returns a PingResult with private attributes:
          ._redirect_to  (str|None) — Location header value
          ._body         (bytes|None) — response body, only when GET+body_limit>0
          ._content_type (str|None) — Content-Type header
          .cert_days_left (int|None) — days until SSL cert expires
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            r = PingResult(success=False, latency_ms=None,
                            failure_reason=f"url_parse:{e}")
            r._redirect_to = r._body = r._content_type = None
            return r

        host    = parsed.hostname
        if not host:
            r = PingResult(success=False, latency_ms=None, failure_reason="invalid_url")
            r._redirect_to = r._body = r._content_type = None
            return r
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path    = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        timings = {}
        sock    = None
        try:
            # ── DNS ──────────────────────────────────────────────────
            t = time.time()
            ipv6_only = self.settings.get("ipv6_only", False)
            af_hint = socket.AF_INET6 if ipv6_only else socket.AF_UNSPEC
            peer    = connect_target or host
            try:
                infos = socket.getaddrinfo(peer, port, af_hint, socket.SOCK_STREAM)
                if not infos:
                    raise socket.gaierror("no address")
            except socket.gaierror as e:
                r = PingResult(success=False, latency_ms=None,
                                failure_reason=f"dns_failed:{e.strerror or e}",
                                timings={"dns_ms": round((time.time()-t)*1000, 1)})
                r._redirect_to = r._body = r._content_type = None
                return r
            timings["dns_ms"] = round((time.time()-t)*1000, 1)

            # ── TCP ──────────────────────────────────────────────────
            # Walk all resolved addresses (IPv6/IPv4) — RFC 6724 may prefer
            # IPv6 first even when the host has no working IPv6 path.
            t = time.time()
            last_err = None
            for conn_af, _, _, _, conn_addr in infos:
                candidate = None
                try:
                    candidate = socket.socket(conn_af, socket.SOCK_STREAM)
                    candidate.settimeout(timeout)
                    candidate.connect(conn_addr)
                    sock = candidate
                    break
                except socket.timeout as e:
                    last_err = e
                except OSError as e:
                    last_err = e
                finally:
                    if candidate is not sock:
                        try:
                            candidate.close()
                        except Exception:
                            pass

            if sock is None:
                if isinstance(last_err, socket.timeout):
                    reason = "tcp_timeout"
                else:
                    reason = (f"tcp_failed:{last_err.strerror or last_err}"
                              if last_err else "tcp_failed")
                r = PingResult(success=False, latency_ms=None,
                                failure_reason=reason, timings=timings)
                r._redirect_to = r._body = r._content_type = None
                return r
            timings["tcp_ms"] = round((time.time()-t)*1000, 1)
            sock.settimeout(timeout)

            # ── TLS ──────────────────────────────────────────────────
            cert_days = None
            if use_tls:
                t = time.time()
                try:
                    ctx = ssl.create_default_context()
                    if not verify_ssl:
                        ctx.check_hostname = False
                        ctx.verify_mode    = ssl.CERT_NONE
                    # RFC 6066 forbids IP literals in the TLS SNI extension.
                    # Strict servers (some Cloudflare configs, NGINX with
                    # ssl_reject_handshake / strict server_name) abort the
                    # handshake with unrecognized_name when they see an IP
                    # in SNI.  Passing server_hostname=None skips SNI, but
                    # would trip Python's "check_hostname requires
                    # server_hostname" guard -- so also disable
                    # check_hostname for IP-literal hosts (cert chain still
                    # validates, but CN/SAN match against an IP is unlikely
                    # to be useful anyway).
                    is_ip_literal = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) \
                                    or ":" in host
                    if is_ip_literal:
                        ctx.check_hostname = False
                        sni_host = None
                    else:
                        sni_host = host
                    sock = ctx.wrap_socket(sock, server_hostname=sni_host)
                except ssl.SSLError as e:
                    r = PingResult(success=False, latency_ms=None,
                                    failure_reason=f"tls_failed:{e}", timings=timings)
                    r._redirect_to = r._body = r._content_type = None
                    return r
                except (socket.timeout, OSError):
                    r = PingResult(success=False, latency_ms=None,
                                    failure_reason="tls_timeout", timings=timings)
                    r._redirect_to = r._body = r._content_type = None
                    return r
                timings["tls_ms"] = round((time.time()-t)*1000, 1)

                # Certificate expiry — only available with verify_ssl=True
                # (CERT_NONE mode returns empty dict from getpeercert())
                if verify_ssl:
                    try:
                        cert = sock.getpeercert()
                        if cert and cert.get("notAfter"):
                            # ssl.cert_time_to_seconds parses the OpenSSL
                            # "%b %d %H:%M:%S %Y %Z" format with HARD-CODED
                            # English month names, so it works regardless of
                            # the process LC_TIME locale.  datetime.strptime
                            # with "%b" would silently raise ValueError on
                            # zh_CN-locale systems (the bare except below
                            # would then swallow it, leaving cert_days=None
                            # forever for every HTTPS target).
                            expires_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                            cert_days  = (datetime.fromtimestamp(expires_ts, timezone.utc)
                                          - datetime.now(timezone.utc)).days
                    except Exception:
                        pass   # cert parsing failures are non-fatal

            # ── Request ───────────────────────────────────────────────
            # Per RFC 7230 §5.4 the Host header may include a port and
            # MUST omit any userinfo from the URL.  Always include the
            # port when the URL specifies a non-default one so strict
            # virtualhost configs (and the rare server_name that pins a
            # port) route correctly.  IPv6 literal hosts need brackets
            # around the address in the header (URL syntax handles it
            # automatically; we have to add brackets back ourselves
            # because parsed.hostname strips them).
            default_port = 443 if parsed.scheme == "https" else 80
            host_in_header = f"[{host}]" if ":" in host else host
            if parsed.port and parsed.port != default_port:
                host_header = f"{host_in_header}:{parsed.port}"
            else:
                host_header = host_in_header
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: NetMonitor/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            t_sent = time.time()
            try:
                sock.sendall(req)
            except (socket.timeout, OSError) as e:
                r = PingResult(success=False, latency_ms=None,
                                failure_reason=f"send_failed:{e}", timings=timings,
                                cert_days_left=cert_days)
                r._redirect_to = r._body = r._content_type = None
                return r

            # ── Read headers (+ start of body) ────────────────────────
            raw = b""
            ttfb = None
            deadline = time.time() + timeout   # total per-request deadline
            max_hdr  = 65536
            body_start = b""
            hdr_lines  = None
            status_code = None
            try:
                while True:
                    while b"\r\n\r\n" not in raw and len(raw) < max_hdr:
                        remain = deadline - time.time()
                        if remain <= 0:
                            raise socket.timeout("total request timeout")
                        sock.settimeout(max(0.01, remain))
                        try:
                            chunk = sock.recv(4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        if ttfb is None:
                            ttfb = round((time.time()-t_sent)*1000, 1)
                        raw += chunk
                    if b"\r\n\r\n" not in raw:
                        r = PingResult(success=False, latency_ms=None,
                                        failure_reason="header_incomplete",
                                        timings=timings,
                                        cert_days_left=cert_days)
                        r._redirect_to = r._body = r._content_type = None
                        return r
                    hdr_block, _, remainder = raw.partition(b"\r\n\r\n")
                    lines = hdr_block.split(b"\r\n")
                    if not lines:
                        r = PingResult(success=False, latency_ms=None,
                                        failure_reason="bad_response",
                                        timings=timings,
                                        cert_days_left=cert_days)
                        r._redirect_to = r._body = r._content_type = None
                        return r
                    status_line = lines[0].decode("ascii", errors="replace")
                    code = HTTPMonitor._parse_http_status_code(status_line)
                    if code is None:
                        r = PingResult(success=False, latency_ms=None,
                                        failure_reason="bad_response",
                                        timings=timings,
                                        cert_days_left=cert_days)
                        r._redirect_to = r._body = r._content_type = None
                        return r
                    # Skip 1xx informational blocks (103 Early Hints, 100
                    # Continue, …).  101 Switching Protocols is final here
                    # because we do not perform protocol upgrades.
                    if HTTPMonitor._is_informational_status(code):
                        raw = remainder
                        continue
                    status_code = code
                    hdr_lines   = lines
                    body_start  = remainder
                    break
            except socket.timeout:
                r = PingResult(success=False, latency_ms=None,
                                failure_reason="recv_timeout", timings=timings,
                                cert_days_left=cert_days)
                r._redirect_to = r._body = r._content_type = None
                return r
            timings["ttfb_ms"] = ttfb if ttfb is not None else 0.0

            location     = None
            content_type = None
            content_length = None
            transfer_encoding = None
            for line in hdr_lines[1:]:
                try:
                    decoded = line.decode("latin-1", errors="replace")
                except Exception:
                    continue
                if ":" not in decoded:
                    continue
                name, _, value = decoded.partition(":")
                name_lower = name.strip().lower()
                if name_lower == "location":
                    location = value.strip()
                elif name_lower == "content-type":
                    content_type = value.strip()
                elif name_lower == "content-length":
                    # Parse the response-body length now so the body
                    # read loop below can stop the moment the framed
                    # body is fully received.  Pre-2025 the loop only
                    # exited on body_limit / EOF / timeout, so a
                    # well-formed Content-Length response from a server
                    # that kept the socket open (proxies, gateways,
                    # custom services) was misclassified as
                    # body_recv_timeout even though the body had
                    # already arrived in full and the keyword had
                    # already matched.  Tolerate bogus values
                    # silently -- a server that lies about the length
                    # falls back to the existing "read until EOF /
                    # body_limit" path.
                    try:
                        n = int(value.strip())
                        if n >= 0:
                            content_length = n
                    except ValueError:
                        pass
                elif name_lower == "transfer-encoding":
                    transfer_encoding = value.strip().lower()

            # ── Read body (GET only, up to body_limit bytes) ─────────
            body = None
            body_framing_complete = True
            is_chunked = "chunked" in (transfer_encoding or "")
            # RFC 9112: 204/304 end at the header block — no body to wait for
            # even when the connection stays open (keep-alive).
            no_message_body = status_code in (204, 304)
            if method == "GET" and body_limit > 0:
                body = body_start
                try:
                    if no_message_body:
                        body = body_start[:body_limit]
                    elif is_chunked:
                        body, chunk_err = HTTPMonitor._read_chunked_body(
                            sock, body, body_limit, deadline)
                        if chunk_err:
                            r = PingResult(success=False, latency_ms=None,
                                            failure_reason=chunk_err,
                                            timings=timings,
                                            cert_days_left=cert_days)
                            r._redirect_to = r._body = r._content_type = None
                            return r
                    elif content_length is not None:
                        body_stop = min(content_length, body_limit)
                        while len(body) < body_stop:
                            remain = deadline - time.time()
                            if remain <= 0:
                                raise socket.timeout("body read total timeout")
                            sock.settimeout(max(0.01, remain))
                            chunk = sock.recv(4096)
                            if not chunk:
                                body_framing_complete = False
                                break
                            body += chunk
                        if len(body) < body_stop:
                            body_framing_complete = False
                    else:
                        while len(body) < body_limit:
                            remain = deadline - time.time()
                            if remain <= 0:
                                raise socket.timeout("body read total timeout")
                            sock.settimeout(max(0.01, remain))
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            body += chunk
                except socket.timeout:
                    r = PingResult(success=False, latency_ms=None,
                                    failure_reason="body_recv_timeout",
                                    timings=timings,
                                    cert_days_left=cert_days)
                    r._redirect_to = r._body = r._content_type = None
                    return r
                except OSError:
                    if is_chunked:
                        r = PingResult(success=False, latency_ms=None,
                                        failure_reason="chunked_premature_eof",
                                        timings=timings,
                                        cert_days_left=cert_days)
                        r._redirect_to = r._body = r._content_type = None
                        return r
                    if content_length is not None:
                        body_framing_complete = False
                body = body[:body_limit]

            r = PingResult(success=True, latency_ms=None,
                            status_code=status_code, timings=timings,
                            cert_days_left=cert_days)
            r._redirect_to = location
            r._body        = body
            r._content_type = content_type
            r._content_length = content_length
            r._body_framing_complete = body_framing_complete
            return r

        except OSError:
            te = locals().get("transfer_encoding") or ""
            reason = ("chunked_premature_eof" if "chunked" in te
                      else "recv_closed")
            r = PingResult(success=False, latency_ms=None,
                            failure_reason=reason,
                            timings=timings or None,
                            cert_days_left=cert_days)
            r._redirect_to = r._body = r._content_type = None
            return r
        except Exception as e:
            r = PingResult(success=False, latency_ms=None,
                            failure_reason=f"unexpected:{type(e).__name__}",
                            timings=timings or None)
            r._redirect_to = r._body = r._content_type = None
            return r
        finally:
            if sock:
                try: sock.close()
                except Exception: pass


    _HTTP_VERSION_RE = re.compile(r"^HTTP/\d+\.\d+$", re.ASCII)

    @staticmethod
    def _parse_http_status_code(status_line: str) -> Optional[int]:
        """Return numeric status when the line is a valid HTTP/ response."""
        parts = status_line.split(None, 2)
        if len(parts) < 2:
            return None
        version, code_text = parts[0], parts[1]
        if not HTTPMonitor._HTTP_VERSION_RE.match(version):
            return None
        if len(code_text) != 3 or not code_text.isdigit():
            return None
        code = int(code_text)
        if code < 100 or code > 599:
            return None
        return code

    @staticmethod
    def _is_informational_status(code: int) -> bool:
        """True for 1xx responses that may precede a final status line."""
        return 100 <= code < 200 and code != 101

    @staticmethod
    def _read_chunked_body(sock, initial: bytes, body_limit: int,
                           deadline: float) -> tuple[bytes, Optional[str]]:
        """
        Minimal HTTP/1.1 chunked decoder.  Stops at the zero-length
        chunk without waiting for the server to close the socket.
        Returns (body, failure_reason).  failure_reason is None on success.
        """
        buf = initial
        out = b""

        def _recv_more() -> bool:
            nonlocal buf
            remain = deadline - time.time()
            if remain <= 0:
                raise socket.timeout("body read total timeout")
            sock.settimeout(max(0.01, remain))
            try:
                chunk = sock.recv(4096)
            except OSError:
                return False
            if chunk:
                buf += chunk
            return bool(chunk)

        def _need(n: int) -> bool:
            while len(buf) < n:
                if not _recv_more():
                    return False
            return True

        def _read_trailer_section() -> Optional[str]:
            """Require the blank line that ends the trailer section."""
            nonlocal buf
            while True:
                while b"\r\n" not in buf:
                    if not _recv_more():
                        return "chunked_premature_eof"
                line, _, buf = buf.partition(b"\r\n")
                if line == b"":
                    return None

        def _read_chunk_header() -> tuple[Optional[int], Optional[str]]:
            nonlocal buf
            while b"\r\n" not in buf:
                if not _recv_more():
                    return None, "chunked_premature_eof"
                if len(buf) > 65536:
                    return None, "chunked_bad_framing"
            size_line, _, buf = buf.partition(b"\r\n")
            try:
                chunk_size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                return None, "chunked_bad_size"
            if chunk_size < 0:
                return None, "chunked_bad_size"
            return chunk_size, None

        def _consume_crlf() -> Optional[str]:
            nonlocal buf
            while len(buf) < 2:
                if not _recv_more():
                    return "chunked_premature_eof"
            if not buf.startswith(b"\r\n"):
                return "chunked_bad_framing"
            buf = buf[2:]
            return None

        def _consume_chunk_data(chunk_size: int, accumulate: bool
                                ) -> Optional[str]:
            nonlocal buf, out
            remaining = chunk_size
            while remaining > 0:
                if buf:
                    n = min(len(buf), remaining, 4096)
                else:
                    remain = deadline - time.time()
                    if remain <= 0:
                        raise socket.timeout("body read total timeout")
                    sock.settimeout(max(0.01, remain))
                    try:
                        piece = sock.recv(min(remaining, 4096))
                    except OSError:
                        return "chunked_premature_eof"
                    if not piece:
                        return "chunked_premature_eof"
                    if accumulate and len(out) < body_limit:
                        take = min(len(piece), body_limit - len(out))
                        out += piece[:take]
                    remaining -= len(piece)
                    continue
                n = min(len(buf), remaining, 4096)
                if accumulate and len(out) < body_limit:
                    take = min(n, body_limit - len(out))
                    out += buf[:take]
                buf = buf[n:]
                remaining -= n
            return _consume_crlf()

        try:
            accumulate = True
            while True:
                chunk_size, err = _read_chunk_header()
                if err:
                    return out[:body_limit], err
                if chunk_size == 0:
                    err = _read_trailer_section()
                    return out[:body_limit], err
                err = _consume_chunk_data(chunk_size, accumulate)
                if err:
                    return out[:body_limit], err
                if accumulate and len(out) >= body_limit:
                    accumulate = False
        except socket.timeout:
            return out[:body_limit], "body_recv_timeout"
        except OSError:
            return out[:body_limit], "chunked_premature_eof"

    @staticmethod
    def _keyword_match(body: bytes, content_type: str, keyword: str, mode: str) -> bool:
        """
        Search for `keyword` in `body`.

        mode="contains" → body must contain keyword (detects expected content)
        mode="absent"   → body must NOT contain keyword (detects error markers)

        Only runs on text-like content (text/*, application/json, /xml, /js).
        Binary responses are ignored — match is treated as True (no penalty).
        Keyword comparison is case-insensitive.
        Charset is extracted from Content-Type; fallback chain: utf-8 → latin-1.
        """
        if not keyword:
            return True   # no keyword configured → always pass

        # Content-type gating: skip binary content
        ct = (content_type or "").lower().split(";")[0].strip()
        text_types = ("text/", "application/json", "application/xml",
                      "application/xhtml", "application/javascript")
        if ct and not any(ct.startswith(t) for t in text_types):
            return True   # non-text: skip keyword check, don't penalise

        # Extract charset from Content-Type header
        import re as _re
        enc = "utf-8"
        m = _re.search(r"charset\s*=\s*([\w-]+)", content_type or "", _re.I)
        if m:
            enc = m.group(1).strip().strip('"\'')

        try:
            text = body.decode(enc, errors="replace")
        except (LookupError, Exception):
            text = body.decode("utf-8", errors="replace")

        found = keyword.lower() in text.lower()
        return found if mode == "contains" else not found

    @staticmethod
    def _is_success(code: int, spec: str) -> bool:
        spec = spec.strip().lower().replace(" ", "")
        for part in spec.split(","):
            if part == "2xx" and 200 <= code < 300: return True
            if part == "3xx" and 300 <= code < 400: return True
            if part == "4xx" and 400 <= code < 500: return True
            if part == "5xx" and 500 <= code < 600: return True
            try:
                if int(part) == code: return True
            except ValueError:
                pass
        return False


# ======================================================================
# Engine
# ======================================================================

class DNSMonitor(TargetMonitor):
    """
    DNS availability + hijacking monitor.

    Settings:
      ip:            DNS server IP to query
      dns_domain:    domain to resolve
      dns_expected:  comma-separated expected IPs (empty = availability only)
    """

    @staticmethod
    def _build_query(domain: str) -> bytes:
        """Build a minimal DNS A-record query packet."""
        import random as _rand
        txid  = _rand.randint(0, 65535).to_bytes(2, "big")
        flags = b"\x01\x00"          # standard query, recursion desired
        hdr   = txid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in domain.rstrip(".").split("."):
            try:
                enc = label.encode("ascii")  # ASCII domain labels (common case)
            except UnicodeEncodeError:
                enc = label.encode("idna")   # IDN international domain labels
            qname += bytes([len(enc)]) + enc
        qname += b"\x00"            # root label
        return hdr + qname + b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN

    @staticmethod
    def _skip_name(data: bytes, offset: int) -> int:
        """Skip a DNS name field, handling RFC 1035 compression pointers.
        Returns the offset just after the name.
        """
        for _ in range(30):          # guard against malformed / circular packets
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:          # end-of-name sentinel
                return offset + 1
            if (length & 0xC0) == 0xC0:  # compression pointer (0b11xxxxxx)
                return offset + 2        # 2-byte pointer; target handled by caller
            offset += 1 + length         # regular label
        return offset

    @staticmethod
    def _parse_a_records(data: bytes) -> list:
        """Extract ALL A-record IPs from a DNS response.
        Correctly handles compressed names in the answer section.
        """
        if len(data) < 12:
            return []
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        if ancount == 0:
            return []

        offset = 12
        # Skip question section
        for _ in range(qdcount):
            offset = DNSMonitor._skip_name(data, offset)
            offset += 4              # QTYPE + QCLASS

        # Parse answer section
        ips = []
        for _ in range(ancount):
            offset = DNSMonitor._skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype    = int.from_bytes(data[offset:offset+2], "big")
            rdlength = int.from_bytes(data[offset+8:offset+10], "big")
            offset  += 10
            if rtype == 1 and rdlength == 4:   # A record = IPv4
                ips.append(".".join(str(b) for b in data[offset:offset+4]))
            offset += rdlength
        return ips

    def _do_ping(self) -> PingResult:
        domain       = self.settings.get("dns_domain", "").strip()
        expected_raw = self.settings.get("dns_expected", "").strip()
        expected_ips = {ip.strip() for ip in expected_raw.split(",")
                        if ip.strip()} if expected_raw else set()

        if not domain:
            return PingResult(success=False, latency_ms=None,
                              failure_reason="dns_no_domain")

        sock = None
        try:
            query     = self._build_query(domain)
            txid_sent = query[:2]          # first 2 bytes are the Transaction ID
            timeout   = float(self.settings.get("timeout", 5.0))
            af        = socket.AF_INET6 if ":" in self.ip else socket.AF_INET
            sock      = socket.socket(af, socket.SOCK_DGRAM)
            t0        = time.time()
            deadline  = t0 + timeout
            # connect() the UDP socket to the configured DNS server so
            # the OS only delivers packets whose source matches
            # (self.ip, 53).  Without this any forged UDP packet that
            # happens to carry our transaction id is accepted as a
            # "successful" reply -- which lets an attacker who can
            # inject UDP into the probe socket make a dead DNS server
            # look healthy on the monitor.  send() + recv() (instead
            # of sendto/recvfrom) ensures the kernel's source filter
            # is what enforces this, not application-level matching
            # we'd otherwise have to add to every recv path below.
            sock.connect((self.ip, 53))
            sock.send(query)

            # Keep reading until we see OUR txid or the total deadline passes.
            # Stray / delayed UDP packets (previous timed-out query, port
            # noise) must be discarded — a single mismatch must not be
            # treated as probe failure while the real answer may still arrive.
            # NB: with connect() above, the OS already filters out any
            # packet whose source is not (self.ip, 53), so a recv()
            # here will only ever return bytes from the configured
            # DNS server.
            data = None
            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(max(0.01, remaining))
                try:
                    packet = sock.recv(4096)
                except socket.timeout:
                    break
                if len(packet) >= 2 and packet[:2] == txid_sent:
                    data = packet
                    break

            if data is None:
                return PingResult(success=False, latency_ms=None,
                                  failure_reason="dns_timeout")

            latency = (time.time() - t0) * 1000

            # ── Response sanity checks ──────────────────────────────
            # A valid DNS response must be at least 12 bytes (header only).
            if len(data) < 12:
                return PingResult(success=False, latency_ms=latency,
                                  failure_reason="dns_bad_response")
            # QR bit (bit 7 of byte 2) must be 1 (response, not a query).
            if not (data[2] & 0x80):
                return PingResult(success=False, latency_ms=latency,
                                  failure_reason="dns_bad_response")
            # ───────────────────────────────────────────────────────

            # RCODE in lower 4 bits of byte 3
            rcode = data[3] & 0x0F
            if rcode == 3:
                return PingResult(success=False, latency_ms=latency,
                                  failure_reason="nxdomain")
            if rcode != 0:
                return PingResult(success=False, latency_ms=latency,
                                  failure_reason=f"dns_rcode_{rcode}")

            # Optional: verify resolved IPs against expected set
            if expected_ips:
                resolved = set(self._parse_a_records(data))
                if not resolved:
                    return PingResult(success=False, latency_ms=latency,
                                      failure_reason="dns_no_a_record")
                if not resolved & expected_ips:
                    # No overlap → hijacking detected
                    return PingResult(
                        success=False, latency_ms=latency,
                        failure_reason="dns_hijack:" + ",".join(sorted(resolved)))

            return PingResult(success=True, latency_ms=latency)

        except socket.timeout:
            return PingResult(success=False, latency_ms=None,
                              failure_reason="dns_timeout")
        except Exception as e:
            return PingResult(success=False, latency_ms=None,
                              failure_reason=f"dns_error:{e}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


class PingEngine:
    """Manager of all monitors. Public API unchanged from previous version."""

    def __init__(self, settings, on_state_change):
        self.settings = settings
        self.on_state_change = on_state_change
        self._monitors: dict[str, TargetMonitor] = {}
        self._monitors_lock = threading.Lock()   # guards _monitors against concurrent add/remove
        # Optional DataStore reference (wired by MainWindow via
        # set_data_store after engine + data_store are both
        # constructed).  _run_loop captures the per-target generation
        # at probe start so record_ping can carry it through to the
        # writer thread's pre-INSERT generation guard -- closing the
        # last TOCTOU window between commit-side identity check and
        # the actual DataStore.record_ping queue submission.
        self._data_store = None

    def set_data_store(self, data_store) -> None:
        """Wire the DataStore reference used for the probe-start
        generation snapshot.  Safe to call once on app startup; the
        engine never mutates the reference and only reads
        current_target_generation() through it.  No-op when called
        with None (synthetic tests can leave the engine detached).
        """
        self._data_store = data_store

    def add_target(self, target_id, ip, ping_type="icmp", custom_settings=None,
                   initial_status: str = "gray", start_paused: bool = False):
        """Register and start a new probe monitor.

        start_paused: arm the monitor's _pause_event BEFORE the thread
        is spawned so the very first _run_loop iteration immediately
        waits on the pause guard, with NO probe issued.  Without this
        the only way to resume-on-create was to call pause_target()
        AFTER add_target() returned -- but the monitor thread is
        already running by then, and a real probe could fire in the
        race window.  Used by the type-change branch of
        MainWindow._on_edit to preserve the paused-card state across
        a rebuild.  Default False keeps the original "live on add"
        behaviour for normal add_target callers.
        """
        with self._monitors_lock:
            if target_id in self._monitors: return
            merged = dict(self.settings)
            if custom_settings: merged.update(custom_settings)
            ping_type = (ping_type or "icmp").lower()
            cls = {"tcp": TCPMonitor, "http": HTTPMonitor, "https": HTTPMonitor,
                   "dns": DNSMonitor}.get(ping_type, TargetMonitor)
            monitor = cls(target_id=target_id, ip=ip,
                           settings=merged, on_state_change=self.on_state_change,
                           initial_status=initial_status)
            # Track which keys came from the per-target override dict so
            # update_global_settings() knows which monitor.settings entries
            # are owned by the target's own config and must NOT be
            # clobbered when the user changes the global defaults.  See
            # update_global_settings() below for the consumption side.
            monitor._override_keys = set(custom_settings.keys()) if custom_settings else set()
            if start_paused:
                # MUST set _pause_event before .start() so the thread
                # sees the pause flag on its very first iteration --
                # otherwise _do_ping fires once before pause_target
                # can race in.
                monitor.pause()
            self._monitors[target_id] = monitor
        monitor.start()   # start outside lock to avoid holding lock during thread spawn

    def remove_target(self, target_id, join_timeout: float = 1.5):
        """
        Remove a monitor and wait briefly for its thread to exit.

        Why join (not just stop):
            The previous implementation only set the stop event and
            returned.  Callers like main_window._on_edit immediately
            invoke add_target() with the same target_id, which means the
            old thread (possibly still inside subprocess.run for a ping
            command, or mid-callback) and the brand-new monitor thread
            briefly coexist.  Both threads then race on:
              • on_state_change → UI/web push for the same target_id
              • history_store / data_store writes
            producing flickering UI status and out-of-order DB rows.

        Why the timeout is small (1.5 s default):
            remove_target may be called from the Tk UI thread; we can't
            block it for long.  1.5 s is enough to outlast a normal
            ICMP / TCP / DNS probe (sub-second to ~1 s).  An HTTP probe
            with a long http_timeout may exceed this; in that case the
            thread is left as a daemon and will exit on its own as soon
            as the probe returns and the next loop iteration sees the
            stop event.  Worst case is a single duplicate state update
            for that target, which is the same as the legacy behaviour.

        Pass join_timeout=0 to skip waiting entirely (matches legacy
        semantics for callers that explicitly want it).
        """
        with self._monitors_lock:
            monitor = self._monitors.pop(target_id, None)
        if monitor:
            monitor.stop()   # stop outside lock
            if join_timeout > 0:
                monitor.join(join_timeout)
                if monitor.is_alive():
                    print(f"[PingEngine] monitor {target_id} did not stop "
                          f"within {join_timeout}s (continuing as daemon)")

    def update_target_ip(self, target_id, new_ip):
        with self._monitors_lock:
            m = self._monitors.get(target_id)
        if not m:
            return
        # No-op when the IP didn't actually move -- bump_target_generation
        # would otherwise needlessly drop in-flight probes and the next
        # legitimate record_ping under the unchanged IP.  monitor.update_ip
        # has its own same-IP guard but we mirror it here so the DS bump
        # below stays tied to a real identity boundary.
        if m.ip == new_ip:
            return
        m.update_ip(new_ip)
        # Also bump the DataStore-side target generation.  Without
        # this, the captured_generation guard in record_ping /
        # record_alert / record_traceroute can't catch a TOCTOU
        # window between _on_state_update's _state_is_current pass
        # and the actual queue.put -- an IP edit landing in that gap
        # bumps the monitor's _ip_version but leaves DS gen alone,
        # so the writer-thread check accepts the stale row.  Pre-
        # 2025 the DS bump only fired on wipe / on_target_removed
        # (since only those paths needed it for diag results); now
        # it also fires for every "the operator changed what we're
        # probing" boundary, matching the monitor.version pre-bumps.
        try:
            _ds = getattr(self, "_data_store", None)
            if _ds is not None:
                _ds.bump_target_generation(target_id)
        except Exception:
            pass

    def invalidate_target_settings(self, target_id) -> None:
        """Pre-emptively bump the monitor's _settings_version (and
        the DataStore-side target generation, when wired).

        Counterpart to update_target_ip's pre-emptive bump.  Called
        from MainWindow._on_edit BEFORE the UI metadata caches are
        rewritten so a probe that started under the OLD config and
        is still in-flight gets dropped by _run_loop's
        settings_version re-check on return -- even though the
        actual settings replacement (via update_target_thresholds)
        happens several function calls later.

        Without this hook there's a real window between "UI caches
        now reflect the new identity" and "monitor.settings carry
        the new config".  An old-config probe completing in that
        window would pass the version check (no bump yet) and be
        attributed to the new identity in DataStore.  Bumping here
        invalidates it; the subsequent update_target_thresholds
        bumps again (idempotent for correctness -- the swap and
        bump aren't perfectly atomic, but the residual sub-call
        window is microscopic compared to the user-perceived
        edit-save window this hook closes).

        DataStore-side bump closes the additional TOCTOU between
        _on_state_update's _state_is_current check and the
        downstream record_ping / record_alert queue submission.  A
        probe that captured (old monitor versions, old DS gen) and
        is suspended INSIDE _on_state_update between the identity
        check and the queue.put would otherwise survive: the
        captured monitor versions still matched at check time, and
        no wipe occurred so the DS gen guard ALSO matched.  Bumping
        DS gen here means the writer thread sees a mismatch on the
        record_*'s captured_generation and drops the row.
        """
        with self._monitors_lock:
            m = self._monitors.get(target_id)
        if m:
            m._settings_version += 1
        try:
            _ds = getattr(self, "_data_store", None)
            if _ds is not None:
                _ds.bump_target_generation(target_id)
        except Exception:
            pass

    def update_target_thresholds(self, target_id, new_thresholds,
                                  clear_keys: tuple = ()):
        """
        Merge new settings into the monitor's existing settings.

        Critical: we do NOT clear the existing settings dict first.
        Clearing was the source of the TCP "connection refused after edit"
        bug — it wiped out type-specific fields like tcp_port and http_url
        that were stored on the monitor when the target was created.
        Just merging preserves those fields when only thresholds change.

        Callers may include type-specific keys in new_thresholds too (e.g.,
        passing the combined thresholds + extra dict from main_window's
        edit flow). Those will be merged in alongside the threshold values
        and take effect on the next ping cycle.

        clear_keys: iterable of setting keys to REMOVE from the monitor
            iff they are NOT present in new_thresholds.  This is how the
            edit-dialog flow signals "user cleared these specific fields
            in the UI, drop them on the live monitor so it reverts to
            global defaults right now."  Without this hook, a cleared
            per-target http_keyword / dns_expected / latency_warn_ms
            stays live on the running monitor until the next app restart
            — even though the disk config (via ConfigManager.update_target's
            snapshot semantics) has already dropped it.

        Atomicity: we build the merged dict first, then rebind
        m.settings in a single attribute assignment.  This matters
        because the monitor thread reads the same dict from many call
        sites (_run_loop → _do_ping → _compute_state, each doing several
        independent .get() calls).  An in-place .update() releases the
        GIL between key writes, so the ping thread could observe a
        partial state — e.g. new loss_red threshold combined with the
        old loss_orange threshold, momentarily inverting the alarm
        ordering.  Rebinding is atomic: every reader either sees the
        whole old dict or the whole new dict.
        """
        with self._monitors_lock:
            m = self._monitors.get(target_id)
        if m:
            # Maintain _override_keys: drop keys the user just cleared,
            # add keys the user just set.  Consumed by
            # update_global_settings() to leave per-target values alone.
            overrides = getattr(m, "_override_keys", set())
            for k in clear_keys:
                if k not in new_thresholds:
                    overrides.discard(k)
            for k in new_thresholds:
                overrides.add(k)
            m._override_keys = overrides

            merged = dict(m.settings)
            for k in clear_keys:
                if k not in new_thresholds:
                    # Clearing a per-target override does NOT mean "use
                    # the hardcoded fallback in _run_loop"; it means
                    # "revert to the current engine-global value".
                    # Without this, clearing the per-target ping_interval
                    # would drop the key entirely and _run_loop's
                    # `settings.get("ping_interval", 1.0)` would fall back
                    # to the hardcoded 1.0 s, ignoring whatever the user
                    # actually configured in the global Ping Interval
                    # box.  Falls through to `merged.pop` only when the
                    # engine itself doesn't carry that key (e.g.
                    # type-specific extras like http_url).
                    if k in self.settings:
                        merged[k] = self.settings[k]
                    else:
                        merged.pop(k, None)
            merged.update(new_thresholds)
            # Atomicity ordering: swap m.settings FIRST, then run
            # invalidate_stale_extended_caches (which bumps
            # _settings_version).  Pre-2025 the bump happened before
            # the swap, so a new probe starting in the gap captured
            # (new_version, old_settings) -- on return the version
            # still matched (no further bump), and the OLD-settings
            # result was accepted under what looked like NEW config.
            # Swapping the order inverts the residual race: a probe
            # in the new gap captures (old_version, new_settings),
            # and on return the version mismatch drops it.  Lossy
            # but never wrong; the next probe restarts cleanly.
            # We capture the OLD settings reference before the swap
            # so invalidate_stale_extended_caches still gets the
            # proper old-vs-new diff for its cache-cleanup decisions.
            # Hold the per-monitor commit lock around BOTH the settings
            # rebind and the invalidate_stale_extended_caches call so
            # the swap + version bump + cache cleanup are visible to
            # _run_loop's commit-lock-protected section as one atomic
            # operation.  RLock so invalidate_stale_extended_caches
            # re-acquiring from inside is safe.  Without the outer
            # lock, a probe finishing between `m.settings = merged`
            # and the invalidate call could observe NEW settings under
            # OLD version, _compute_state with the new settings, then
            # have invalidate's cleanup undone -- the same shape as
            # the rollback-overwrites-edit bug.
            old_settings = m.settings
            with m._commit_lock:
                m.settings = merged
                m.invalidate_stale_extended_caches(old_settings, merged)
            # Window-size override may have changed — keep the deque in sync.
            self._resize_window_if_needed(m, merged.get("window_size", 10))

    def pause_target(self, target_id):
        with self._monitors_lock:
            m = self._monitors.get(target_id)
        if m:
            m.pause()

    def resume_target(self, target_id):
        with self._monitors_lock:
            m = self._monitors.get(target_id)
        if m:
            m.resume()

    def update_global_settings(self, new_settings):
        # Atomic-replace at both engine and monitor scope — see
        # update_target_thresholds for the rationale.  Engine-scope
        # replacement matters because future add_target() calls will copy
        # whichever dict self.settings currently points at.
        self.settings = {**self.settings, **new_settings}
        with self._monitors_lock:
            monitors = list(self._monitors.values())
        for m in monitors:
            # Per-target overrides win over a global change.  The previous
            # `m.settings = {**m.settings, **new_settings}` blindly pushed
            # the new global values onto every monitor -- silently
            # clobbering any per-target override the user had set via the
            # edit dialog.  The config file still had the override, so a
            # restart resurrected it; runtime behaviour differed from
            # disk state until then.  Filter out anything the target
            # owns per-target before applying.
            overrides = getattr(m, "_override_keys", set())
            applied = {k: v for k, v in new_settings.items()
                        if k not in overrides}
            m.settings = {**m.settings, **applied}
            # If the new global window_size actually reached this monitor
            # (i.e. it isn't overridden per-target), resize its deque so
            # the change takes effect immediately on the running
            # statistics window.  Otherwise the settings dict says the
            # new size but loss_rate / jitter keep using the old, smaller
            # window until the next restart.
            if "window_size" in applied:
                self._resize_window_if_needed(m, applied["window_size"])

    @staticmethod
    def _resize_window_if_needed(monitor, new_size):
        """Rebind monitor._window to a deque of the new maxlen, keeping the
        most-recent N samples.  No-op if maxlen is already correct.

        Deque construction with maxlen consumes the iterable left-to-right
        and discards items beyond the new cap, so shrinking the window
        keeps the most recent samples (which is what the loss-rate /
        jitter calculation cares about) and growing it preserves all
        existing samples with room for more.

        Rebinding (vs in-place shrink) is atomic and matches the same
        "build new, swap once" discipline used for m.settings — the
        monitor thread's iteration over self._window either sees the
        complete old deque or the complete new one, never a half-resized
        one.
        """
        try:
            new_size = int(new_size)
        except (TypeError, ValueError):
            return
        if new_size <= 0 or monitor._window.maxlen == new_size:
            return
        monitor._window = deque(monitor._window, maxlen=new_size)

    def update_settings(self, new_settings):
        """Legacy alias."""
        self.update_global_settings(new_settings)

    def start_all(self, targets, initial_statuses: dict | None = None):
        initial_statuses = initial_statuses or {}
        for t in targets:
            if not t.get("enabled", True): continue
            custom = dict(t.get("thresholds") or {})
            # NOTE: "timeout" must be propagated because TCPMonitor and
            # DNSMonitor read it via self.settings.get("timeout", ...).
            # Without it, a per-target timeout override (e.g. 8s for a
            # weak-link node) is silently dropped at start_all and the
            # monitor falls back to the 3s / 5s default -- producing
            # spurious "timeout" outages right after every restart.
            # HTTPMonitor uses its own "http_timeout" key already.
            # NOTE: http_keyword / http_keyword_mode MUST be propagated
            # because HTTPMonitor._do_single_request reads them via
            # self.settings.get("http_keyword", ...) — without these in
            # the whitelist, a per-target keyword check set in the edit
            # dialog was silently dropped at every restart, leaving the
            # config alive on disk but inert at runtime.
            for k in ("tcp_port", "tcp_probe_ports", "timeout",
                      "http_url", "http_success_codes",
                      "http_timeout", "http_verify_ssl",
                      "http_follow_redirects", "http_expected_status",
                      "http_keyword", "http_keyword_mode",
                      "dns_domain", "dns_expected",
                      "ipv6_only"):
                if k in t: custom[k] = t[k]
            self.add_target(t["id"], t["ip"],
                             ping_type=t.get("ping_type", "icmp"),
                             custom_settings=custom or None,
                             initial_status=initial_statuses.get(t["id"], "gray"))

    def stop_all(self, join_timeout: float = 3.0):
        """
        Stop every monitor and wait (briefly) for them to terminate.

        Uses a single deadline shared across all join() calls so total
        wait is bounded by join_timeout regardless of monitor count.
        Without this, shutting down 50 nodes serially at 1.5s each would
        block the UI thread for over a minute.  All monitors are still
        daemon threads, so anything that doesn't exit in time will be
        killed when the process exits.
        """
        with self._monitors_lock:
            monitors = list(self._monitors.values())
            self._monitors.clear()
        # Signal all stop events first so threads can begin unwinding
        # concurrently while we wait below.
        for m in monitors:
            m.stop()
        if join_timeout <= 0:
            return
        deadline = time.time() + join_timeout
        stragglers = 0
        for m in monitors:
            remaining = max(0.0, deadline - time.time())
            if remaining == 0.0:
                # Out of budget — don't bother waiting further.
                if m.is_alive(): stragglers += 1
                continue
            m.join(remaining)
            if m.is_alive(): stragglers += 1
        if stragglers:
            print(f"[PingEngine] stop_all: {stragglers}/{len(monitors)} "
                  f"monitor(s) still running after {join_timeout}s "
                  f"(will exit as daemons)")
