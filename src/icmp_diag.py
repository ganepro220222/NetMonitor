"""
icmp_diag.py — ICMP advanced diagnostics (large/small packet, DF, PMTU)

Architecture principle: this module is COMPLETELY isolated from the regular
monitoring loop (PingEngine / ICMPMonitor).  Nothing here runs automatically
or touches alert/status state.  All entry points are manual / on-demand.

Phase 1:  single-shot + DF probing
Phase 2:  PMTU binary-search + stability test
Phase 3:  history persistence
"""
from __future__ import annotations

import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

# ── Concurrent diagnostic task limit ────────────────────────────────────
# Shared with dns_diag and ad-hoc traceroute via src.diag_sem; ensures the
# user can only run one on-demand diagnostic at a time across the whole
# app (C-side ICMP, C-side DNS, Web ICMP tab, manual tracert).  Centralised
# in diag_sem.py so adding a new diagnostic type doesn't require touching
# every existing module.
from src.diag_sem import DIAG_TASK_SEM as _TASK_SEM

# Cached platform check — avoids calling platform.system() on every probe.
_IS_WIN = platform.system().lower() == "windows"

# How often the probe poll loop wakes up to check cancellation.
# 100 ms is the sweet spot: fast enough to feel instant on the UI, slow
# enough to add negligible CPU vs. true blocking subprocess.run().
_POLL_INTERVAL_S = 0.1

# ── Unified error codes ─────────────────────────────────────────────────
# These are stable identifiers; UI maps them to human-readable text.
ERROR_OK           = "ok"
ERROR_TIMEOUT      = "timeout"
ERROR_FRAG_NEEDED  = "frag_needed"    # DF=on and packet too large for path
ERROR_UNREACHABLE  = "host_unreachable"
ERROR_NET_UNREACH  = "network_unreachable"
ERROR_PERM_DENIED  = "permission_denied"
ERROR_PARAM        = "param_invalid"
ERROR_TOOL_UNAVAIL = "tool_unavailable"
ERROR_UNKNOWN      = "unknown_error"

# ── Data models ─────────────────────────────────────────────────────────

DiagMode = Literal["single", "stability", "pmtu"]



@dataclass
class IcmpDiagRequest:
    """Unified diagnostic request — platform-agnostic semantics."""
    host:          str
    mode:          DiagMode       = "single"
    payload_size:  int            = 32       # ICMP payload bytes (excl. IP/ICMP headers)
    df:            bool           = False    # Don't-Fragment flag
    count:         int            = 4        # probes per run
    timeout_s:     float          = 2.0      # per-probe timeout
    interval_s:    float          = 1.0      # inter-probe gap (stability mode)
    max_runtime_s: float          = 30.0     # hard ceiling for the entire task


@dataclass
class IcmpProbeSample:
    """Result of a single ICMP probe attempt."""
    seq:         int
    success:     bool
    rtt_ms:      Optional[float] = None
    error_code:  str             = ERROR_OK
    raw_message: str             = ""


@dataclass
class IcmpDiagResult:
    """Aggregated result of a diagnostic run."""
    host:               str
    payload_size:       int
    df:                 bool
    mode:               str
    count:              int
    success_count:      int
    loss_count:         int
    avg_rtt_ms:         Optional[float]
    min_rtt_ms:         Optional[float]
    max_rtt_ms:         Optional[float]
    error_summary:      Optional[str]
    conclusion:         str
    samples:            list = field(default_factory=list)
    # PMTU fields (Phase 2)
    max_df_payload:     Optional[int]  = None
    estimated_path_mtu: Optional[int]  = None


# ── JSON serialisation helpers ──────────────────────────────────────────
# Used by the web layer to ship live-task progress and final results to
# the browser. Keeping the serializer next to the dataclass means any
# field rename is caught here rather than as a silent missing key in JSON.

def icmp_sample_to_dict(s: IcmpProbeSample) -> dict:
    """Serialize one probe sample for JSON transport.

    raw_message is intentionally dropped — it's the full ping stdout/stderr
    (hundreds of bytes per probe), useful only for offline debugging, not
    for live UI rendering.
    """
    return {
        "seq":        s.seq,
        "success":    s.success,
        "rtt_ms":     s.rtt_ms,
        "error_code": s.error_code,
    }


def icmp_result_to_dict(r: IcmpDiagResult) -> dict:
    """Serialize an IcmpDiagResult to a plain dict for JSON transport.

    Shape matches what the Web frontend expects for both live-task /status
    responses and the /history endpoint.
    """
    return {
        "host":               r.host,
        "mode":               r.mode,
        "payload_size":       r.payload_size,
        "df":                 r.df,
        "count":              r.count,
        "success_count":      r.success_count,
        "loss_count":         r.loss_count,
        "avg_rtt_ms":         r.avg_rtt_ms,
        "min_rtt_ms":         r.min_rtt_ms,
        "max_rtt_ms":         r.max_rtt_ms,
        "error_summary":      r.error_summary,
        "conclusion":         r.conclusion,
        "max_df_payload":     r.max_df_payload,
        "estimated_path_mtu": r.estimated_path_mtu,
        "samples":            [icmp_sample_to_dict(s) for s in r.samples],
    }


# ── Parameter validation ─────────────────────────────────────────────────

def validate_request(req: IcmpDiagRequest) -> Optional[str]:
    """Return error string if invalid, else None."""
    if not req.host or not req.host.strip():
        return "目标地址不能为空"
    if not (0 <= req.payload_size <= 9000):
        return "载荷大小须在 0–9000 字节范围内"
    if not (1 <= req.count <= 50):
        return "探测次数须在 1–50 之间"
    if not (0.2 <= req.timeout_s <= 10):
        return "超时须在 0.2–10 秒范围内"
    if not (0.2 <= req.interval_s <= 5):
        return "间隔须在 0.2–5 秒范围内"
    return None


# ── Command builder ──────────────────────────────────────────────────────

def build_ping_cmd(req: IcmpDiagRequest) -> list[str]:
    """
    Build platform-specific ping command for a single probe.
    Returns a list of strings (no shell interpolation).
    """
    if _IS_WIN:
        cmd = ["ping", "-n", "1",
               "-l", str(req.payload_size),
               "-w", str(int(req.timeout_s * 1000)),
               req.host]
        if req.df:
            cmd.insert(1, "-f")
    else:
        cmd = ["ping", "-c", "1",
               "-s", str(req.payload_size),
               "-W", str(max(1, int(req.timeout_s))),
               req.host]
        if req.df:
            cmd.extend(["-M", "do"])

    return cmd


# ── Output parser ────────────────────────────────────────────────────────

# Patterns for frag-needed detection across Windows locales and Linux.
# Windows: varies by system language and Windows version.
_WIN_FRAG_PATTERNS = [
    r"packet needs to be fragmented",   # English
    r"数据包需要进行分段",               # Simplified Chinese
    r"封包必須分段",                     # Traditional Chinese
    r"needs to be fragmented but df",
    r"fragmented.*df set",
]
_LINUX_FRAG_PATTERNS = [
    r"frag needed.*df set",
    r"message too long",
    r"packet too big",
]

def _has_frag_needed(text: str, is_win: bool) -> bool:
    t = text.lower()
    patterns = _WIN_FRAG_PATTERNS if is_win else _LINUX_FRAG_PATTERNS
    return any(re.search(p, t) for p in patterns)


def parse_ping_output(stdout: str, stderr: str,
                      is_win: bool) -> tuple[Optional[float], str]:
    """
    Parse combined ping output into (rtt_ms, error_code).
    rtt_ms is None on failure; error_code is ERROR_OK on success.
    """
    combined = (stdout + stderr).lower()

    # ── frag_needed (must check before generic failure) ─────────────────
    if _has_frag_needed(stdout + stderr, is_win):
        return None, ERROR_FRAG_NEEDED

    # ── permission denied ────────────────────────────────────────────────
    if any(p in combined for p in ["permission denied", "operation not permitted",
                                    "无法访问", "access is denied"]):
        return None, ERROR_PERM_DENIED

    # ── host / network unreachable ───────────────────────────────────────
    if any(p in combined for p in ["destination host unreachable",
                                    "无法访问目标主机", "host unreachable"]):
        return None, ERROR_UNREACHABLE
    if any(p in combined for p in ["network unreachable", "网络不可达",
                                    "destination net unreachable"]):
        return None, ERROR_NET_UNREACH

    # ── extract RTT ──────────────────────────────────────────────────────
    if is_win:
        # Use same regex as ICMPMonitor._parse_latency — handles both English
        # ("time=3ms") and Chinese Windows where GBK→UTF-8 drops "时间" leaving
        # just "=3ms"; the character class absorbs "=" and \d+ grabs the number.
        m = re.search(r"[时间=time]+\s*(\d+(?:\.\d+)?)\s*ms",
                      stdout + stderr, re.IGNORECASE)
        if m:
            return float(m.group(1)), ERROR_OK
        # Sub-millisecond on Windows: "时间<1ms" or garbled "<1ms"
        if re.search(r"[时间time<]+\s*1\s*ms", stdout + stderr, re.IGNORECASE):
            return 0.5, ERROR_OK
    else:
        m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms",
                      stdout + stderr, re.IGNORECASE)
        if m:
            return float(m.group(1)), ERROR_OK

    # ── explicit timeout text ────────────────────────────────────────────
    if any(p in combined for p in ["request timed out", "请求超时",
                                    "100% packet loss", "100%丢失",
                                    "no response"]):
        return None, ERROR_TIMEOUT

    # ── fallback: if returncode non-zero but no specific pattern ─────────
    return None, ERROR_TIMEOUT


# ── Single-probe executor ────────────────────────────────────────────────

def run_one_probe(req: IcmpDiagRequest, seq: int,
                  task: Optional["DiagTask"] = None) -> IcmpProbeSample:
    """Run a single ICMP probe and return a parsed sample.

    `task`, if provided, is registered as owner of the live subprocess so
    that task.cancel() can SIGKILL it immediately instead of waiting for
    the full timeout.  Polling at 100 ms keeps perceived cancel latency
    well under "feels stuck" territory.
    """
    cmd = build_ping_cmd(req)
    # Hard ceiling on subprocess wall-clock time.  Slightly longer than
    # ping -w/-W so that ping has its own chance to time out cleanly
    # before we forcefully kill it (forced kill yields garbled output).
    hard_deadline = time.monotonic() + req.timeout_s + 2

    popen_kw: dict = {
        "stdout":   subprocess.PIPE,
        "stderr":   subprocess.PIPE,
        "text":     True,
        "encoding": "utf-8",
        "errors":   "ignore",
    }
    if _IS_WIN:
        si = subprocess.STARTUPINFO()
        si.dwFlags     |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow  = subprocess.SW_HIDE
        popen_kw["startupinfo"]   = si
        popen_kw["creationflags"] = subprocess.CREATE_NO_WINDOW

    try:
        proc = subprocess.Popen(cmd, **popen_kw)
    except FileNotFoundError:
        return IcmpProbeSample(seq=seq, success=False,
                                error_code=ERROR_TOOL_UNAVAIL,
                                raw_message="ping command not found")
    except PermissionError:
        return IcmpProbeSample(seq=seq, success=False,
                                error_code=ERROR_PERM_DENIED)
    except Exception as e:
        return IcmpProbeSample(seq=seq, success=False,
                                error_code=ERROR_UNKNOWN,
                                raw_message=str(e)[:200])

    if task is not None:
        task._set_proc(proc)

    cancelled = False
    timed_out = False
    try:
        # Poll loop: wakes every _POLL_INTERVAL_S to check cancel + deadline.
        # proc.wait(timeout=_POLL_INTERVAL_S) blocks at most that long, then
        # raises TimeoutExpired if the process is still alive — loop continues.
        while True:
            try:
                proc.wait(timeout=_POLL_INTERVAL_S)
                break                              # ← process exited
            except subprocess.TimeoutExpired:
                pass                               # ← still running, check guards
            if task is not None and task._cancel.is_set():
                cancelled = True
                break
            if time.monotonic() > hard_deadline:
                timed_out = True
                break

        if cancelled or timed_out:
            try: proc.kill()
            except Exception: pass
            try: proc.wait(timeout=1.0)            # reap zombie
            except Exception: pass
    finally:
        if task is not None:
            task._set_proc(None)

    # Cancel takes precedence — UI shouldn't show a half-finished sample
    # as if it were a real result.  Use TIMEOUT error_code for both so the
    # display remains uniform; conclusion text picks up the cancel intent
    # from the higher level (early loop exit + samples count < req.count).
    if cancelled:
        return IcmpProbeSample(seq=seq, success=False,
                                error_code=ERROR_TIMEOUT,
                                raw_message="cancelled")
    if timed_out:
        return IcmpProbeSample(seq=seq, success=False, error_code=ERROR_TIMEOUT)

    try:
        stdout = proc.stdout.read() if proc.stdout else ""
        stderr = proc.stderr.read() if proc.stderr else ""
    except Exception:
        stdout, stderr = "", ""

    rtt, code = parse_ping_output(stdout, stderr, _IS_WIN)
    return IcmpProbeSample(seq=seq, success=(rtt is not None),
                            rtt_ms=rtt, error_code=code,
                            raw_message=(stdout + stderr)[:400])


# ── Conclusion generator ─────────────────────────────────────────────────

def _make_conclusion(req: IcmpDiagRequest, samples: list[IcmpProbeSample],
                     success_n: int) -> str:
    total  = len(samples)
    errors = [s.error_code for s in samples if not s.success]
    df_str = "（禁止分片）" if req.df else ""

    # Stability mode gets a different opening line — it's a multi-probe
    # consistency test, not a single-shot connectivity check.
    is_stability = req.mode == "stability"
    mode_str = "稳定性测试中" if is_stability else ""

    if success_n == total:
        if is_stability:
            return (f"稳定性测试通过：使用 {req.payload_size} 字节载荷{df_str}，"
                    f"连续 {total} 次探测全部成功，链路在该包长下表现稳定。")
        return (f"使用 {req.payload_size} 字节载荷{df_str}，{total} 次探测均成功，"
                f"链路畅通，无 MTU 或分片问题。")

    if ERROR_FRAG_NEEDED in errors:
        if not req.df:
            return (f"探测失败，路径设备返回\u300c需要分片\u300d，"
                    f"但当前 DF 未开启，这是异常情况，建议排查中间设备。")
        return (f"使用 {req.payload_size} 字节载荷且开启 DF 时探测失败，"
                f"路径存在 MTU 瓶颈。该链路需要分片才能通过此包长，"
                f"建议排查 VPN / 隧道封装或中间设备 MTU 限制。")

    if ERROR_PERM_DENIED in errors:
        return "权限不足，无法发起带指定参数的 ping，请以管理员/root 身份运行。"

    if ERROR_TOOL_UNAVAIL in errors:
        return "系统 ping 命令不可用，请确认已安装并在 PATH 中。"

    if success_n == 0:
        code = errors[0] if errors else ERROR_TIMEOUT
        if code == ERROR_TIMEOUT:
            return (f"使用 {req.payload_size} 字节载荷{df_str}，{total} 次探测全部超时，"
                    f"目标不可达或包长超出路径承载能力。")
        return (f"探测全部失败（{code}），建议检查目标可达性和路径设备状态。")

    loss_pct = int((total - success_n) / total * 100)
    if is_stability:
        # Stability test surfaces "fluctuating" link character
        return (f"稳定性测试：{total} 次中成功 {success_n} 次，丢包率 {loss_pct}%，"
                f"链路在 {req.payload_size} 字节载荷下表现不稳定，"
                f"建议结合 RTT 抖动情况和告警历史进一步排查。")
    return (f"使用 {req.payload_size} 字节载荷{df_str}，"
            f"{total} 次中成功 {success_n} 次，丢包率 {loss_pct}%，"
            f"链路存在不稳定情况。")


def _make_pmtu_conclusion(host: str, max_payload: Optional[int],
                          failed_at: Optional[int],
                          first_failure: Optional[str]) -> str:
    """Human-readable PMTU result.  max_payload=None means even payload=0
    (a 28-byte IP+ICMP-only packet) failed — link is broken or DF is being
    fully stripped by an intermediate device."""
    if first_failure and first_failure not in (ERROR_FRAG_NEEDED, ERROR_OK):
        # Probe failed for reasons unrelated to MTU (timeout, unreachable, …)
        return (f"PMTU 探测中断：路径在某次探测中返回非 MTU 类错误（{first_failure}），"
                f"无法精确判断路径 MTU。建议先排查可达性后重试。")
    if max_payload is None:
        return (f"PMTU 探测：即使最小载荷也无法通过 DF 探测，"
                f"目标 {host} 在禁止分片条件下完全不可达。")
    mtu = max_payload + 28
    if max_payload >= 1472:
        return (f"PMTU 探测：路径在 DF 开启下可承载至少 1472 字节载荷，"
                f"路径 MTU 约 {mtu} 字节，符合标准以太网 MTU，"
                f"无分片瓶颈。")
    return (f"PMTU 探测：本次最大成功 payload = {max_payload} 字节，"
            f"估算路径 MTU ≈ {mtu} 字节（< 标准 1500）。"
            f"该路径可能存在 VPN / 隧道封装或中间设备 MTU 限制。")


# ── Aggregated result builder ─────────────────────────────────────────────

def _build_result(req: IcmpDiagRequest,
                  samples: list[IcmpProbeSample]) -> IcmpDiagResult:
    rtts      = [s.rtt_ms for s in samples if s.rtt_ms is not None]
    success_n = sum(1 for s in samples if s.success)
    errors    = [s.error_code for s in samples if not s.success]
    err_sum   = errors[0] if errors else None

    # count = len(samples), NOT req.count.  Truncated runs (deadline-
    # cut stability tests, user cancellation, etc.) have len(samples)
    # < req.count; reporting req.count there made loss_count
    # (= len(samples) - success_n) internally inconsistent with the
    # denominator the dashboard divides by, so a 50-probe run that
    # only completed 5 samples showed loss_rate=0 instead of "5 of
    # 50, the rest never ran".  The PMTU branch (~line 742) already
    # uses len(samples); align this builder with it.
    return IcmpDiagResult(
        host          = req.host,
        payload_size  = req.payload_size,
        df            = req.df,
        mode          = req.mode,
        count         = len(samples),
        success_count = success_n,
        loss_count    = len(samples) - success_n,
        avg_rtt_ms    = round(sum(rtts) / len(rtts), 2) if rtts else None,
        min_rtt_ms    = round(min(rtts), 2)              if rtts else None,
        max_rtt_ms    = round(max(rtts), 2)              if rtts else None,
        error_summary = err_sum,
        conclusion    = _make_conclusion(req, samples, success_n),
        samples       = samples,
    )


# ── Async runner ─────────────────────────────────────────────────────────

class DiagTask:
    """Handle to a running diagnostic task — call .cancel() to stop it.

    cancel() does two things:
      1. Sets the cancel Event (loop level — stops the next iteration)
      2. Kills the currently-running ping subprocess if any (probe level —
         interrupts a long timeout immediately instead of waiting for it)

    The subprocess kill is what makes the UI "stop" button feel instant.
    Without it, cancel() only signalled the loop, and a probe with
    timeout=10s would still hold the global semaphore for up to 10
    seconds before the next user could start a diagnostic.
    """

    def __init__(self):
        self._cancel  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Protect _proc swap so cancel() and the probe runner don't race.
        self._proc_lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None

    def cancel(self):
        self._cancel.set()
        with self._proc_lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()         # SIGKILL / TerminateProcess
            except Exception:
                pass

    def _set_proc(self, proc: Optional[subprocess.Popen]):
        with self._proc_lock:
            self._proc = proc

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


def run_icmp_diag_async(
        req: IcmpDiagRequest,
        on_progress: Optional[Callable[[IcmpProbeSample, int, int], None]] = None,
        on_done:     Optional[Callable[[IcmpDiagResult], None]]            = None,
        on_error:    Optional[Callable[[str], None]]                        = None,
        data_store=None,
        target_id:   Optional[str] = None,
) -> DiagTask:
    """
    Start an ICMP diagnostic run in a background thread.

    on_progress(sample, completed, total) – called after each probe
    on_done(result)                        – called when all probes finish
    on_error(message)                      – called on fatal pre-run error

    Returns a DiagTask handle; call handle.cancel() to abort mid-run.
    Enforces global concurrency limit of 1 simultaneous diagnostic task.
    """
    err = validate_request(req)
    if err:
        if on_error:
            on_error(err)
        return DiagTask()

    task = DiagTask()

    def _run():
        if not _TASK_SEM.acquire(blocking=False):
            if on_error:
                on_error("当前有诊断任务正在进行，请稍后再试")
            return
        try:
            # Snapshot the target's identity generation at task START so
            # the persist call at the end can detect a mid-run wipe /
            # removal: a stable mismatch means this result no longer
            # belongs to the current target identity (someone called
            # wipe_target_history / on_target_removed while we were
            # probing) and DataStore.record_diag_result will skip
            # the write.  Without this guard, a long ICMP run that
            # finished AFTER the wipe would re-insert the very rows
            # the wipe just deleted.
            captured_gen = (data_store.current_target_generation(target_id)
                             if (data_store is not None and target_id is not None)
                             else None)
            samples: list[IcmpProbeSample] = []
            deadline = time.monotonic() + req.max_runtime_s

            for i in range(req.count):
                if task._cancel.is_set():
                    break
                if time.monotonic() > deadline:
                    break

                # Pass `task` so run_one_probe can register its Popen handle
                # and be killed instantly on cancel (otherwise a slow probe
                # would hold the semaphore for its full timeout).
                sample = run_one_probe(req, seq=i + 1, task=task)
                samples.append(sample)

                if on_progress:
                    try:
                        on_progress(sample, i + 1, req.count)
                    except Exception:
                        pass

                # Inter-probe delay (skip after last probe)
                if i < req.count - 1 and not task._cancel.is_set():
                    cancel_fired = task._cancel.wait(timeout=req.interval_s)
                    if cancel_fired:
                        break

            # If the user explicitly cancelled, throw away whatever
            # partial samples we managed to collect: do NOT persist them
            # to the diagnostic history, and do NOT fire on_done.  The
            # UI's stop button already showed "已停止" the moment the
            # user clicked; without this early return, _build_result +
            # _persist_result + on_done would still run with the partial
            # samples, and the UI's _on_done callback would then flip
            # the status back to "诊断完成" -- a confusing state ping
            # the operator never asked for.  This matches DNS diag,
            # which builds an ERROR_CANCELLED result and likewise
            # skips persistence on user cancel.
            if task._cancel.is_set():
                return
            if samples:
                result = _build_result(req, samples)
                # Persist BEFORE invoking on_done so a UI callback that
                # immediately opens the history list sees the new row.
                # data_store can be None in test paths — no-op then.
                if data_store is not None:
                    _persist_result(data_store, result, target_id, captured_gen)
                if on_done:
                    try:
                        on_done(result)
                    except Exception:
                        pass
        finally:
            _TASK_SEM.release()

    task._thread = threading.Thread(target=_run, daemon=True,
                                     name="icmp-diag")
    task._thread.start()
    return task


def _persist_result(data_store, result: IcmpDiagResult,
                    target_id: Optional[str],
                    captured_generation: Optional[int] = None) -> None:
    """Hand the result to DataStore.  Wrapped in broad except so a DB
    write failure can NEVER kill the diagnostic — the UI must still
    see the result even if persistence fails.

    captured_generation: snapshot taken at task start by the async
    runner.  Forwarded to record_diag_result so it can skip the
    write when an identity-changing event (wipe / removal) happened
    mid-run.
    """
    try:
        # Compact sample list for details_json: drop raw_message (can be
        # 100s of bytes per probe) and keep just seq/success/rtt/error.
        compact_samples = [{"seq": s.seq, "ok": s.success,
                            "rtt": s.rtt_ms, "err": s.error_code}
                           for s in result.samples]
        data_store.record_diag_result(
            target_id          = target_id,
            host               = result.host,
            mode               = result.mode,
            payload_size       = result.payload_size,
            df                 = result.df,
            count              = result.count,
            success_count      = result.success_count,
            loss_count         = result.loss_count,
            avg_rtt_ms         = result.avg_rtt_ms,
            min_rtt_ms         = result.min_rtt_ms,
            max_rtt_ms         = result.max_rtt_ms,
            estimated_path_mtu = result.estimated_path_mtu,
            max_df_payload     = result.max_df_payload,
            error_summary      = result.error_summary,
            conclusion         = result.conclusion,
            details            = {"samples": compact_samples},
            captured_generation= captured_generation,
        )
    except Exception:
        pass


# ── PMTU binary search ───────────────────────────────────────────────────

# Standard upper bound: 1500 (Ethernet MTU) - 20 (IPv4 header) - 8 (ICMP
# echo header) = 1472 bytes of ICMP payload.  Jumbo-frame paths are out
# of Phase 2 scope.
PMTU_UPPER_PAYLOAD = 1472
PMTU_LOWER_PAYLOAD = 0


def run_pmtu_async(
        host:        str,
        timeout_s:   float = 2.0,
        on_progress: Optional[Callable[[int, bool, str], None]] = None,
        on_done:     Optional[Callable[[IcmpDiagResult],   None]] = None,
        on_error:    Optional[Callable[[str],              None]] = None,
        data_store=None,
        target_id:   Optional[str] = None,
) -> DiagTask:
    """Probe the path MTU via binary search of ICMP payload size with DF=on.

    Algorithm:
      low, high = 0, 1472
      while low <= high:
        mid = (low + high) // 2
        probe(payload=mid, df=True)
        if success      → low  = mid + 1
        if frag_needed  → high = mid - 1
        if other error  → abort (link itself is the problem, not MTU)
      max_payload = low - 1

    Approximately log2(1472) ≈ 11 probes total, so a 2-second timeout
    setting yields ~25 second worst case + cancel-responsive thanks to
    the Popen kill path added in Bug 2.

    on_progress(payload_size, success, error_code) is fired after each probe
    so the UI can show a "测试 768B... ✓" running log.

    Returns a DiagTask handle — cancel() kills the current ping and exits
    the search loop on the next iteration.
    """
    if not host or not host.strip():
        if on_error: on_error("目标地址不能为空")
        return DiagTask()
    if not (0.2 <= timeout_s <= 10):
        if on_error: on_error("超时须在 0.2–10 秒范围内")
        return DiagTask()

    task = DiagTask()

    def _run():
        if not _TASK_SEM.acquire(blocking=False):
            if on_error: on_error("当前有诊断任务正在进行，请稍后再试")
            return
        try:
            # See run_icmp_diag_async for the rationale -- capture the
            # target generation now so the persist call below skips
            # the DB write if a wipe / removal happened mid-search.
            captured_gen = (data_store.current_target_generation(target_id)
                             if (data_store is not None and target_id is not None)
                             else None)
            low, high     = PMTU_LOWER_PAYLOAD, PMTU_UPPER_PAYLOAD
            samples:      list[IcmpProbeSample] = []
            first_failure: Optional[str] = None
            iteration = 0
            # Hard upper iteration limit as a safety net in case the
            # binary-search invariants are violated by an unexpected
            # error_code (shouldn't happen, but log2(1472)≈11 + 5 slack).
            while low <= high and iteration < 16:
                if task._cancel.is_set():
                    break
                iteration += 1
                mid = (low + high) // 2

                req = IcmpDiagRequest(
                    host=host, mode="pmtu",
                    payload_size=mid, df=True,
                    count=1, timeout_s=timeout_s)
                sample = run_one_probe(req, seq=iteration, task=task)
                samples.append(sample)

                if on_progress:
                    try: on_progress(mid, sample.success, sample.error_code)
                    except Exception: pass

                if sample.success:
                    low = mid + 1
                elif sample.error_code == ERROR_FRAG_NEEDED:
                    high = mid - 1
                else:
                    # Non-MTU failure (timeout, unreachable, perm denied, …)
                    # — we can't trust the search to converge. Abort with
                    # what we've learned so far, and surface the error.
                    first_failure = sample.error_code
                    break

            if task._cancel.is_set():
                # User cancelled — discard whatever partial PMTU search
                # state we have and skip persistence + on_done, same
                # rationale as the regular ICMP path above.  The
                # previous version of this guard only fired when there
                # were zero samples; cancel-mid-search still fell
                # through to build a (now meaningless) IcmpDiagResult,
                # write it to the history, and re-flip the UI status
                # back to "诊断完成".
                return

            max_payload = (low - 1) if (low - 1) >= PMTU_LOWER_PAYLOAD else None
            # If we never had a successful probe, max_payload is invalid
            if not any(s.success for s in samples):
                max_payload = None

            est_mtu = (max_payload + 28) if max_payload is not None else None
            result = IcmpDiagResult(
                host               = host,
                payload_size       = max_payload if max_payload is not None else 0,
                df                 = True,
                mode               = "pmtu",
                count              = len(samples),
                success_count      = sum(1 for s in samples if s.success),
                loss_count         = sum(1 for s in samples if not s.success),
                avg_rtt_ms         = None,
                min_rtt_ms         = None,
                max_rtt_ms         = None,
                error_summary      = first_failure,
                conclusion         = _make_pmtu_conclusion(
                                         host, max_payload,
                                         high + 1 if max_payload is not None else None,
                                         first_failure),
                samples            = samples,
                max_df_payload     = max_payload,
                estimated_path_mtu = est_mtu,
            )
            if data_store is not None:
                _persist_result(data_store, result, target_id, captured_gen)
            if on_done:
                try: on_done(result)
                except Exception: pass
        finally:
            _TASK_SEM.release()

    task._thread = threading.Thread(target=_run, daemon=True, name="icmp-pmtu")
    task._thread.start()
    return task
