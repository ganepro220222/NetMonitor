from __future__ import annotations

"""
alert_manager.py
----------------
告警管理器：声音告警 + 桌面通知。

本版本的核心改进：彻底解决跨线程声音播放问题
=================================================
问题根源：
  Windows 的 MessageBeep() 和 Beep() 底层都依赖 Win32 消息机制。
  当从子线程调用时，如果该线程没有消息循环（tkinter 的子线程通常没有），
  系统会将播音请求静默丢弃，函数返回 True（"成功"）但没有任何声音输出。
  这就是为什么之前两个版本在子线程里调用都不响。

解决方案：
  使用 winsound.PlaySound(文件路径, winsound.SND_FILENAME | winsound.SND_ASYNC)
  这个函数直接将 WAV 文件交给 Windows 音频引擎播放，
  完全绕开消息循环机制，在任何线程里都能可靠工作。

WAV 文件来源：
  程序第一次运行时自动在 assets/ 目录里生成三个 WAV 文件。
  生成过程使用 Python 标准库的 wave 和 struct 模块，
  零外部依赖，任何 Python 环境都能运行。
  生成后的文件会一直保留，不会每次启动都重新生成。
"""

import copy
import json
import math
import os
import queue
import struct
import threading
import time
import urllib.request
import uuid
import wave
from dataclasses import dataclass
from pathlib import Path

_WEBHOOK_HTTP_OPEN = urllib.request.urlopen
_ORIGINAL_HTTP_OPEN = _WEBHOOK_HTTP_OPEN

from src.trace_policy import (
    should_request_traceroute,
    summarize_for_alert,
    trace_skip_summary,
    trace_signature_from_summary,
)
from src.webhook_outbox import (
    CLOSED_SUMMARY_DELAY_SEC,
    WebhookDeliveryAborted,
    max_attempts_for_event,
)

try:
    import winsound
    WINSOUND_AVAILABLE = True
except ImportError:
    WINSOUND_AVAILABLE = False

try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False


# ──────────────────────────────────────────────────────────────────────
# WAV 文件生成器
# ──────────────────────────────────────────────────────────────────────

def _generate_wav(filepath: str, tones: list):
    """
    生成一个 WAV 音频文件。
    
    参数 tones 是一个列表，每个元素是一个三元组：
      (频率Hz, 持续时间秒, 音量0.0~1.0)
    
    多个 tone 会按顺序拼接成一段完整的音频。
    
    WAV 格式说明：
      采样率 44100 Hz（CD 质量），16位单声道。
      每一帧音频 = int16 范围内的正弦波采样值。
    """
    sample_rate = 44100
    all_frames = bytearray()

    for freq, duration, volume in tones:
        n_samples = int(sample_rate * duration)
        for i in range(n_samples):
            # 正弦波：value = sin(2π * 频率 * 时间点)
            # 乘以 32767 * volume 缩放到 int16 范围
            t = i / sample_rate
            value = int(math.sin(2 * math.pi * freq * t) * 32767 * volume)
            # 写入小端序 int16（WAV 格式要求）
            all_frames += struct.pack('<h', value)

        # 在每段音之间加入 30ms 的静音，让声音听起来更清晰
        silence_samples = int(sample_rate * 0.03)
        all_frames += bytes(silence_samples * 2)

    with wave.open(filepath, 'w') as wav_file:
        wav_file.setnchannels(1)        # 单声道
        wav_file.setsampwidth(2)        # 16位 = 2字节
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(bytes(all_frames))


def ensure_sound_files(assets_dir: str) -> dict:
    """
    确保三个告警音效文件存在。
    如果不存在则自动生成，已存在则直接使用。
    返回包含三个文件路径的字典。
    """
    assets_path = Path(assets_dir)
    assets_path.mkdir(exist_ok=True)

    files = {
        "warning":  str(assets_path / "alert_warning.wav"),
        "alarm":    str(assets_path / "alert_alarm.wav"),
        "recovery": str(assets_path / "alert_recovery.wav"),
    }

    # 橙色警告音：两声中高频短促提示音
    # 听起来像 "叮叮"，提醒注意但不紧迫
    if not os.path.exists(files["warning"]):
        _generate_wav(files["warning"], [
            (880, 0.12, 0.6),   # A5，短促
            (880, 0.12, 0.6),   # 重复一次
        ])

    # 红色告警音：低频→高频→低频，产生紧迫感
    # 模拟"紧急警报"的节奏感，有穿透力
    if not os.path.exists(files["alarm"]):
        _generate_wav(files["alarm"], [
            (440, 0.15, 0.8),   # A4，低
            (880, 0.15, 0.8),   # A5，高
            (440, 0.30, 0.8),   # A4，低（拉长）
        ])

    # 恢复正常提示音：由低到高的两声，传达"好消息"
    # 听起来像"叮咚"，让人感到放松
    if not os.path.exists(files["recovery"]):
        _generate_wav(files["recovery"], [
            (523, 0.15, 0.5),   # C5，低
            (784, 0.20, 0.5),   # G5，高
        ])

    return files


# ──────────────────────────────────────────────────────────────────────
# Webhook incident lifecycle (reminder + traceroute diagnostics)
# ──────────────────────────────────────────────────────────────────────

_AGGREGATE_LIST_MAX = 10
_AGGREGATE_TRACE_MAX = 5


@dataclass
class WebhookIncident:
    tid: str
    label: str
    ip: str
    started_at: float
    current_status: str = "red"
    last_reminder_at: float = 0.0
    reminder_count: int = 0
    last_trace_at: float = 0.0
    last_trace_request_at: float = 0.0
    last_trace_summary: dict | None = None
    last_trace_signature: tuple | None = None
    acknowledged: bool = False
    incident_id: str = ""
    ping_type: str = "icmp"
    failure_reason: str = ""
    trace_applicable: bool = True
    push_seq: int = 0


# ──────────────────────────────────────────────────────────────────────
# 告警管理器主体
# ──────────────────────────────────────────────────────────────────────

class AlertManager:

    def __init__(self, enabled: bool = True, assets_dir: str = "assets"):
        self.enabled = enabled

        # 生成（或复用）WAV 音效文件
        self._sound_files = ensure_sound_files(assets_dir)

        # 每个目标上次触发告警的颜色，用于去重判断
        self._last_alert_status: dict[str, str] = {}
        self._status_lock = threading.Lock()  # guards _last_alert_status + _red_targets

        # 红色循环告警控制
        self._red_alarm_active = False
        self._red_alarm_stop = threading.Event()
        self._red_targets: set[str] = set()
        self._alarm_lock = threading.Lock()   # prevents duplicate alarm threads

        self._toaster = ToastNotifier() if TOAST_AVAILABLE else None
        self._data_store = None
        self._config     = None
        self._last_trace: dict = {}

        self._webhook_incidents: dict[str, WebhookIncident] = {}
        self._webhook_incident_lock = threading.RLock()
        # Monotonic per-target seq: open incident assigns seq N; close
        # bumps to N+1 so in-flight webhooks for a recovered flap drop.
        self._webhook_valid_seq: dict[str, int] = {}
        # Configured target ids (reseed / remove keep this in sync for gate).
        self._webhook_known_targets: set[str] = set()
        self._webhook_known_targets_initialized = False
        self._webhook_outbox_baselines_restored = False
        self._webhook_queue_lock = threading.Lock()
        self._webhook_queues: dict[str, queue.Queue] = {}
        # Throttles the multi-node aggregate reminder to one push per
        # reminder interval.  An aggregate already lists EVERY open-red
        # node, so when incidents come due on different 30s ticks (the
        # normal case — nodes rarely fail in the same second) each due
        # event must not fire its own full aggregate, or the "avoid group
        # message storm" feature would itself produce a storm.
        self._last_aggregate_reminder_at = 0.0
        self._reminder_stop = threading.Event()
        self._trace_request_callback = None
        self._outbox_dispatcher = None
        self._webhook_outbox_send_lock = threading.Lock()
        self._webhook_send_cancelled: set[str] = set()
        self._webhook_send_epochs: dict[str, int] = {}
        threading.Thread(
            target=self._webhook_reminder_loop,
            daemon=True, name="webhook-reminder",
        ).start()

    # ──────────────────────────────────────────────────────────────
    # 主接口
    # ──────────────────────────────────────────────────────────────

    def on_status_change(self, target_id: str, target_label: str,
                         target_ip: str, new_status: str, *,
                         ping_type: str | None = None,
                         failure_reason: str | None = None):
        self._webhook_known_targets.add(target_id)
        """状态颜色发生变化时由主窗口调用，判断是否触发声音和通知。

        self.enabled controls AUDIO ONLY (sound files, red-alarm loop).
        Desktop notifications, webhook pushes, and auto-traceroute all
        fire regardless -- the settings dialog's switch is labelled
        "启用声音告警" and the help text explicitly says "关闭后程序
        仍会显示颜色变化，只是不播放声音", so a disabled flag must
        NOT silence the external alert channels.  The previous
        entry-point `if not self.enabled: return` collapsed all four
        side effects under the sound toggle.
        """
        # Atomically read-check-write to prevent duplicate triggers if
        # multiple threads ever call this simultaneously.
        with self._status_lock:
            old_status = self._last_alert_status.get(target_id, "gray")
            if old_status == new_status:
                return
            self._last_alert_status[target_id] = new_status
            was_red = target_id in self._red_targets
            if new_status == "red":
                self._red_targets.add(target_id)
            elif new_status == "green":
                self._red_targets.discard(target_id)

        # Side effects (sound / network / notification) outside the lock
        # so they don't block other threads during I/O operations.
        if new_status == "red":
            if self.enabled:
                self._ensure_red_alarm_running()
            self._send_notification(
                title="🔴 网络严重故障",
                msg=f"「{target_label}」({target_ip}) 持续丢包，可能已断连！"
            )
            self._trigger_auto_trace(target_id, target_label, target_ip)
            pt = ping_type or "icmp"
            fr = failure_reason or ""
            trace_ok = should_request_traceroute(pt, fr)
            _, is_new = self._open_or_update_webhook_incident(
                target_id, target_label, target_ip, status="red",
                ping_type=pt, failure_reason=fr,
                trace_applicable=trace_ok)
            if is_new:
                self._push_alert_red_webhook(
                    target_id, target_label, target_ip,
                    pending_trace=trace_ok)

        elif new_status == "orange":
            if old_status in ("gray", "green"):
                if self.enabled:
                    self._play_async(self._sound_files["warning"])
                self._send_notification(
                    title="🟠 网络质量告警",
                    msg=f"「{target_label}」({target_ip}) 出现丢包，请留意。"
                )
            elif old_status == "red":
                # Partial recovery: red → orange.  Previously this
                # transition fired NO sound, NO notification, NO webhook,
                # leaving operators who were paged for the red outage in
                # the dark about the (partial) improvement until either
                # green recovery or another red episode.  Mirror the
                # orange-in policy: local notification + warning chime,
                # but no webhook (the service is still degraded, the
                # external alert channel already knows about the open
                # incident from the red push -- a second webhook would
                # read as a new event).
                self._update_webhook_incident_status(target_id, "orange")
                if self.enabled:
                    self._play_async(self._sound_files["warning"])
                self._send_notification(
                    title="🟠 网络部分恢复",
                    msg=f"「{target_label}」({target_ip}) 由中断转为丢包状态，仍未完全恢复。"
                )

        elif new_status == "green":
            # NOTE: alarm stopping is handled by evaluate_alarm() in MainWindow.
            # Never call _stop_red_alarm() directly here -- it cannot see
            # the full picture of which nodes are still red/paused.
            if old_status in ("orange", "red"):
                if self.enabled:
                    self._play_async(self._sound_files["recovery"])
                if was_red:
                    # Full recovery from a severe outage: notification +
                    # webhook, matching the loudness of the original red
                    # alert.  Operators paged for an outage deserve a
                    # follow-up "all clear" through the same channel.
                    closed = self._close_webhook_incident(target_id)
                    with self._webhook_incident_lock:
                        rec_seq = self._webhook_valid_seq.get(target_id, 0)
                    self._send_notification(
                        title="🟢 网络已恢复",
                        msg=f"「{target_label}」({target_ip}) 连接已恢复正常。"
                    )
                    self._push_webhook(
                        event="recovery", target=target_label,
                        ip=target_ip, status="green",
                        message="连接已恢复正常",
                        extra=self._build_recovery_extra(closed),
                        order_key=target_id,
                        gate=("recovery", target_id, rec_seq),
                    )
                else:
                    # Recovery from orange (warning, never went red):
                    # mirror orange-in's notification policy -- local
                    # notification only, NO webhook.  Warning-level
                    # flapping shouldn't flood the external alert channel
                    # (企业微信/钉钉/飞书) and create alert fatigue, but
                    # symmetry with the orange-in notification is required
                    # so operators get a recovery confirmation matching the
                    # warning they received on the way in.
                    self._send_notification(
                        title="🟢 性能已恢复",
                        msg=f"「{target_label}」({target_ip}) 链路质量已恢复正常。"
                    )

    def on_target_removed(self, target_id: str):
        """Node deleted.  Clean up tracking state; alarm handled by evaluate_alarm()."""
        with self._status_lock:
            self._last_alert_status.pop(target_id, None)
            self._red_targets.discard(target_id)
        self._drop_webhook_incident(target_id)
        self._cancel_inflight_outbox_sends(
            target_id, reason="target_removed")
        # Permanent deletion: also reclaim the per-target delivery worker and
        # seq entry that _drop_webhook_incident (shared with pause) leaves in
        # place, so a removed target doesn't leak a queue + daemon thread +
        # _webhook_valid_seq entry forever.
        self._drop_webhook_delivery(target_id)
        self._webhook_known_targets.discard(target_id)
        with self._webhook_incident_lock:
            self._webhook_valid_seq.pop(target_id, None)
        # Do NOT call _stop_red_alarm() here — evaluate_alarm() in MainWindow
        # will decide based on the full current state after the card is removed.

    def on_target_paused(self, target_id: str):
        """
        节点被手动暂停时调用。
        将该节点从 _red_targets 移除（暂停期间不计入告警），
        但仅当其他节点都不再红色时才停止告警声——
        不允许暂停单个节点后"误伤"其他仍在告警的节点。
        """
        with self._status_lock:
            self._last_alert_status.pop(target_id, None)
            self._red_targets.discard(target_id)
        self._drop_webhook_incident(target_id)
        self._cancel_inflight_outbox_sends(
            target_id, reason="target_paused")
        # Do NOT call _stop_red_alarm() here — evaluate_alarm() in MainWindow
        # will do a fresh scan and decide.  This prevents pausing any node
        # (even a green one) from accidentally silencing alarms on other nodes.

    def set_data_store(self, ds) -> None:
        self._data_store = ds

    def set_outbox_dispatcher(self, dispatcher) -> None:
        self._outbox_dispatcher = dispatcher

    def ensure_webhook_outbox_baselines(self) -> None:
        """Restore seq floors and reconcile orphan outbox rows once after restart."""
        if self._data_store is None or self._webhook_outbox_baselines_restored:
            return
        self._webhook_outbox_baselines_restored = True
        try:
            self._reconcile_webhook_outbox_targets()
        except Exception:
            pass
        self._restore_webhook_seq_from_outbox(None)

    def _config_target_ids(self) -> set[str] | None:
        cfg = self._config
        if cfg is None or not hasattr(cfg, "get_targets"):
            return None
        try:
            return {
                t["id"] for t in cfg.get_targets()
                if isinstance(t, dict) and t.get("id")
            }
        except Exception:
            return None

    @staticmethod
    def _log_outbox_cleanup(label: str, count: int) -> None:
        if count:
            print(f"[WebhookOutbox] {label}: dropped {count} row(s)")

    def _reconcile_webhook_outbox_targets(self) -> None:
        """Drop orphan/stale outbox rows using the current configured target set."""
        if self._data_store is None:
            return
        cfg_ids = self._config_target_ids()
        if cfg_ids is not None:
            self._webhook_known_targets = set(cfg_ids)
            self._webhook_known_targets_initialized = True
            try:
                open_iid_map: dict[str, str] = {}
                if cfg_ids:
                    open_inc = self._data_store.get_open_incidents(list(cfg_ids))
                    open_iid_map = {
                        tid: str(info.get("incident_id") or "").strip()
                        for tid, info in open_inc.items()
                    }
                n_orphan = self._data_store.drop_orphan_webhook_outbox(cfg_ids)
                n_stale = (
                    self._data_store
                    .drop_stale_webhook_outbox_for_closed_incidents(
                        open_iid_map))
                self._log_outbox_cleanup("reconcile orphan", n_orphan)
                self._log_outbox_cleanup("reconcile stale incident", n_stale)
            except Exception:
                pass
        else:
            if self._webhook_known_targets_initialized:
                self._webhook_known_targets.clear()
            self._webhook_known_targets_initialized = False

    def set_config(self, config) -> None:
        self._config = config

    def set_trace_request_callback(self, cb) -> None:
        """Bind urgent traceroute requests (e.g. WebServer.request_traceroute_now)."""
        self._trace_request_callback = cb

    def seed_status_tracking(self, statuses: dict[str, str]) -> None:
        """Restore _last_alert_status / _red_targets after restart."""
        with self._status_lock:
            for tid, st in statuses.items():
                self._last_alert_status[tid] = st
                if st == "red":
                    self._red_targets.add(tid)
                else:
                    self._red_targets.discard(tid)

    def reseed_webhook_incidents(self, targets: list, paused_ids: set) -> int:
        """Rebuild in-memory webhook incidents from DB open incidents.

        Sends a catch-up ``alert_red`` for each reseeded red incident so
        operators are notified after a restart mid-outage.  Sets
        last_reminder_at=now so restart does not immediately burst reminders.
        """
        if self._data_store is None:
            return 0
        target_map = {
            t["id"]: t for t in targets
            if isinstance(t, dict) and t.get("id")
        }
        self._webhook_known_targets = set(target_map.keys())
        self._webhook_known_targets_initialized = True
        tids = [tid for tid in target_map if tid not in paused_ids]
        open_inc: dict = {}
        open_iid_map: dict[str, str] = {}
        if tids:
            try:
                open_inc = self._data_store.get_open_incidents(tids)
                open_iid_map = {
                    tid: str(info.get("incident_id") or "").strip()
                    for tid, info in open_inc.items()
                }
            except Exception:
                open_inc = {}

        try:
            n_orphan = self._data_store.drop_orphan_webhook_outbox(
                self._webhook_known_targets)
            n_stale = self._data_store.drop_stale_webhook_outbox_for_closed_incidents(
                open_iid_map)
            self._log_outbox_cleanup("reseed orphan", n_orphan)
            self._log_outbox_cleanup("reseed stale incident", n_stale)
            self._restore_webhook_seq_from_outbox(list(self._webhook_known_targets))
        except Exception:
            pass

        if not tids:
            return 0

        now = time.time()
        count = 0
        created_red: list[str] = []
        for tid, info in open_inc.items():
            t = target_map.get(tid)
            if t is None:
                continue
            last_st = info.get("last_status", "red")
            if last_st == "paused":
                continue
            cur_st = last_st if last_st in ("red", "orange") else "red"
            started_at = float(info.get("started_at") or now)
            label = info.get("label") or t.get("label", tid)
            ip = info.get("ip") or t.get("ip", "")
            iid = info.get("incident_id")
            ping_type = (info.get("ping_type") or "icmp").strip().lower() or "icmp"
            failure_reason = info.get("failure_reason") or ""
            trace_ok = should_request_traceroute(ping_type, failure_reason)

            summary = None
            signature = None
            last_trace_at = 0.0
            try:
                trace_snap = self._data_store.get_incident_traceroute(
                    tid, started_at, incident_id=iid)
                if trace_snap and trace_snap.get("hops"):
                    summary = summarize_for_alert(
                        trace_snap["hops"],
                        ping_type=ping_type,
                        failure_reason=failure_reason,
                        tcp_checks=trace_snap.get("tcp_checks"),
                    )
                    signature = trace_signature_from_summary(summary)
                    last_trace_at = float(trace_snap.get("ts") or 0)
            except Exception:
                pass

            acked = False
            if iid:
                try:
                    acked = self._data_store.is_webhook_acknowledged(iid)
                except Exception:
                    acked = False

            with self._webhook_incident_lock:
                if tid in self._webhook_incidents:
                    continue
                seq = self._reseed_incident_seq_locked(tid, iid or "")
                inc = WebhookIncident(
                    tid=tid,
                    label=label,
                    ip=ip,
                    started_at=started_at,
                    current_status=cur_st,
                    last_reminder_at=now,
                    last_trace_at=last_trace_at,
                    last_trace_summary=summary,
                    last_trace_signature=signature,
                    ping_type=ping_type,
                    failure_reason=failure_reason,
                    trace_applicable=trace_ok,
                    push_seq=seq,
                    incident_id=iid or "",
                    acknowledged=acked,
                )
                if not trace_ok and summary is None:
                    skip = trace_skip_summary(ping_type, failure_reason)
                    inc.last_trace_summary = skip
                    inc.last_trace_signature = trace_signature_from_summary(skip)
                self._webhook_incidents[tid] = inc
                count += 1
                if cur_st == "red":
                    created_red.append(tid)

        if self._webhook_configured():
            for tid in created_red:
                inc = self._webhook_incidents.get(tid)
                if inc is None:
                    continue
                iid = (inc.incident_id or "").strip()
                if iid and self._data_store.has_pending_webhook_outbox_event(
                        tid, "alert_red", incident_id=iid):
                    continue
                pending = inc.trace_applicable and inc.last_trace_summary is None
                self._push_alert_red_webhook(
                    tid, inc.label, inc.ip,
                    message="连接中断（程序重启后续报）",
                    pending_trace=pending)
        return count

    def acknowledge_incident(self, target_id: str) -> bool:
        """Stop webhook reminders for one open incident; recovery still fires."""
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(target_id)
            if inc is None:
                return False
            inc.acknowledged = True
        self._persist_incident_ack(inc)
        self._cancel_inflight_outbox_sends(
            target_id,
            events=("alert_reminder", "diagnostic_update",
                    "alert_reminder_aggregate"),
            reason="acknowledged")
        return True

    def acknowledge_all_incidents(self) -> int:
        """ACK every open incident."""
        acked: list[WebhookIncident] = []
        with self._webhook_incident_lock:
            for inc in self._webhook_incidents.values():
                if not inc.acknowledged:
                    inc.acknowledged = True
                    acked.append(inc)
        for inc in acked:
            self._persist_incident_ack(inc)
        return len(acked)

    def count_pending_ack_incidents(self) -> int:
        """Un-ACK'd red incidents — matches webhook reminder eligibility."""
        with self._webhook_incident_lock:
            return sum(
                1 for inc in self._webhook_incidents.values()
                if inc.current_status == "red" and not inc.acknowledged
            )

    def is_incident_acknowledged(self, target_id: str) -> bool:
        """Whether the open webhook incident for this target is ACK'd."""
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(target_id)
            return inc is not None and inc.acknowledged

    def set_enabled(self, enabled: bool,
                    current_statuses: dict | None = None) -> None:
        """Toggle the alert manager on or off.

        When turning OFF, also stop any red alarm that's currently
        looping -- otherwise it would keep playing until evaluate_alarm
        eventually saw a non-red state, but evaluate_alarm short-circuits
        on `not self.enabled` and never gets to call _stop_red_alarm()
        itself.  Net result of the old `alerter.enabled = False`
        assignment: the user toggled sound off, but the already-running
        alarm WAV kept replaying every 3 seconds until they restarted
        the app or every node went green.

        When turning ON, re-seed _last_alert_status / _red_targets from
        the caller's current view of node statuses.  Status changes
        that fired while we were disabled were short-circuited at
        on_status_change's entry guard, so our internal bookkeeping
        drifted out of sync with reality -- without this re-seed, the
        first transition AFTER re-enable would hit the
        `old_status == new_status` filter (both look like "gray" or
        a stale value from before disable), silently swallowing a
        legitimate transition.  Caller is expected to follow up with
        evaluate_alarm() to actually start the alarm if any node is
        currently red.
        """
        self.enabled = enabled
        if not enabled:
            self._stop_red_alarm()
            return
        if current_statuses is not None:
            with self._status_lock:
                self._last_alert_status = dict(current_statuses)
                self._red_targets = {tid for tid, st in current_statuses.items()
                                      if st == "red"}

    def evaluate_alarm(self, current_statuses: dict, paused_ids: set):
        """
        全局告警调度中心 (Alarm Dispatcher).
        
        由 MainWindow 在任何状态变化后调用（包括：ping 结果更新、
        节点暂停/恢复/删除）。每次调用都对所有当前有效节点做完整扫描，
        不依赖事件累积的中间状态，彻底消除事件互相污染的并发问题。
        
        规则：
          - 有任意一个"有效且未暂停"节点处于 RED → 确保告警音播放
          - 所有有效节点均非 RED（或已暂停）  → 停止告警音
        
        参数：
          current_statuses: {tid: "red"|"orange"|"green"|"gray"|"paused"}
          paused_ids:       当前被手动暂停的节点 ID 集合
        """
        if not self.enabled:
            return
        any_active_red = any(
            status == "red" and tid not in paused_ids
            for tid, status in current_statuses.items()
        )
        if any_active_red:
            self._ensure_red_alarm_running()
        else:
            self._stop_red_alarm()

    # ── Auto-traceroute ──────────────────────────────────────────────

    def _trigger_auto_trace(self, tid: str, label: str, ip: str) -> None:
        """Request an immediate traceroute via the scheduler when a node turns red.

        Previously this ran its own separate traceroute thread and wrote to DB
        directly.  That caused double-writes when the scheduler also processed
        a request_now() for the same event — producing two near-identical
        history records seconds apart.

        Now the scheduler is the single authoritative executor: all traceroutes
        (periodic or event-triggered) run through _run_one() and write through
        the same path.  alert_manager's only job here is to signal urgency.
        """
        import time
        now = time.time()
        if now - self._last_trace.get(tid, 0) < 60:
            return
        self._last_trace[tid] = now
        # Delegate to web_server scheduler — it already calls request_now()
        # when a node turns red in update_target(), so this is now a no-op
        # at the alert_manager level.  The method is kept for future use
        # (e.g. attaching route-change detection hooks here).
        # Direct DB writes removed to eliminate double-write.

    # ── Webhook incident lifecycle ───────────────────────────────────

    def _alloc_incident_seq_locked(self, tid: str) -> int:
        """Allocate the next valid push seq.  Caller holds incident lock."""
        seq = self._webhook_valid_seq.get(tid, 0) + 1
        self._webhook_valid_seq[tid] = seq
        return seq

    def _reseed_incident_seq_locked(self, tid: str, incident_id: str) -> int:
        """Restore push seq after restart without invalidating pending outbox."""
        pending_max = 0
        if self._data_store and incident_id:
            try:
                pending_max = self._data_store.max_pending_incident_seq(
                    tid, incident_id=incident_id)
            except Exception:
                pending_max = 0
        cur = self._webhook_valid_seq.get(tid, 0)
        if pending_max:
            seq = max(cur, pending_max)
            self._webhook_valid_seq[tid] = seq
            return seq
        return self._alloc_incident_seq_locked(tid)

    def _restore_webhook_seq_from_outbox(
            self, target_ids: list[str] | None) -> None:
        """Raise per-target seq floor from durable outbox before reseed alloc."""
        if self._data_store is None:
            return
        try:
            seq_map = self._data_store.max_pending_incident_seq_by_target(
                target_ids)
        except Exception:
            return
        with self._webhook_incident_lock:
            for tid, mx in seq_map.items():
                if mx > self._webhook_valid_seq.get(tid, 0):
                    self._webhook_valid_seq[tid] = int(mx)

    def _webhook_target_known(self, tid: str) -> bool:
        if not tid:
            return False
        if self._webhook_known_targets_initialized:
            return tid in self._webhook_known_targets
        if tid in self._webhook_known_targets:
            return True
        cfg_ids = self._config_target_ids()
        if cfg_ids is not None:
            return tid in cfg_ids
        return False

    _TARGET_GATED_OUTBOX_EVENTS = frozenset({
        "alert_red", "alert_reminder", "diagnostic_update", "recovery",
        "incident_closed_summary",
    })
    _KNOWN_WEBHOOK_OUTBOX_EVENTS = frozenset({
        "alert_red", "alert_reminder", "alert_reminder_aggregate",
        "diagnostic_update", "recovery", "incident_closed_summary",
    })

    def _parse_outbox_gate(self, gate) -> tuple | None | bool:
        """Return parsed gate tuple, None if absent, False if malformed."""
        if gate is None:
            return None
        if not isinstance(gate, (list, tuple)) or len(gate) < 1:
            return False
        kind = gate[0]
        if kind == "aggregate":
            if len(gate) != 2:
                return False
            pairs = gate[1]
            if not isinstance(pairs, (list, tuple)):
                return False
            norm_pairs: list[tuple[str, int]] = []
            for item in pairs:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    return False
                tid, seq = item[0], item[1]
                if not isinstance(tid, str) or not tid:
                    return False
                try:
                    norm_pairs.append((tid, int(seq)))
                except (TypeError, ValueError):
                    return False
            return ("aggregate", tuple(norm_pairs))
        if kind in ("reminder", "incident", "alert_red", "recovery"):
            if len(gate) != 3:
                return False
            tid, seq = gate[1], gate[2]
            if not isinstance(tid, str) or not tid:
                return False
            try:
                return (kind, tid, int(seq))
            except (TypeError, ValueError):
                return False
        return False

    def _outbox_row_target_ok(
            self, row: dict, *, payload_event: str = "") -> bool:
        tid = (row.get("target_id") or "").strip()
        if not tid:
            return True
        row_ev = (row.get("event") or "").strip()
        payload_ev = (payload_event or "").strip()
        if row_ev in self._TARGET_GATED_OUTBOX_EVENTS:
            if not self._webhook_target_known(tid):
                return False
        if payload_ev in self._TARGET_GATED_OUTBOX_EVENTS:
            if not self._webhook_target_known(tid):
                return False
        if row_ev and payload_ev and row_ev != payload_ev:
            if (row_ev in self._TARGET_GATED_OUTBOX_EVENTS
                    or payload_ev in self._TARGET_GATED_OUTBOX_EVENTS):
                return False
        if payload_ev and payload_ev not in self._KNOWN_WEBHOOK_OUTBOX_EVENTS:
            return False
        return True

    def _outbox_row_event_mismatch(self, row: dict, payload: dict) -> bool:
        row_ev = (row.get("event") or "").strip()
        payload_ev = (payload.get("event") or "").strip()
        if not row_ev or not payload_ev:
            return False
        return row_ev != payload_ev

    def _is_recovery_outbox_row(self, row: dict, payload: dict) -> bool:
        row_ev = (row.get("event") or "").strip()
        payload_ev = (payload.get("event") or "").strip()
        return row_ev == "recovery" or payload_ev == "recovery"

    def _recovery_closed_summary_red(self, row: dict):
        ds = self._data_store
        if ds is None:
            return None
        return ds.find_undelivered_alert_red(
            row.get("order_key") or "",
            row.get("incident_id") or "",
            exclude_id=row.get("delivery_id") or "",
        )

    def _recovery_closed_summary_eligible(
            self, row: dict, payload: dict, *, now: float,
            red: dict | None = None) -> bool:
        if self._outbox_row_event_mismatch(row, payload):
            return False
        if not self._is_recovery_outbox_row(row, payload):
            return False
        red = red if red is not None else self._recovery_closed_summary_red(row)
        if not red or red.get("delivery_state") == "delivered":
            return False
        age = now - float(red.get("first_queued_ts") or now)
        superseded = (
            red.get("last_error") == "superseded_by_closed_summary"
            or red.get("delivery_state") == "dropped_stale"
        )
        return age >= CLOSED_SUMMARY_DELAY_SEC or superseded

    def _prepare_recovery_closed_summary(
            self, row: dict, payload: dict, now: float):
        if not self._is_recovery_outbox_row(row, payload):
            return None
        ds = self._data_store
        if ds is None:
            return None
        red = self._recovery_closed_summary_red(row)
        if not self._recovery_closed_summary_eligible(
                row, payload, now=now, red=red):
            return None
        if red.get("delivery_state") not in ("dropped_stale", "delivered"):
            ds.finish_webhook_outbox(
                red["delivery_id"],
                state="dropped_stale",
                error="superseded_by_closed_summary",
                now=now,
            )
        return self._build_closed_summary_delivery(payload, red, now)

    def _invalidate_incident_seq_locked(self, tid: str) -> None:
        """Bump seq so queued/in-flight webhooks for the closed flap drop."""
        self._webhook_valid_seq[tid] = self._webhook_valid_seq.get(tid, 0) + 1

    def _open_or_update_webhook_incident(self, tid: str, label: str, ip: str,
                                         *, status: str = "red",
                                         ping_type: str = "icmp",
                                         failure_reason: str = "",
                                         trace_applicable: bool = True):
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is None:
                now = time.time()
                seq = self._alloc_incident_seq_locked(tid)
                inc = WebhookIncident(
                    tid=tid, label=label, ip=ip,
                    started_at=now, current_status=status,
                    last_reminder_at=now,
                    ping_type=ping_type,
                    failure_reason=failure_reason,
                    trace_applicable=trace_applicable,
                    push_seq=seq,
                )
                if not trace_applicable:
                    skip = trace_skip_summary(ping_type, failure_reason)
                    inc.last_trace_summary = skip
                    inc.last_trace_signature = trace_signature_from_summary(skip)
                self._webhook_incidents[tid] = inc
                return self._snapshot_incident(inc), True
            inc.label = label
            inc.ip = ip
            inc.current_status = status
            probe_changed = (
                inc.ping_type != ping_type
                or inc.failure_reason != failure_reason
                or inc.trace_applicable != trace_applicable
            )
            inc.ping_type = ping_type
            inc.failure_reason = failure_reason
            inc.trace_applicable = trace_applicable
            if probe_changed:
                if not trace_applicable:
                    skip = trace_skip_summary(ping_type, failure_reason)
                    inc.last_trace_summary = skip
                    inc.last_trace_signature = trace_signature_from_summary(skip)
                    inc.last_trace_at = 0.0
                    inc.last_trace_request_at = 0.0
                else:
                    # Probe context changed — discard stale skip/ICMP
                    # summary until a fresh traceroute lands.
                    inc.last_trace_summary = None
                    inc.last_trace_signature = None
                    inc.last_trace_at = 0.0
            return self._snapshot_incident(inc), False

    def _update_webhook_incident_status(self, tid: str, status: str) -> None:
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is not None:
                inc.current_status = status

    def _close_webhook_incident(self, tid: str) -> dict | None:
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.pop(tid, None)
            if inc is None:
                return None
        snap = self._snapshot_incident(inc)
        snap["closed_at"] = time.time()
        self._clear_persisted_incident_ack(inc)
        return snap

    def _resolve_incident_id(self, inc: WebhookIncident) -> str:
        iid = (inc.incident_id or "").strip()
        if iid:
            return iid
        if self._data_store is None:
            return ""
        try:
            open_inc = self._data_store.get_open_incidents([inc.tid])
            iid = (open_inc.get(inc.tid) or {}).get("incident_id") or ""
            iid = str(iid).strip()
            if iid:
                inc.incident_id = iid
            return iid
        except Exception:
            return ""

    def _persist_incident_ack(self, inc: WebhookIncident) -> None:
        if self._data_store is None:
            return
        iid = self._resolve_incident_id(inc)
        if iid:
            try:
                self._data_store.record_webhook_ack(iid, inc.tid)
            except Exception:
                pass

    def _clear_persisted_incident_ack(self, inc: WebhookIncident) -> None:
        if self._data_store is None:
            return
        iid = (inc.incident_id or "").strip() or self._resolve_incident_id(inc)
        if iid:
            try:
                self._data_store.clear_webhook_ack(iid)
            except Exception:
                pass

    def _drop_webhook_incident(self, tid: str) -> None:
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.pop(tid, None)
            if inc is None:
                return
            self._invalidate_incident_seq_locked(tid)
        self._clear_persisted_incident_ack(inc)

    @staticmethod
    def _snapshot_incident(inc: WebhookIncident) -> dict:
        return {
            "tid": inc.tid,
            "label": inc.label,
            "ip": inc.ip,
            "started_at": inc.started_at,
            "current_status": inc.current_status,
            "reminder_count": inc.reminder_count,
            "last_trace_at": inc.last_trace_at,
            "last_trace_summary": copy.deepcopy(inc.last_trace_summary),
            "last_trace_signature": inc.last_trace_signature,
            "ping_type": inc.ping_type,
            "failure_reason": inc.failure_reason,
            "trace_applicable": inc.trace_applicable,
            "push_seq": inc.push_seq,
        }

    @staticmethod
    def _incident_probe_fields(snap: dict) -> dict:
        from src.trace_policy import describe_failure, ping_type_label
        fr = snap.get("failure_reason") or ""
        pt = snap.get("ping_type") or "icmp"
        return {
            "ping_type": pt,
            "ping_type_label": ping_type_label(pt),
            "failure_reason": fr,
            "failure_reason_text": describe_failure(fr),
            "trace_applicable": bool(snap.get("trace_applicable", True)),
        }

    @staticmethod
    def _format_duration(seconds: float) -> str:
        s = max(0, int(seconds))
        if s < 60:
            return f"{s} 秒"
        if s < 3600:
            return f"{s // 60} 分钟"
        hours = s // 3600
        mins = (s % 3600) // 60
        return f"{hours} 小时 {mins} 分钟" if mins else f"{hours} 小时"

    @staticmethod
    def _webhook_failure_line(event: str, inc: dict) -> str | None:
        fr_text = inc.get("failure_reason_text") or ""
        if not fr_text:
            return None
        label = "故障原因" if event == "recovery" else "失败原因"
        return f"{label}：{fr_text}"

    @staticmethod
    def _webhook_timing_lines(event: str, inc: dict) -> list[str]:
        """Event-aware duration labels — avoid '0 秒' on new alerts."""
        dur_text = inc.get("duration_text") or ""
        dur_sec = inc.get("duration_seconds")
        started = inc.get("started_at")
        lines: list[str] = []

        if event == "recovery":
            if dur_text:
                lines.append(f"故障历时：{dur_text}")
            if inc.get("recovered_at"):
                lines.append(f"恢复时间：{inc['recovered_at']}")
            return lines

        if event == "alert_red":
            if dur_sec is not None and dur_sec < 1:
                if started:
                    lines.append(f"故障开始：{started}")
            elif dur_text:
                lines.append(f"已持续：{dur_text}")
                if started:
                    lines.append(f"故障开始：{started}")
            return lines

        if dur_text:
            lines.append(f"已持续：{dur_text}")
        return lines

    def _cfg_bool(self, key: str, default: bool = False) -> bool:
        if self._config is None:
            return default
        val = self._config.get_setting(key)
        return default if val is None else bool(val)

    def _cfg_int(self, key: str, default: int) -> int:
        if self._config is None:
            return default
        val = self._config.get_setting(key)
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    def _webhook_configured(self) -> bool:
        if self._config is None:
            return False
        return bool((self._config.get_setting("webhook_url") or "").strip())

    def _build_trace_extra(self, snap: dict, *, pending: bool = False) -> dict:
        if pending:
            return {
                "available": False,
                "summary": "已触发 traceroute，等待结果",
            }
        if not self._cfg_bool("webhook_include_trace", True):
            return {"available": False, "summary": None}
        summary = snap.get("last_trace_summary")
        if not summary:
            return {"available": False, "summary": "暂无 traceroute 结果"}
        trace_time = None
        if snap.get("last_trace_at"):
            trace_time = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(snap["last_trace_at"]))
        return {
            "available": True,
            "trace_time": trace_time,
            "summary": summary.get("text"),
            "reached": summary.get("reached"),
            "last_ok": summary.get("last_ok"),
            "break_at": summary.get("break_at"),
            "route_changed": False,
        }

    def _build_incident_extra(self, tid: str, *, pending_trace: bool = False) -> dict:
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            snap = self._snapshot_incident(inc) if inc else None
        if not snap:
            return {}
        now = time.time()
        duration = now - snap["started_at"]
        return {
            "incident": {
                "started_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(snap["started_at"])),
                "duration_seconds": round(duration),
                "duration_text": self._format_duration(duration),
                "reminder_count": snap["reminder_count"],
                "recovered": False,
                "recovered_at": None,
                **self._incident_probe_fields(snap),
            },
            "trace": self._build_trace_extra(snap, pending=pending_trace),
        }

    def _build_recovery_extra(self, closed: dict | None) -> dict | None:
        if not closed:
            return None
        recovered_at = closed.get("closed_at", time.time())
        duration = recovered_at - closed["started_at"]
        trace_extra = self._build_trace_extra(closed, pending=False)
        if not trace_extra.get("available"):
            trace_extra = {"available": False,
                           "summary": "故障期间 traceroute 未完成 / 无可用结果"}
        return {
            "incident": {
                "started_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(closed["started_at"])),
                "recovered_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(recovered_at)),
                "duration_seconds": round(duration),
                "duration_text": self._format_duration(duration),
                "reminder_count": closed["reminder_count"],
                "recovered": True,
                **self._incident_probe_fields(closed),
            },
            "trace": trace_extra,
        }

    def _webhook_reminder_loop(self) -> None:
        while not self._reminder_stop.wait(30):
            try:
                self._tick_webhook_reminders()
            except Exception as e:
                print(f"[AlertManager] reminder loop error: {e}")

    def _tick_webhook_reminders(self) -> None:
        if not self._cfg_bool("webhook_reminder_enabled"):
            return
        interval_sec = self._cfg_int("webhook_reminder_interval_min", 5) * 60
        max_count = self._cfg_int("webhook_reminder_max_count", 0)
        aggregate_on = self._cfg_bool("webhook_reminder_aggregate_enabled", False)
        aggregate_threshold = self._cfg_int("webhook_reminder_aggregate_threshold", 3)
        url_ok = self._webhook_configured()
        now = time.time()
        open_red: list[dict] = []
        due: list[dict] = []

        with self._webhook_incident_lock:
            for inc in self._webhook_incidents.values():
                if inc.current_status != "red":
                    continue
                if inc.acknowledged:
                    continue
                if max_count and inc.reminder_count >= max_count:
                    continue
                is_due = now - inc.last_reminder_at >= interval_sec
                # Only advance reminder counters when a webhook can actually
                # be sent — otherwise max_count / last_reminder_at are
                # silently consumed with no external effect.
                if is_due and url_ok:
                    inc.last_reminder_at = now
                    inc.reminder_count += 1
                snap = self._snapshot_incident(inc)
                open_red.append(snap)
                if is_due and url_ok:
                    due.append(snap)

        if not due:
            return

        if aggregate_on and len(open_red) >= aggregate_threshold:
            # One aggregate per interval: it already covers every open-red
            # node (including the ones that just came due), so a second
            # aggregate fired by the next node's due tick would be redundant
            # noise.  Trace refreshes for the due nodes still proceed.
            if now - self._last_aggregate_reminder_at >= interval_sec:
                self._last_aggregate_reminder_at = now
                self._push_aggregate_reminder(open_red, now)
            for snap in due:
                self._maybe_request_trace_refresh(snap, now)
            return

        for snap in due:
            self._push_webhook(
                event="alert_reminder",
                target=snap["label"],
                ip=snap["ip"],
                status=snap["current_status"],
                message="连接仍未恢复",
                extra=self._build_reminder_extra(snap),
                order_key=snap["tid"],
                gate=("reminder", snap["tid"], snap["push_seq"]),
            )
            self._maybe_request_trace_refresh(snap, now)

    def _push_alert_red_webhook(self, tid: str, label: str, ip: str, *,
                                message: str = "连接中断",
                                pending_trace: bool = True) -> None:
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is None:
                return
            seq = inc.push_seq
        self._push_webhook(
            event="alert_red", target=label, ip=ip, status="red",
            message=message,
            extra=self._build_incident_extra(tid, pending_trace=pending_trace),
            order_key=tid,
            gate=("alert_red", tid, seq),
        )

    def _push_aggregate_reminder(self, open_snaps: list[dict], now: float) -> None:
        """Queue aggregate reminder; payload rebuilt at delivery from live state."""
        tid_seq_pairs = [(s["tid"], s["push_seq"]) for s in open_snaps]
        threshold = self._cfg_int("webhook_reminder_aggregate_threshold", 3)
        rebuild_spec = {
            "type": "aggregate",
            "tid_seq_pairs": tid_seq_pairs,
            "threshold": threshold,
        }
        self._push_webhook(
            event="alert_reminder_aggregate",
            target="汇总",
            ip="",
            status="red",
            message="",
            order_key="_aggregate_",
            rebuild_spec=rebuild_spec,
        )

    def _build_aggregate_reminder_extra(self, snaps: list[dict],
                                        now: float) -> dict:
        nodes = []
        max_seconds = 0
        for snap in snaps:
            dur_s = max(0, int(now - snap["started_at"]))
            max_seconds = max(max_seconds, dur_s)
            trace = self._build_trace_extra(snap, pending=False)
            nodes.append({
                "tid": snap["tid"],
                "target": snap["label"],
                "ip": snap["ip"],
                "duration_seconds": dur_s,
                "duration_text": self._format_duration(dur_s),
                "reminder_count": snap["reminder_count"],
                "trace_summary": trace.get("summary"),
                **self._incident_probe_fields(snap),
            })
        return {
            "aggregate": {
                "count": len(nodes),
                "max_duration_seconds": max_seconds,
                "max_duration_text": self._format_duration(max_seconds),
                "nodes": nodes,
            },
        }

    def _build_reminder_extra(self, snap: dict) -> dict:
        now = time.time()
        duration = now - snap["started_at"]
        return {
            "incident": {
                "started_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(snap["started_at"])),
                "duration_seconds": round(duration),
                "duration_text": self._format_duration(duration),
                "reminder_count": snap["reminder_count"],
                "recovered": False,
                "recovered_at": None,
                **self._incident_probe_fields(snap),
            },
            "trace": self._build_trace_extra(snap, pending=False),
        }

    def _maybe_request_trace_refresh(self, snap: dict, now: float) -> None:
        if not self._cfg_bool("webhook_include_trace", True):
            return
        if not self._cfg_bool("webhook_trace_update_enabled", True):
            return
        interval_sec = (
            self._cfg_int("webhook_trace_refresh_interval_min", 15) * 60)
        tid = snap["tid"]
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is None:
                return
            if not inc.trace_applicable:
                return
            if not should_request_traceroute(inc.ping_type, inc.failure_reason):
                return
            if now - inc.last_trace_request_at < interval_sec:
                return
            inc.last_trace_request_at = now
        cb = self._trace_request_callback
        if cb is None:
            return
        try:
            cb(tid)
        except Exception as e:
            print(f"[AlertManager] trace refresh request failed: {e}")

    def on_traceroute_result(self, result: dict) -> None:
        """Called by WebServer scheduler after a committed traceroute."""
        tid = result.get("tid")
        if not tid:
            return
        if result.get("ip") is None:
            return

        route_changed = bool(result.get("route_changed"))
        should_send = False
        snap: dict | None = None
        summary = None
        signature = None

        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is None:
                return
            if inc.current_status not in ("red", "orange"):
                return
            if result.get("ip") != inc.ip:
                return
            if not inc.trace_applicable:
                return

            summary = summarize_for_alert(
                result.get("hops", []),
                ping_type=inc.ping_type,
                failure_reason=inc.failure_reason,
                tcp_checks=result.get("tcp_checks"),
            )
            signature = trace_signature_from_summary(summary)

            first_trace = inc.last_trace_summary is None
            changed = signature != inc.last_trace_signature
            inc.last_trace_at = float(result.get("ts") or time.time())
            inc.last_trace_summary = summary
            inc.last_trace_signature = signature

            if inc.acknowledged:
                should_send = False
            elif not self._cfg_bool("webhook_include_trace", True):
                should_send = False
            elif self._cfg_bool("webhook_trace_update_enabled", True):
                change_only = self._cfg_bool("webhook_trace_change_only", True)
                should_send = first_trace or (not change_only) or changed
            snap = self._snapshot_incident(inc)

        if not should_send or snap is None:
            return

        trace_extra = self._build_trace_extra(snap, pending=False)
        trace_extra["route_changed"] = route_changed
        now = time.time()
        duration = now - snap["started_at"]
        extra = {
            "incident": {
                "started_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(snap["started_at"])),
                "duration_seconds": round(duration),
                "duration_text": self._format_duration(duration),
                "reminder_count": snap["reminder_count"],
                "recovered": False,
                "recovered_at": None,
                **self._incident_probe_fields(snap),
            },
            "trace": trace_extra,
        }
        self._push_webhook(
            event="diagnostic_update",
            target=snap["label"],
            ip=snap["ip"],
            status=snap["current_status"],
            message=summary.get("text", "traceroute 诊断更新"),
            extra=extra,
            order_key=snap["tid"],
            gate=("incident", snap["tid"], snap["push_seq"]),
        )

    # ── Webhook push ─────────────────────────────────────────────────

    def _webhook_gate_ok(self, gate, *, incident_id: str = "") -> bool:
        """Return True if a deferred webhook should still be delivered."""
        parsed = self._parse_outbox_gate(gate)
        if parsed is False:
            return False
        if parsed is None:
            return True
        gate = parsed
        kind = gate[0]
        row_iid = (incident_id or "").strip()
        with self._webhook_incident_lock:
            if kind == "recovery":
                tid, seq = gate[1], gate[2]
                if not self._webhook_target_known(tid):
                    return False
                return self._webhook_valid_seq.get(tid, 0) == seq
            if kind == "reminder":
                tid, seq = gate[1], gate[2]
                if not self._webhook_target_known(tid):
                    return False
                if self._webhook_valid_seq.get(tid) != seq:
                    return False
                inc = self._webhook_incidents.get(tid)
                if inc is None or inc.push_seq != seq:
                    return False
                if row_iid and inc.incident_id and row_iid != inc.incident_id:
                    return False
                if inc.acknowledged:
                    return False
                return inc.current_status == "red"
            if kind == "incident":
                tid, seq = gate[1], gate[2]
                if not self._webhook_target_known(tid):
                    return False
                if self._webhook_valid_seq.get(tid) != seq:
                    return False
                inc = self._webhook_incidents.get(tid)
                if inc is None or inc.push_seq != seq:
                    return False
                if row_iid and inc.incident_id and row_iid != inc.incident_id:
                    return False
                if inc.acknowledged:
                    return False
                return inc.current_status in ("red", "orange")
            if kind == "alert_red":
                # Allow delivery after close if still the current generation
                # (queued before recovery on a short flap).  Recovery closes
                # the incident without bumping seq, so cur == seq still holds.
                tid, seq = gate[1], gate[2]
                if not self._webhook_target_known(tid):
                    return False
                cur = self._webhook_valid_seq.get(tid, 0)
                if cur == seq:
                    return True
                inc = self._webhook_incidents.get(tid)
                if inc is not None:
                    if inc.push_seq != seq:
                        return False
                    if row_iid and inc.incident_id and row_iid != inc.incident_id:
                        return False
                return False
            if kind == "aggregate":
                # Legacy gate path — aggregate reminders now rebuild at
                # delivery and no longer enqueue through _push_webhook.
                for tid, seq in gate[1]:
                    if self._webhook_valid_seq.get(tid) != seq:
                        continue
                    inc = self._webhook_incidents.get(tid)
                    if (inc is not None and inc.push_seq == seq
                            and inc.current_status == "red"
                            and not inc.acknowledged):
                        return True
                return False
        return False

    def _eligible_red_reminder_snaps(self, tid_seq_pairs: list) -> list[dict]:
        """Live reminder-eligible snapshots for deferred delivery rebuild."""
        snaps: list[dict] = []
        with self._webhook_incident_lock:
            for tid, seq in tid_seq_pairs:
                if self._webhook_valid_seq.get(tid) != seq:
                    continue
                inc = self._webhook_incidents.get(tid)
                if (inc is None or inc.push_seq != seq
                        or inc.current_status != "red"
                        or inc.acknowledged):
                    continue
                snaps.append(self._snapshot_incident(inc))
        return snaps

    def _ensure_webhook_worker(self, order_key: str) -> queue.Queue:
        with self._webhook_queue_lock:
            q = self._webhook_queues.get(order_key)
            if q is None:
                q = queue.Queue()
                self._webhook_queues[order_key] = q
                threading.Thread(
                    target=self._webhook_delivery_worker,
                    args=(order_key, q),
                    daemon=True,
                    name=f"webhook-q-{order_key[:24]}",
                ).start()
            return q

    def _webhook_delivery_worker(self, order_key: str, q: queue.Queue) -> None:
        while True:
            job = q.get()
            if job is None:
                # Sentinel from _drop_webhook_delivery: the target was
                # removed.  Any jobs queued ahead of the sentinel have
                # already been drained (FIFO) — e.g. a recovery webhook
                # pushed just before deletion still goes out — so the
                # worker can exit cleanly here.
                q.task_done()
                return
            try:
                job()
            except Exception as e:
                print(f"[Webhook] delivery error ({order_key}): {e}")
            finally:
                q.task_done()

    def _drop_webhook_delivery(self, order_key: str) -> None:
        """Tear down a per-target delivery worker after target removal.

        _ensure_webhook_worker spawns one queue.Queue + one daemon thread
        per order_key (the target id) and never reclaims them.  On target
        deletion this leaks a queue, a thread, and a _webhook_valid_seq
        entry permanently — unbounded under add/remove churn since tids are
        fresh UUIDs.  Pop the queue and enqueue a sentinel so the worker
        drains anything still pending (stale jobs gate-drop themselves) and
        then exits.
        """
        with self._webhook_queue_lock:
            q = self._webhook_queues.pop(order_key, None)
        if q is not None:
            q.put(None)

    def _make_delivery_id(self) -> str:
        return f"WH-{uuid.uuid4().hex[:16].upper()}"

    def _resolve_outbox_incident(self, tid: str | None) -> tuple[str, int | None]:
        if not tid:
            return "", None
        with self._webhook_incident_lock:
            inc = self._webhook_incidents.get(tid)
            if inc is None:
                return "", None
            return self._resolve_incident_id(inc), inc.push_seq

    def _rebuild_aggregate_payload(self, rebuild_spec: dict):
        tid_seq_pairs = rebuild_spec.get("tid_seq_pairs") or []
        threshold = int(rebuild_spec.get("threshold") or 2)
        eligible = self._eligible_red_reminder_snaps(tid_seq_pairs)
        if len(eligible) < threshold:
            return None
        now2 = time.time()
        sorted_snaps = sorted(
            eligible,
            key=lambda s: now2 - s["started_at"],
            reverse=True,
        )
        extra = self._build_aggregate_reminder_extra(sorted_snaps, now2)
        count = extra["aggregate"]["count"]
        max_dur = extra["aggregate"]["max_duration_text"]
        message = f"当前仍有 {count} 个节点 red，最长已持续 {max_dur}"
        return extra, message, f"汇总({count}节点)"

    def _build_closed_summary_delivery(
            self, recovery_payload: dict, red_row: dict | None, now: float):
        extra = dict(recovery_payload.get("extra") or {})
        inc = dict(extra.get("incident") or {})
        red_payload = {}
        if red_row:
            try:
                red_payload = json.loads(red_row.get("payload_json") or "{}")
            except Exception:
                red_payload = {}
        red_extra = red_payload.get("extra") or {}
        red_inc = red_extra.get("incident") or {}
        last_err = (red_row or {}).get("last_error") or "delivery_failed"
        trace = extra.get("trace") or red_extra.get("trace") or {}
        closed = {
            "incident": {
                **inc,
                "started_at": inc.get("started_at") or red_inc.get("started_at"),
                "recovered_at": inc.get("recovered_at"),
                "duration_text": inc.get("duration_text", ""),
                "closed_summary": True,
                "red_never_delivered": True,
                "last_delivery_error": last_err,
                **self._incident_probe_fields(inc if inc else red_inc),
            },
            "trace": trace,
        }
        target = recovery_payload.get("target") or red_payload.get("target") or "?"
        ip = recovery_payload.get("ip") or red_payload.get("ip") or ""
        message = (
            "该故障曾发生但首次告警推送失败，现补发闭环信息"
        )
        return (
            "incident_closed_summary",
            target,
            ip,
            "green",
            message,
            closed,
            {"event_ts": recovery_payload.get("event_ts") or now},
        )

    def outbox_row_gate_ok(self, row: dict) -> bool:
        """Re-check persisted outbox gate before/after network send."""
        import json as _json
        try:
            payload = _json.loads(row.get("payload_json") or "{}")
        except Exception:
            return False
        event = payload.get("event") or row.get("event") or ""
        gate = self._parse_outbox_gate(payload.get("gate"))
        if gate is False:
            return False
        if gate is None:
            if self._recovery_closed_summary_eligible(
                    row, payload, now=time.time()):
                return True
            return self._outbox_row_target_ok(row, payload_event=event)
        return self._webhook_gate_ok(
            gate, incident_id=row.get("incident_id") or "")

    def outbox_row_gate(self, row: dict):
        """Return parsed gate tuple from an outbox row, or None / False."""
        import json as _json
        try:
            payload = _json.loads(row.get("payload_json") or "{}")
        except Exception:
            return False
        return self._parse_outbox_gate(payload.get("gate"))

    def assert_outbox_webhook_send_allowed(
            self, *, delivery_id: str = "", gate=None) -> None:
        """Raise WebhookDeliveryAborted if delivery must not proceed."""
        self._raise_if_outbox_send_blocked(delivery_id=delivery_id, gate=gate)

    def _cancel_inflight_outbox_sends(
            self, target_id: str,
            *, events: tuple[str, ...] | None = None,
            reason: str = "dropped") -> None:
        """Invalidate in-flight sends and drop matching outbox rows."""
        if not target_id or self._data_store is None:
            return
        with self._webhook_outbox_send_lock:
            delivery_ids = self._data_store.list_sending_webhook_delivery_ids(
                target_id, events=events)
            for did in delivery_ids:
                self._webhook_send_epochs[did] = (
                    self._webhook_send_epochs.get(did, 0) + 1)
                self._webhook_send_cancelled.add(did)
            if events is not None:
                self._data_store.drop_pending_webhook_events(
                    target_id, events, reason)
            else:
                self._data_store.drop_pending_webhook_for_target(
                    target_id, reason)

    def _verify_outbox_send_commit(
            self, *, delivery_id: str, gate, commit_epoch: int) -> None:
        if self._webhook_send_epochs.get(delivery_id, 0) != commit_epoch:
            raise WebhookDeliveryAborted("superseded")
        if delivery_id in self._webhook_send_cancelled:
            raise WebhookDeliveryAborted("cancelled")
        if gate is not None:
            parsed = self._parse_outbox_gate(gate)
            if parsed is False or not self._webhook_gate_ok(parsed, incident_id=""):
                raise WebhookDeliveryAborted("gate")
        if self._data_store is not None:
            state = self._data_store.get_webhook_outbox_delivery_state(
                delivery_id)
            if state != "sending":
                raise WebhookDeliveryAborted(state or "missing")

    def _raise_if_outbox_send_blocked(
            self, *, delivery_id: str = "", gate=None) -> None:
        """Early gate/state check (non-atomic; used before payload build)."""
        if delivery_id in self._webhook_send_cancelled:
            raise WebhookDeliveryAborted("cancelled")
        if gate is not None:
            parsed = self._parse_outbox_gate(gate)
            if parsed is False or not self._webhook_gate_ok(parsed, incident_id=""):
                raise WebhookDeliveryAborted("gate")
        if delivery_id and self._data_store is not None:
            state = self._data_store.get_webhook_outbox_delivery_state(
                delivery_id)
            if state != "sending":
                raise WebhookDeliveryAborted(state or "missing")

    def _webhook_pre_http_send_hook(
            self, *, delivery_id: str = "", gate=None) -> None:
        """No-op hook for tests to simulate a pre-network race window."""

    def release_outbox_send_tracking(self, delivery_id: str) -> None:
        """Reclaim per-send cancel tracking once a delivery leaves 'sending'.

        _cancel_inflight_outbox_sends records an epoch bump + cancelled flag
        for every delivery that is mid-send when an ACK/pause/remove fires.
        Those entries are keyed by the unique (uuid4) delivery_id and were
        never removed, so _webhook_send_epochs / _webhook_send_cancelled grew
        without bound over a long-running process.  The dispatcher calls this
        once the row is finalized (terminal or back to pending) — at which
        point it is no longer 'sending', so no concurrent cancel can re-add
        it after we clear it.
        """
        if not delivery_id:
            return
        with self._webhook_outbox_send_lock:
            self._webhook_send_epochs.pop(delivery_id, None)
            self._webhook_send_cancelled.discard(delivery_id)

    def _outbox_http_open(
            self, req, timeout: int, *, delivery_id: str, commit_epoch: int,
            gate) -> None:
        """Perform HTTP POST; caller must not hold _webhook_outbox_send_lock."""
        with self._webhook_outbox_send_lock:
            self._verify_outbox_send_commit(
                delivery_id=delivery_id, gate=gate,
                commit_epoch=commit_epoch)
            with _ORIGINAL_HTTP_OPEN(req, timeout=timeout):
                pass
            self._verify_outbox_send_commit(
                delivery_id=delivery_id, gate=gate,
                commit_epoch=commit_epoch)

    def _commit_outbox_webhook_http(
            self, req, *, delivery_id: str = "", gate=None, timeout: int = 10):
        """Verify send permission under send lock, then perform HTTP POST."""
        commit_epoch = 0
        try:
            with self._webhook_outbox_send_lock:
                commit_epoch = self._webhook_send_epochs.get(delivery_id, 0)
                self._verify_outbox_send_commit(
                    delivery_id=delivery_id, gate=gate,
                    commit_epoch=commit_epoch)

            self._webhook_pre_http_send_hook(
                delivery_id=delivery_id, gate=gate)

            self._outbox_http_open(
                req, timeout, delivery_id=delivery_id,
                commit_epoch=commit_epoch, gate=gate)
        finally:
            with self._webhook_outbox_send_lock:
                self._webhook_send_cancelled.discard(delivery_id)

    def prepare_outbox_delivery(self, row: dict, now: float):
        """Resolve a persisted outbox row into a send-ready payload."""
        import json as _json
        try:
            payload = _json.loads(row.get("payload_json") or "{}")
        except Exception:
            return None

        event = payload.get("event") or row.get("event") or ""
        parsed_gate = self._parse_outbox_gate(payload.get("gate"))
        if parsed_gate is False:
            return None

        closed_summary = self._prepare_recovery_closed_summary(
            row, payload, now)
        if closed_summary is not None:
            return closed_summary

        if parsed_gate is not None:
            if not self._webhook_gate_ok(
                    parsed_gate, incident_id=row.get("incident_id") or ""):
                return None
        elif not self._outbox_row_target_ok(row, payload_event=event):
            return None

        rebuild_spec = payload.get("rebuild_spec")
        if rebuild_spec and rebuild_spec.get("type") == "aggregate":
            rebuilt = self._rebuild_aggregate_payload(rebuild_spec)
            if rebuilt is None:
                return None
            extra, message, target = rebuilt
            payload = {**payload, "extra": extra, "message": message,
                       "target": target}

        event_ts = float(payload.get("event_ts") or row.get("event_ts") or now)
        event_ts_str = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(event_ts))
        meta = {"event_ts": event_ts, "event_ts_str": event_ts_str}
        return (
            payload.get("event") or event,
            payload.get("target") or "",
            payload.get("ip") or "",
            payload.get("status") or "",
            payload.get("message") or "",
            payload.get("extra"),
            meta,
        )

    def _push_webhook(self, *, event: str, target: str, ip: str,
                      status: str, message: str,
                      extra: dict | None = None,
                      order_key: str | None = None,
                      gate=None,
                      rebuild_spec: dict | None = None) -> None:
        """Persist webhook to outbox; background dispatcher delivers."""
        if self._config is None or self._data_store is None:
            return
        url = (self._config.get_setting("webhook_url") or "").strip()
        if not url:
            return

        tid = order_key if order_key and order_key != "_aggregate_" else ""
        incident_id, incident_seq = self._resolve_outbox_incident(tid or None)
        event_ts = time.time()
        payload = {
            "event": event,
            "target": target,
            "ip": ip,
            "status": status,
            "message": message,
            "extra": extra or {},
            "gate": list(gate) if gate else None,
            "rebuild_spec": rebuild_spec,
            "event_ts": event_ts,
        }
        delivery_id = self._make_delivery_id()
        ok = order_key or tid or "_broadcast_"
        try:
            self._data_store.enqueue_webhook_outbox(
                delivery_id=delivery_id,
                target_id=tid,
                incident_id=incident_id,
                incident_seq=incident_seq,
                event=event,
                order_key=ok,
                payload=payload,
                event_ts=event_ts,
                max_attempts=max_attempts_for_event(event),
            )
        except Exception as e:
            print(f"[Webhook] outbox enqueue failed: {e}")
            return
        if self._outbox_dispatcher is not None:
            self._outbox_dispatcher.wake()

    def _send_webhook(self, url, event, target, ip, status, message, ts_str,
                      extra=None, *, event_ts=None, queued_ts=None,
                      sent_ts=None, attempt=1, delivery_id="", gate=None):
        """Build platform-aware payload and POST it. Raises on failure."""
        import json
        import urllib.request

        self.assert_outbox_webhook_send_allowed(
            delivery_id=delivery_id, gate=gate)

        icons = {
            "alert_red": "🔴",
            "recovery": "🟢",
            "alert_reminder": "🔴",
            "alert_reminder_aggregate": "🔴",
            "diagnostic_update": "🧭",
            "incident_closed_summary": "🟢",
        }
        titles = {
            "alert_red": "网络监控告警",
            "recovery": "网络监控恢复",
            "alert_reminder": "告警仍未恢复",
            "alert_reminder_aggregate": "告警仍未恢复汇总",
            "diagnostic_update": "故障诊断更新",
            "incident_closed_summary": "网络故障已恢复",
        }
        icon = icons.get(event, "🟠")
        title = titles.get(event, "网络监控告警")
        if event == "incident_closed_summary":
            title = "网络故障已恢复｜补发闭环"
        text = AlertManager._format_webhook_text(
            icon, title, event, target, ip, status, message, ts_str, extra,
            event_ts=event_ts, queued_ts=queued_ts, sent_ts=sent_ts,
            attempt=attempt)

        url_l = url.lower()
        if "feishu" in url_l or "larkoffice" in url_l:
            payload = {"msg_type": "text", "content": {"text": text}}
        elif ("qyapi" in url_l or "weixin" in url_l
              or "dingtalk" in url_l or "oapi" in url_l):
            payload = {"msgtype": "text", "text": {"content": text}}
        else:
            payload = {
                "event": event, "target": target, "ip": ip,
                "status": status, "message": message,
                "timestamp": ts_str,
                "delivery_id": delivery_id,
                "attempt": attempt,
            }
            if extra:
                payload.update(extra)
        body = json.dumps(payload, ensure_ascii=False).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST")
        if delivery_id:
            self._commit_outbox_webhook_http(
                req, delivery_id=delivery_id, gate=gate)
        else:
            with urllib.request.urlopen(req, timeout=10):
                pass

    @staticmethod
    def _format_ts(ts_val) -> str:
        if ts_val is None:
            return ""
        try:
            return time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(float(ts_val)))
        except (TypeError, ValueError, OSError):
            return str(ts_val)

    @staticmethod
    def _format_webhook_text(icon, title, event, target, ip, status,
                             message, ts_str, extra, *,
                             event_ts=None, queued_ts=None, sent_ts=None,
                             attempt=1):
        if event == "alert_reminder_aggregate":
            return AlertManager._format_aggregate_webhook_text(
                icon, title, message, ts_str, extra,
                event_ts=event_ts, queued_ts=queued_ts, sent_ts=sent_ts,
                attempt=attempt)

        if event == "incident_closed_summary":
            inc = (extra or {}).get("incident") or {}
            trace = (extra or {}).get("trace") or {}
            lines = [
                f"{icon}【{title}】",
                f"节点：{target}",
                f"IP：{ip}",
            ]
            if inc.get("started_at"):
                lines.append(f"故障开始：{inc['started_at']}")
            if inc.get("recovered_at"):
                lines.append(f"恢复时间：{inc['recovered_at']}")
            if inc.get("duration_text"):
                lines.append(f"故障历时：{inc['duration_text']}")
            lines.append(
                "说明：故障期间 webhook 首次告警投递失败，现补发完整闭环信息。")
            if inc.get("last_delivery_error"):
                lines.append(f"最后错误：{inc['last_delivery_error']}")
            lines.append(f"详情：{message}")
            if trace.get("summary"):
                lines.append(f"诊断：{trace['summary']}")
            AlertManager._append_delivery_timing_lines(
                lines, event_ts, queued_ts, sent_ts, attempt)
            return "\n".join(lines)

        lines = [
            f"{icon}【{title}】",
            f"节点：{target}",
            f"IP：{ip}",
            f"状态：{status}",
        ]
        inc = (extra or {}).get("incident") or {}
        trace = (extra or {}).get("trace") or {}
        if inc.get("ping_type_label"):
            lines.append(f"探测类型：{inc['ping_type_label']}")
        fail_line = AlertManager._webhook_failure_line(event, inc)
        if fail_line:
            lines.append(fail_line)
        lines.extend(AlertManager._webhook_timing_lines(event, inc))
        if inc.get("reminder_count") is not None and event == "alert_reminder":
            lines.append(f"提醒次数：{inc['reminder_count']}")
        lines.append(f"详情：{message}")
        if trace.get("summary"):
            lines.append(f"诊断：{trace['summary']}")
        elif event == "alert_red":
            lines.append("诊断：已触发 traceroute，等待结果")
        if trace.get("trace_time"):
            lines.append(f"追踪时间：{trace['trace_time']}")
        AlertManager._append_delivery_timing_lines(
            lines, event_ts, queued_ts, sent_ts, attempt)
        return "\n".join(lines)

    @staticmethod
    def _append_delivery_timing_lines(lines, event_ts, queued_ts, sent_ts,
                                      attempt):
        if event_ts is not None:
            lines.append(f"消息生成：{AlertManager._format_ts(event_ts)}")
        if queued_ts is not None:
            lines.append(f"入队时间：{AlertManager._format_ts(queued_ts)}")
        if sent_ts is not None:
            lines.append(f"发送时间：{AlertManager._format_ts(sent_ts)}")
        if attempt and int(attempt) > 1:
            lines.append(f"投递状态：第 {int(attempt)} 次尝试成功")

    @staticmethod
    def _format_aggregate_webhook_text(icon, title, message, ts_str, extra, *,
                                      event_ts=None, queued_ts=None,
                                      sent_ts=None, attempt=1):
        agg = (extra or {}).get("aggregate") or {}
        nodes = agg.get("nodes") or []
        lines = [
            f"{icon}【{title}】",
            f"详情：{message}",
            "",
        ]
        listed = nodes[:_AGGREGATE_LIST_MAX]
        for i, n in enumerate(listed, 1):
            pt = n.get("ping_type_label") or ""
            fr = n.get("failure_reason_text") or ""
            ctx = ""
            if pt and fr:
                ctx = f"，{pt}/{fr}"
            elif pt:
                ctx = f"，{pt}"
            elif fr:
                ctx = f"，{fr}"
            lines.append(
                f"{i}. {n.get('target', '?')} {n.get('ip', '')}，"
                f"持续 {n.get('duration_text', '?')}{ctx}")
        omitted = len(nodes) - len(listed)
        if omitted > 0:
            lines.append(f"其余 {omitted} 个节点请查看 Web Dashboard。")

        trace_lines = []
        if any(n.get("trace_summary") for n in nodes[:_AGGREGATE_TRACE_MAX]):
            lines.append("")
            lines.append("诊断摘要（疑似定位，前若干节点）：")
            for n in nodes[:_AGGREGATE_TRACE_MAX]:
                summary = n.get("trace_summary")
                if not summary:
                    continue
                trace_lines.append(f"- {n.get('target', '?')}：{summary}")
            lines.extend(trace_lines)

        AlertManager._append_delivery_timing_lines(
            lines, event_ts, queued_ts, sent_ts, attempt)
        return "\n".join(lines)

    def acknowledge_alarm(self):
        """人工确认告警，停止循环告警声。"""
        self._stop_red_alarm()

    def test_sounds(self):
        """
        测试所有告警音效。依次播放：警告 → 告警 → 恢复。
        供界面上的「测试声音」按钮调用。
        """
        def _run():
            self._play_sync(self._sound_files["warning"])
            time.sleep(1.2)
            self._play_sync(self._sound_files["alarm"])
            time.sleep(1.2)
            self._play_sync(self._sound_files["recovery"])
        threading.Thread(target=_run, daemon=True, name="sound-test").start()

    # ──────────────────────────────────────────────────────────────
    # 红色循环告警
    # ──────────────────────────────────────────────────────────────

    def _ensure_red_alarm_running(self):
        with self._alarm_lock:
            if self._red_alarm_active:
                # A thread is already running (or just about to exit).
                # Rescind any pending stop signal so that thread keeps
                # looping instead of bailing -- otherwise we'd race
                # between "stop the thread" and "start a fresh one",
                # ending up with two concurrent alarm threads playing
                # the WAV at the same time.  See _stop_red_alarm.
                self._red_alarm_stop.clear()
                return
            self._red_alarm_stop.clear()
            self._red_alarm_active = True
            threading.Thread(
                target=self._red_alarm_loop,
                daemon=True, name="alert-red-loop"
            ).start()

    def _stop_red_alarm(self):
        # ONLY signal the loop to stop.  Do NOT flip _red_alarm_active
        # ourselves -- the running thread might still be mid-_play_sync
        # (a 2s WAV) and cannot react instantly.  If we cleared the
        # flag here, a fast red→green→red flip would pass the active=
        # False check in _ensure_red_alarm_running, clear the stop
        # event, and spawn a SECOND thread; the original thread,
        # waking from play_sync, would see stop=False (just cleared)
        # and continue looping -- two threads playing the alarm in
        # parallel, with the loss-of-flag eventually corrupting the
        # bookkeeping into "active=False but thread still alive".
        # The thread sets active=False itself in _red_alarm_loop's
        # finally; until then, _ensure can safely no-op.
        with self._alarm_lock:
            if self._red_alarm_active:
                self._red_alarm_stop.set()

    def _red_alarm_loop(self):
        try:
            while True:
                # Decide whether to keep looping ATOMICALLY with the
                # active-flag reset, under the same lock _ensure/_stop use.
                # The old code checked stop in the UNLOCKED `while` head and
                # cleared active in a `finally` -- two non-atomic steps with
                # a gap where a concurrent _ensure_red_alarm_running() saw
                # active=True, no-op'd (clearing the stop event), then this
                # thread exited: a node that stayed red afterwards got NO
                # alarm until the next evaluate_alarm.  A finally reset is
                # itself unsafe here -- it would run AFTER the locked return,
                # by which point _ensure may have started a fresh thread and
                # set active=True, so finally would flip it back to False and
                # the NEXT _ensure would spawn a SECOND concurrent loop.
                # Fix: check stop + clear active under one lock, return with
                # NO finally.  If _ensure cleared stop after signalling us,
                # we simply keep looping (the node is red again).
                with self._alarm_lock:
                    if self._red_alarm_stop.is_set():
                        self._red_alarm_active = False
                        return
                self._play_sync(self._sound_files["alarm"])
                # Event.wait() instead of sleep — lower CPU, instant stop.
                self._red_alarm_stop.wait(timeout=3.0)
        except Exception as e:
            print(f"[AlertManager._red_alarm_loop] unexpected error: {e}")
            with self._alarm_lock:
                self._red_alarm_active = False

    # ──────────────────────────────────────────────────────────────
    # 播放函数
    # ──────────────────────────────────────────────────────────────

    def _play_sync(self, filepath: str):
        """
        同步播放 WAV 文件（阻塞直到播完）。
        在循环告警线程和测试线程里使用，因为它们本身就是独立线程。
        """
        if not WINSOUND_AVAILABLE or not os.path.exists(filepath):
            return
        try:
            winsound.PlaySound(filepath, winsound.SND_FILENAME)
        except Exception as e:
            print(f"[AlertManager] 播放失败: {e}")

    def _play_async(self, filepath: str):
        """
        异步播放 WAV 文件（非阻塞，立即返回）。
        在主线程的状态更新回调里使用，避免卡住 UI。
        """
        if not WINSOUND_AVAILABLE or not os.path.exists(filepath):
            return
        try:
            winsound.PlaySound(
                filepath,
                winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT
            )
        except Exception as e:
            print(f"[AlertManager] 播放失败: {e}")

    # ──────────────────────────────────────────────────────────────
    # 桌面通知
    # ──────────────────────────────────────────────────────────────

    def _send_notification(self, title: str, msg: str):
        if not TOAST_AVAILABLE or not self._toaster:
            return
        def _notify():
            try:
                self._toaster.show_toast(title, msg, duration=5, threaded=True)
            except Exception:
                pass
        threading.Thread(target=_notify, daemon=True).start()
