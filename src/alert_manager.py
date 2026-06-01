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

import math
import os
import struct
import threading
import time
import wave
from pathlib import Path

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

    # ──────────────────────────────────────────────────────────────
    # 主接口
    # ──────────────────────────────────────────────────────────────

    def on_status_change(self, target_id: str, target_label: str,
                         target_ip: str, new_status: str):
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
            self._push_webhook(event="alert_red", target=target_label,
                               ip=target_ip, status="red", message="连接中断")

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
                    self._send_notification(
                        title="🟢 网络已恢复",
                        msg=f"「{target_label}」({target_ip}) 连接已恢复正常。"
                    )
                    self._push_webhook(event="recovery", target=target_label,
                                       ip=target_ip, status="green",
                                       message="连接已恢复正常")
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
        # Do NOT call _stop_red_alarm() here — evaluate_alarm() in MainWindow
        # will do a fresh scan and decide.  This prevents pausing any node
        # (even a green one) from accidentally silencing alarms on other nodes.

    def set_data_store(self, ds) -> None:
        self._data_store = ds

    def set_config(self, config) -> None:
        self._config = config

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

    # ── Webhook push ─────────────────────────────────────────────────

    def _push_webhook(self, *, event: str, target: str, ip: str,
                      status: str, message: str) -> None:
        """Fire-and-forget webhook push in a daemon thread.
        Silently does nothing if no URL is configured.
        Auto-detects WeCom/DingTalk, Feishu, or generic JSON format.
        """
        # set_config() may not have been called yet (or ever); guard so a
        # status-change event never crashes the caller thread.
        if self._config is None:
            return
        url = (self._config.get_setting("webhook_url") or "").strip()
        if not url:
            return
        import time
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
        threading.Thread(
            target=self._send_webhook,
            args=(url, event, target, ip, status, message, ts_str),
            daemon=True, name="webhook"
        ).start()

    @staticmethod
    def _send_webhook(url, event, target, ip, status, message, ts_str):
        """Build platform-aware payload and POST it. Errors are logged only."""
        import json, urllib.request, urllib.error
        icon = {"alert_red": "🔴", "recovery": "🟢"}.get(event, "🟠")
        text = (f"{icon} 【网络监控告警】\n"
                f"节点：{target}\nIP：{ip}\n"
                f"状态：{status}\n详情：{message}\n时间：{ts_str}")
        url_l = url.lower()
        if "feishu" in url_l or "larkoffice" in url_l:
            # Feishu / Lark
            payload = {"msg_type": "text",
                       "content": {"text": text}}
        elif ("qyapi" in url_l or "weixin" in url_l
              or "dingtalk" in url_l or "oapi" in url_l):
            # WeCom / DingTalk
            payload = {"msgtype": "text",
                       "text": {"content": text}}
        else:
            # Generic / custom HTTP endpoint
            payload = {"event": event, "target": target, "ip": ip,
                       "status": status, "message": message,
                       "timestamp": ts_str}
        try:
            body = json.dumps(payload, ensure_ascii=False).encode()
            req  = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST")
            with urllib.request.urlopen(req, timeout=10): pass
        except Exception as e:
            print(f"[Webhook] push failed: {e}")

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
            while not self._red_alarm_stop.is_set():
                self._play_sync(self._sound_files["alarm"])
                # Use Event.wait() instead of 30×sleep(0.1) — lower CPU,
                # faster response to stop signal.
                self._red_alarm_stop.wait(timeout=3.0)
        except Exception as e:
            print(f"[AlertManager._red_alarm_loop] unexpected error: {e}")
        finally:
            # Reset flag UNCONDITIONALLY -- whether we exited the loop
            # because of a stop signal, an exception, or anything else,
            # this thread is gone and _ensure_red_alarm_running must
            # be able to start a fresh one next time.
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
