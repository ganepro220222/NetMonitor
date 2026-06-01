"""
logger.py
---------
负责将告警事件写入日志文件。

日志设计思路：
  日志按"天"分文件，格式为 logs/monitor_2025-01-15.log，
  这样查找某天的事件很方便，也不会让单个文件无限膨胀。

  每条日志记录包含：时间戳、事件类型、目标名称、IP，
  以及触发原因（连续丢包数/延时值等）。

  日志是纯文本格式（不是 JSON），便于人工直接阅读，
  也可以用 grep 快速过滤。

日志级别：
  [INFO]  程序启动、停止、目标添加/删除等操作事件
  [WARN]  橙色告警触发、恢复
  [ERROR] 红色告警触发
"""

import os
import threading
from datetime import datetime
from pathlib import Path


class Logger:
    """
    日志记录器。线程安全（用 threading.Lock 保护写操作）。
    """

    # Keep at most this many daily log files; older ones are deleted on startup.
    MAX_LOG_DAYS = 30

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)   # 确保 logs/ 目录存在
        self._lock = threading.Lock()
        self._cleanup_old_logs()

    def _cleanup_old_logs(self):
        """Delete daily log files older than MAX_LOG_DAYS.
        Silently ignores any errors so it never affects the main program.

        Sort by modification time rather than filename so the cleanup remains
        correct even if the filename format ever changes (the previous
        lexicographic sort only worked because ISO dates happen to sort
        chronologically — a brittle coincidence).
        """
        try:
            files = list(self.log_dir.glob("monitor_*.log"))
            # Oldest first; tolerate stat() errors per-file by deferring to
            # epoch 0 so unreadable files are treated as oldest and removed
            # first when over quota.
            def _mtime(p):
                try: return p.stat().st_mtime
                except Exception: return 0.0
            files.sort(key=_mtime)
            excess = len(files) - self.MAX_LOG_DAYS
            for f in files[:max(0, excess)]:
                try: f.unlink()
                except Exception: pass
        except Exception:
            pass

    def _get_log_file(self) -> Path:
        """返回今天的日志文件路径，例如 logs/monitor_2025-01-15.log。"""
        today = datetime.now().strftime("%Y-%m-%d")
        return self.log_dir / f"monitor_{today}.log"

    def _write(self, level: str, message: str):
        """
        底层写入方法。加锁保证多线程同时写入时不会内容交错。
        跨天时顺带触发一次旧日志清理，确保长期运行下 MAX_LOG_DAYS 限制生效。
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{level}] {message}\n"

        need_cleanup = False
        with self._lock:
            log_file = self._get_log_file()
            is_new_day = not log_file.exists()
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(line)
            except IOError as e:
                print(f"[Logger] 日志写入失败: {e}")
            if is_new_day:
                need_cleanup = True
        # Spawn outside the lock so other threads aren't blocked during
        # the OS-level thread-creation syscall.
        if need_cleanup:
            import threading as _th
            _th.Thread(target=self._cleanup_old_logs,
                        daemon=True, name="log-cleanup").start()

    # ──────────────────────────────────────────────────────────────
    # 对外提供的日志接口
    # ──────────────────────────────────────────────────────────────

    def info(self, message: str):
        self._write("INFO ", message)

    def warn(self, message: str):
        self._write("WARN ", message)

    def error(self, message: str):
        self._write("ERROR", message)

    # ──────────────────────────────────────────────────────────────
    # 语义化的日志方法（给 alert_manager 和 main_window 调用）
    # ──────────────────────────────────────────────────────────────

    def log_status_change(self, label: str, ip: str,
                          old_status: str, new_status: str,
                          consecutive_loss: int = 0,
                          latency_ms: float = None):
        """记录状态变化事件。"""

        # 根据新状态选择日志级别
        if new_status == "red":
            log_fn = self.error
        elif new_status == "orange":
            log_fn = self.warn
        else:
            log_fn = self.info

        # 构造可读的描述
        reason_parts = []
        if consecutive_loss > 0:
            reason_parts.append(f"连续丢包 {consecutive_loss} 次")
        if latency_ms is not None:
            reason_parts.append(f"延时 {latency_ms:.1f}ms")
        reason = "，".join(reason_parts) if reason_parts else "状态变化"

        status_map = {"green": "正常", "orange": "警告", "red": "告警", "gray": "未知"}
        old_label = status_map.get(old_status, old_status)
        new_label = status_map.get(new_status, new_status)

        log_fn(
            f"「{label}」({ip})  {old_label} → {new_label}  [{reason}]"
        )

    def log_startup(self, target_count: int):
        self.info(f"程序启动，共加载 {target_count} 个监测目标")

    def log_target_paused(self, label: str, ip: str):
        self._write("INFO ", f"[手动暂停] {label} ({ip}) — 监测已暂停，暂停期间的数据不计入统计")

    def log_target_resumed(self, label: str, ip: str):
        self._write("INFO ", f"[手动恢复] {label} ({ip}) — 监测已恢复，重置连续计数器重新开始统计")

    def log_shutdown(self):
        self.info("程序正常退出")

    def log_target_added(self, label: str, ip: str):
        self.info(f"添加监测目标：「{label}」({ip})")

    def log_target_removed(self, label: str, ip: str):
        self.info(f"删除监测目标：「{label}」({ip})")
