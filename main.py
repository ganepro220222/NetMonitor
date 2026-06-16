"""
main.py — program entry point
"""
import sys
import os

# PyInstaller console=False sets stdout/stderr to None; any early print()
# (config load, ping monitor errors) would crash threads before Web starts.
if getattr(sys, "frozen", False):
    _devnull = open(os.devnull, "w", encoding="utf-8", errors="ignore")
    if sys.stdout is None:
        sys.stdout = _devnull
    if sys.stderr is None:
        sys.stderr = _devnull

# IMPORTANT: must run BEFORE any tkinter window is created.
def _set_windows_app_id():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Local.NetMonitor.Desktop.1.0")
    except Exception:
        pass

_set_windows_app_id()

# ── 基准目录（开发 vs PyInstaller 两用）────────────────────────────────
_FROZEN  = getattr(sys, 'frozen', False)
BASE_DIR = (os.path.dirname(sys.executable) if _FROZEN
            else os.path.dirname(os.path.abspath(__file__)))

# ── MAIN-2: 运行期可写数据目录 ─────────────────────────────────────────
# 只读资源（assets）仍放在 BASE_DIR（exe 旁）。
# 可写状态（config、db、logs、crash.log）在 frozen 态放到
# %LOCALAPPDATA%\NetMonitor，避免在 Program Files 等受保护目录下
# 因权限不足而静默失败。
# 向后兼容：若旧目录（BASE_DIR）已有 config.json，自动迁移到新目录。
if _FROZEN:
    _lad = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    DATA_DIR = os.path.join(_lad, "NetMonitor")
    os.makedirs(DATA_DIR, exist_ok=True)

    # 一次性迁移：旧版本把数据写在 exe 旁边
    _old_cfg = os.path.join(BASE_DIR, "config.json")
    _new_cfg = os.path.join(DATA_DIR, "config.json")
    if os.path.exists(_old_cfg) and not os.path.exists(_new_cfg):
        import shutil
        for _item in ("config.json", "logs", "data", "crash.log"):
            _src = os.path.join(BASE_DIR, _item)
            _dst = os.path.join(DATA_DIR, _item)
            if os.path.exists(_src) and not os.path.exists(_dst):
                try:
                    if os.path.isdir(_src):
                        shutil.copytree(_src, _dst)
                    else:
                        shutil.copy2(_src, _dst)
                except Exception:
                    pass
else:
    DATA_DIR = BASE_DIR

# ── MAIN-3: 崩溃记录覆盖主线程 + 后台线程 ──────────────────────────────
if _FROZEN:
    import traceback
    def _crash_handler(exc_type, exc_value, exc_tb):
        crash_path = os.path.join(DATA_DIR, 'crash.log')
        try:
            import datetime as _dt
            sep = f"\n{'='*60}\n[{_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n"
            with open(crash_path, 'a', encoding='utf-8') as f:
                f.write(sep)
                traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    def _thread_crash_handler(args):
        """Catch uncaught exceptions in background threads (Python 3.8+)."""
        import threading as _th
        thread_name = getattr(args.thread, 'name', '?') if args.thread else '?'
        crash_path = os.path.join(DATA_DIR, 'crash.log')
        try:
            import datetime as _dt
            sep = (f"\n{'='*60}\n"
                   f"[{_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
                   f" [thread: {thread_name}]\n")
            with open(crash_path, 'a', encoding='utf-8') as f:
                f.write(sep)
                traceback.print_exception(
                    args.exc_type, args.exc_value, args.exc_traceback, file=f)
        except Exception:
            pass

    sys.excepthook = _crash_handler
    import threading as _threading
    _threading.excepthook = _thread_crash_handler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config_manager import ConfigManager
from src.ping_engine import PingEngine
from src.alert_manager import AlertManager
from src.logger import Logger
from src.web_server import WebServer
from src.icon_generator import ensure_icon
from src.ui.main_window import MainWindow


def main():
    config  = ConfigManager(config_path=os.path.join(DATA_DIR, "config.json"))
    engine  = PingEngine(settings=config.config["settings"], on_state_change=None)
    # Read-only assets (icon) live next to the exe (BASE_DIR).
    # Generated/writable assets (WAV sound files) go to DATA_DIR so frozen
    # installs under Program Files never hit a write-permission failure on
    # first run. In dev mode BASE_DIR == DATA_DIR so behaviour is unchanged.
    _assets_rw = os.path.join(DATA_DIR, "assets")   # writable: WAV generation
    # Honour the persisted sound-alert preference instead of always
    # starting at True; otherwise users who turned the alarm off in
    # settings see it pop back on at every restart.  Missing key
    # (legacy configs / fresh installs) falls back to True so
    # behaviour is unchanged on first run.
    _sound_pref = config.get_setting("sound_alert_enabled")
    alerter = AlertManager(enabled=(True if _sound_pref is None else bool(_sound_pref)),
                            assets_dir=_assets_rw)
    logger  = Logger(log_dir=os.path.join(DATA_DIR, "logs"))
    web     = WebServer(port=config.get_setting("web_port") or 8765,
                        log_dir=os.path.join(DATA_DIR, "logs"),
                        sound_dir=_assets_rw)

    # MAIN-1: apply saved traceroute settings immediately so the scheduler
    # uses the user's config from the first second, not the defaults.
    _tr_interval = config.get_setting("traceroute_interval")
    if _tr_interval:
        web.set_traceroute_interval(int(_tr_interval))
    _tr_hops = config.get_setting("tracert_max_hops")
    if _tr_hops:
        web.set_traceroute_max_hops(int(_tr_hops))

    from src.data_store import DataStore
    _db_path = config.get_setting("db_path") or "data/monitor.db"
    if not os.path.isabs(_db_path):
        _db_path = os.path.join(DATA_DIR, _db_path)
    # MAIN-4: pass traceroute_retention_days so startup matches runtime behaviour
    data_store = DataStore(
        db_path=_db_path,
        raw_retention_days=int(config.get_setting("db_raw_retention_days") or 8),
        hourly_retention_days=int(config.get_setting("db_hourly_retention_days") or 90),
        alert_retention_days=int(config.get_setting("db_alert_retention_days") or 365),
        traceroute_retention_days=int(
            config.get_setting("db_traceroute_retention_days") or 30),
        diag_retention_days=int(config.get_setting("db_diag_retention_days") or 180),
    )
    web.set_data_store(data_store)

    alerter.set_data_store(data_store)
    alerter.set_config(config)
    alerter.set_trace_request_callback(web.request_traceroute_now)
    web.set_traceroute_result_callback(alerter.on_traceroute_result)
    web.set_alert_ack_callback(alerter.acknowledge_incident)
    web.set_incident_ack_status_fn(alerter.is_incident_acknowledged)

    app = MainWindow(
        config_manager=config,
        ping_engine=engine,
        alert_manager=alerter,
        logger=logger,
        web_server=web,
        data_store=data_store,
    )

    # Set application icon.
    #
    # Order matters here: with the AppUserModelID call above already
    # executed, Windows now treats this process as its own application.
    # iconbitmap()/iconphoto() therefore also affects the taskbar, not
    # just the title bar.
    #
    # Why absolute path: relative paths are resolved against the current
    # working directory. If the user launches start.bat from elsewhere
    # (e.g., a desktop shortcut that sets a different CWD), a relative
    # path silently fails to load.
    icon_path = ensure_icon()
    if icon_path:
        icon_path = os.path.abspath(icon_path)
        ico_path  = icon_path.replace(".png", ".ico")
        ico_path  = os.path.abspath(ico_path)

        # Strategy: try .ico via iconbitmap first (Windows prefers this
        # path for taskbar rendering), then fall back to .png via
        # iconphoto (which is cross-platform).
        applied = False
        if sys.platform == "win32" and os.path.exists(ico_path):
            try:
                app.iconbitmap(default=ico_path)   # `default` makes it apply to all toplevels
                applied = True
            except Exception:
                pass

        if not applied:
            try:
                from PIL import ImageTk, Image
                img = Image.open(icon_path).resize((64, 64))
                photo = ImageTk.PhotoImage(img)
                app.iconphoto(True, photo)
            except Exception:
                pass

    # ── 静默启动（--minimized）：开机自启时直接进托盘 ────────────
    import sys as _sys
    if "--minimized" in _sys.argv or "-minimized" in _sys.argv:
        # 隐藏主窗口，触发托盘最小化逻辑（与点击关闭按钮相同路径）
        try:
            app.withdraw()               # 隐藏窗口
            if not app._ensure_tray():
                # 托盘不可用 → 退化为普通启动：显示主窗口，让监控
                # 进程在没有托盘的环境（缺 pystray / Pillow / Linux
                # 无系统托盘等）下也能继续运行。 之前 _ensure_tray
                # 失败时会直接 destroy 窗口，开机自启场景表现为程序
                # "启动一下就没了"。
                app.deiconify()
        except Exception:
            # withdraw / deiconify 不应抛错，但兜底一次 -- 防止异常
            # 路径让窗口处于隐藏却无入口的状态。
            try: app.deiconify()
            except Exception: pass

    app.mainloop()

    # ── 优雅退出：确保 DataStore 正常关闭 ──────────────────────────
    # _on_close() 里已调 flush()（同步等待数据写入），但没有调 conn.close()。
    # shutdown() 补上 conn.close() + WAL checkpoint，并让写线程干净退出。
    # 此时写线程仍活着（daemon 线程在进程退出才被杀），可以正常处理消息。
    try:
        data_store.shutdown()
    except Exception:
        pass


if __name__ == "__main__":
    main()
