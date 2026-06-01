"""
utils_autostart.py
------------------
Windows 开机自启管理。通过写入注册表 HKCU Run 键实现。
- 无需管理员权限（HKCU 当前用户键）
- 打包 exe 模式：直接使用 exe 路径
- 源码运行模式：使用 pythonw.exe + 脚本路径（不弹控制台）
- 启动参数 --minimized：程序启动后直接进托盘，不显示主窗口
"""
import sys
import os

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_NAME = "NetworkMonitor"


def _get_run_cmd() -> str:
    """返回注册表里要写入的启动命令字符串。"""
    if getattr(sys, "frozen", False):
        # PyInstaller 打包后：直接调用 exe
        exe = sys.executable
        return f'"{exe}" --minimized'
    else:
        # Build the pythonw.exe path from the interpreter directory rather
        # than using str.replace(), which would corrupt any path containing
        # "python.exe" as a directory component.
        py_dir = os.path.dirname(sys.executable)
        py = os.path.join(py_dir, "pythonw.exe")
        if not os.path.isfile(py):   # fallback: pythonw absent (some venvs)
            py = sys.executable
        script = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "main.py"))
        return f'"{py}" "{script}" --minimized'


def set_autostart(enabled: bool) -> None:
    """
    enabled=True  → 写入注册表，开机自启
    enabled=False → 删除注册表键，取消自启
    在非 Windows 系统上静默忽略。
    """
    if sys.platform != "win32":
        return
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH,
                            0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, REG_NAME, 0, winreg.REG_SZ, _get_run_cmd())
            else:
                try:
                    winreg.DeleteValue(key, REG_NAME)
                except FileNotFoundError:
                    pass  # 键不存在时忽略
    except Exception as e:
        raise RuntimeError(f"写注册表失败: {e}") from e


def is_autostart_enabled() -> bool:
    """检查当前是否已设置开机自启。"""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH,
                            0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, REG_NAME)
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False
