"""
check_build_env.py — 打包前环境检查
由 build.bat 调用。所有复杂逻辑在 Python 里处理，避免 CMD 语法陷阱。
返回 0 = 环境 OK；非 0 = 有问题，已打印说明。
"""
import sys, subprocess

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr

def check_pathlib():
    """pathlib 回退包和 PyInstaller 不兼容，必须移除。"""
    try:
        import pkg_resources
        pkg_resources.get_distribution('pathlib')
    except Exception:
        return True  # 不存在，OK

    # 存在，尝试移除
    print("  Found incompatible 'pathlib' package. Removing...")
    ok, _ = run([sys.executable, '-m', 'pip', 'uninstall', 'pathlib', '-y'])
    try:
        import pkg_resources
        pkg_resources.get_distribution('pathlib')
        # 还在，权限不够
        print()
        print("  [ACTION REQUIRED]")
        print("  Cannot remove 'pathlib' automatically (needs admin rights).")
        print()
        print("  Please double-click fix_pathlib.bat first.")
        print("  It will ask for administrator permission - click YES.")
        print("  Then run build.bat again.")
        return False
    except Exception:
        print("  pathlib removed OK.")
        return True

def check_pyinstaller():
    """确认 PyInstaller 已安装。"""
    try:
        import PyInstaller
        return True
    except ImportError:
        print()
        print("  [ERROR] PyInstaller not found.")
        print("  Run:  python -m pip install --user pyinstaller")
        return False

if __name__ == '__main__':
    print("  Checking environment...")
    if not check_pathlib():
        sys.exit(1)
    if not check_pyinstaller():
        sys.exit(2)
    print("  Environment OK.")
    sys.exit(0)
