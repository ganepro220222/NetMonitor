# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec — 网络连通性监测
构建方式：在项目根目录运行 build.bat 或 pyinstaller build_exe.spec --clean
输出：dist/网络连通性监测/ 文件夹（onedir，启动快，路径干净）
"""
import sys, os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_all

block_cipher = None

# ── 数据文件 ────────────────────────────────────────────────────────────
datas = [
    # 应用图标 + 告警音效
    ('assets', 'assets'),
]

# customtkinter 内置了主题和图片资源，必须打包进去
try:
    datas += collect_data_files('customtkinter')
except Exception as e:
    print(f'[WARN] collect_data_files(customtkinter) failed: {e}')

# collect_all 同时收集模块代码、数据文件和二进制（PyInstaller 官方推荐方式）
# 比单独用 collect_data_files + collect_submodules 更完整可靠
try:
    flask_all = collect_all('flask')
    datas    += flask_all[0]
    hiddenimports_flask = flask_all[2]   # 稍后合并进 hiddenimports
except Exception as e:
    print(f'[WARN] collect_all(flask) failed: {e}')
    hiddenimports_flask = []
try:
    wz_all = collect_all('werkzeug')
    datas  += wz_all[0]
    hiddenimports_wz = wz_all[2]
except Exception as e:
    print(f'[WARN] collect_all(werkzeug) failed: {e}')
    hiddenimports_wz = []

# dnspython（DNS 高级诊断使用，纯 Python 包；collect_all 拿到所有子模块）
try:
    dns_all = collect_all('dns')
    datas  += dns_all[0]
    hiddenimports_dns = dns_all[2]
except Exception as e:
    print(f'[WARN] collect_all(dns) failed: {e}')
    hiddenimports_dns = []

# Phase 3C-5 — cryptography (DNSSEC modern-algorithm support).
# dnspython delegates ECDSA / Ed25519 / RSASHA256 verification to
# python-cryptography; without these binaries on disk the DNSSEC mode
# would raise UnsupportedAlgorithm at import time for every signed zone.
# collect_all pulls the bundled .pyd / .dll bindings that PyInstaller's
# static analysis otherwise misses.
try:
    crypto_all = collect_all('cryptography')
    datas    += crypto_all[0]
    hiddenimports_crypto = crypto_all[2]
except Exception as e:
    print(f'[WARN] collect_all(cryptography) failed: {e}')
    hiddenimports_crypto = []

# ── 隐式导入（PyInstaller 静态分析找不到的） ──────────────────────────
hiddenimports = [
    # Web 服务（collect_submodules 确保 werkzeug/flask 所有子模块都打进去）
    'flask', 'flask.json', 'flask.logging', 'flask.templating', 'flask.wrappers',
    'werkzeug', 'werkzeug.routing', 'werkzeug.serving', 'werkzeug.utils',
    'werkzeug.wrappers', 'werkzeug.middleware', 'werkzeug.exceptions',
    'werkzeug.sansio', 'werkzeug.datastructures',
    'jinja2', 'jinja2.ext',
    # Flask/Werkzeug submodules collected via collect_all above
    *hiddenimports_flask,
    *hiddenimports_wz,
    # dnspython（DNS 诊断）
    'dns', 'dns.resolver', 'dns.rdatatype', 'dns.rdataclass',
    'dns.exception', 'dns.name', 'dns.message', 'dns.flags',
    'dns.rcode', 'dns.rdata', 'dns.rdtypes', 'dns.rdtypes.ANY',
    'dns.rdtypes.IN',
    # Phase 3C-5 — dns.dnssec is loaded on demand by run_dnssec_validate;
    # PyInstaller's static analysis can't follow the deferred import so
    # we list it explicitly alongside its rrset/rrsig dependencies.
    'dns.dnssec', 'dns.rrset', 'dns.query',
    *hiddenimports_dns,
    # Phase 3C-5 — python-cryptography (needed by dns.dnssec.validate
    # for ECDSA / Ed25519 / RSASHA256 algorithms).  hazmat.primitives is
    # the public-key path; backends.openssl is the actual implementation.
    'cryptography', 'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.asymmetric',
    'cryptography.hazmat.primitives.serialization',
    'cryptography.hazmat.backends', 'cryptography.hazmat.backends.openssl',
    *hiddenimports_crypto,
    # UI
    'customtkinter',
    'PIL', 'PIL.Image', 'PIL.ImageTk', 'PIL.ImageDraw',
    'PIL._tkinter_finder',
    # 系统托盘（Windows 后端）
    'pystray', 'pystray._win32',
    # 图表
    'matplotlib', 'matplotlib.backends.backend_tkagg',
    'matplotlib.backends._backend_tk',
    # 数据 / 导出
    'sqlite3', '_sqlite3',
    'openpyxl', 'openpyxl.cell._writer', 'openpyxl.styles.stylesheet',
    # 杂项（winsound 是 Windows 内置模块，不需要在此声明）
    'pkg_resources',
]

# ── Analysis ────────────────────────────────────────────────────────────
a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 只排除确认不会被任何依赖导入的模块
    # 绝不排除 email/html.parser/difflib 等 — pkg_resources/Flask/werkzeug 依赖它们
    excludes=[
        'tkinter.test',   # tkinter 测试代码
        'turtle',         # 海龟绘图
        'turtledemo',     # 海龟演示
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── EXE（不含数据，由 COLLECT 统一放到目录里）────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,     # onedir 模式：二进制单独放
    name='NetMonitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,             # 不显示黑色控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets\\icon.ico',   # Windows 任务栏图标（需先运行程序生成 ico）
)

# ── COLLECT：把 exe + 依赖 + 数据合并到一个目录 ──────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetMonitor',         # → dist/NetMonitor/
)
