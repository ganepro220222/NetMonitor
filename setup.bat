@echo off
echo ============================================================
echo  网络连通性监测 - 环境初始化
echo ============================================================
echo.

REM 检查 Python 是否安装
python --version > nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.8 或更高版本。
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] 创建虚拟环境...
python -m venv .venv
if errorlevel 1 (
    echo [错误] 创建虚拟环境失败。
    pause
    exit /b 1
)

echo [2/3] 安装依赖包，需要联网，仅首次...
.venv\Scripts\pip install -r requirements.txt -q

if errorlevel 1 (
    echo [错误] 安装依赖失败，请检查网络连接。
    pause
    exit /b 1
)

echo [3/3] 写入启动脚本...

REM 生成 start.bat，用户以后双击它启动程序
(
echo @echo off
echo cd /d "%%~dp0"
echo .venv\Scripts\python.exe main.py
echo if errorlevel 1 pause
) > start.bat

echo.
echo ============================================================
echo  初始化完成！以后直接双击 start.bat 即可启动程序。
echo ============================================================
echo.
pause
