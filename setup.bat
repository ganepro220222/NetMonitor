@echo off
cd /d "%~dp0"
title Network Monitor - First-time Setup
echo.
echo  =====================================================
echo   NetMonitor first-time setup (run once)
echo  =====================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python 3.8+ not found in PATH.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo  [1/4] Creating virtualenv .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtualenv.
        pause
        exit /b 1
    )
) else (
    echo  [1/4] Virtualenv exists, skip.
)

echo  [2/4] Installing dependencies ...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo  [ERROR] pip install failed.
    pause
    exit /b 1
)

echo  [3/4] Downloading ip2region_v4.xdb (~11MB, needs network) ...
.venv\Scripts\python.exe scripts\download_ip2region.py
if errorlevel 1 (
    echo  [WARN] Geo DB download failed - app works but map auto-geo is limited.
    echo         Re-run setup.bat or start.bat when online.
)

echo  [4/5] Generating icon ...
.venv\Scripts\python.exe -c "from src.icon_generator import ensure_icon; ensure_icon()"

echo  [5/5] Writing start.bat ...
(
echo @echo off
echo cd /d "%%~dp0"
echo.
echo if not exist ".venv\Scripts\python.exe" ^(
echo     echo.
echo     echo  First run: please execute setup.bat once.
echo     echo.
echo     pause
echo     exit /b 1
echo ^)
echo.
echo echo [NetMonitor] Checking geo database...
echo .venv\Scripts\python.exe scripts\download_ip2region.py --quiet
echo if errorlevel 1 ^(
echo     echo [WARN] Geo DB not ready - map auto-geo limited until download succeeds.
echo ^)
echo.
echo .venv\Scripts\python.exe main.py
echo if errorlevel 1 pause
) > start.bat

echo.
echo  =====================================================
echo   Done. Double-click start.bat to launch.
echo  =====================================================
echo.
pause
