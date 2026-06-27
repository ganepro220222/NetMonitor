@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo  First run: please execute setup.bat once.
    echo.
    pause
    exit /b 1
)

echo [NetMonitor] Checking geo database...
.venv\Scripts\python.exe scripts\download_ip2region.py --quiet
if errorlevel 1 (
    echo [WARN] Geo DB not ready - map auto-geo limited until download succeeds.
)

.venv\Scripts\python.exe main.py
if errorlevel 1 pause
