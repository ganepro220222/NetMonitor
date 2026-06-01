@echo off
cd /d "%~dp0"
title Network Monitor - Build

echo.
echo  =====================================================
echo   Network Monitor -- PyInstaller Build Script
echo  =====================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found in PATH.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  Python: %%v

echo.
echo  [1/4] Using .venv Python to ensure clean isolated build...
set VENV_PY=.venv\Scripts\python.exe

if not exist "%VENV_PY%" (
    echo  [ERROR] .venv not found. Run setup.bat first.
    pause
    exit /b 1
)

%VENV_PY% -m pip install pyinstaller --quiet

echo  [2/4] Checking environment...
%VENV_PY% check_build_env.py
if errorlevel 1 (
    echo.
    pause
    exit /b 1
)

echo  [3/4] Generating icon and cleaning old build...
%VENV_PY% -c "from src.icon_generator import ensure_icon; ensure_icon()" 2>nul
if exist "build" rmdir /s /q "build"
if exist "dist"  rmdir /s /q "dist"

echo  [4/4] Building... (2-5 minutes)
echo.
%VENV_PY% -m PyInstaller build_exe.spec --clean --noconfirm
if errorlevel 1 (
    echo.
    echo  [ERROR] Build failed. See messages above.
    pause
    exit /b 1
)

echo.
echo  =====================================================
echo   SUCCESS!  dist\NetMonitor\NetMonitor.exe
echo  =====================================================
echo.
pause
