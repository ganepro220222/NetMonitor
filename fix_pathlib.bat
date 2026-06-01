@echo off
chcp 65001 >nul

:: Self-elevate: if not already admin, relaunch with UAC prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    exit /b
)

echo.
echo  Running as Administrator - removing pathlib backport...
echo.

:: Find python in common locations
set PYTHON=python
C:\ProgramData\Anaconda3\python.exe --version >nul 2>&1
if %errorlevel% equ 0 set PYTHON=C:\ProgramData\Anaconda3\python.exe

%PYTHON% -m pip uninstall pathlib -y
if %errorlevel% equ 0 (
    echo.
    echo  Done! pathlib has been removed.
    echo  You can now run build.bat normally.
) else (
    echo.
    echo  pip uninstall returned an error (pathlib may already be gone).
    echo  Try running build.bat - it may work now.
)
echo.
pause
