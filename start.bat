@echo off
setlocal
cd /d "%~dp0"

set "PYTHON="
where python >nul 2>nul
if not errorlevel 1 set "PYTHON=python"
if not defined PYTHON (
    where py >nul 2>nul
    if not errorlevel 1 set "PYTHON=py -3"
)
if not defined PYTHON (
    echo.
    echo Python 3.9+ was not found in PATH.
    echo Install Python from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo.
echo Starting IP Probe web panel...
echo URL: http://127.0.0.1:8848/
echo Press Ctrl+C to stop the server.
echo.
%PYTHON% -u ip_probe.py --serve --open
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" echo IP Probe exited with code %RC%.
echo Press any key to close this window.
pause >nul
exit /b %RC%