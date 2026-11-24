@echo off
chcp 65001 >nul
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 ip_probe.py --serve --open
) else (
    python ip_probe.py --serve --open
)

if errorlevel 1 (
    echo.
    echo 启动失败：请确认已安装 Python 3.9+，并已加入 PATH。
    pause
)
