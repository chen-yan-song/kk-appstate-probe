@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === kk-appstate-probe inspect ===
kk-appstate-probe.exe inspect
echo.
pause
