@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================================
echo   kk-appstate-probe.exe  一键打包（Windows）
echo   KakaoTalk appstate 根钥 / DEK 临时验证工具
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [X] 未找到 python。请安装 Python 3.10+ 并勾选 Add to PATH。
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [i] %%v

echo.
echo [1/3] 安装 PyInstaller + cryptography（加速 find-root）...
python -m pip install -U pip pyinstaller cryptography
if errorlevel 1 (
    echo [X] pip 安装失败
    pause
    exit /b 1
)

echo.
echo [2/3] 本地自检 ...
python appstate_probe.py selftest
if errorlevel 1 (
    echo [X] selftest 失败，中止打包
    pause
    exit /b 1
)

echo.
echo [3/3] PyInstaller 打包 onefile ...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
python -m PyInstaller --noconfirm --clean --onefile --console --name kk-appstate-probe ^
  --hidden-import cryptography.hazmat.primitives.keywrap ^
  appstate_probe.py
if errorlevel 1 (
    echo [X] 打包失败
    pause
    exit /b 1
)

echo.
echo ============================================================
if exist "dist\kk-appstate-probe.exe" (
    echo   [OK] 产物: %cd%\dist\kk-appstate-probe.exe
    echo.
    echo   拷到目标机后示例:
    echo     kk-appstate-probe.exe inspect
    echo     kk-appstate-probe.exe find-root --appstate "%%LOCALAPPDATA%%\Kakao\KakaoTalk\users\^<id^>\appstate.dat"
    echo     kk-appstate-probe.exe unwrap --appstate "...\appstate.dat" --root ^<64hex^>
) else (
    echo   [X] 未找到 dist\kk-appstate-probe.exe
)
echo ============================================================
pause
endlocal
