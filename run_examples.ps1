# 在目标 Windows 机上的示例（管理员 PowerShell 推荐）
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$exe = Join-Path $root "dist\kk-appstate-probe.exe"
if (Test-Path $exe) {
    function Invoke-Probe { param([Parameter(ValueFromRemainingArguments=$true)]$Args) & $exe @Args }
} else {
    function Invoke-Probe { param([Parameter(ValueFromRemainingArguments=$true)]$Args) & python (Join-Path $root "appstate_probe.py") @Args }
}

$users = Join-Path $env:LOCALAPPDATA "Kakao\KakaoTalk\users"
$app = Get-ChildItem -Path $users -Filter "appstate.dat" -Recurse -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 1

if (-not $app) {
    Write-Host "未找到 appstate.dat，请确认已安装并登录 KakaoTalk"
    exit 2
}

Write-Host "使用: $($app.FullName)  size=$($app.Length)"
Write-Host ""
Write-Host "=== inspect ==="
Invoke-Probe inspect --appstate $app.FullName

Write-Host ""
Write-Host "=== find-root（可能较久，请保持 KakaoTalk 登录）==="
$out = Join-Path $env:USERPROFILE "Desktop\kk-root-key.json"
Invoke-Probe find-root --appstate $app.FullName --out $out
Write-Host "结果: $out"
