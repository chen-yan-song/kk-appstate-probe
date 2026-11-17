# 用 kk-collect / SDK 已解出的 DEK 缩小找 R 的范围
# 用法：与 kk-appstate-probe.exe 放同一目录，管理员 PowerShell 运行
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $here "kk-appstate-probe.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path (Get-Location) "kk-appstate-probe.exe" }
if (-not (Test-Path $exe)) { throw "找不到 kk-appstate-probe.exe" }

Write-Host "=== 查找 win-key-cache.json ==="
$caches = @()
$roots = @(
  $env:RUYILING_STATE_DIR,
  (Join-Path $env:APPDATA "RuyiLing"),
  (Join-Path $env:APPDATA "ruyiling"),
  (Join-Path $env:LOCALAPPDATA "RuyiLing"),
  (Join-Path $env:LOCALAPPDATA "ruyiling"),
  (Join-Path $env:USERPROFILE ".kakao-edb-sdk"),
  (Join-Path $env:USERPROFILE "AppData\Roaming"),
  (Join-Path $env:USERPROFILE "AppData\Local")
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($r in $roots) {
  $caches += Get-ChildItem -Path $r -Recurse -Filter "win-key-cache.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
}
$caches = $caches | Sort-Object LastWriteTime -Descending | Select-Object -Unique -First 10
if (-not $caches -or $caches.Count -eq 0) {
  Write-Host "未找到 win-key-cache.json。请确认 kk-collect 曾成功解过至少一间房。"
  Write-Host "也可手动: kk-appstate-probe.exe find-root --appstate <path> --known-keys <json>"
  exit 2
}

Write-Host "候选缓存:"
$caches | ForEach-Object { Write-Host ("  {0}  size={1}  time={2}" -f $_.FullName, $_.Length, $_.LastWriteTime) }
$cache = $caches[0]
Write-Host "使用: $($cache.FullName)"

# 规范化成 probe 能吃的 keys 映射
$raw = Get-Content $cache.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$map = @{}
if ($raw.byName) {
  $raw.byName.PSObject.Properties | ForEach-Object { $map[$_.Name] = [string]$_.Value }
} elseif ($raw.keys) {
  $raw.keys.PSObject.Properties | ForEach-Object { $map[$_.Name] = [string]$_.Value }
} else {
  $raw.PSObject.Properties | ForEach-Object {
    $v = [string]$_.Value
    if ($v -match '^[0-9a-fA-F]{64}$') { $map[$_.Name] = $v }
  }
}
if ($map.Count -lt 1) { throw "缓存里没有 64 位 hex 密钥" }

$norm = Join-Path $env:TEMP "kk-known-keys.json"
$payload = @{ keys = @{} }
foreach ($k in $map.Keys) {
  $name = $k
  if ($name -notmatch '\\' -and $name -match 'chatLogs_') {
    $name = "chat_data\$name"
  }
  $payload.keys[$name] = $map[$k]
}
($payload | ConvertTo-Json -Depth 5) | Set-Content -Path $norm -Encoding UTF8
Write-Host "规范化密钥条数: $($payload.keys.Count) -> $norm"

$app = Get-ChildItem "$env:LOCALAPPDATA\Kakao\KakaoTalk\users\*\appstate.dat" |
  Sort-Object Length -Descending | Select-Object -First 1
if (-not $app) { throw "未找到 appstate.dat" }
Write-Host "appstate: $($app.FullName) size=$($app.Length)"

Write-Host ""
Write-Host "=== 请先在 KakaoTalk 打开缓存里对应的几个聊天室，再继续 ==="
Write-Host "5 秒后开始 find-root（Ctrl+C 可取消）…"
Start-Sleep -Seconds 5

$out = Join-Path $env:USERPROFILE "Desktop\kk-root-key.json"
& $exe find-root `
  --appstate $app.FullName `
  --known-keys $norm `
  --known-only `
  --near-radius 8388608 `
  --out $out
Write-Host "结果: $out"
pause
