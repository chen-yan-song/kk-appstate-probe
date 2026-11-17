# 最小结构验证：不装 Python，只确认 appstate 仍是 v2 keystore
$users = Join-Path $env:LOCALAPPDATA "Kakao\KakaoTalk\users"
$f = Get-ChildItem $users -Recurse -Filter appstate.dat | Sort-Object Length -Descending | Select-Object -First 1
if (-not $f) { Write-Host "未找到 appstate.dat"; exit 2 }
$b = [IO.File]::ReadAllBytes($f.FullName)
$head = ($b[0..([Math]::Min(80,$b.Length-1))] | ForEach-Object { '{0:x2}' -f $_ }) -join ''
$ascii = -join ($b[0..([Math]::Min(200,$b.Length-1))] | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
Write-Host "file=$($f.FullName)"
Write-Host "size=$($b.Length)"
Write-Host "headHex=$head"
Write-Host "ascii=$ascii"
if ($ascii -match 'info_prefix' -and $ascii -match 'v2:') {
  Write-Host "RESULT=COMPAT_LIKELY (含 info_prefix + v2:)"
} elseif ($ascii -match 'info_prefix') {
  Write-Host "RESULT=HAS_INFO_PREFIX (再确认前缀是 v1:/v2:)"
} else {
  Write-Host "RESULT=UNKNOWN"
}
