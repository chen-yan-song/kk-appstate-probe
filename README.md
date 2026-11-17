# kk-appstate-probe

KakaoTalk Windows `appstate.dat` **临时验证**工具（独立项目，不依赖 kk-collect）。

目标：在员工 Windows 机上验证「一次拿到运行时根钥 `R` → 批量解出全部房间 DEK」是否成立（针对 26.9.2.5342 等仍使用 v2 keystore 的版本）。

## 能力

| 命令 | 作用 |
|------|------|
| `inspect` | 解析 `appstate.dat`，确认 `info_prefix` / `salt(32)` / `wrap(40)` |
| `find-root` | 读取 KakaoTalk 进程内存，搜索能通过 AES-KW ICV 的 32 字节 `R` |
| `unwrap` | 给定 `R`，批量解出全部 DEK，写出 JSON |
| `selftest` | 本地合成数据自检（AES-KW / 路径敏感性） |

## 在 Windows 上打包成 exe

1. 把整个 `kk-appstate-probe` 文件夹拷到一台有 Python 3.10+ 的 Windows 机  
2. 双击或在 cmd 中运行：

```bat
build_windows.bat
```

3. 产物：`dist\kk-appstate-probe.exe`（目标机无需再装 Python）

> 也可不打包，直接：`python appstate_probe.py …`

## 目标机用法（建议顺序）

先登录 KakaoTalk 并保持运行。**建议以管理员身份**打开终端。

### 1) 检查 keystore 结构

```bat
kk-appstate-probe.exe inspect
```

或指定文件：

```bat
kk-appstate-probe.exe inspect --appstate "%LOCALAPPDATA%\Kakao\KakaoTalk\users\<账号目录>\appstate.dat"
```

看到 `COMPAT` 且 `prefix='v2:'`（或某个号是 `v1:`）即可。

### 2) 搜索根钥 R

```bat
kk-appstate-probe.exe find-root --appstate "%LOCALAPPDATA%\Kakao\KakaoTalk\users\<账号目录>\appstate.dat" --out kk-root-key.json
```

若已有某房间 DEK（来自现有 memscan 缓存），强烈建议带上，会先扫 DEK 附近内存，快很多：

```bat
kk-appstate-probe.exe find-root --appstate "...\appstate.dat" --known-dek "chat_data\chatLogs_123.edb=<64位hex>" --out kk-root-key.json
```

成功时会打印 `R = …` 并写出 `kk-root-key.json`。

### 3) 批量解包 DEK

```bat
kk-appstate-probe.exe unwrap --appstate "...\appstate.dat" --root <上一步的64位hex> --out kk-unwrapped-keys.json
```

可选：对磁盘上的 `chatLogs_*.edb` 做页头弱校验：

```bat
kk-appstate-probe.exe unwrap --appstate "...\appstate.dat" --root <hex> --verify-edb "%LOCALAPPDATA%\Kakao\KakaoTalk\users\<账号目录>"
```

## 离线（Mac）快速检查样本

```bash
python3 appstate_probe.py selftest
python3 appstate_probe.py inspect --sample-dir /path/to/kk-appstate-xxxx
```

## 说明与限制

- `profile.dat` 解出的「文件根」按公开研究是 **Stray Root**，一般**不能**解当前 `appstate`；本工具以内存中的运行时 `R` 为准。
- `find-root` 全量扫描可能较慢（私有可写内存可达数百 MB～1GB+）；有 `--known-dek` 时优先邻域扫描。
- 杀软可能拦截 `ReadProcessMemory`，需加白或临时关闭。
- 本仓库仅作临时验证，验证成功后再考虑并入 `kakao-edb-sdk-py`。

## 公式摘要

```
PRK = HMAC-SHA256(salt, R)
info = info_prefix || relpath_raw   # 反斜杠原样保留
KEK = HKDF-Expand-SHA256(PRK, info, 32)
DEK = AES-KW-Unwrap(KEK, wrapped40)
```
