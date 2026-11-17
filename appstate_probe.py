#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kk-appstate-probe — KakaoTalk Windows appstate.dat 临时验证工具

用途（独立于 kk-collect / kakao-edb-sdk-py）：
  1) inspect   解析 appstate.dat，确认 v1/v2 keystore 结构
  2) unwrap    给定 32 字节运行时根钥 R，批量 AES-KW 解出全部 DEK
  3) find-root 在 KakaoTalk 进程内存中搜索能解包 appstate 的 R

公式（公开逆向，针对 v2 keystore）：
  PRK  = HMAC-SHA256(salt, R)          # key=salt, msg=R
  info = info_prefix || relpath_raw    # 路径反斜杠原样保留
  KEK  = HKDF-Expand-SHA256(PRK, info, 32)
  DEK  = AES-KW-Unwrap(KEK, wrapped40)

目标机：Windows（find-root 需管理员/同用户读进程内存）
打包：build_windows.bat → dist\\kk-appstate-probe.exe
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

__version__ = "0.1.2"

# 供 PyInstaller 收集（运行时仍可回退纯 Python）
try:
    import cryptography.hazmat.primitives.keywrap as _pyi_kw  # noqa: F401
except Exception:
    _pyi_kw = None  # type: ignore

# ---------------------------------------------------------------------------
# 工具输出
# ---------------------------------------------------------------------------

def _ensure_utf8_stdio() -> None:
    """Windows CI/控制台默认可能是 charmap，避免中文输出炸掉。"""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_ensure_utf8_stdio()


def _print(*args, **kwargs) -> None:
    kwargs.setdefault("flush", True)
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        kwargs.pop("file", None)
        sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))
        sys.stdout.buffer.flush()


def _eprint(*args, **kwargs) -> None:
    kwargs.setdefault("flush", True)
    try:
        print(*args, file=sys.stderr, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        sys.stderr.buffer.write((text + "\n").encode("utf-8", errors="replace"))
        sys.stderr.buffer.flush()


# ---------------------------------------------------------------------------
# 轻量 CBOR（仅支持本工具需要的整数/字节/文本/数组/映射）
# ---------------------------------------------------------------------------

def _cbor_decode(data: bytes, i: int = 0):
    def take(n: int) -> bytes:
        nonlocal i
        if i + n > len(data):
            raise ValueError("CBOR 截断")
        b = data[i : i + n]
        i += n
        return b

    if i >= len(data):
        raise ValueError("CBOR 空输入")
    ai = data[i]
    i += 1
    major, add = ai >> 5, ai & 31

    def arg() -> int:
        nonlocal i, add
        if add < 24:
            return add
        if add == 24:
            return take(1)[0]
        if add == 25:
            return int.from_bytes(take(2), "big")
        if add == 26:
            return int.from_bytes(take(4), "big")
        if add == 27:
            return int.from_bytes(take(8), "big")
        raise ValueError(f"不支持的 CBOR 附加值 add={add}")

    if major == 0:
        return arg(), i
    if major == 1:
        return -1 - arg(), i
    if major == 2:
        n = arg()
        return take(n), i
    if major == 3:
        n = arg()
        return take(n).decode("utf-8"), i
    if major == 4:
        n = arg()
        out = []
        for _ in range(n):
            v, i = _cbor_decode(data, i)
            out.append(v)
        return out, i
    if major == 5:
        n = arg()
        out = {}
        for _ in range(n):
            k, i = _cbor_decode(data, i)
            v, i = _cbor_decode(data, i)
            if isinstance(k, list):
                # 整数数组形式的 key → 用 bytes 作为映射键
                k = ("_bytes", bytes(k))
            elif isinstance(k, bytearray):
                k = bytes(k)
            out[k] = v
        return out, i
    if major == 7:
        if add == 20:
            return False, i
        if add == 21:
            return True, i
        if add == 22:
            return None, i
    raise ValueError(f"不支持的 CBOR major={major} add={add} @ {i - 1}")


def _as_bytes(v) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, tuple) and len(v) == 2 and v[0] == "_bytes":
        return bytes(v[1])
    if isinstance(v, list) and all(isinstance(x, int) and 0 <= x < 256 for x in v):
        return bytes(v)
    raise TypeError(f"无法转为字节: {type(v).__name__}")


def _as_text(v) -> str:
    b = _as_bytes(v)
    return b.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# AES-256-ECB + RFC 3394 AES Key Wrap（纯 Python，无第三方依赖）
# ---------------------------------------------------------------------------

_SBOX = bytes(
    [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]
)
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _aes_expand_key(key: bytes) -> list[list[int]]:
    key_len = len(key)
    if key_len not in (16, 24, 32):
        raise ValueError("AES 密钥长度必须是 16/24/32")
    nk = key_len // 4
    nr = {16: 10, 24: 12, 32: 14}[key_len]
    w = [list(key[i : i + 4]) for i in range(0, key_len, 4)]
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1][:]
        if i % nk == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    # 轮密钥按 16 字节分组
    rounds = []
    for r in range(nr + 1):
        block = []
        for c in range(4):
            block.extend(w[r * 4 + c])
        rounds.append(block)
    return rounds


def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = list(block)
    rk0 = round_keys[0]
    for i in range(16):
        state[i] ^= rk0[i]
    nr = len(round_keys) - 1
    for rnd in range(1, nr + 1):
        # SubBytes + ShiftRows
        s = [_SBOX[b] for b in state]
        state = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        if rnd != nr:
            # MixColumns
            mixed = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = state[4 * c : 4 * c + 4]
                mixed[4 * c] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
                mixed[4 * c + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
                mixed[4 * c + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
                mixed[4 * c + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
            state = mixed
        rk = round_keys[rnd]
        for i in range(16):
            state[i] ^= rk[i]
    return bytes(state)


_DEFAULT_IV = b"\xa6" * 8

_INV_SBOX = bytes([_SBOX.index(i) for i in range(256)])


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = list(block)
    nr = len(round_keys) - 1
    rk = round_keys[nr]
    for i in range(16):
        state[i] ^= rk[i]
    for rnd in range(nr - 1, -1, -1):
        # InvShiftRows + InvSubBytes
        s = state
        state = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        state = [_INV_SBOX[b] for b in state]
        rk = round_keys[rnd]
        for i in range(16):
            state[i] ^= rk[i]
        if rnd != 0:
            mixed = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = state[4 * c : 4 * c + 4]
                mixed[4 * c] = _mul(a0, 0x0E) ^ _mul(a1, 0x0B) ^ _mul(a2, 0x0D) ^ _mul(a3, 0x09)
                mixed[4 * c + 1] = _mul(a0, 0x09) ^ _mul(a1, 0x0E) ^ _mul(a2, 0x0B) ^ _mul(a3, 0x0D)
                mixed[4 * c + 2] = _mul(a0, 0x0D) ^ _mul(a1, 0x09) ^ _mul(a2, 0x0E) ^ _mul(a3, 0x0B)
                mixed[4 * c + 3] = _mul(a0, 0x0B) ^ _mul(a1, 0x0D) ^ _mul(a2, 0x09) ^ _mul(a3, 0x0E)
            state = mixed
    return bytes(state)


class _Aes:
    def __init__(self, key: bytes):
        self._rk = _aes_expand_key(key)

    def encrypt(self, block: bytes) -> bytes:
        return _aes_encrypt_block(block, self._rk)

    def decrypt(self, block: bytes) -> bytes:
        return _aes_decrypt_block(block, self._rk)


def _aes_kw_unwrap_pure(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES-KW Unwrap（纯 Python）。ICV 不匹配时抛 ValueError。"""
    if len(wrapped) < 24 or len(wrapped) % 8 != 0:
        raise ValueError("wrapped 长度非法")
    n = (len(wrapped) // 8) - 1
    a = wrapped[:8]
    r = [wrapped[8 + 8 * i : 16 + 8 * i] for i in range(n)]
    aes = _Aes(kek)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = n * j + i
            block = bytes(x ^ y for x, y in zip(a, t.to_bytes(8, "big"))) + r[i - 1]
            pt = aes.decrypt(block)
            a = pt[:8]
            r[i - 1] = pt[8:]
    if a != _DEFAULT_IV:
        raise ValueError("AES-KW ICV 校验失败")
    return b"".join(r)


def _aes_kw_wrap_pure(kek: bytes, plain: bytes) -> bytes:
    """RFC 3394 AES-KW Wrap（纯 Python，自测用）。"""
    if len(plain) < 16 or len(plain) % 8 != 0:
        raise ValueError("明文长度非法")
    n = len(plain) // 8
    a = _DEFAULT_IV
    r = [plain[8 * i : 8 * i + 8] for i in range(n)]
    aes = _Aes(kek)
    for j in range(6):
        for i in range(1, n + 1):
            block = a + r[i - 1]
            ct = aes.encrypt(block)
            t = n * j + i
            a = bytes(x ^ y for x, y in zip(ct[:8], t.to_bytes(8, "big")))
            r[i - 1] = ct[8:]
    return a + b"".join(r)


_CRYPTOGRAPHY_KW = None  # type: ignore


def _try_load_cryptography_kw():
    global _CRYPTOGRAPHY_KW
    if _CRYPTOGRAPHY_KW is not None:
        return _CRYPTOGRAPHY_KW
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

        _CRYPTOGRAPHY_KW = (aes_key_unwrap, aes_key_wrap)
    except Exception:
        _CRYPTOGRAPHY_KW = False
    return _CRYPTOGRAPHY_KW


def aes_kw_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    fast = _try_load_cryptography_kw()
    if fast:
        try:
            return fast[0](kek, wrapped)
        except Exception as e:
            raise ValueError(str(e)) from e
    return _aes_kw_unwrap_pure(kek, wrapped)


def aes_kw_wrap(kek: bytes, plain: bytes) -> bytes:
    fast = _try_load_cryptography_kw()
    if fast:
        return fast[1](kek, plain)
    return _aes_kw_wrap_pure(kek, plain)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Expand（Hash=SHA-256）。"""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("HKDF 输出过长")
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_kek(root_key: bytes, salt: bytes, info_prefix: bytes, relpath: bytes) -> bytes:
    if len(root_key) != 32:
        raise ValueError("R 必须是 32 字节")
    if len(salt) != 32:
        raise ValueError("salt 必须是 32 字节")
    prk = hmac.new(salt, root_key, hashlib.sha256).digest()  # HMAC(key=S, msg=R)
    info = info_prefix + relpath
    return hkdf_expand_sha256(prk, info, 32)


def try_unwrap_one(
    root_key: bytes,
    salt: bytes,
    info_prefix: bytes,
    relpath: bytes,
    wrapped: bytes,
) -> bytes | None:
    try:
        kek = derive_kek(root_key, salt, info_prefix, relpath)
        return aes_kw_unwrap(kek, wrapped)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# appstate 解析
# ---------------------------------------------------------------------------

@dataclass
class WrapEntry:
    relpath: bytes  # 原始路径字节（含反斜杠）
    wrapped: bytes  # 40 字节 AES-KW


@dataclass
class AppState:
    path: Path
    info_prefix: bytes
    salt: bytes
    entries: list[WrapEntry] = field(default_factory=list)

    @property
    def chatlog_entries(self) -> list[WrapEntry]:
        return [e for e in self.entries if b"chatLogs_" in e.relpath]


def _top_key_str(k) -> str:
    if isinstance(k, str):
        return k
    if isinstance(k, (bytes, bytearray)):
        return bytes(k).decode("utf-8", errors="replace")
    if isinstance(k, tuple) and k and k[0] == "_bytes":
        return bytes(k[1]).decode("utf-8", errors="replace")
    if isinstance(k, list):
        return bytes(k).decode("utf-8", errors="replace")
    return str(k)


def parse_appstate(path: Path) -> AppState:
    raw = path.read_bytes()
    obj, _ = _cbor_decode(raw)
    if not isinstance(obj, dict):
        raise ValueError("appstate 顶层不是 CBOR map")
    top = {_top_key_str(k): v for k, v in obj.items()}
    if "info_prefix" not in top or "salt" not in top:
        raise ValueError(f"缺少字段，现有键: {sorted(top)}")
    prefix = _as_bytes(top["info_prefix"])
    salt = _as_bytes(top["salt"])
    wraw = top.get("wrapped_dek_map")
    if wraw is None:
        raise ValueError("缺少 wrapped_dek_map")
    entries: list[WrapEntry] = []
    if isinstance(wraw, dict):
        for k, v in wraw.items():
            entries.append(WrapEntry(relpath=_as_bytes(k), wrapped=_as_bytes(v)))
    elif isinstance(wraw, list):
        # 实测 26.9.2：[[path_int_arr, wrap_int_arr], ...]
        for item in wraw:
            if not (isinstance(item, list) and len(item) == 2):
                raise ValueError("wrapped_dek_map 数组元素不是二元组")
            entries.append(WrapEntry(relpath=_as_bytes(item[0]), wrapped=_as_bytes(item[1])))
    else:
        raise ValueError(f"wrapped_dek_map 类型异常: {type(wraw).__name__}")
    bad = [e for e in entries if len(e.wrapped) != 40]
    if bad:
        raise ValueError(f"存在非 40 字节 wrap: {len(bad)} 条，例 {bad[0].relpath!r} len={len(bad[0].wrapped)}")
    return AppState(path=path, info_prefix=prefix, salt=salt, entries=entries)


def default_users_root() -> Path:
    local = os.environ.get("LOCALAPPDATA") or ""
    if local:
        return Path(local) / "Kakao" / "KakaoTalk" / "users"
    return Path.home() / "AppData" / "Local" / "Kakao" / "KakaoTalk" / "users"


def discover_appstates(root: Path | None = None) -> list[Path]:
    root = root or default_users_root()
    if not root.is_dir():
        return []
    found = list(root.glob("*/appstate.dat"))
    return sorted(found, key=lambda p: p.stat().st_size, reverse=True)


# ---------------------------------------------------------------------------
# Windows 内存转储（ctypes）
# ---------------------------------------------------------------------------

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
PAGE_WRITABLE = 0x04 | 0x08 | 0x40 | 0x80


def _is_windows() -> bool:
    return os.name == "nt"


def find_kakao_pids() -> list[int]:
    if not _is_windows():
        return []
    import ctypes
    import ctypes.wintypes as wt

    pids: list[int] = []
    # 用 CreateToolhelp32Snapshot 枚举
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", wt.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return []
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(pe)):
            return []
        while True:
            name = (pe.szExeFile or "").lower()
            if name in ("kakaotalk.exe", "kakaotalk"):
                pids.append(int(pe.th32ProcessID))
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return sorted(set(pids))


def dump_process_memory(
    pid: int,
    max_bytes: int = 1536 * 1024 * 1024,
    *,
    writable_only: bool = False,
) -> bytes:
    """转储进程已提交可读内存。

    默认：私有 + 可读（含只读），因运行时根钥 R 可能不在可写堆上。
    writable_only=True 时退回旧行为（仅私有可写）。
    """
    if not _is_windows():
        raise RuntimeError("仅 Windows 支持内存转储")
    import ctypes
    import ctypes.wintypes as wt

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(f"OpenProcess({pid}) 失败，err={ctypes.get_last_error()}")
    chunks: list[bytes] = []
    total = 0
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    try:
        while total < max_bytes:
            ok = kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not ok:
                break
            base = mbi.BaseAddress or 0
            size = int(mbi.RegionSize or 0)
            if size == 0:
                break
            prot = int(mbi.Protect or 0)
            state = int(mbi.State or 0)
            typ = int(mbi.Type or 0)
            readable = (prot & PAGE_READABLE) and not (prot & PAGE_GUARD) and prot != PAGE_NOACCESS
            writable = bool(prot & PAGE_WRITABLE)
            private = typ == MEM_PRIVATE
            take = state == MEM_COMMIT and readable and private
            if take and writable_only:
                take = writable
            if take:
                remain = max_bytes - total
                to_read = min(size, remain)
                buf = (ctypes.c_char * to_read)()
                read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(base), buf, to_read, ctypes.byref(read)
                ):
                    n = int(read.value)
                    if n:
                        chunks.append(bytes(buf[:n]))
                        total += n
            nxt = base + size
            if nxt <= address:
                break
            address = nxt
    finally:
        kernel32.CloseHandle(handle)
    return b"".join(chunks)


def dump_process_private_rw(pid: int, max_bytes: int = 1536 * 1024 * 1024) -> bytes:
    """兼容旧名：仅私有可写。"""
    return dump_process_memory(pid, max_bytes=max_bytes, writable_only=True)


# ---------------------------------------------------------------------------
# SQLCipher 页头弱校验（无 sqlcipher 子进程）：解密页 1 后看保留区等字段
# ---------------------------------------------------------------------------

def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("密文长度必须是 16 的倍数")
    aes = _Aes(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        plain = bytes(x ^ y for x, y in zip(aes.decrypt(block), prev))
        out.extend(plain)
        prev = block
    return bytes(out)


def sqlcipher_page1_plausible(dek: bytes, edb_path: Path) -> bool:
    """对照论文：页大小 0x1000、保留 0x50、payload fractions。不强制 SQLite 魔数。"""
    try:
        raw = edb_path.read_bytes()
    except OSError:
        return False
    if len(raw) < 4096:
        return False
    salt = raw[:16]
    # SQLCipher 4：page1 = salt(16) + enc(page_body)；实际页 4096，末尾 80 为 IV+HMAC
    page = raw[:4096]
    # 常见实现：用 DEK 对 (page[16:-80]) 做 AES-CBC，IV 在 page[-80:-64]
    # 这里做宽松探测：多试几种布局，任一命中即算 plausible
    candidates = []
    # 布局 A：IV = 页末 80 区前 16 字节
    if len(page) >= 80:
        iv = page[-80:-64]
        body = page[16:-80]
        if len(body) % 16 == 0 and body:
            candidates.append((iv, body))
    for iv, body in candidates:
        try:
            pt = _aes_cbc_decrypt(dek, iv, body)
        except Exception:
            continue
        # 解密后应接近 SQLite 头（有的实现仍无明文魔数）；检查页大小字段
        # 明文页布局：offset0 魔数，16-17 页大小
        # 因 salt 占了前 16，解密 body 对应原页 offset16 起
        if len(pt) < 20:
            continue
        # body[0:2] == page_size at file offset 16
        page_size = struct.unpack(">H", pt[0:2])[0]
        reserved = pt[4] if len(pt) > 4 else 0
        if page_size == 4096 and reserved == 0x50:
            return True
        # 若完整含魔数（少见）
        if pt.startswith(b"SQLite format 3"):
            return True
    return False


# ---------------------------------------------------------------------------
# 命令实现
# ---------------------------------------------------------------------------

def cmd_selftest(_: argparse.Namespace) -> int:
    """本地合成数据验证 AES-KW / HKDF 管道。"""
    root = os.urandom(32)
    salt = os.urandom(32)
    prefix = b"v2:"
    path = b"chat_data\\chatLogs_123.edb"
    dek = os.urandom(32)
    kek = derive_kek(root, salt, prefix, path)
    wrapped = aes_kw_wrap(kek, dek)
    assert len(wrapped) == 40
    out = aes_kw_unwrap(kek, wrapped)
    assert out == dek
    out2 = try_unwrap_one(root, salt, prefix, path, wrapped)
    assert out2 == dek
    # 故意改路径应失败
    bad = try_unwrap_one(root, salt, prefix, b"chat_data/chatLogs_123.edb", wrapped)
    assert bad is None
    _print("[OK] selftest 通过（KW 往返 + 路径敏感）")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    paths: list[Path] = []
    if args.appstate:
        paths = [Path(args.appstate)]
    else:
        paths = discover_appstates(Path(args.users_root) if args.users_root else None)
        if not paths and args.sample_dir:
            paths = sorted(Path(args.sample_dir).glob("*_appstate.dat"), key=lambda p: p.stat().st_size, reverse=True)
    if not paths:
        _eprint("未找到 appstate.dat。可用 --appstate 指定，或 --users-root / --sample-dir。")
        return 2
    report = []
    for p in paths:
        try:
            st = parse_appstate(p)
        except Exception as e:
            _print(f"[FAIL] {p}: {e}")
            continue
        chat_n = len(st.chatlog_entries)
        wrap_lens = {len(e.wrapped) for e in st.entries}
        sample = st.chatlog_entries[0].relpath if st.chatlog_entries else (st.entries[0].relpath if st.entries else b"")
        row = {
            "file": str(p),
            "size": p.stat().st_size,
            "info_prefix": st.info_prefix.decode("utf-8", "replace"),
            "salt_hex": st.salt.hex(),
            "entries": len(st.entries),
            "chatLogs": chat_n,
            "wrap_lens": sorted(wrap_lens),
            "sample_path": sample.decode("utf-8", "replace"),
            "compat": (
                st.info_prefix in (b"v2:", b"v1:")
                and len(st.salt) == 32
                and wrap_lens == {40}
            ),
        }
        report.append(row)
        _print(
            f"[{'COMPAT' if row['compat'] else 'CHECK'}] {p.name}  "
            f"prefix={row['info_prefix']!r} entries={row['entries']} "
            f"chatLogs={row['chatLogs']} wrap={row['wrap_lens']}  "
            f"sample={row['sample_path']}"
        )
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        _print(f"已写入 {args.out}")
    return 0 if report and all(r["compat"] for r in report) else 1


def _load_root_hex(text: str) -> bytes:
    t = text.strip().lower().replace("0x", "").replace(" ", "")
    if len(t) != 64:
        raise ValueError("根钥 R 必须是 64 位十六进制（32 字节）")
    return bytes.fromhex(t)


def cmd_unwrap(args: argparse.Namespace) -> int:
    st = parse_appstate(Path(args.appstate))
    root = _load_root_hex(args.root)
    t0 = time.time()
    ok = 0
    fail = 0
    keys: dict[str, str] = {}
    # 先试 1 条
    probe = st.chatlog_entries[0] if st.chatlog_entries else st.entries[0]
    one = try_unwrap_one(root, st.salt, st.info_prefix, probe.relpath, probe.wrapped)
    if one is None:
        _eprint(f"根钥无法解包探测项: {probe.relpath.decode('utf-8', 'replace')}")
        return 3
    _print(f"[OK] 探测项解包成功: {probe.relpath.decode('utf-8', 'replace')}")
    for e in st.entries:
        dek = try_unwrap_one(root, st.salt, st.info_prefix, e.relpath, e.wrapped)
        if dek is None:
            fail += 1
            continue
        ok += 1
        keys[e.relpath.decode("utf-8", "replace")] = dek.hex()
    elapsed = time.time() - t0
    _print(f"解包完成: ok={ok} fail={fail} 用时 {elapsed:.3f}s")
    out = {
        "version": __version__,
        "appstate": str(st.path),
        "info_prefix": st.info_prefix.decode("utf-8", "replace"),
        "salt_hex": st.salt.hex(),
        "root_hex": root.hex(),
        "ok": ok,
        "fail": fail,
        "keys": keys,
    }
    out_path = Path(args.out or "kk-unwrapped-keys.json")
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _print(f"已写入 {out_path}")

    if args.verify_edb:
        edb_root = Path(args.verify_edb)
        hit = 0
        checked = 0
        for rel, hx in keys.items():
            if "chatLogs_" not in rel:
                continue
            # rel 形如 chat_data\chatLogs_xxx.edb
            name = Path(rel.replace("\\", "/")).name
            # 在用户目录下搜索
            matches = list(edb_root.rglob(name))
            if not matches:
                continue
            checked += 1
            if sqlcipher_page1_plausible(bytes.fromhex(hx), matches[0]):
                hit += 1
        _print(f"EDB 页头弱校验: hit={hit}/{checked}")
    return 0 if fail == 0 else 1


def _iter_candidates(blob: bytes, step: int = 4) -> Iterator[tuple[int, bytes]]:
    limit = len(blob) - 32
    i = 0
    while i <= limit:
        yield i, blob[i : i + 32]
        i += step


def _regions_near_needles(blob: bytes, needles: list[bytes], radius: int) -> list[tuple[int, int]]:
    """返回 [start, end) 区间列表（已合并）。"""
    spans: list[tuple[int, int]] = []
    for nd in needles:
        if not nd or len(nd) < 16:
            continue
        start = 0
        while True:
            pos = blob.find(nd, start)
            if pos < 0:
                break
            spans.append((max(0, pos - radius), min(len(blob), pos + len(nd) + radius)))
            start = pos + 1
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for a, b in spans[1:]:
        if a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _hex_to_dek32(hx: str) -> bytes | None:
    try:
        dek = bytes.fromhex(str(hx).strip().lower().replace("0x", "").replace(" ", ""))
    except ValueError:
        return None
    return dek if len(dek) == 32 else None


def _extract_key_map(data: Any) -> dict[str, str]:
    """兼容 win-key-cache / unwrap 导出 / 查看器多种形态 → {name_or_path: hex}。"""
    out: dict[str, str] = {}
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            hx = item.get("keyHex") or item.get("key_hex") or item.get("hex")
            name = item.get("probe") or item.get("edb") or item.get("name") or item.get("path") or ""
            if hx and name:
                out[str(name)] = str(hx)
        return out
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("keys"), dict):
        return {str(k): str(v) for k, v in data["keys"].items() if v}
    if isinstance(data.get("byName"), dict):
        return {str(k): str(v) for k, v in data["byName"].items() if v}
    if isinstance(data.get("sample_keys"), dict):
        return {str(k): str(v) for k, v in data["sample_keys"].items() if v}
    # 扁平 {name: hex}；忽略明显非密钥字段
    skip = {"version", "appstate", "info_prefix", "salt_hex", "root_hex", "ok", "fail", "hits"}
    for k, v in data.items():
        if k in skip or not isinstance(v, str):
            continue
        if len(v.replace("0x", "").replace(" ", "")) == 64:
            out[str(k)] = v
    return out


def _parse_known_deks(args: argparse.Namespace) -> list[tuple[bytes, bytes]]:
    """返回 [(relpath_bytes_or_empty, dek32), ...]。"""
    out: list[tuple[bytes, bytes]] = []
    if args.known_dek:
        for item in args.known_dek:
            if "=" not in item:
                raise ValueError("--known-dek 格式: 相对路径=64hex  或  =64hex")
            path_s, hx = item.split("=", 1)
            dek = _hex_to_dek32(hx)
            if dek is None:
                raise ValueError("known DEK 必须 32 字节 hex")
            rel = path_s.encode("utf-8") if path_s else b""
            out.append((rel, dek))
    if args.known_keys:
        data = json.loads(Path(args.known_keys).read_text(encoding="utf-8"))
        key_map = _extract_key_map(data)
        if not key_map:
            raise ValueError("known-keys 未解析到任何 32 字节密钥（支持 win-key-cache.json）")
        for p, hx in key_map.items():
            dek = _hex_to_dek32(hx)
            if dek is not None:
                out.append((str(p).encode("utf-8"), dek))
    return out


def _match_known_to_entries(
    known: list[tuple[bytes, bytes]],
    entries: list[WrapEntry],
) -> list[tuple[WrapEntry, bytes]]:
    """把缓存里的短名/路径对齐到 appstate 条目。"""
    by_name: dict[bytes, WrapEntry] = {}
    by_full: dict[bytes, WrapEntry] = {}
    for e in entries:
        by_full[e.relpath] = e
        name = e.relpath.replace(b"\\", b"/").split(b"/")[-1]
        by_name[name] = e
    matched: list[tuple[WrapEntry, bytes]] = []
    seen: set[bytes] = set()
    for rel, dek in known:
        if not rel:
            continue
        ent = by_full.get(rel) or by_name.get(rel.replace(b"\\", b"/").split(b"/")[-1])
        if ent is None:
            # 缓存键可能是 chatLogs_xxx.edb 无前缀
            name = rel.replace(b"\\", b"/").split(b"/")[-1]
            ent = by_name.get(name)
        if ent is None or ent.relpath in seen:
            continue
        seen.add(ent.relpath)
        matched.append((ent, dek))
    return matched


def cmd_find_root(args: argparse.Namespace) -> int:
    if not _is_windows() and not args.dump_file:
        _eprint("非 Windows：请提供 --dump-file（预先转储的内存），或到 Windows 上运行。")
        return 2
    st = parse_appstate(Path(args.appstate))
    probes = st.chatlog_entries[: max(1, args.probe_count)]
    if not probes:
        probes = st.entries[:1]
    _print(f"探测条目: {len(probes)}  前缀={st.info_prefix!r}  salt={st.salt.hex()[:16]}…")

    known = _parse_known_deks(args)
    known_matched = _match_known_to_entries(known, st.chatlog_entries or st.entries)
    if known:
        _print(f"已知 DEK: {len(known)} 条，对齐 appstate: {len(known_matched)} 条")
        # 有对齐条目时，优先用它们做 ICV 探测（并可核对明文 DEK）
        if known_matched:
            probes = [ent for ent, _ in known_matched[: max(1, args.probe_count)]]

    if args.dump_file:
        blob = Path(args.dump_file).read_bytes()
        _print(f"已加载 dump: {args.dump_file}  size={len(blob)}")
    else:
        pids = find_kakao_pids()
        if not pids:
            _eprint("未找到 KakaoTalk.exe 进程，请先登录并保持客户端运行。")
            return 2
        _print(f"KakaoTalk PID: {pids}")
        writable_only = bool(getattr(args, "writable_only", False))
        mode = "仅私有可写" if writable_only else "私有可读(含只读)"
        _print(f"转储模式: {mode}")
        parts = []
        for pid in pids:
            _print(f"转储 PID {pid} …")
            part = dump_process_memory(
                pid,
                max_bytes=args.max_dump_mb * 1024 * 1024,
                writable_only=writable_only,
            )
            _print(f"  得到 {len(part)} 字节")
            parts.append(part)
        blob = b"".join(parts)
        if args.save_dump:
            Path(args.save_dump).write_bytes(blob)
            _print(f"dump 已保存: {args.save_dump}")

    # 优先扫描：已知 DEK 附近
    scan_plan: list[tuple[str, Iterable[tuple[int, bytes]]]] = []
    if known:
        needles = [dek for _, dek in known]
        hit_count = sum(blob.count(nd) for nd in needles)
        regions = _regions_near_needles(blob, needles, radius=args.near_radius)
        _print(f"已知 DEK 在 dump 中出现次数≈{hit_count}，邻域段数={len(regions)}，半径={args.near_radius}")
        if hit_count == 0:
            _eprint("警告: 缓存里的 DEK 字节未出现在当前内存。请先在 KakaoTalk 打开对应聊天室再扫。")
        else:
            def near_iter():
                for a, b in regions:
                    for off, cand in _iter_candidates(blob[a:b], step=args.step):
                        yield a + off, cand
            scan_plan.append(("near-known-dek", near_iter()))
    if not getattr(args, "known_only", False):
        scan_plan.append(("full", _iter_candidates(blob, step=args.step)))
    elif not scan_plan:
        _eprint("指定了 --known-only，但没有可用邻域（DEK 未驻留内存）。")
        return 4

    known_dek_by_path = {ent.relpath: dek for ent, dek in known_matched}

    def _accept_root(cand: bytes) -> bool:
        """有已知 DEK 时：任意一条 unwrap==已知即可（避免旧缓存 DEK 误拒）。
        无已知时：至少 1 条 ICV 通过，另抽查最多 2 条。"""
        if known_dek_by_path:
            for ent, expect in known_matched:
                got = try_unwrap_one(cand, st.salt, st.info_prefix, ent.relpath, ent.wrapped)
                if got is not None and got == expect:
                    return True
            return False
        dek0 = try_unwrap_one(cand, st.salt, st.info_prefix, probes[0].relpath, probes[0].wrapped)
        if dek0 is None:
            return False
        ok_extra = 0
        need = max(0, min(2, len(probes) - 1))
        for p in probes[1:]:
            if try_unwrap_one(cand, st.salt, st.info_prefix, p.relpath, p.wrapped) is not None:
                ok_extra += 1
        return ok_extra >= need

    checked = 0
    t0 = time.time()
    found_root: bytes | None = None
    found_at = -1
    phase_name = ""

    for phase_name, it in scan_plan:
        _print(f"开始扫描阶段: {phase_name}")
        for off, cand in it:
            checked += 1
            if checked % 200000 == 0:
                _print(f"  …已试 {checked} 个候选  elapsed={time.time()-t0:.1f}s")
            if cand == b"\x00" * 32 or cand == b"\xff" * 32:
                continue
            if not _accept_root(cand):
                continue
            found_root = cand
            found_at = off
            break
        if found_root is not None:
            break

    elapsed = time.time() - t0
    if found_root is None:
        _eprint(f"未找到根钥。已试候选={checked} 用时={elapsed:.1f}s phase={phase_name}")
        _eprint("建议：打开已解过钥的聊天室后再扫；或加大 --near-radius；或去掉 --known-only 做扩大 dump 全扫。")
        return 4

    _print(f"[HIT] 找到 R @ dump_offset={found_at}  phase={phase_name}")
    _print(f"R = {found_root.hex()}")
    sample_keys = {}
    for e in (st.chatlog_entries or st.entries)[:20]:
        dek = try_unwrap_one(found_root, st.salt, st.info_prefix, e.relpath, e.wrapped)
        if dek:
            sample_keys[e.relpath.decode("utf-8", "replace")] = dek.hex()
    result = {
        "version": __version__,
        "appstate": str(st.path),
        "info_prefix": st.info_prefix.decode("utf-8", "replace"),
        "salt_hex": st.salt.hex(),
        "root_hex": found_root.hex(),
        "dump_offset": found_at,
        "phase": phase_name,
        "candidates_tried": checked,
        "elapsed_sec": round(elapsed, 3),
        "sample_keys": sample_keys,
    }
    out_path = Path(args.out or "kk-root-key.json")
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    _print(f"已写入 {out_path}")
    _print("下一步: 用同一 R 执行 unwrap 导出全量 DEK：")
    _print(f"  kk-appstate-probe unwrap --appstate \"{st.path}\" --root {found_root.hex()} --out kk-unwrapped-keys.json")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kk-appstate-probe",
        description="KakaoTalk Windows appstate.dat 临时验证工具（独立 exe）",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sp = p.add_subparsers(dest="cmd", required=True)

    p0 = sp.add_parser("selftest", help="本地合成数据自检")
    p0.set_defaults(func=cmd_selftest)

    p1 = sp.add_parser("inspect", help="解析 appstate 结构")
    p1.add_argument("--appstate", help="appstate.dat 路径")
    p1.add_argument("--users-root", help=r"默认 %%LocalAppData%%\Kakao\KakaoTalk\users")
    p1.add_argument("--sample-dir", help="离线样本目录（*_appstate.dat）")
    p1.add_argument("--out", help="写出 JSON 报告")
    p1.set_defaults(func=cmd_inspect)

    p2 = sp.add_parser("unwrap", help="给定 R，批量解出 DEK")
    p2.add_argument("--appstate", required=True)
    p2.add_argument("--root", required=True, help="32 字节根钥的 64 位 hex")
    p2.add_argument("--out", default="kk-unwrapped-keys.json")
    p2.add_argument("--verify-edb", help="可选：用户目录，对 chatLogs 做页头弱校验")
    p2.set_defaults(func=cmd_unwrap)

    p3 = sp.add_parser("find-root", help="在 KakaoTalk 内存中搜索 R")
    p3.add_argument("--appstate", required=True)
    p3.add_argument("--dump-file", help="已有内存 dump 文件（非 Windows 调试用）")
    p3.add_argument("--save-dump", help="把本次转储写到文件")
    p3.add_argument("--max-dump-mb", type=int, default=1536)
    p3.add_argument("--step", type=int, default=4, help="候选窗口步进（字节）")
    p3.add_argument("--probe-count", type=int, default=3)
    p3.add_argument("--known-dek", action="append", default=[], help="path=64hex，可重复；加速邻域扫描")
    p3.add_argument("--known-keys", help="已有 keys JSON（win-key-cache.json / unwrap 导出均可）")
    p3.add_argument("--known-only", action="store_true", help="只扫已知 DEK 邻域，不做全量")
    p3.add_argument("--writable-only", action="store_true", help="仅转储私有可写（旧行为）；默认含只读私有")
    p3.add_argument("--near-radius", type=int, default=4 * 1024 * 1024, help="已知 DEK 邻域半径，默认 4MB")
    p3.add_argument("--out", default="kk-root-key.json")
    p3.set_defaults(func=cmd_find_root)

    return p


def _pause_if_double_clicked() -> None:
    """双击运行时控制台会立刻关掉；无参数/失败时暂停，方便看输出。"""
    if not _is_windows():
        return
    # 有父控制台且是交互传入参数时不暂停
    if len(sys.argv) > 1:
        return
    try:
        input("\n按回车键退出…")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    # 双击无参数：默认跑 inspect，避免一闪而过只看到用法错误
    if argv is None and len(sys.argv) <= 1:
        argv = ["inspect"]
        _print("未指定命令，默认执行: inspect")
        _print("完整用法示例:")
        _print("  kk-appstate-probe.exe inspect")
        _print("  kk-appstate-probe.exe find-root --appstate \"%LOCALAPPDATA%\\Kakao\\KakaoTalk\\users\\<账号>\\appstate.dat\"")
        _print("")
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = int(e.code or 0) if isinstance(e.code, int) or e.code is None else 1
        if len(sys.argv) <= 1:
            _pause_if_double_clicked()
        return code
    try:
        code = int(args.func(args))
    except BrokenPipeError:
        return 0
    except Exception as e:
        _eprint(f"[错误] {e}")
        code = 1
    if argv == ["inspect"] and len(sys.argv) <= 1:
        _pause_if_double_clicked()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
