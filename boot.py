#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
boot.py — 加密版启动器

exe 里只有这个启动器 + payload.bin（加密载荷），源码在内存里解密后执行，
磁盘和打包产物里都不存在 .py / .pyc。

开发时仍然直接跑 dnsguard_app.py，不受影响。
"""

from __future__ import annotations

import base64
import json
import os
import sys
import types
import zlib

KEY = b"parkerli:dnsguard:2026:v1"
MODULES = ("dnsguard", "dnsguard_app")


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for idx, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[idx] = byte ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _base_dir() -> str:
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _load() -> None:
    base = _base_dir()
    with open(os.path.join(base, "payload.bin"), "rb") as fh:
        blob = json.loads(fh.read().decode("utf-8"))

    for modname in MODULES:
        key = f"{modname}.py"
        if key not in blob:
            continue
        src = zlib.decompress(rc4(base64.b64decode(blob[key]), KEY)).decode("utf-8")
        mod = types.ModuleType(modname)
        mod.__file__ = os.path.join(base, key)
        mod.__package__ = ""
        sys.modules[modname] = mod
        exec(compile(src, key, "exec"), mod.__dict__)


def main() -> int:
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    try:
        _load()
    except Exception as exc:                                   # noqa: BLE001
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f"启动失败：{exc}", "DNS Guard", 0x10)
        except Exception:                                      # noqa: BLE001
            pass
        return 1
    app = sys.modules.get("dnsguard_app")
    if app is None:
        return 1
    return app.main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
