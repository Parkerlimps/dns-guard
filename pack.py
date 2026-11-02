#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack.py — 把源码压成加密载荷，供 boot.py 在内存里解密执行

产物：build/payload.bin（JSON + base64 + zlib + RC4）
这样 exe 里不会留下任何 .py / .pyc，pyinstxtractor 之类的工具拿不到可直接反编译的字节码。

    python pack.py
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import zlib

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "build", "payload.bin")
SOURCES = ["dnsguard.py", "dnsguard_app.py"]

# 密钥只影响"随手一看"的成本，不是密码学意义上的安全
KEY = b"parkerli:dnsguard:2026:v1"


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


def main() -> int:
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    blob = {}
    for name in SOURCES:
        path = os.path.join(BASE, name)
        with io.open(path, encoding="utf-8") as fh:
            src = fh.read()
        packed = rc4(zlib.compress(src.encode("utf-8"), 9), KEY)
        blob[name] = base64.b64encode(packed).decode("ascii")
        print(f"· {name}  {len(src)/1024:.1f} KB -> {len(packed)/1024:.1f} KB")

    with open(OUT, "wb") as fh:
        fh.write(json.dumps(blob).encode("utf-8"))
    print(f"payload -> {OUT}  ({os.path.getsize(OUT)/1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
