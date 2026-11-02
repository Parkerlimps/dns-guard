#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build.py — 把 DNS Guard 打包成单文件桌面客户端

    python build.py             # 普通打包
    python build.py --protect   # 加密打包：源码压成加密载荷，运行时内存解密

产物：dist/DNSGuard.exe（双击即开，独立窗口，不经过浏览器标签页）
需要：pip install pyinstaller pywebview pillow
"""

from __future__ import annotations

import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(BASE, "build")
DIST = os.path.join(BASE, "dist")
ICON = os.path.join(BASE, "assets", "icon.ico")
VERSION = "0.4.7"

VERSION_INFO = """VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(0, 4, 7, 0), prodvers=(0, 4, 7, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('080404B0', [
        StringStruct('CompanyName', 'parkerli'),
        StringStruct('FileDescription', 'DNS Guard · DNS 劫持体检与隐私暴露自查'),
        StringStruct('FileVersion', '{v}'),
        StringStruct('InternalName', 'DNSGuard'),
        StringStruct('OriginalFilename', 'DNSGuard.exe'),
        StringStruct('ProductName', 'DNS Guard'),
        StringStruct('ProductVersion', '{v}'),
        StringStruct('LegalCopyright', '© parkerli')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
""".format(v=VERSION)


def main() -> int:
    protect = "--protect" in sys.argv[1:]

    if not os.path.exists(ICON):
        print("· 生成图标…")
        subprocess.check_call([sys.executable, os.path.join(BASE, "make_icon.py")])

    os.makedirs(BUILD, exist_ok=True)
    vfile = os.path.join(BUILD, "version_info.txt")
    with open(vfile, "w", encoding="utf-8") as fh:
        fh.write(VERSION_INFO)

    entry = os.path.join(BASE, "dnsguard_app.py")
    extra: list[str] = []
    if protect:
        print("· 生成加密载荷…")
        subprocess.check_call([sys.executable, os.path.join(BASE, "pack.py")])
        entry = os.path.join(BASE, "boot.py")
        extra = ["--add-data", os.path.join(BUILD, "payload.bin") + os.pathsep + "."]

    # PyInstaller 覆盖旧产物时会先删文件；某些环境的删除钩子会拦下来，先自己挪走
    exe = os.path.join(DIST, "DNSGuard.exe")
    if os.path.exists(exe):
        try:
            os.replace(exe, os.path.join(BUILD, "DNSGuard.prev.exe"))
        except OSError:
            pass

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "DNSGuard",
        "--icon", ICON,
        "--version-file", vfile,
        "--distpath", DIST,
        "--workpath", BUILD,
        "--specpath", BUILD,
        "--collect-all", "webview",
        "--collect-all", "pythonnet",
        "--collect-all", "clr_loader",
        "--hidden-import", "webview.platforms.winforms",
    ]
    if not protect:                     # 加密模式下绝不能让 PyInstaller 把源码打成 .pyc 塞进来
        cmd += ["--hidden-import", "dnsguard", "--hidden-import", "dnsguard_app"]
    cmd += extra + [entry]

    print("· 开始打包…")
    subprocess.check_call(cmd, cwd=BASE)

    if os.path.exists(exe):
        print(f"\n完成：{exe}  ({os.path.getsize(exe) / 1048576:.1f} MB)"
              f"{'  [已加密]' if protect else ''}")
        return 0
    print("打包失败，请检查上方日志")
    return 1


if __name__ == "__main__":
    sys.exit(main())
