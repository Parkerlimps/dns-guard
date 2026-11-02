#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 DNS Guard 图标（构建期用，运行时不依赖 Pillow）"""

import os
import sys

from PIL import Image, ImageDraw

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "assets", "icon.ico")


def rounded(draw, box, r, fill):
    draw.rounded_rectangle(box, radius=r, fill=fill)


def make(size: int) -> Image.Image:
    scale = 8
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 背景：圆角方块 + 斜向渐变
    bg = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    grad = Image.new("RGBA", (s, s))
    gd = ImageDraw.Draw(grad)
    for y in range(s):
        for_x = y / max(1, s - 1)
        r = int(0x3B + (0x23 - 0x3B) * for_x)
        g = int(0x7B + (0x54 - 0x7B) * for_x)
        b = int(0xF7 + (0xD8 - 0xF7) * for_x)
        gd.line([(0, y), (s, y)], fill=(r, g, b, 255))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.24), fill=255)
    bg.paste(grad, (0, 0), mask)
    img.alpha_composite(bg)

    # 盾牌
    w = s
    shield = [
        (w * 0.50, w * 0.16),
        (w * 0.80, w * 0.28),
        (w * 0.80, w * 0.52),
        (w * 0.50, w * 0.84),
        (w * 0.20, w * 0.52),
        (w * 0.20, w * 0.28),
    ]
    d.polygon(shield, fill=(255, 255, 255, 255))

    # 勾
    d.line([(w * 0.35, w * 0.50), (w * 0.46, w * 0.62), (w * 0.67, w * 0.38)],
           fill=(0x2F, 0x6D, 0xF6, 255), width=max(2, int(w * 0.055)), joint="curve")
    for pt in [(w * 0.35, w * 0.50), (w * 0.46, w * 0.62), (w * 0.67, w * 0.38)]:
        rr = w * 0.028
        d.ellipse([pt[0] - rr, pt[1] - rr, pt[0] + rr, pt[1] + rr], fill=(0x2F, 0x6D, 0xF6, 255))

    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [make(sz) for sz in sizes]
    frames[-1].save(OUT, format="ICO", sizes=[(s, s) for s in sizes])
    png = os.path.join(os.path.dirname(OUT), "icon.png")
    frames[-1].save(png, format="PNG")
    print("icon ->", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
