#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
诊断：ReBAR 失效原因
比对当前芯片内容 flash_now3.bin 与各版本镜像，判断到底刷进去的是哪一份、
NVRAM 是否被覆盖、注入驱动是否在位。
"""
import os
import re
import hashlib

W = "."
FILES = {
    "ORIG(stock)":  "JYZ6PA08_ORIG.bin",
    "v3":           "JYZ6PA08_ReBAR_v3.bin",
    "v4":           "JYZ6PA08_ReBAR_v4.bin",
    "live_prev":    "flash_now2.bin",
    "chip_now":     "flash_now3.bin",
}

def load(p):
    if not os.path.exists(p):
        return None
    return open(p, "rb").read()

imgs = {k: load(v) for k, v in FILES.items()}
chip = imgs["chip_now"]
print("=== 文件加载 ===")
for k, d in imgs.items():
    if d is None:
        print("   %-12s 缺失" % k)
    else:
        print("   %-12s %d bytes  md5=%s" % (k, len(d), hashlib.md5(d).hexdigest()))

if chip is None:
    raise SystemExit("没有 flash_now3.bin")

print()
print("=== 1) 当前芯片 vs 各镜像：差异字节数（全局）===")
for k, d in imgs.items():
    if d is None or k == "chip_now" or len(d) != len(chip):
        continue
    n = sum(1 for a, b in zip(chip, d) if a != b)
    print("   vs %-12s 差异 %8d 字节  (%.3f%%)" % (k, n, 100.0 * n / len(chip)))

print()
print("=== 2) 当前芯片 vs 各镜像：按 64KB 区块列出差异（含区域标注）===")
def zone(k):
    if k < 0x1000:
        return "Flash Descriptor"
    if k < 0x3DA000:
        return "ME 区"
    if 0x400000 <= k < 0x470000:
        return "NVRAM 运行时区"
    if 0x470000 <= k < 0x990000:
        return "FVMAIN(含注入驱动)"
    if k == 0x800000:
        return "注入驱动块(独立FV?)"
    return "BIOS 其他"

for k, d in imgs.items():
    if d is None or k == "chip_now" or len(d) != len(chip):
        continue
    blocks = {}
    for i in range(0, len(chip), 0x10000):
        n = sum(1 for a, b in zip(chip[i:i + 0x10000], d[i:i + 0x10000]) if a != b)
        if n:
            blocks[i] = n
    print("   --- vs %s : %d 个区块有差异" % (k, len(blocks)))
    for b in sorted(blocks):
        print("        0x%06x  %7d 字节   %s" % (b, blocks[b], zone(b)))

print()
print("=== 3) 注入驱动是否在位（v3/v4 的插入点 0x80CA40）===")
INS, IEND = 0x80CA40, 0x80FF7C
ffs_release = load("NvStrapsReBar.ffs")
for k, d in imgs.items():
    if d is None:
        continue
    seg = d[INS:IEND]
    nonff = sum(1 for b in seg if b != 0xFF)
    # 找 NvStrapsReBar UI 名
    has_ui = b"N\x00v\x00S\x00t\x00r\x00a\x00p\x00s\x00R\x00e\x00B\x00a\x00r\x00" in d
    # 找驱动 GUID
    import uuid
    g = str(uuid.UUID(bytes_le=d[INS:INS + 16])) if nonff else "-"
    print("   %-12s 非FF=%5d/%d  UI字符串=%s  首16B GUID=%s" %
          (k, nonff, len(seg), has_ui, g))

print()
print("=== 4) NVRAM 区（0x400000-0x470000）指纹：找明文线索 ===")
probes = ["SecureBoot", "NvStrapsReBar", "ReBar", "BootOrder", "PKDefault", "dbDefault", "KEKDefault"]
for k, d in imgs.items():
    if d is None:
        continue
    seg = d[0x400000:0x470000]
    nonff = sum(1 for b in seg if b != 0xFF)
    hits = {}
    for p in probes:
        hits[p] = len(re.findall(re.escape(p.encode("utf-16-le")), seg))
    print("   %-12s 非FF=%7d/%d  明文命中=%s" % (k, nonff, len(seg),
          {p: c for p, c in hits.items() if c}))

print()
print("=== 5) 关键：当前芯片 vs live_prev(刷前运行态) 的差异 ===")
lp = imgs.get("live_prev")
if lp is not None and len(lp) == len(chip):
    n = sum(1 for a, b in zip(chip, lp) if a != b)
    print("   总差异 %d 字节" % n)
    blocks = {}
    for i in range(0, len(chip), 0x10000):
        m = sum(1 for a, b in zip(chip[i:i + 0x10000], lp[i:i + 0x10000]) if a != b)
        if m:
            blocks[i] = m
    for b in sorted(blocks):
        print("      0x%06x  %7d 字节   %s" % (b, blocks[b], zone(b)))
