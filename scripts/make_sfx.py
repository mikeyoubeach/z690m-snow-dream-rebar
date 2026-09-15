"""通用 SFX 重组：把任意镜像塞回官方 win刷 exe 的 RAR5 overlay。
用法: python make_sfx.py <new_bios.bin> <out.exe>
"""
import sys, struct, zlib, hashlib, os

SRC_EXE = "PA08_ext/JYZ6PA08/win系统刷/Z690M Snow Dream D4.exe"
INNER   = "sfx_inner.rar"
P_BIOS  = 0x19d
P_TXT   = 0x79b2df
P_QO    = 0x8139b0
P_ENDARC= 0x813b05

def venc(v):
    out = bytearray()
    while True:
        b = v & 0x7f; v >>= 7
        if v: out.append(b | 0x80)
        else:
            out.append(b); break
    return bytes(out)

def vdec(buf, p):
    v = 0; shift = 0
    while True:
        b = buf[p]; p += 1
        v |= (b & 0x7f) << shift; shift += 7
        if not b & 0x80: return v, p

def build(new_bin, out_exe):
    rom = open(new_bin, 'rb').read()
    assert len(rom) == 0x1000000, "镜像必须是 16MB"
    d = open(INNER, 'rb').read()

    # ---- MAIN 头（去掉 locator extra）----
    htype, p = vdec(d, 0xd); hflags, p = vdec(d, p); archflags, p = vdec(d, p)
    assert htype == 1, "inner rar MAIN 头异常"
    nhflags = hflags & ~0x01
    mbody = venc(1) + venc(nhflags) + venc(archflags)
    mhsize = len(mbody)
    mcrc = zlib.crc32(venc(mhsize) + mbody) & 0xffffffff
    new_main = struct.pack('<I', mcrc) + venc(mhsize) + mbody

    # ---- 原 BIOS.rom 头（取 attr/hostos）----
    assert d[P_BIOS+4] == 0x5d, "原 BIOS.rom 头尺寸 vint 变了"
    p = P_BIOS + 4 + 1
    htype, p = vdec(d, p); hflags, p = vdec(d, p)
    assert htype == 2
    extra, p = vdec(d, p); data, p = vdec(d, p)
    fflags, p = vdec(d, p); unp, p = vdec(d, p); attr, p = vdec(d, p)
    if fflags & 2: p += 4
    p += 4                                   # 原 DataCRC32
    comp, p = vdec(d, p); hostos, p = vdec(d, p)
    nsz, p = vdec(d, p); name = d[p:p+nsz]
    assert name == b'BIOS.rom' and unp == 0x1000000
    print("原 BIOS.rom: attr=%#x hostos=%d" % (attr, hostos))

    # ---- 新的 BIOS.rom 记录：store 明文 + CRC 重算 ----
    bbody = (venc(2) + venc(0x02) + venc(0x1000000)
             + venc(0x04) + venc(0x1000000) + venc(attr)
             + struct.pack('<I', zlib.crc32(rom) & 0xffffffff)
             + venc(0) + venc(hostos) + venc(8) + b'BIOS.rom')
    bhsize = len(bbody)
    bcrc = zlib.crc32(venc(bhsize) + bbody) & 0xffffffff
    new_bios = struct.pack('<I', bcrc) + venc(bhsize) + bbody

    assert d[P_ENDARC+5] == 0x05
    out = bytearray()
    out += d[:8]                              # Rar! 魔数
    out += new_main
    out += d[0x1a:P_BIOS]                     # CMT 记录+数据 原样
    out += new_bios + rom                     # 新 BIOS.rom
    out += d[P_TXT:P_QO]                      # txt/favicon/FPTW64/jy.bat 原样
    out += d[P_ENDARC:]                       # ENDARC 原样

    exe_old = open(SRC_EXE, 'rb').read()
    assert exe_old[:0xad000] == open(SRC_EXE,'rb').read()[:0xad000]
    exe_new = exe_old[:0xad000] + bytes(out)
    open(out_exe, 'wb').write(exe_new)
    print("写出 %s (%d 字节, 原 %d)" % (out_exe, len(exe_new), len(exe_old)))
    print("  exe PE 部分字节一致: %s" % (exe_new[:0xad000] == exe_old[:0xad000]))
    print("  内含 BIOS md5 = %s (源 %s)" % (hashlib.md5(rom).hexdigest(), hashlib.md5(open(new_bin,'rb').read()).hexdigest()))

if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])
