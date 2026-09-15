"""全面测绘：枚举镜像内所有固件卷（含压缩嵌套），找 PciBus、算空闲空间"""
import struct, uuid, lzma, re

IMG = open("JYZ6PA08_ORIG.bin",'rb').read()
PCIBUS = '3c1de39f-d207-408a-aacc-731cfb7f1dd7'
PCIBUS_B = uuid.UUID(PCIBUS).bytes_le
LZMA_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
FT = {0x01:'RAW',0x02:'FREEFORM',0x03:'SEC',0x04:'PEI_CORE',0x05:'DXE_CORE',0x06:'PEIM',
      0x07:'DRIVER',0x09:'APP',0x0A:'SMM',0x0B:'FV_IMAGE',0x0D:'SMM_CORE',0xF0:'PAD'}

seen = []
def parse_fv(buf, base, tag, depth=0):
    """buf=容器buffer, base=FV 起始偏移"""
    if base+0x38 > len(buf): return
    if buf[base+0x28:base+0x2C] != b'_FVH': return
    fvlen = struct.unpack_from('<Q', buf, base+0x20)[0]
    hlen  = struct.unpack_from('<H', buf, base+0x30)[0]
    attr  = struct.unpack_from('<I', buf, base+0x2C)[0]
    if fvlen < 0x39 or hlen < 0x39 or base+fvlen > len(buf): return
    # blockmap
    bm, p = [], base+0x38
    while p+8 <= base+hlen:
        nb, blk = struct.unpack_from('<II', buf, p)
        if nb == 0: break
        bm.append((nb,blk)); p += 8
    bm_total = sum(n*b for n,b in bm)
    # files
    off = (base+hlen+7)&~7; end = base+fvlen; files=[]; pcibus=False; free_total=0
    while off+24 <= end:
        g = buf[off:off+16]
        sz = int.from_bytes(buf[off+20:off+23],'little')
        if sz < 24 or off+sz > end: break
        gs = str(uuid.UUID(bytes_le=g))
        if g == PCIBUS_B or gs == PCIBUS: pcibus = True
        files.append((off, gs, buf[off+18], sz))
        off = (off+sz+7)&~7
    # count trailing FF
    tail = 0
    i = end-1
    while i > base+hlen and buf[i] == 0xFF:
        tail += 1; i -= 1
    kind = {'06':'PEI','07':'DXE'}.get('%02X' % attr if False else '', '')
    print("%sFV @%s  len=0x%-8x hdrlen=0x%x files=%-4d bm_total=0x%-8x bm==fvlen:%-5s 尾部连续FF=%dKB  PciBus=%s"
          % ("  "*depth, tag, fvlen, hlen, len(files), bm_total, bm_total==fvlen, tail//1024, "YES" if pcibus else "-"))
    # 找 FV_IMAGE 文件里的 GUIDed LZMA section 并解压递归
    for (o, gs, t, sz) in files:
        if t != 0x0B: continue
        soff = o+24
        while soff+4 <= o+sz:
            ssz = int.from_bytes(buf[soff:soff+3],'little'); st = buf[soff+3]
            if ssz < 4 or soff+ssz > o+sz: break
            if st == 0x02:
                sg = str(uuid.UUID(bytes_le=buf[soff+4:soff+20]))
                do = struct.unpack_from('<H', buf, soff+20)[0]
                if sg == LZMA_GUID:
                    try:
                        sub = lzma.decompress(bytes(buf[soff+do:soff+ssz]), format=lzma.FORMAT_ALONE)
                    except Exception as e:
                        print("   ! LZMA 解压失败", e); sub = None
                    if sub:
                        print("  %s└ 解压 GUIDed LZMA @%s: %d -> %d 字节" % ("  "*depth, hex(soff), ssz-do, len(sub)))
                        # 内部 section 流
                        q = 0
                        while q+4 <= len(sub):
                            qs = int.from_bytes(sub[q:q+3],'little'); qt = sub[q+3]
                            if qs < 4 or q+qs > len(sub): break
                            if qt == 0x17:
                                parse_fv(sub, q+4, "%s/子FV(流内0x%x)" % (tag, q), depth+1)
                            q = (q+qs+3)&~3
            soff = (soff+ssz+3)&~3

print("=== 顶层 _FVH 扫描 ===")
for m in re.finditer(re.escape(b'_FVH'), IMG):
    base = m.start()-0x28
    if base < 0: continue
    parse_fv(IMG, base, "镜像 0x%08x" % base)
print()
print("=== PciBus GUID 在整镜像中的出现次数(含压缩后不可见的部分) ===")
print("raw:", len(re.findall(re.escape(PCIBUS_B), IMG)))
