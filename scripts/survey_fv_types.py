"""列出各 FV 内文件类型分布 + 空闲空间，判断哪些卷会被 DXE 调度（含 DRIVER 的卷）"""
import struct, uuid, lzma, re
from collections import Counter

IMG = open("JYZ6PA08_ORIG.bin",'rb').read()
LZMA_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
FT = {0x01:'RAW',0x02:'FREEFORM',0x03:'SEC',0x04:'PEI_CORE',0x05:'DXE_CORE',0x06:'PEIM',
      0x07:'DRIVER',0x08:'COMBO',0x09:'APP',0x0A:'SMM',0x0B:'FV_IMAGE',0x0D:'SMM_CORE',
      0x0E:'SMM_STANDALONE',0x0F:'SMM_CORE_STANDALONE',0xF0:'PAD'}

NAMES = {
 'e3b331d0-1159-4c30-8c3c-9dc00bf1fd0e':'FV_BB?',
 '7a9354d9-0468-444a-81ce-0bf617d890df':'NVRAM store',
 'fff12b8d-7696-4c8b-a985-2747075b4f50':'NVRAM FV',
 'f4ed7ab3-d4a2-4e58-9f61-... ':'x',
}

def enumerate_fv(buf, base, tag, depth=0):
    if buf[base+0x28:base+0x2C] != b'_FVH': return
    fvlen = struct.unpack_from('<Q', buf, base+0x20)[0]
    hlen  = struct.unpack_from('<H', buf, base+0x30)[0]
    if fvlen < 0x39 or base+fvlen > len(buf): return
    fsguid = str(uuid.UUID(bytes_le=buf[base+0x10:base+0x20]))
    off = (base+hlen+7)&~7; end = base+fvlen
    files=[]; imgs=[]
    while off+24 <= end:
        g = buf[off:off+16]
        sz = int.from_bytes(buf[off+20:off+23],'little')
        if sz < 24 or off+sz > end: break
        files.append((buf[off+18], str(uuid.UUID(bytes_le=g)), sz, off))
        off = (off+sz+7)&~7
    tail = 0; i = end-1
    while i > base+hlen and buf[i]==0xFF: tail += 1; i -= 1
    c = Counter(FT.get(t, hex(t)) for t,_,_,_ in files)
    drivers = c.get('DRIVER',0) + c.get('DXE_CORE',0) + c.get('SMM',0) + c.get('SMM_CORE',0)
    print("%sFV %s  fvlen=0x%-7x files=%-3d free=%-7dKB  %s%s"
          % ("  "*depth, tag, fvlen, len(files), tail//1024, dict(c), "  <== 含可调度驱动" if drivers else ""))
    for (o, gs, sz, s_) in files:
        if o == 0x0B: pass
    return files

print("=== 各 FV 文件类型分布 ===")
for m in re.finditer(re.escape(b'_FVH'), IMG):
    base = m.start()-0x28
    if base < 0: continue
    fs = enumerate_fv(IMG, base, "@0x%08x" % base)
    # 递归进压缩子卷
    if not fs: continue
    for (t, gs, sz, o) in fs:
        if t != 0x0B: continue
        soff = o+24
        while soff+4 <= o+sz:
            ssz = int.from_bytes(IMG[soff:soff+3],'little'); st = IMG[soff+3]
            if ssz < 4 or soff+ssz > o+sz: break
            if st == 0x02 and str(uuid.UUID(bytes_le=IMG[soff+4:soff+20])) == LZMA_GUID:
                do = struct.unpack_from('<H', IMG, soff+20)[0]
                try:
                    sub = lzma.decompress(bytes(IMG[soff+do:soff+ssz]), format=lzma.FORMAT_ALONE)
                except Exception:
                    sub = None
                if sub:
                    q = 0
                    while q+4 <= len(sub):
                        qs = int.from_bytes(sub[q:q+3],'little'); qt = sub[q+3]
                        if qs < 4 or q+qs > len(sub): break
                        if qt == 0x17:
                            enumerate_fv(sub, q+4, "└压缩子FV(流0x%x)" % q, 1)
                        q = (q+qs+3)&~3
            soff = (soff+ssz+3)&~3
