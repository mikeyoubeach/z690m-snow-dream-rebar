import struct, lzma, uuid

def load(path):
    return open(path,'rb').read()

MINE = load("JYZ6PA08_ReBAR.bin"); ORIG = load("JYZ6PA08_ORIG.bin")
foff = 0x4d10c0
def stream_of(img):
    soff = foff+24
    ssz = int.from_bytes(img[soff:soff+3],'little')
    dataoff = struct.unpack_from('<H', img, soff+20)[0]
    comp = img[soff+dataoff:soff+ssz]
    return comp, lzma.decompress(comp, format=lzma.FORMAT_ALONE)

cm, sm = stream_of(MINE)
co, so = stream_of(ORIG)

print("stream lengths: mine=0x%x orig=0x%x" % (len(sm), len(so)))
print()
print("=== 解压流开头 0x20 字节 ===")
print("mine:", sm[:0x20].hex())
print("orig:", so[:0x20].hex())
print("开头 16 字节是否一致:", sm[:0x10] == so[:0x10])
print()
print("=== 尝试按 section 头解释 offset 0 ===")
for tag, s in (("mine", sm), ("orig", so)):
    sz = int.from_bytes(s[0:3],'little'); t = s[3]
    print("  %s: header size=0x%x type=0x%02x  (stream len=0x%x, 若为包裹section则其size应=%d=0x%x)"
          % (tag, sz, t, len(s), len(s)-0 if False else 0, 0))
print()
print("=== 内层 FV 头字段 (FV @ 0x10) ===")
for tag, s in (("mine", sm), ("orig", so)):
    b = 0x10
    fvlen = struct.unpack_from('<Q', s, b+32)[0]
    sig   = s[b+40:b+44]
    attr  = struct.unpack_from('<I', s, b+44)[0]
    hlen  = struct.unpack_from('<H', s, b+48)[0]
    csum  = struct.unpack_from('<H', s, b+50)[0]
    extoff= struct.unpack_from('<H', s, b+52)[0]
    rev   = s[b+55]
    print("  %s: filesysguid=%s" % (tag, uuid.UUID(bytes_le=s[b+16:b+32])))
    print("      fvlen=0x%x sig=%s attr=0x%08x hdrlen=0x%x csum=0x%04x extoff=0x%x rev=0x%02x"
          % (fvlen, sig, attr, hlen, csum, extoff, rev))
    # block map at 0x38
    print("      block map:")
    p = b + 0x38
    total = 0
    while p + 8 <= b + hlen:
        nb, blk = struct.unpack_from('<II', s, p)
        print("        numblocks=0x%x blocklen=0x%x" % (nb, blk))
        if nb == 0:
            break
        total += nb * blk
        p += 8
    print("      blockmap total = 0x%x   FvLength = 0x%x   相等=%s  差=0x%x"
          % (total, fvlen, total == fvlen, fvlen - total))
    print("      FV end = 0x%x ; stream end = 0x%x ; diff = 0x%x" % (b+fvlen, len(s), len(s)-(b+fvlen)))
print()
print("=== 开头 0x10 字节区域 差异 ===")
d = [i for i in range(0x20) if sm[i]!=so[i]]
print("  差异字节:", [hex(i) for i in d])
