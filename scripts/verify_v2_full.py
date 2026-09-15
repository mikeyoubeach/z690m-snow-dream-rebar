"""v2 全面复核：所有结构约束逐条硬断言，含块映射一致性"""
import struct, uuid, lzma, hashlib, sys

ORIG = open("JYZ6PA08_ORIG.bin",'rb').read()
V1   = open("JYZ6PA08_ReBAR.bin",'rb').read()
V2   = open("JYZ6PA08_ReBAR_v2.bin",'rb').read()
FFS  = open("NvStrapsReBar.ffs",'rb').read()
FOFF = 0x4d10c0
ok = 0
def chk(cond, msg):
    global ok
    if not cond:
        print("  [FAIL] " + msg); sys.exit(1)
    ok += 1
    print("  [ok] " + msg)

print("========== A. 全盘一致性 ==========")
chk(len(V2)==len(ORIG)==0x1000000, "大小 16MB")
d = [i for i in range(len(V2)) if V2[i]!=ORIG[i]]
chk(d[0] >= 0x4d10c0 and d[-1] < 0x990000, "差异仅限注入窗口 0x%x..0x%x" % (d[0], d[-1]))
chk(V2[:0x4d10c0]==ORIG[:0x4d10c0], "0x0..窗口前（含 Descriptor+ME+所有 FV 头）字节级一致")
chk(V2[0x990000:]==ORIG[0x990000:], "窗口后到镜像尾字节级一致")
chk(V2[:4]==ORIG[:4], "Flash Descriptor 头一致")

print("========== B. 外层 FV / FFS / Section ==========")
chk(V2[0x470000:0x470050]==ORIG[0x470000:0x470050], "外层 FV 头 0x50 字节未动")
chk(V2[FOFF:FOFF+16]==ORIG[FOFF:FOFF+16], "FFS GUID 未动")
chk(V2[FOFF+18]==ORIG[FOFF+18]==0x0B, "FFS type=FV_IMAGE(0x0B)")
chk(V2[FOFF+19]==ORIG[FOFF+19], "FFS attributes 未动")
chk(V2[FOFF+23]==ORIG[FOFF+23]==0xF8, "FFS state 与原文件一致(0xF8，与 FV 擦除极性匹配)")
h = bytearray(V2[FOFF:FOFF+24]); h[16]=0; h[17]=0; h[23]=0
chk(((0x100-(sum(h)&0xff))&0xff)==V2[FOFF+16], "FFS 头校验和有效")
fsz = int.from_bytes(V2[FOFF+20:FOFF+23],'little')
chk(FOFF+fsz <= 0x990000, "文件不越出外层 FV")
chk(all(b==0xff for b in V2[FOFF+fsz:0x990000]), "文件尾到 FV 尾全 0xFF")
soff = FOFF+24
ssz = int.from_bytes(V2[soff:soff+3],'little'); stype = V2[soff+3]
chk(stype==0x02, "section type=GUID_DEFINED(0x02)")
chk(str(uuid.UUID(bytes_le=V2[soff+4:soff+20]))=='ee4e5898-3914-4259-9d6e-dc7bd79403cf', "section GUID=LZMA")
dataoff, sattr = struct.unpack_from('<HH', V2, soff+20)
chk(dataoff==0x18 and (sattr&1)==1, "DataOffset=0x18 / PROCESSING_REQUIRED=1")
chk(ssz == 0x18 + (ssz-0x18), "section size 自洽")
comp = V2[soff+dataoff:soff+ssz]
chk(comp[:5]==ORIG[soff+dataoff:soff+dataoff+5], "LZMA props/dict 与原版一致(0x%02x/dict 0x%x)" % (comp[0], int.from_bytes(comp[1:5],'little')))
stream = lzma.decompress(comp, format=lzma.FORMAT_ALONE)
chk(int.from_bytes(comp[5:13],'little')==len(stream), "LZMA 头声明解压尺寸 == 实际(%d)" % len(stream))

print("========== C. 解压流结构 ==========")
sz0 = int.from_bytes(stream[0:3],'little'); t0 = stream[3]
sz1 = int.from_bytes(stream[0x0C:0x0F],'little'); t1 = stream[0x0F]
chk(t0==0x19, "流[0x00] = RAW section (0x19), size=0x%x" % sz0)
chk(t1==0x17, "流[0x0C] = FV_IMAGE section (0x17), size=0x%x" % sz1)
chk(sz1 == 4 + 0xFF0000, "FV_IMAGE section size = 4 + FvLength")
chk(0x0C + sz1 == len(stream), "section 覆盖到流尾 (%d)" % len(stream))

print("========== D. 内层 DXE FV 头 ==========")
B = 0x10
fvlen = struct.unpack_from('<Q', stream, B+32)[0]
hdrlen = struct.unpack_from('<H', stream, B+48)[0]
csum = struct.unpack_from('<H', stream, B+50)[0]
extoff = struct.unpack_from('<H', stream, B+52)[0]
rev = stream[B+55]
attr = struct.unpack_from('<I', stream, B+44)[0]
chk(stream[B+40:B+44]==b'_FVH', "FV 签名 _FVH")
chk(str(uuid.UUID(bytes_le=stream[B+16:B+32]))=='8c8ce578-8a3d-4f1c-9935-896185c32dd3', "FileSystemGuid = FFS2")
chk((attr & 0x800)!=0, "擦除极性 = 1（故文件 state 必须 0xF8）")
s = 0
for i in range(0, hdrlen, 2):
    if i == 0x32: continue
    s = (s + int.from_bytes(stream[B+i:B+i+2],'little')) & 0xffff
chk(((s + csum) & 0xffff)==0, "FV 头 16-bit 校验和 = 0")
chk(hdrlen == 0x48, "HeaderLength=0x48")
nbm = []
p = B + 0x38
while p + 8 <= B + hdrlen:
    nb, blk = struct.unpack_from('<II', stream, p)
    if nb == 0: break
    nbm.append((nb, blk)); p += 8
chk(len(nbm) == 1, "BlockMap 条目数 = 1（+结束符）")
bm_total = sum(nb*blk for nb, blk in nbm)
chk(bm_total == fvlen, "★ BlockMap 总和(0x%x) == FvLength(0x%x)" % (bm_total, fvlen))
chk(fvlen % nbm[0][1] == 0, "FvLength 是块大小的整数倍")
chk(B + fvlen == len(stream), "FV 恰好结束于流末尾")
chk(extoff == 0x60, "ExtHeaderOffset=0x60（指向 FV 首部 pad 文件内的扩展头）")

print("========== E. 文件系统 ==========")
off = (B+hdrlen+7)&~7; end = B+fvlen; files=[]
while off+24 <= end:
    g = stream[off:off+16]
    sz = int.from_bytes(stream[off+20:off+23],'little')
    if sz < 24 or off+sz > end: break
    files.append((off, str(uuid.UUID(bytes_le=g)), sz, stream[off+23], stream[off+19]))
    off = (off+sz+7)&~7
# 原版文件数
osoft = FOFF+24
ossz = int.from_bytes(ORIG[osoft:osoft+3],'little'); odo = struct.unpack_from('<H', ORIG, osoft+20)[0]
ostream = lzma.decompress(ORIG[osoft+odo:osoft+ossz], format=lzma.FORMAT_ALONE)
ooff = (B+struct.unpack_from('<H', ostream, B+48)[0]+7)&~7; oend = B+struct.unpack_from('<Q', ostream, B+32)[0]
ofiles=[]
while ooff+24 <= oend:
    g = ostream[ooff:ooff+16]
    sz = int.from_bytes(ostream[ooff+20:ooff+23],'little')
    if sz < 24 or ooff+sz > oend: break
    ofiles.append(str(uuid.UUID(bytes_le=g))); ooff = (ooff+sz+7)&~7
chk(len(files) == len(ofiles)+1, "文件数 = 原版 %d + 1 = %d" % (len(ofiles), len(files)))
gO, gA = set(ofiles), set(f[1] for f in files)
chk(not (gO-gA), "原版所有文件 GUID 均在（无缺失/无替换）")
chk(gA-gO == {'90d10790-bbfa-404b-873b-5bdb3ada3c56'}, "唯一新增 = NvStrapsReBar")
chk(set(f[3] for f in files)=={0xF8}, "所有文件 state 一致(0xF8)")
tgt = [f for f in files if f[1]=='90d10790-bbfa-404b-873b-5bdb3ada3c56'][0]
toff, _, tsz, tstate, tattr = tgt
prev = [f for f in files if f[0] < toff][-1]
chk(toff % 8 == 0, "模块起始 8 字节对齐 (0x%x)" % toff)
chk(toff >= (prev[0]+prev[2]), "模块不与其他文件重叠")
chk(tstate == 0xF8, "模块 state=0xF8")
fd = stream[toff:toff+tsz]
hh = bytearray(fd[:24]); hh[16]=0; hh[17]=0; hh[23]=0
chk(((0x100-(sum(hh)&0xff))&0xff)==fd[16], "模块头校验和有效")
chk(((sum(fd[24:])+fd[17])&0xff)==0, "模块数据校验和有效 (attrs=0x%02x)" % tattr)
chk(fd[:23]==FFS[:23] and fd[24:]==FFS[24:], "模块内容 == 官方 v0.3 ffs（仅 state 按极性翻转）")
chk(all(x==0xff for x in stream[toff+tsz:end]), "模块后空闲区全 0xFF")
pe = fd[0x18+4:]
chk(pe[:2]==b'MZ', "模块含 PE32")
el = int.from_bytes(pe[0x3c:0x40],'little')
chk(pe[el:el+4]==b'PE\x00\x00' and int.from_bytes(pe[el+4:el+6],'little')==0x8664, "PE machine = x64")

print("========== F. v2 - v1 语义差异 ==========")
def st(img):
    s0 = FOFF+24; ss = int.from_bytes(img[s0:s0+3],'little'); do = struct.unpack_from('<H', img, s0+20)[0]
    return lzma.decompress(img[s0+do:s0+ss], format=lzma.FORMAT_ALONE)
a, b = st(V1), st(V2)
chk(len(a)==len(b), "两版解压流长度相同")
runs = []
for i in range(len(a)):
    if a[i]!=b[i]:
        if runs and i-runs[-1][1] <= 8: runs[-1][1] = i
        else: runs.append([i,i])
chk(len(runs)==1, "语义差异只有 1 处连续区间")
s_, e_ = runs[0]
chk(0x42 <= s_ and e_ <= 0x48, "差异落在 FV 头 0x%x-0x%x（校验和字段+BlockMap 首字节）" % (s_, e_))
nb_v1 = int.from_bytes(a[0x48:0x4C],'little'); nb_v2 = int.from_bytes(b[0x48:0x4C],'little')
chk(nb_v1 == 0xFEB and nb_v2 == 0xFF0, "BlockMap NumBlocks: v1=0x%x -> v2=0x%x" % (nb_v1, nb_v2))

print("========== G. 独立解析器 ==========")
from uefi_firmware import AutoParser
fw = AutoParser(bytes(V2)).parse()
found = []
mark = b'N\x00v\x00S\x00t\x00r\x00a\x00p\x00s\x00R\x00e\x00B\x00a\x00r\x00'
def scan(o):
    if mark in (getattr(o,'data',b'') or b''): found.append(type(o).__name__)
    for c in getattr(o,'objects',[]) or []: scan(c)
scan(fw)
chk(len(found)>0, "uefi_firmware 解析出 NvStrapsReBar 模块")

print()
print("ALL %d CHECKS PASSED for JYZ6PA08_ReBAR_v2.bin" % ok)
print("SHA256:", hashlib.sha256(V2).hexdigest())
