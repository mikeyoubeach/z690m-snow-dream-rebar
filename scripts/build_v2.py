"""Build v2: 与 v1 相同，但把内层 FV 的块映射表(BlockMap)与 FvLength 修正一致
   v1: FvLength=0xFF0000 但 BlockMap=0xFEB*0x1000=0xFEB000  ← 不一致(我的失误)
   v2: BlockMap numblocks 0xFEB -> 0xFF0 (=0xFF0000) + 重算 FV 头校验和
"""
import struct, lzma, uuid, hashlib

SRC = "JYZ6PA08_ORIG.bin"
OUT = "JYZ6PA08_ReBAR_v2.bin"
FFS = open("NvStrapsReBar.ffs",'rb').read()
img = bytearray(open(SRC,'rb').read())
FOFF = 0x4d10c0

soff = FOFF+24
ssz = int.from_bytes(img[soff:soff+3],'little')
dataoff = struct.unpack_from('<H', img, soff+20)[0]
comp = bytes(img[soff+dataoff:soff+ssz])
stream = bytearray(lzma.decompress(comp, format=lzma.FORMAT_ALONE))
print("[1] 原流 0x%x 字节, 原压缩 0x%x" % (len(stream), len(comp)))

B = 0x10
old_fvlen = struct.unpack_from('<Q', stream, B+32)[0]
old_hlen  = struct.unpack_from('<H', stream, B+48)[0]
nb, blk = struct.unpack_from('<II', stream, B+0x38)
print("[2] 原 FV: fvlen=0x%x hdrlen=0x%x blockmap=(0x%x x 0x%x)=0x%x" % (old_fvlen, old_hlen, nb, blk, nb*blk))

# 目标: 新长度 (v1 已算出) 与 模块插入
NEW_FVLEN = 0xFF0000
assert NEW_FVLEN % blk == 0, "not block aligned"
NEW_NB = NEW_FVLEN // blk
# 模块位置: 原 FV 末尾空闲区起点 (原最后一个文件结束的 8 字节对齐处)
off = (B+old_hlen+7)&~7; end_old = B+old_fvlen; last_end = off
while off+24 <= end_old:
    sz = int.from_bytes(stream[off+20:off+23],'little')
    if sz < 24 or off+sz > end_old: break
    last_end = (off+sz+7)&~7
    off = last_end
INS = last_end
print("[3] 最后一个文件结束(对齐) = 0x%x, 插入位置 = 0x%x" % (last_end, INS))

# 扩展流
if len(stream) < B + NEW_FVLEN:
    stream.extend(b'\xff' * (B + NEW_FVLEN - len(stream)))
# 翻转 ffs state (擦除极性 1)
mod = bytearray(FFS); mod[23] = 0xF8
# 插入
stream[INS:INS+len(mod)] = mod
# 之后填空
for i in range(INS+len(mod), B+NEW_FVLEN):
    stream[i] = 0xFF
print("[4] 插入 %d 字节模块" % len(mod))

# 修 FV 头: FvLength + BlockMap
struct.pack_into('<Q', stream, B+32, NEW_FVLEN)
stream[B+0x38:B+0x3C] = struct.pack('<I', NEW_NB)
stream[B+0x3C:B+0x40] = struct.pack('<I', blk)
# 校验和 = 使头 16bit 和 = 0 (Exclude 校验和字段 @0x32)
stream[B+0x32:B+0x34] = b'\x00\x00'
s = 0
for i in range(0, old_hlen, 2):
    if i == 0x32: continue
    s = (s + int.from_bytes(stream[B+i:B+i+2],'little')) & 0xffff
csum = (0x10000 - s) & 0xffff
struct.pack_into('<H', stream, B+0x32, csum)
print("[5] 新 FV: fvlen=0x%x blockmap=0x%x x 0x%x=0x%x  csum=0x%04x"
      % (NEW_FVLEN, NEW_NB, blk, NEW_NB*blk, csum))
assert NEW_NB*blk == NEW_FVLEN

# 流内的 FV_IMAGE section 尺寸 (offset 0x0C, 头 = size(3字节) + type(1字节), 只能写 3 字节!)
sec_size = 4 + NEW_FVLEN
assert stream[0x0F] == 0x17, "section type @0x0F 不是 FV_IMAGE(0x17)!"
stream[0x0C:0x0F] = sec_size.to_bytes(3,'little')
print("[6] 流内 FV_IMAGE section size = 0x%x ; 流长 = 0x%x ; 校验: 0x0C+0x%x = 0x%x"
      % (sec_size, len(stream), sec_size, 0x0C+sec_size))
assert 0x0C + sec_size == len(stream)

# 重新 LZMA 压缩 (保留原 props/dict)
props = comp[0]; dictsz = int.from_bytes(comp[1:5],'little')
filt = [{"id": lzma.FILTER_LZMA1, "preset": 9 | lzma.PRESET_EXTREME,
         "dict_size": dictsz, "lc": props % 9, "lp": (props//9) % 5, "pb": (props//45) % 5}]
newcomp = bytearray(lzma.compress(bytes(stream), format=lzma.FORMAT_ALONE, filters=filt))
struct.pack_into('<Q', newcomp, 5, len(stream))          # 写真实解压尺寸 (EDK2 需要)
assert newcomp[:5] == comp[:5], "props 不一致!"
print("[7] 新压缩 0x%x 字节 (原 0x%x), props/dict 一致" % (len(newcomp), len(comp)))

# 重建外层 FFS 文件
new_file_size = 24 + 0x18 + len(newcomp)
nsec = 0x18 + len(newcomp)
img[FOFF:FOFF+new_file_size] = b'\x00'*new_file_size   # clear
img[FOFF:FOFF+16] = open(SRC,'rb').read()[FOFF:FOFF+16]
img[FOFF+16:FOFF+24] = bytes([0,0,0x40,0,0,0,0,0])     # placeholder
img[FOFF+18] = 0x0B
img[FOFF+19] = 0x00
img[FOFF+20:FOFF+23] = new_file_size.to_bytes(3,'little')
img[FOFF+23] = 0xF8
img[FOFF+24:FOFF+28] = nsec.to_bytes(3,'little') + b'\x02'
img[FOFF+28:FOFF+44] = open(SRC,'rb').read()[FOFF+28:FOFF+44]
img[FOFF+44:FOFF+46] = (0x18).to_bytes(2,'little')
img[FOFF+46:FOFF+48] = (0x0001).to_bytes(2,'little')
img[FOFF+48:FOFF+48+len(newcomp)] = newcomp
# 文件头校验和 (HeaderChecksum/FileChecksum/State 均按 0 计)
h = bytearray(img[FOFF:FOFF+24]); h[16]=0; h[17]=0; h[23]=0
hsum = (0x100 - (sum(h)&0xff)) & 0xff
img[FOFF+16] = hsum
# 文件数据校验和 (attrs=0, 无校验和位 -> 保持 0)
img[FOFF+17] = 0x00
# 文件后到 FV 末尾全 FF
for i in range(FOFF+new_file_size, 0x990000):
    img[i] = 0xFF
open(OUT,'wb').write(bytes(img))
print("[8] 写出 %s (size=0x%x, 文件 end=0x%x)" % (OUT, len(img), FOFF+new_file_size))
