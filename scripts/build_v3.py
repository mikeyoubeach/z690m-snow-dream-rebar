"""v3 = 方案B：把驱动插入外层 FVMAIN(0x470000) 的空闲区。不改任何尺寸、不改 FV 头、DXE 子卷 100% 原厂。"""
import struct, uuid, lzma, hashlib

FFS = bytearray(open("NvStrapsReBar.ffs",'rb').read())
mod = bytearray(FFS); mod[23] = 0xF8                 # 擦除极性 1 -> state 0xF8
img = bytearray(open("JYZ6PA08_ORIG.bin",'rb').read())

FV = 0x470000
fvlen  = struct.unpack_from('<Q', img, FV+0x20)[0]
hdrlen = struct.unpack_from('<H', img, FV+0x30)[0]
attr   = struct.unpack_from('<I', img, FV+0x2C)[0]
print("FVMAIN: fvlen=0x%x hdrlen=0x%x attr=0x%08x 擦除极性=%d" % (fvlen, hdrlen, attr, 1 if attr & 0x800 else 0))
assert attr & 0x800, "极性不是 1"

off = (FV+hdrlen+7)&~7; end = FV+fvlen; files=[]
while off+24 <= end:
    g = img[off:off+16]
    sz = int.from_bytes(img[off+20:off+23],'little')
    if sz < 24 or off+sz > end: break
    files.append((off, str(uuid.UUID(bytes_le=bytes(g))), img[off+18], sz, img[off+23]))
    off = (off+sz+7)&~7
print("FVMAIN 现有 %d 个文件:" % len(files))
for o,g,t,sz,st in files:
    print("   @0x%x type=0x%02x size=0x%x state=0x%02x %s" % (o,t,sz,st,g))
last = files[-1]
INS = (last[0]+last[3]+7)&~7
print("插入位置 = 0x%x (最后一个文件结束对齐处)，其前 32 字节:" % INS, img[INS-32:INS].hex())
print("插入位置起 32 字节:", img[INS:INS+32].hex())
assert all(b==0xFF for b in img[INS:INS+len(mod)+4096]), "插入点不是空闲 FF 区!"
assert INS+len(mod) <= end, "放不下"

img[INS:INS+len(mod)] = mod
open("JYZ6PA08_ReBAR_v3.bin",'wb').write(bytes(img))
print("写出 JYZ6PA08_ReBAR_v3.bin  (插入 %d 字节)" % len(mod))

# ---- 自验 ----
O = open("JYZ6PA08_ORIG.bin",'rb').read(); V = open("JYZ6PA08_ReBAR_v3.bin",'rb').read()
assert len(V)==len(O)==0x1000000
d = [i for i in range(len(V)) if V[i]!=O[i]]
print("\n[1] 与原始镜像差异: %d 字节, 范围 0x%x..0x%x (应恰好 = 插入的 %d 字节)"
      % (len(d), d[0], d[-1], len(mod)))
assert d[0] >= INS and d[-1] < INS+len(mod), "差异越出插入区间!"
assert V[:INS] == O[:INS] and V[INS+len(mod):] == O[INS+len(mod):], "插入区间外有改动!"
print("[1b] 插入区间外 0x%x..0x%x 与 0x%x.. 全部字节级一致" % (0, INS, INS+len(mod)))
print("[1c] 模块内 %d 字节与原空闲区同值(0xFF)故不计入差异" % (len(mod)-len(d)))
print("[2] FVMAIN 头 0x%x 字节未改: %s" % (hdrlen, V[FV:FV+hdrlen]==O[FV:FV+hdrlen]))
print("[3] 整块压缩 DXE 子卷未改(容器 FFs 与压缩数据均原样): %s"
      % (V[0x4d10c0:0x80ca57]==O[0x4d10c0:0x80ca57]))
# 模块校验
f = V[INS:INS+len(mod)]
h = bytearray(f[:24]); h[16]=0; h[17]=0; h[23]=0
print("[4] 模块头校验和: %s ; 数据校验和: %s ; state=0x%02x"
      % (((0x100-(sum(h)&0xff))&0xff)==f[16], ((sum(f[24:])+f[17])&0xff)==0, f[23]))
print("[5] 内容 == 官方 v0.3 ffs(仅 state 翻转): %s"
      % (f[:23]==open("NvStrapsReBar.ffs",'rb').read()[:23] and f[24:]==open("NvStrapsReBar.ffs",'rb').read()[24:]))
print("[6] 插入后剩余空闲: %d KB 全 FF: %s" % ((end-INS-len(mod))//1024, all(b==0xFF for b in V[INS+len(mod):end])))
print("\nSHA256 v3 =", hashlib.sha256(V).hexdigest())
