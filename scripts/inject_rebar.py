# Inject NvStrapsReBar.ffs into JYZ6PA08.bin (FvMainCompact LZMA route)
# Original bin preserved as JYZ6PA08_ORIG.bin
import struct, uuid, lzma, shutil, sys

SRC = "PA08_ext/JYZ6PA08/U盘自动刷/EFI/BIN/JYZ6PA08.bin"
OUT = "JYZ6PA08_ReBAR.bin"
FFS = "NvStrapsReBar.ffs"
FFS_GUID = uuid.UUID("90d10790-bbfa-404b-873b-5bdb3ada3c56")

data = open(SRC, 'rb').read()
ffs = open(FFS, 'rb').read()
decomp = bytearray(open("fvmain_decomp.bin", 'rb').read())

assert len(data) == 0x1000000

# ---------- 1) modify decompressed FV ----------
b = 0x10                      # FV base in decomp
fvlen = struct.unpack_from('<Q', decomp, b+32)[0]
hdrlen = struct.unpack_from('<H', decomp, b+48)[0]
assert decomp[b+40:b+44] == b'_FVH'

# find last real file end
off = (b + hdrlen + 7) & ~7
end = b + fvlen
last_end = b + hdrlen
guids = []
while off + 24 <= end:
    fg = bytes(decomp[off:off+16])
    sz = int.from_bytes(decomp[off+20:off+23], 'little')
    if fg == b'\xff'*16 and sz == 0xFFFFFF:
        break
    if sz < 24 or off + sz > end:
        break
    guids.append(str(uuid.UUID(bytes_le=fg)))
    last_end = off + sz
    off = (off + sz + 7) & ~7
print(f"[1] inner FV: files={len(guids)} last_end={last_end:#x} fvlen={fvlen:#x}")

# insert point = last_end aligned 8
ins = (last_end + 7) & ~7
ins = ins - b + 0x10  # keep absolute in stream (b==0x10 so same arithmetic)
ffs_mod = bytearray(ffs)
assert ffs_mod[23] == 0x07
ffs_mod[23] = 0xf8          # erase polarity 1
new_fvlen = 0xff0000
assert ins + len(ffs_mod) <= b + new_fvlen, "no room"

# write ffs + free space (extend buffer to new FV end first)
decomp[ins:ins+len(ffs_mod)] = ffs_mod
if len(decomp) < b + new_fvlen:
    decomp.extend(b'\xff' * (b + new_fvlen - len(decomp)))
for i in range(ins + len(ffs_mod), b + new_fvlen):
    decomp[i] = 0xFF
# pad tail of old FV area is already covered (we wrote FF up to new end)

# patch FvLength + FV header checksum
old_fvlen = struct.unpack_from('<Q', decomp, b+32)[0]
struct.pack_into('<Q', decomp, b+32, new_fvlen)
s = 0
for i in range(0, hdrlen, 2):
    if i == 0x32: continue
    s = (s + int.from_bytes(decomp[b+i:b+i+2], 'little')) & 0xffff
csum = (0x10000 - s) & 0xffff
struct.pack_into('<H', decomp, b+0x32, csum)
print(f"[1] inserted ffs @stream {ins:#x} size {len(ffs_mod):#x}; fvlen {old_fvlen:#x} -> {new_fvlen:#x}; fvh csum={csum:#06x}")

# ---------- 2) rebuild section stream ----------
RAW_PAD = bytes(decomp[0:0xc])          # original leading RAW section
assert decomp[3] == 0x19
stream = bytearray()
stream += RAW_PAD
sec_hdr = bytearray(4)
sec_len = 4 + new_fvlen
sec_hdr[0] = sec_len & 0xff; sec_hdr[1] = (sec_len >> 8) & 0xff; sec_hdr[2] = (sec_len >> 16) & 0xff
sec_hdr[3] = 0x17
stream += sec_hdr
stream += decomp[b: b + new_fvlen]
print(f"[2] new section stream size: {len(stream):#x}")

# ---------- 3) recompress LZMA (same props: lc3 lp0 pb2 dict 16M) ----------
filt = [{'id': lzma.FILTER_LZMA1, 'preset': 9, 'dict_size': 0x1000000, 'lc': 3, 'lp': 0, 'pb': 2}]
comp = bytearray(lzma.compress(bytes(stream), format=lzma.FORMAT_ALONE, filters=filt))
# python writes unknown-size (0xFFFF..) + EOS marker; EDK2 needs the real unpacked size in header
struct.pack_into('<Q', comp, 5, len(stream))
print(f"[3] compressed: {len(comp):#x} (orig 0x33b967)  props={comp[:5].hex()} declen={int.from_bytes(comp[5:13],'little')}")
assert comp[:5] == b'\x5d\x00\x00\x00\x01', "props mismatch"
assert int.from_bytes(comp[5:13],'little') == len(stream)
# roundtrip check
rt = lzma.decompress(comp, format=lzma.FORMAT_ALONE)
assert rt == bytes(stream), "roundtrip mismatch"
print("[3] roundtrip OK")

# ---------- 4) rebuild outer FFS file + section header ----------
foff = 0x4d10c0
fopts = bytes(data[foff:foff+24])       # original file header
sec_off = foff + 24
new_sec_size = 0x18 + len(comp)         # GUIDED section header is 24 (0x18) bytes total
new_file_size = 24 + new_sec_size
assert new_file_size < 0xFFFFFF

new_file = bytearray(24)
new_file[0:16] = data[foff:foff+16]     # GUID 9e21fd93...
new_file[16] = 0                        # header checksum, computed below
new_file[17] = 0xAA                     # fixed file checksum (attrs=0)
new_file[18] = data[foff+18]            # type
new_file[19] = data[foff+19]            # attrs = 0
new_file[20] = new_file_size & 0xff
new_file[21] = (new_file_size >> 8) & 0xff
new_file[22] = (new_file_size >> 16) & 0xff
new_file[23] = 0x00                     # state placeholder (excluded from csum)
# PI spec: header checksum computed with HeaderChecksum, FileChecksum and State all zeroed
new_file[17] = 0x00                     # temporarily zero FileChecksum for the sum
hsum = (0x100 - (sum(new_file) & 0xff)) & 0xff
new_file[16] = hsum
new_file[17] = 0xAA                     # fixed file checksum (attrs=0)
new_file[23] = data[foff+23]            # keep original state (0xf8)

new_sec = bytearray(24)
new_sec[0] = new_sec_size & 0xff
new_sec[1] = (new_sec_size >> 8) & 0xff
new_sec[2] = (new_sec_size >> 16) & 0xff
new_sec[3] = 0x02                       # GUID_DEFINED
new_sec[4:20] = data[sec_off+4:sec_off+20]   # LZMA GUID
struct.pack_into('<H', new_sec, 20, 0x18)    # DataOffset
struct.pack_into('<H', new_sec, 22, data[sec_off+22] | (data[sec_off+23] << 8))  # Attributes

blob = bytes(new_file) + bytes(new_sec) + comp

# ---------- 5) splice into bin ----------
NEXT = 0x990000                          # next FV region boundary
out = bytearray(data)
out[foff:NEXT] = blob + b'\xff' * (NEXT - foff - len(blob))
assert len(out) == 0x1000000
# sanity: everything outside [foff, NEXT) must be identical
assert out[:foff] == data[:foff] and out[NEXT:] == data[NEXT:]
print(f"[5] new file region: {foff:#x}..{foff+len(blob):#x} (grow {len(blob)-(0x990000-foff-b'\xff'.__len__())+0:+d} vs orig content)")

open(OUT, 'wb').write(bytes(out))
print("[5] written", OUT, len(out), "bytes")
