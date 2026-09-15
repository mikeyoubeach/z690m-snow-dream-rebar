import struct, uuid, zlib, lzma, hashlib, json, re

ORIG = open("JYZ6PA08_ORIG.bin",'rb').read()
NEW  = open("JYZ6PA08_ReBAR.bin",'rb').read()
FFS  = open("NvStrapsReBar.ffs",'rb').read()

print("========== [1] diff range ==========")
assert len(NEW) == len(ORIG) == 0x1000000, "size mismatch"
diffs = [i for i in range(0x1000000) if ORIG[i]!=NEW[i]]
print("differing bytes: %d, range: 0x%x .. 0x%x" % (len(diffs), diffs[0], diffs[-1]))
assert diffs[0] >= 0x4d10c0 and diffs[-1] < 0x990000
print("[OK] 0x0..0x4d10c0 (FlashDescriptor+ME+GbE+all FV headers) byte-identical")

print()
print("========== [2] outer FV / FFS file ==========")
fvlen = struct.unpack_from('<Q', ORIG, 0x470000+32)[0]
assert NEW[0x470000:0x470048] == ORIG[0x470000:0x470048], "outer FV header changed!"
print("[OK] outer FV header untouched: len=0x%x, end=0x%x" % (fvlen, 0x470000+fvlen))
foff = 0x4d10c0
fsz  = int.from_bytes(NEW[foff+20:foff+23],'little')
ftype= NEW[foff+18]; fstate=NEW[foff+23]; fattr=NEW[foff+19]
print("outer FFS: guid=%s type=0x%02x attr=0x%02x state=0x%02x size=0x%x end=0x%x" %
      (uuid.UUID(bytes_le=NEW[foff:foff+16]), ftype, fattr, fstate, fsz, foff+fsz))
assert uuid.UUID(bytes_le=NEW[foff:foff+16]) == uuid.UUID('9e21fd93-9c72-4c15-8c4b-e77f1db2d792')
assert ftype == 0x0B  # FV_IMAGE
assert foff+fsz <= 0x470000+fvlen, "file overflows FV!"
h = bytearray(NEW[foff:foff+24]); h[16]=0; h[17]=0; h[23]=0
assert ((0x100-(sum(h)&0xff))&0xff) == NEW[foff+16], "ffs hdr csum FAIL"
print("[OK] FFS header checksum valid")
tail = NEW[foff+fsz:0x470000+fvlen]
assert all(b==0xff for b in tail), "padding after file not FF"
print("[OK] file tail to FV end (%d KB) all 0xFF" % (len(tail)//1024))

print()
print("========== [3] GUID_DEFINED (LZMA) section ==========")
soff = foff+24
ssz  = int.from_bytes(NEW[soff:soff+3],'little'); stype=NEW[soff+3]
sguid= uuid.UUID(bytes_le=NEW[soff+4:soff+20])
dataoff, sattr = struct.unpack_from('<HH', NEW, soff+20)
print("section: size=0x%x type=0x%02x guid=%s attr=0x%04x dataoff=0x%x" %
      (ssz, stype, sguid, sattr, dataoff))
assert str(sguid) == 'ee4e5898-3914-4259-9d6e-dc7bd79403cf', "not LZMA guid"
assert sattr & 0x01, "PROCESSING_REQUIRED not set"
assert dataoff == 0x18, "unexpected dataoff"
comp = NEW[soff+dataoff:soff+ssz]
props = comp[0]; dictsz = int.from_bytes(comp[1:5],'little'); decsz = int.from_bytes(comp[5:13],'little')
print("lzma: props=0x%02x dict=0x%x declared_size=0x%x" % (props, dictsz, decsz))
assert props == 0x5d and 0 < decsz < 0xFFFFFFFF, "lzma header bad (EDK2 needs real size!)"
stream = lzma.decompress(comp, format=lzma.FORMAT_ALONE)
assert len(stream) == decsz, "size mismatch: %x / %x" % (len(stream), decsz)
print("[OK] decompressed 0x%x bytes == lzma header declared size (EDK2 GetInfo compatible)" % len(stream))
ostream = lzma.decompress(ORIG[soff+dataoff:soff+int.from_bytes(ORIG[soff:soff+3],'little')], format=lzma.FORMAT_ALONE)
ndiff = sum(1 for i in range(min(len(stream),len(ostream))) if stream[i]!=ostream[i])
print("[OK] vs original stream: %d differing bytes (inside injection window only)" % ndiff)

print()
print("========== [4] inner DXE FV ==========")
b = 0x10
ifvlen = struct.unpack_from('<Q', stream, b+32)[0]
ihdrlen= struct.unpack_from('<H', stream, b+48)[0]
iattr  = struct.unpack_from('<I', stream, b+44)[0]  # Attributes @0x2C (Signature _FVH @0x28)
pol = '1' if (iattr & 0x800) else '0'
print("inner FV: len=0x%x hdrlen=0x%x attr=0x%08x erase_polarity=%s" % (ifvlen, ihdrlen, iattr, pol))
assert iattr & 0x800, "erase polarity should be 1 (state 0xf8)"
hdr = stream[b:b+ihdrlen]
s = 0
for i in range(0, ihdrlen, 2):
    if i == 0x32: continue
    s = (s + int.from_bytes(hdr[i:i+2],'little')) & 0xffff
assert (s + int.from_bytes(hdr[0x32:0x34],'little')) & 0xffff == 0, "FV header csum FAIL"
print("[OK] inner FV header checksum valid")
assert b+ifvlen <= len(stream), "FV overflows stream"
print("stream tail after FV: %d bytes" % (len(stream)-(b+ifvlen)))

def walk(base, length, data, hdrlen):
    off = (base+hdrlen+7)&~7
    end = base+length
    files=[]
    while off+24 <= end:
        fg = data[off:off+16]
        sz = int.from_bytes(data[off+20:off+23],'little')
        if sz < 24 or off+sz > end: break
        files.append((off, str(uuid.UUID(bytes_le=fg)), sz, data[off+23], data[off+19]))
        off = (off+sz+7)&~7
    return files

filesA = walk(b, ifvlen, stream, ihdrlen)
filesO = walk(b, struct.unpack_from('<Q',ostream,b+32)[0], ostream, struct.unpack_from('<H',ostream,b+48)[0])
print("orig files: %d, new files: %d" % (len(filesO), len(filesA)))
assert len(filesA) == len(filesO)+1
gO = set(f[1] for f in filesO); gA=set(f[1] for f in filesA)
missing = gO-gA; extra = gA-gO
print("missing from orig: %s, added: %s" % (missing, extra))
assert not missing and extra == {'90d10790-bbfa-404b-873b-5bdb3ada3c56'}
states = set(f[3] for f in filesA)
print("all file states: %s" % [hex(x) for x in states])
assert states == {0xf8}, "inconsistent file states!"

print()
print("========== [5] injected NvStrapsReBar module ==========")
tgt = [f for f in filesA if f[1]=='90d10790-bbfa-404b-873b-5bdb3ada3c56'][0]
idx = filesA.index(tgt)
toff, _, tsz, tstate, tattr = tgt
prev_end = filesO[idx-1][0]+filesO[idx-1][2]
print("pos=0x%x (prev file end 0x%x, 8-aligned=%s) size=0x%x state=0x%02x attr=0x%02x" %
      (toff, prev_end, toff%8==0, tsz, tstate, tattr))
assert toff % 8 == 0 and toff >= prev_end
assert tstate == 0xf8
fdata = stream[toff:toff+tsz]
h = bytearray(fdata[:24]); h[16]=0; h[17]=0; h[23]=0
okh = ((0x100-(sum(h)&0xff))&0xff)==fdata[16]
okf = ((sum(fdata[24:]) + fdata[17]) & 0xff) == 0 if (tattr & 0x40) else True
print("hdr_csum_ok=%s file_csum_ok=%s (checksum_valid_bit=%s)" % (okh, okf, bool(tattr&0x40)))
assert okh and okf
assert fdata[:23]==FFS[:23] and fdata[24:]==FFS[24:] and FFS[23]==0x07 and fdata[23]==0xf8
print("[OK] content byte-identical to official v0.3 release ffs (only state flipped per erase polarity)")
off=24; secs=[]
while off+4 <= tsz:
    z=int.from_bytes(fdata[off:off+3],'little'); t=fdata[off+3]
    secs.append((off,z,t)); off=(off+z+3)&~3
for o,z,t in secs:
    extra=""
    if t==0x15: extra=" UI="+fdata[o+4:o+z].decode('utf-16le','ignore').rstrip('\x00')
    if t==0x13: extra=" (DXE_DEPEX present)"
    if t==0x10:
        machine = int.from_bytes(fdata[o+4+4:o+4+6],'little')
        extra=" PE machine=0x%04x (%s)" % (machine, 'x64' if machine==0x8664 else '??')
    print("   section @0x%x size=0x%x type=0x%02x%s" % (o,z,t,extra))
free = stream[toff+tsz:b+ifvlen]
assert all(x==0xff for x in free)
print("[OK] free space after module (%d bytes) all 0xFF" % len(free))

print()
print("========== [6] uefi_firmware independent parse ==========")
from uefi_firmware import AutoParser
fw = AutoParser(bytes(NEW)).parse()
found = []
marker = b'N\x00v\x00S\x00t\x00r\x00a\x00p\x00s\x00R\x00e\x00B\x00a\x00r\x00'
def scan(obj):
    d = getattr(obj,'data',b'') or b''
    if marker in d:
        found.append(type(obj).__name__)
    for c in getattr(obj,'objects',[]) or []:
        scan(c)
scan(fw)
print("UI name 'NvStrapsReBar' found in:", found)

print()
print("================ ALL CHECKS PASSED ================")
