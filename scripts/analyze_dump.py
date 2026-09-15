import hashlib, struct

D = open("received/20260913-160333_1.bin",'rb').read()
MINE = open("JYZ6PA08_ReBAR.bin",'rb').read()
ORIG = open("JYZ6PA08_ORIG.bin",'rb').read()

print("sizes: dump=%d mine=%d orig=%d" % (len(D), len(MINE), len(ORIG)))
print("sha256 dump =", hashlib.sha256(D).hexdigest()[:32])
print("sha256 mine =", hashlib.sha256(MINE).hexdigest()[:32])
print("sha256 orig =", hashlib.sha256(ORIG).hexdigest()[:32])
print()

def blocks(buf, name):
    print("=== per-1MB block content profile: %s ===" % name)
    print("  offset      FF%%    00%%   other%   first-nonFF  last-nonFF")
    for i in range(16):
        b = buf[i<<20:(i+1)<<20]
        ff = b.count(0xFF); z = b.count(0x00)
        other = len(b) - ff - z
        nz = [j for j in range(len(b)) if b[j] != 0xFF]
        f = ("0x%x" % ((i<<20)+nz[0])) if nz else "-"
        l = ("0x%x" % ((i<<20)+nz[-1])) if nz else "-"
        print("  0x%06x  %6.2f  %6.2f  %6.2f   %-10s %s" % (i<<20, ff/len(b)*100, z/len(b)*100, other/len(b)*100, f, l))
    print()

blocks(D, "PROGRAMMER DUMP")
blocks(MINE, "MY INJECTED IMAGE")
blocks(ORIG, "ORIGINAL VENDOR")

# diff dump vs mine
diff_m = [i for i in range(len(D)) if D[i]!=MINE[i]]
diff_o = [i for i in range(len(D)) if D[i]!=ORIG[i]]
print("dump vs MINE : differing bytes = %d" % len(diff_m))
if diff_m:
    print("   first=0x%x last=0x%x" % (diff_m[0], diff_m[-1]))
print("dump vs ORIG : differing bytes = %d" % len(diff_o))
if diff_o:
    print("   first=0x%x last=0x%x" % (diff_o[0], diff_o[-1]))
print()

# what does the dump look like in the injection window?
print("=== injection window 0x4d10c0 area sample ===")
for off in (0x0, 0x4d10c0, 0x4d10e0, 0x4d1200, 0x500000, 0x800000, 0x809bf2, 0x810000, 0x900000, 0xa00000, 0xc00000, 0xe00000, 0xfff000):
    print("  0x%07x dump=%s" % (off, D[off:off+16].hex()), end="")
    print("   mine=%s" % MINE[off:off+16].hex(), end="")
    print("   orig=%s" % ORIG[off:off+16].hex())
print()

# region-level: which 64KB blocks of dump are all-FF and what mine says there
print("=== all-FF 64KB blocks in dump vs mine ===")
allff = []
for i in range(0, len(D), 0x10000):
    if all(b == 0xFF for b in D[i:i+0x10000]):
        allff.append(i)
print("dump all-FF 64K blocks: %d  (first=0x%x last=0x%x)" % (len(allff), allff[0] if allff else -1, allff[-1] if allff else -1))
mine_ff = [i for i in range(0, len(MINE), 0x10000) if all(b == 0xFF for b in MINE[i:i+0x10000])]
print("mine all-FF 64K blocks: %d  (first=0x%x last=0x%x)" % (len(mine_ff), mine_ff[0] if mine_ff else -1, mine_ff[-1] if mine_ff else -1))
orig_ff = [i for i in range(0, len(ORIG), 0x10000) if all(b == 0xFF for b in ORIG[i:i+0x10000])]
print("orig all-FF 64K blocks: %d  (first=0x%x last=0x%x)" % (len(orig_ff), orig_ff[0] if orig_ff else -1, orig_ff[-1] if orig_ff else -1))

print()
print("=== all-ZERO 64KB blocks ===")
for nm, buf in (("dump", D), ("mine", MINE), ("orig", ORIG)):
    z = [i for i in range(0, len(buf), 0x10000) if all(b == 0x00 for b in buf[i:i+0x10000])]
    print("%s: %d all-zero 64K blocks %s" % (nm, len(z), ("first=0x%x last=0x%x" % (z[0], z[-1])) if z else ""))
