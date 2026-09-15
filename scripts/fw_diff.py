import sys
from uefi_firmware import AutoParser

def walk(obj, out, path=""):
    from uefi_firmware.guids import get_guid_name
    try:
        if hasattr(obj, 'guid'):
            guid = obj.guid
        else:
            guid = None
    except Exception:
        guid = None
    # generic: iterate objects structure via uefi object model is complex;
    # instead use parse_classes
    return out

def collect(path):
    data = open(path, 'rb').read()
    p = AutoParser(data)
    fw = p.parse()
    mods = {}

    def recurse(obj):
        from uefi_firmware.firmware import Firmware
        for attr in ('objects',):
            pass
        # FirmwareTreeNode style
        if hasattr(obj, 'fla'):
            pass
        # generic children
        kids = []
        if hasattr(obj, 'objects') and isinstance(obj.objects, list):
            kids += obj.objects
        if hasattr(obj, 'parsing_objects') and isinstance(obj.parsing_objects, list):
            kids += obj.parsing_objects
        for child in kids:
            recurse(child)
        # record
        name = getattr(obj, 'name', None)
        guid = getattr(obj, 'guid', None)
        if guid is not None:
            import binascii
            try:
                g = binascii.hexlify(guid).decode() if isinstance(guid, (bytes, bytearray)) else str(guid)
            except Exception:
                g = str(guid)
            key = g
            info = mods.setdefault(key, {'name': '', 'type': getattr(obj, 'type', None), 'size': 0})
            if name:
                try:
                    info['name'] = name.decode('utf-16-le', 'ignore').rstrip('\x00') if isinstance(name, (bytes, bytearray)) else str(name)
                except Exception:
                    pass
            if hasattr(obj, 'size'):
                try:
                    info['size'] = max(info['size'], int(obj.size))
                except Exception:
                    pass

    recurse(fw)
    return mods

a = collect(sys.argv[1])
b = collect(sys.argv[2])
ka, kb = set(a), set(b)
print(f"PA08 modules: {len(ka)}  PA05 modules: {len(kb)}")
print(f"only in PA08: {len(ka-kb)}, only in PA05: {len(kb-ka)}")
for g in sorted(ka - kb):
    print("  +PA08", g, a[g])
for g in sorted(kb - ka):
    print("  +PA05", g, b[g])
# size/name changes
changed = 0
for g in ka & kb:
    if a[g]['name'] != b[g]['name'] or abs(a[g]['size'] - b[g]['size']) > 0:
        changed += 1
        print(f"  ~diff {g}\n      PA05: {b[g]}\n      PA08: {a[g]}")
print(f"changed modules: {changed}")
