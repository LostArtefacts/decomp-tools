"""Copies the resources of a PE image (its .rsrc tree) into a .res file.

    rsrc.py IMAGE OUT.res

The .res is what rc would write for the same resources, so the linker
(through cvtres) builds an identical .rsrc from it. The original game's
resources are its icon and the icon's group. write_obj() writes the
object cvtres 5.00 would make of them, for a toolchain whose cvtres
lays them out differently.
"""
import struct, sys

import coff

RESOURCE_DIRECTORY = 2


def resources(path):
    """Yields (type, name, language, data) for each resource in the image,
    in the order of their data: cvtres lays the data out in .res order, so
    that is the order of the original .res. type and name are an int ID or
    a string."""
    img = coff.Image(path)
    pe = struct.unpack_from("<I", img.data, 0x3C)[0]
    rva, size = struct.unpack_from("<II", img.data, pe + 24 + 96 + 8 * RESOURCE_DIRECTORY)
    if not size:
        return
    base = img.base + rva
    tree = img.read(base, size)

    def entries(off):
        named, ids = struct.unpack_from("<HH", tree, off + 12)
        for i in range(named + ids):
            key, ptr = struct.unpack_from("<II", tree, off + 16 + 8 * i)
            if key & 0x80000000:
                at = key & 0x7FFFFFFF
                n = struct.unpack_from("<H", tree, at)[0]
                key = tree[at + 2:at + 2 + 2 * n].decode("utf-16-le")
            yield key, ptr

    found = []
    for typ, p1 in entries(0):
        for name, p2 in entries(p1 & 0x7FFFFFFF):
            for lang, p3 in entries(p2 & 0x7FFFFFFF):
                data_rva, data_size = struct.unpack_from("<II", tree, p3)
                found.append((data_rva, typ, name, lang, data_size))
    for data_rva, typ, name, lang, data_size in sorted(found):
        yield typ, name, lang, img.read(img.base + data_rva, data_size)


def id_or_name(key):
    if isinstance(key, int):
        return struct.pack("<HH", 0xFFFF, key)
    return (key + "\0").encode("utf-16-le")


def pad4(b):
    return b + bytes(-len(b) % 4)


def write_res(path, items):
    # A .res starts with an empty entry that marks it as 32-bit.
    out = bytearray(struct.pack("<II", 0, 32) + id_or_name(0) + id_or_name(0) + bytes(16))
    for typ, name, lang, data in items:
        # Moveable, pure, discardable: what rc gives icons. The image does
        # not keep these flags.
        head = pad4(id_or_name(typ) + id_or_name(name))
        head += struct.pack("<IHHII", 0, 0x1030, lang, 0, 0)
        out += struct.pack("<II", len(data), 8 + len(head)) + head + pad4(data)
    open(path, "wb").write(out)


DIR32NB = 0x07  # IMAGE_REL_I386_DIR32NB: an image-relative address
RSRC_FLAGS = 0x40 | 0x40000000 | 0x00300000  # initialized, read, align 4


def write_obj(path, items, align=8, timestamp=0):
    """Writes the resources' COFF object the way cvtres 5.00 does: the
    directory tree, breadth first, its data entries (in the tree's order)
    and names in .rsrc$01; the data, in the .res order, each `align`ed,
    in .rsrc$02."""
    items = list(items)
    tree = {}
    for index, (typ, name, lang, _) in enumerate(items):
        tree.setdefault(typ, {}).setdefault(name, {})[lang] = index

    def order(keys):
        # Named entries first, by name; then IDs in increasing order.
        return sorted(keys, key=lambda k: (0, k.upper(), "") if isinstance(k, str) else (1, "", k))

    levels = [[((), tree)]]
    while True:
        nxt = [(path + (k,), node[k]) for path, node in levels[-1] for k in order(node)
               if isinstance(node[k], dict)]
        if not nxt:
            break
        levels.append(nxt)
    offsets, at, leaves = {}, 0, []
    for level in levels:
        for key, node in level:
            offsets[key] = at
            at += 16 + 8 * len(node)
            leaves += [node[k] for k in order(node) if not isinstance(node[k], dict)]
    slot = {index: n for n, index in enumerate(leaves)}  # data entries in tree order
    entries = at
    at += 16 * len(items)
    strings, names = {}, bytearray()
    for level in levels:
        for _, node in level:
            for key in node:
                if isinstance(key, str) and key not in strings:
                    strings[key] = at + len(names)
                    names += struct.pack("<H", len(key)) + key.encode("utf-16-le")
    head = bytearray(at) + names
    head += bytes(-len(head) % 4)
    data, relocs, placed = bytearray(), [], {}
    for index, (_, _, _, blob) in enumerate(items):
        data += bytes(-len(data) % align)
        placed[index] = len(data)
        data += blob
    data += bytes(-len(data) % align)
    for level in levels:
        for key, node in level:
            off = offsets[key]
            keys = order(node)
            named = sum(1 for k in keys if isinstance(k, str))
            struct.pack_into("<IIHHHH", head, off, 0, timestamp, 0, 0, named, len(keys) - named)
            for i, k in enumerate(keys):
                ident = 0x80000000 | strings[k] if isinstance(k, str) else k
                child = node[k]
                if isinstance(child, dict):
                    target = 0x80000000 | offsets[key + (k,)]
                else:
                    target = entries + 16 * slot[child]
                struct.pack_into("<II", head, off + 16 + 8 * i, ident, target)
    for index, (_, _, _, blob) in enumerate(items):
        struct.pack_into("<IIII", head, entries + 16 * slot[index], placed[index], len(blob), 0, 0)
        relocs.append((entries + 16 * slot[index], "$R000000", DIR32NB))
    coff.write_object(path, [(".rsrc$01", RSRC_FLAGS, bytes(head), relocs),
                             (".rsrc$02", RSRC_FLAGS, bytes(data), [])],
                      {"$R000000": (2, 0)}, [], {})


def main():
    write_res(sys.argv[2], resources(sys.argv[1]))


if __name__ == "__main__":
    main()
