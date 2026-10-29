"""Copies the resources of a PE image (its .rsrc tree) into a .res file.

    rsrc.py IMAGE OUT.res

The .res is what rc would write for the same resources, so the linker
(through cvtres) builds an identical .rsrc from it. The original game's
resources are its icon and the icon's group.
"""
import struct, sys

import coff

RESOURCE_DIRECTORY = 2


def resources(path):
    """Yields (type, name, language, data) for each resource in the image.
    type and name are an int ID or a string."""
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

    for typ, p1 in entries(0):
        for name, p2 in entries(p1 & 0x7FFFFFFF):
            for lang, p3 in entries(p2 & 0x7FFFFFFF):
                data_rva, data_size = struct.unpack_from("<II", tree, p3)
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


def main():
    write_res(sys.argv[2], resources(sys.argv[1]))


if __name__ == "__main__":
    main()
