"""Makes a copy of the game executable that loads the hook DLL.

    patch_exe.py ORIGINAL OUTPUT

Appends a section with a copy of the import directory plus one more entry,
for Init() from <name>.dll (game.name in project.toml), and points the import directory at it.
Windows then loads the DLL before the game starts. Nothing else changes.
With game.format = "le", patch_le.py patches instead.
"""
import os, struct, sys

import project

DLL = os.path.basename(project.DLL).encode()
FUNC = b"Init"


def align(n, a):
    return (n + a - 1) // a * a


def main():
    if project.FORMAT == "le":
        import patch_le
        return patch_le.main()
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    patch(*sys.argv[1:])


def patch(src, dst):
    d = bytearray(open(src, "rb").read())
    pe, = struct.unpack_from("<I", d, 0x3C)
    nsec, = struct.unpack_from("<H", d, pe + 6)
    optsz, = struct.unpack_from("<H", d, pe + 20)
    opt = pe + 24
    secalign, filealign = struct.unpack_from("<II", d, opt + 32)
    headers_size, = struct.unpack_from("<I", d, opt + 60)
    imp_rva, imp_size = struct.unpack_from("<II", d, opt + 96 + 8)
    sechdr = opt + optsz + nsec * 40
    if sechdr + 40 > headers_size:
        sys.exit("no room for another section header")
    if any(d[sechdr:sechdr + 40]):
        # Linkers can leave junk there (th08 has a compiler banner string).
        # It is free unless a data directory points into it; the bound
        # imports that usually live there are dropped below anyway.
        for i in range(16):
            dir_rva, dir_size = struct.unpack_from("<II", d, opt + 96 + 8 * i)
            if i != 11 and dir_size and dir_rva < sechdr + 40 and sechdr < dir_rva + dir_size:
                sys.exit("the space after the section headers is in use")
        d[sechdr:sechdr + 40] = bytes(40)

    last = sechdr - 40
    vsize, va = struct.unpack_from("<II", d, last + 8)
    rva = align(va + vsize, secalign)
    rawptr = align(len(d), filealign)

    # Original descriptors without the terminator, then ours, then a null one.
    descs = []
    for off in range(0, imp_size, 20):
        desc = bytes(d[rva_to_off(d, opt + optsz, nsec, imp_rva + off):][:20])
        if not any(desc):
            break
        descs.append(desc)
    table = 20 * (len(descs) + 2)
    ilt = rva + table
    iat = ilt + 8
    name = iat + 8
    hint = name + align(len(DLL) + 1, 2)
    body = b"".join(descs)
    body += struct.pack("<IIIII", ilt, 0, 0, name, iat) + bytes(20)
    body += struct.pack("<II", hint, 0) + struct.pack("<II", hint, 0)
    body += DLL.ljust(align(len(DLL) + 1, 2), b"\0")
    body += struct.pack("<H", 0) + FUNC + b"\0"
    rawsize = align(len(body), filealign)

    flags = 0x40 | 0x40000000 | 0x80000000  # initialized data, read, write
    struct.pack_into("<8sIIIIIIHHI", d, sechdr, b".patch", len(body), rva, rawsize,
                     rawptr, 0, 0, 0, 0, flags)
    struct.pack_into("<H", d, pe + 6, nsec + 1)
    struct.pack_into("<I", d, opt + 56, align(rva + len(body), secalign))  # SizeOfImage
    struct.pack_into("<II", d, opt + 96 + 8, rva, table)
    struct.pack_into("<II", d, opt + 96 + 11 * 8, 0, 0)  # no bound imports
    d += bytes(rawptr - len(d)) + body.ljust(rawsize, b"\0")
    open(dst, "wb").write(d)


def rva_to_off(d, sec, nsec, rva):
    for i in range(nsec):
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, sec + i * 40 + 8)
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + rva - va
    raise ValueError(hex(rva))


if __name__ == "__main__":
    main()
