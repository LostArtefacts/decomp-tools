"""Minimal reader and writer for i386 COFF objects and PE images."""
import struct

CODE = 0x20  # IMAGE_SCN_CNT_CODE
REL32 = 0x14
DIR32 = 0x06
SYM_UNDEFINED = 0
SYM_ABSOLUTE = -1
CLASS_EXTERNAL = 2


class Section:
    def __init__(self, name, data, relocs, flags):
        self.name, self.data, self.relocs, self.flags = name, data, relocs, flags


class Symbol:
    def __init__(self, name, value, section, storage):
        self.name, self.value, self.section, self.storage = name, value, section, storage


class Object:
    def __init__(self, path):
        d = open(path, "rb").read()
        _, nsec, _, symptr, nsym, optsz, _ = struct.unpack_from("<HHIIIHH", d, 0)
        strtab = symptr + nsym * 18

        def name(raw):
            if raw[:4] == b"\0\0\0\0":
                off = struct.unpack_from("<I", raw, 4)[0]
                raw = d[strtab + off:d.index(b"\0", strtab + off)]
            return raw.rstrip(b"\0").decode("latin-1")

        self.symbols = []  # index -> Symbol (None for aux entries)
        i = 0
        while i < nsym:
            raw = d[symptr + i * 18:symptr + i * 18 + 18]
            value, secnum, _, storage, naux = struct.unpack_from("<IhHBB", raw, 8)
            self.symbols.append(Symbol(name(raw[:8]), value, secnum, storage))
            self.symbols.extend([None] * naux)
            i += 1 + naux

        self.sections = []
        for s in range(nsec):
            h = 20 + optsz + s * 40
            size, rawptr, relptr, _, nrel, _, flags = struct.unpack_from("<IIIIHHI", d, h + 16)
            data = d[rawptr:rawptr + size] if rawptr else bytes(size)
            relocs = [struct.unpack_from("<IIH", d, relptr + r * 10) for r in range(nrel)]
            self.sections.append(Section(name(d[h:h + 8]), data, relocs, flags))

    def externals(self):
        return [s for s in self.symbols if s and s.storage == CLASS_EXTERNAL]


class Image:
    """A PE image, addressed by virtual address."""

    def __init__(self, path):
        self.data = open(path, "rb").read()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec, = struct.unpack_from("<H", self.data, pe + 6)
        optsz, = struct.unpack_from("<H", self.data, pe + 20)
        self.base, = struct.unpack_from("<I", self.data, pe + 24 + 28)
        self.sections = []
        for s in range(nsec):
            h = pe + 24 + optsz + s * 40
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", self.data, h + 8)
            self.sections.append((self.base + va, vsize, rawptr, rawsize))

    def read(self, addr, size):
        for va, vsize, rawptr, rawsize in self.sections:
            if va <= addr < va + vsize:
                off = addr - va
                return self.data[rawptr + off:rawptr + min(off + size, rawsize)]
        raise ValueError(f"{addr:#x} is not mapped")


TEXT = 0x20 | 0x20000000 | 0x40000000 | 0x00500000  # code, exec, read, align 16
RDATA = 0x40 | 0x40000000 | 0x00300000  # initialized data, read, align 4


def write_object(path, sections, defined, undefined, absolute):
    """Writes an object file.

    sections: [(name, flags, data, [(offset, symbol, type)])],
    defined: {name: (section index from 1, offset)}, undefined: [name],
    absolute: {name: address}.
    """
    syms = [(n, v, s) for n, (s, v) in defined.items()]
    syms += [(n, 0, SYM_UNDEFINED) for n in undefined]
    syms += [(n, v, SYM_ABSOLUTE) for n, v in absolute.items()]
    index = {n: i for i, (n, _, _) in enumerate(syms)}

    ptr = 20 + 40 * len(sections)
    headers, body = bytearray(), bytearray()
    for name, flags, data, relocs in sections:
        relptr = ptr + len(data)
        headers += struct.pack("<8sIIIIIIHHI", name.encode(), 0, 0, len(data),
                               ptr, relptr, 0, len(relocs), 0, flags)
        body += data
        for off, sym, typ in relocs:
            body += struct.pack("<IIH", off, index[sym], typ)
        ptr = relptr + len(relocs) * 10
    out = bytearray(struct.pack("<HHIIIHH", 0x14C, len(sections), 0, ptr, len(syms), 0, 0))
    out += headers + body
    strings = bytearray()
    for name, value, secnum in syms:
        raw = name.encode("latin-1")
        if len(raw) <= 8:
            field = raw.ljust(8, b"\0")
        else:
            field = struct.pack("<II", 0, 4 + len(strings))
            strings += raw + b"\0"
        out += field + struct.pack("<IhHBB", value, secnum, 0, CLASS_EXTERNAL, 0)
    out += struct.pack("<I", 4 + len(strings)) + strings
    open(path, "wb").write(out)
