"""Reads the DOS/4GW LE executable and flattens it into an ELF file.

    le.py info [EXE]
    le.py elf [EXE] [OUT]
    le.py roundtrip [EXE] [OUT]

`elf` loads each object at its relocation base, applies the fixups and
writes an ELF32 i386 executable with one program header and one section
per object, so objdump and Ghidra can load it directly. The fixup
targets are also written to OUT.fixups as `source,target` lines, which
tells code references from plain numbers.

EXE defaults to game.original in project.toml, the ELF file to
build/<game.name>.elf.

`Patch` edits an executable: bytes, fixups and a new object, and writes
it back. Pages whose fixups are untouched keep their original fixup
records. `roundtrip` rewrites the executable without changes, which must
give the same file.
"""
import os, struct, sys

import project

EXE = project.ORIGINAL


class LE:
    def __init__(self, path):
        d = self.data = open(path, "rb").read()
        h = self.hdr = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[h:h + 2] == b"LE", "not an LE executable"
        u = lambda o: struct.unpack_from("<I", d, h + o)[0]
        self.npages = u(0x14)
        self.eip_obj, self.eip = u(0x18), u(0x1C)
        self.esp_obj, self.esp = u(0x20), u(0x24)
        self.pagesize, self.lastpage = u(0x28), u(0x2C)
        objtab, nobj, pagetab = u(0x40), u(0x44), u(0x48)
        fixpage, fixrec = u(0x68), u(0x6C)
        self.datapages = u(0x80)
        self.objects = []
        for i in range(nobj):
            size, base, flags, page, npages, _ = struct.unpack_from("<6I", d, h + objtab + i * 24)
            self.objects.append({"size": size, "base": base, "flags": flags, "page": page, "npages": npages})
        self.pages = []
        for i in range(self.npages):
            b = d[h + pagetab + i * 4:h + pagetab + i * 4 + 4]
            self.pages.append(((b[0] << 16) | (b[1] << 8) | b[2], b[3]))
        offs = struct.unpack_from(f"<{self.npages + 1}I", d, h + fixpage)
        self.fixrec = h + fixrec
        self.fixoffs = offs

    def page_data(self, i):
        num, flags = self.pages[i]
        assert flags == 0, f"page {i + 1} has flags {flags:#x}"
        size = self.lastpage if i == self.npages - 1 else self.pagesize
        off = self.datapages + (num - 1) * self.pagesize
        return self.data[off:off + size]

    def fixups(self, page):
        """Yields (source offset in page, kind, target object, target offset)."""
        d = self.data
        p, end = self.fixrec + self.fixoffs[page], self.fixrec + self.fixoffs[page + 1]
        while p < end:
            src, flags = d[p], d[p + 1]
            p += 2
            assert flags & 3 == 0, f"non-internal fixup {flags:#x}"
            assert not src & 0xD0 and not flags & 0xAC, f"unsupported fixup {src:#x} {flags:#x}"
            if src & 0x20:
                count = d[p]
                p += 1
            else:
                srcoff, = struct.unpack_from("<h", d, p)
                p += 2
            if flags & 0x40:
                obj, = struct.unpack_from("<H", d, p)
                p += 2
            else:
                obj = d[p]
                p += 1
            kind = src & 0x0F
            target = 0
            if kind != 2:
                if flags & 0x10:
                    target, = struct.unpack_from("<I", d, p)
                    p += 4
                else:
                    target, = struct.unpack_from("<H", d, p)
                    p += 2
            if src & 0x20:
                for _ in range(count):
                    srcoff, = struct.unpack_from("<h", d, p)
                    p += 2
                    yield srcoff, kind, obj, target
            else:
                yield srcoff, kind, obj, target

    def image(self):
        """Returns [(base, bytearray, flags)] with fixups applied, and the fixup list."""
        mems = []
        for o in self.objects:
            m = bytearray(o["size"])
            for k in range(o["npages"]):
                pd = self.page_data(o["page"] - 1 + k)
                n = min(len(pd), max(0, o["size"] - k * self.pagesize))
                m[k * self.pagesize:k * self.pagesize + n] = pd[:n]
            mems.append(m)
        found = []
        for oi, o in enumerate(self.objects):
            m = mems[oi]
            for k in range(o["npages"]):
                page = o["page"] - 1 + k
                for srcoff, kind, obj, target in self.fixups(page):
                    at = k * self.pagesize + srcoff
                    tgt = self.objects[obj - 1]["base"] + target
                    src = o["base"] + at
                    if kind in (6, 7):
                        raw = struct.pack("<I", tgt)
                    elif kind == 8:
                        raw = struct.pack("<i", tgt - (src + 4))
                    elif kind in (3, 5):
                        raw = struct.pack("<H", target & 0xFFFF)
                    elif kind == 2:
                        continue
                    else:
                        raise ValueError(f"fixup kind {kind} at {src:#x}")
                    for j, b in enumerate(raw):
                        if 0 <= at + j < len(m):
                            m[at + j] = b
                    if 0 <= at:
                        found.append((src, tgt, kind))
        return [(o["base"], mems[i], o["flags"]) for i, o in enumerate(self.objects)], sorted(set(found))

    def entry(self):
        return self.objects[self.eip_obj - 1]["base"] + self.eip


class Patch:
    def __init__(self, le):
        self.le = le
        self.objects = [dict(o) for o in le.objects]
        self.pages = []
        for i in range(le.npages):
            pd = bytearray(le.page_data(i))
            self.pages.append(pd + bytes(le.pagesize - len(pd)))
        self.lastpage = le.lastpage
        self.page_fixups = [None] * le.npages

    def locate(self, addr):
        for i, o in enumerate(self.objects):
            if o["base"] <= addr < o["base"] + o["size"]:
                return i, addr - o["base"]
        raise ValueError(f"{addr:#x} is in no object")

    def page_of(self, addr):
        i, off = self.locate(addr)
        o = self.objects[i]
        k = off // self.le.pagesize
        if k >= o["npages"]:
            raise ValueError(f"{addr:#x} is in the zero-filled part of object {i + 1}")
        return o["page"] - 1 + k, o["base"] + k * self.le.pagesize

    def fixup_list(self, page):
        if self.page_fixups[page] is None:
            self.page_fixups[page] = list(self.le.fixups(page))
        return self.page_fixups[page]

    def add_object(self, base, data, flags):
        n = (len(data) + self.le.pagesize - 1) // self.le.pagesize
        if self.pages:
            self.lastpage = self.le.pagesize
        first = len(self.pages) + 1
        for k in range(n):
            chunk = bytearray(data[k * self.le.pagesize:(k + 1) * self.le.pagesize])
            self.pages.append(chunk + bytes(self.le.pagesize - len(chunk)))
            self.page_fixups.append([])
        self.lastpage = len(data) - (n - 1) * self.le.pagesize
        self.objects.append({"size": len(data), "base": base, "flags": flags, "page": first, "npages": n})
        return len(self.objects)

    def write(self, addr, data):
        for j, b in enumerate(data):
            page, start = self.page_of(addr + j)
            self.pages[page][addr + j - start] = b

    def remove_fixups(self, start, end):
        first, _ = self.page_of(start)
        last, _ = self.page_of(end - 1)
        for page in range(max(0, first - 1), last + 2):
            if page >= len(self.pages):
                continue
            pbase = self.page_base(page)
            if pbase is None:
                continue
            keep = []
            for f in self.fixup_list(page):
                src = pbase + f[0]
                size = {2: 2, 3: 4, 5: 2, 6: 6, 7: 4, 8: 4}[f[1]]
                if src < end and src + size > start:
                    continue
                keep.append(f)
            self.page_fixups[page] = keep

    def page_base(self, page):
        for o in self.objects:
            if o["page"] - 1 <= page < o["page"] - 1 + o["npages"]:
                return o["base"] + (page - o["page"] + 1) * self.le.pagesize
        return None

    def add_fixup(self, src, kind, target):
        obj, off = self.locate(target)
        size = {7: 4, 8: 4}[kind]
        pages = {self.page_of(src)[0], self.page_of(src + size - 1)[0]}
        for page in sorted(pages):
            self.fixup_list(page).append((src - self.page_base(page), kind, obj + 1, off))

    def save(self, path):
        le, d, h = self.le, self.le.data, self.le.hdr
        u = lambda o: struct.unpack_from("<I", d, h + o)[0]
        npages = len(self.pages)
        loader = bytearray()
        objtab = 0xC4
        for o in self.objects:
            loader += struct.pack("<6I", o["size"], o["base"], o["flags"], o["page"], o["npages"], 0)
        pagetab = objtab + len(loader)
        for i in range(npages):
            n = i + 1
            loader += bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF, 0])
        resident = objtab + len(loader)
        loader += d[h + u(0x58):h + u(0x5C)]
        entry = objtab + len(loader)
        loader += d[h + u(0x5C):h + u(0x68)]
        fixpage = objtab + len(loader)
        records = bytearray()
        offsets = []
        for page in range(npages):
            offsets.append(len(records))
            if self.page_fixups[page] is None:
                records += d[le.fixrec + le.fixoffs[page]:le.fixrec + le.fixoffs[page + 1]]
                continue
            for srcoff, kind, obj, target in self.page_fixups[page]:
                records += struct.pack("<BBh", kind, 0x10 | (0x40 if obj > 255 else 0), srcoff)
                records += struct.pack("<H", obj) if obj > 255 else bytes([obj])
                if kind != 2:
                    records += struct.pack("<I", target)
        offsets.append(len(records))
        loader += struct.pack(f"<{npages + 1}I", *offsets)
        fixrec = objtab + len(loader)
        loader += records
        imports = objtab + len(loader)
        loader += b"\0"
        end = objtab + len(loader)
        datapages = (h + end + 0x1FF) & ~0x1FF
        hdr = bytearray(d[h:h + objtab])
        for off, val in [(0x14, npages), (0x2C, self.lastpage), (0x30, end - fixpage), (0x38, end - objtab),
                         (0x40, objtab), (0x44, len(self.objects)), (0x48, pagetab), (0x50, resident),
                         (0x58, resident), (0x5C, entry), (0x68, fixpage), (0x6C, fixrec),
                         (0x70, imports), (0x78, imports), (0x80, datapages)]:
            struct.pack_into("<I", hdr, off, val)
        out = bytearray(d[:h]) + hdr + loader
        out += bytes(datapages - len(out))
        for i, pg in enumerate(self.pages):
            out += pg[:self.lastpage] if i == npages - 1 else pg
        open(path, "wb").write(out)


def write_elf(le, out):
    objs, fixups = le.image()
    shstr = b"\0.shstrtab\0" + b"".join(f".obj{i + 1}\0".encode() for i in range(len(objs)))
    phoff, ehsize, phsize, shsize = 52, 52, 32, 40
    off = phoff + phsize * len(objs)
    blobs = []
    for base, m, flags in objs:
        off = (off + 0xFFF) & ~0xFFF
        blobs.append(off)
        off += len(m)
    shstroff = off
    shoff = (shstroff + len(shstr) + 3) & ~3
    nsh = len(objs) + 2
    e = bytearray(b"\x7fELF\x01\x01\x01" + bytes(9))
    e += struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, le.entry(), phoff, shoff, 0, ehsize, phsize,
                     len(objs), shsize, nsh, 1)
    for (base, m, flags), fo in zip(objs, blobs):
        pf = (4 if flags & 1 else 0) | (2 if flags & 2 else 0) | (1 if flags & 4 else 0)
        e += struct.pack("<8I", 1, fo, base, base, len(m), len(m), pf, 0x1000)
    for (base, m, flags), fo in zip(objs, blobs):
        e += bytes(fo - len(e)) + m
    e += bytes(shstroff - len(e)) + shstr
    e += bytes(shoff - len(e)) + bytes(shsize)
    e += struct.pack("<10I", 1, 3, 0, 0, shstroff, len(shstr), 0, 0, 1, 0)
    name = 11
    for i, ((base, m, flags), fo) in enumerate(zip(objs, blobs)):
        shflags = 2 | (1 if flags & 2 else 0) | (4 if flags & 4 else 0)
        e += struct.pack("<10I", name, 1, shflags, base, fo, len(m), 0, 0, 16, 0)
        name += len(f".obj{i + 1}\0")
    open(out, "wb").write(e)
    with open(out + ".fixups", "w") as f:
        for src, tgt, kind in fixups:
            f.write(f"0x{src:08x},0x{tgt:08x}{',rel' if kind == 8 else ''}\n")
    return objs, fixups


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "info"
    path = sys.argv[2] if len(sys.argv) > 2 else EXE
    le = LE(path)
    if cmd == "info":
        print(f"entry {le.entry():#x}, stack {le.objects[le.esp_obj - 1]['base'] + le.esp:#x}, "
              f"{le.npages} pages of {le.pagesize:#x}")
        for i, o in enumerate(le.objects):
            print(f"object {i + 1}: base {o['base']:#010x} size {o['size']:#x} flags {o['flags']:#06x} "
                  f"pages {o['page']}+{o['npages']}")
    elif cmd == "elf":
        out = sys.argv[3] if len(sys.argv) > 3 else project.ELF
        objs, fixups = write_elf(le, out)
        print(f"wrote {out}: {len(objs)} objects, {len(fixups)} fixups")
    elif cmd == "roundtrip":
        out = sys.argv[3] if len(sys.argv) > 3 else "build/roundtrip.exe"
        Patch(le).save(out)
        same = open(out, "rb").read() == le.data
        print(f"wrote {out}, {'identical' if same else 'DIFFERENT'}")
        sys.exit(0 if same else 1)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
