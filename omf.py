"""Reads Watcom OMF object files and libraries.

    omf.py dump FILE.OBJ|FILE.LIB

Each module has its segments with their bytes, the fixups in them and
the public symbols defined in them. A fixup records where it is, how
wide it is, whether it is self-relative and what it targets: a segment
of the module or an external name, with a displacement.
"""
import struct, sys

LOC_SIZE = {0: 1, 1: 2, 2: 2, 3: 4, 4: 1, 5: 2, 9: 4, 11: 6, 13: 4}


class Segment:
    def __init__(self, name, cls, size, align):
        self.name, self.cls, self.size, self.align = name, cls, size, align
        self.data = bytearray(size)
        self.fixups = []
        self.publics = []

    def is_code(self):
        return self.cls.upper().endswith("CODE")


class Fixup:
    def __init__(self, offset, size, rel, target, disp):
        self.offset, self.size, self.rel = offset, size, rel
        self.target, self.disp = target, disp

    def __repr__(self):
        return f"Fixup({self.offset:#x}, {self.size}, {'rel' if self.rel else 'abs'}, {self.target}, {self.disp:#x})"


class Module:
    def __init__(self, data):
        self.name = None
        self.lnames = [None]
        self.segments = [None]
        self.groups = [None]
        self.externs = [None]
        self.publics = {}
        self.comdefs = {}
        self.parse(data)

    def parse(self, d):
        p = 0
        last = None
        threads = {}
        while p < len(d):
            typ = d[p]
            ln, = struct.unpack_from("<H", d, p + 1)
            body = d[p + 3:p + 3 + ln - 1]
            p += 3 + ln
            big = typ & 1
            r = Reader(body, big)
            t = typ & ~1
            if t == 0x80:
                self.name = r.name()
            elif t == 0x96:
                while not r.done():
                    self.lnames.append(r.name())
            elif t == 0x98:
                attr = r.byte()
                if attr & 0xE0 == 0:
                    r.word(), r.byte()
                size = r.word_or_dword()
                if attr & 2:
                    size = 1 << (32 if big else 16)
                name, cls = self.lnames[r.index()], self.lnames[r.index()]
                self.segments.append(Segment(name, cls, size, attr >> 5))
            elif t == 0x9A:
                self.groups.append(self.lnames[r.index()])
            elif t in (0x8C, 0xB4):
                while not r.done():
                    self.externs.append(r.name())
                    r.index()
            elif t == 0xBC:
                while not r.done():
                    self.externs.append(self.lnames[r.index()])
                    r.index()
            elif t == 0xB0:
                while not r.done():
                    name = r.name()
                    r.index()
                    kind = r.byte()
                    n = r.comlen() * (r.comlen() if kind == 0x61 else 1)
                    self.externs.append(name)
                    self.comdefs[name] = n
            elif t in (0x90, 0xB6):
                grp, seg = r.index(), r.index()
                if seg == 0:
                    r.word()
                while not r.done():
                    name, off = r.name(), r.word_or_dword()
                    r.index()
                    if seg:
                        self.publics[name] = (seg, off)
                        self.segments[seg].publics.append((off, name, t == 0x90))
            elif t == 0xA0:
                seg = self.segments[r.index()]
                off = r.word_or_dword()
                chunk = body[r.p:]
                seg.data[off:off + len(chunk)] = chunk
                last = (seg, off)
            elif t == 0xA2:
                seg = self.segments[r.index()]
                off = r.word_or_dword()
                out = bytearray()
                while not r.done():
                    out += r.iterated()
                seg.data[off:off + len(out)] = out
                last = None
            elif t == 0x9C:
                while not r.done():
                    b = r.byte()
                    if not b & 0x80:
                        method = (b >> 2) & 7
                        index = r.index() if (b & 0x40 and method < 3) or not b & 0x40 else 0
                        threads[("F" if b & 0x40 else "T", b & 3)] = (method, index)
                        continue
                    locat = (b << 8) | r.byte()
                    rel = not locat & 0x4000
                    loc = (locat >> 10) & 0xF
                    where = locat & 0x3FF
                    fix = r.byte()
                    if fix & 0x80:
                        threads[("F", (fix >> 4) & 3)]
                    else:
                        if (fix >> 4) & 7 < 3:
                            r.index()
                    if fix & 0x08:
                        method, index = threads[("T", fix & 3)]
                    else:
                        method, index = fix & 3, r.index()
                    disp = 0 if fix & 0x04 else r.word_or_dword()
                    method &= 3
                    if method == 0:
                        target = ("seg", index)
                    elif method == 1:
                        target = ("grp", self.groups[index])
                    elif method == 2:
                        target = ("ext", self.externs[index])
                    else:
                        target = ("frame", index)
                    if last is None:
                        continue
                    seg, base = last
                    seg.fixups.append(Fixup(base + where, LOC_SIZE[loc], rel, target, disp))
            elif t == 0xC2:
                raise NotImplementedError("COMDAT")
            elif t == 0x8A:
                break
        for s in self.segments[1:]:
            s.publics.sort()
            s.fixups.sort(key=lambda f: f.offset)

    def functions(self):
        """Yields (segment, name, start, end) for each public in a code segment."""
        for s in self.segments[1:]:
            if not s.is_code():
                continue
            pubs = s.publics
            for i, (off, name, _) in enumerate(pubs):
                end = pubs[i + 1][0] if i + 1 < len(pubs) else s.size
                yield s, name, off, end


class Reader:
    def __init__(self, d, big):
        self.d, self.p, self.big = d, 0, big

    def done(self):
        return self.p >= len(self.d)

    def byte(self):
        self.p += 1
        return self.d[self.p - 1]

    def word(self):
        self.p += 2
        return struct.unpack_from("<H", self.d, self.p - 2)[0]

    def word_or_dword(self):
        if self.big:
            self.p += 4
            return struct.unpack_from("<I", self.d, self.p - 4)[0]
        return self.word()

    def index(self):
        b = self.byte()
        return ((b & 0x7F) << 8) | self.byte() if b & 0x80 else b

    def name(self):
        n = self.byte()
        self.p += n
        return self.d[self.p - n:self.p].decode("latin-1")

    def comlen(self):
        b = self.byte()
        if b <= 0x80:
            return b
        n = {0x81: 2, 0x84: 3, 0x88: 4}[b]
        self.p += n
        return int.from_bytes(self.d[self.p - n:self.p], "little")

    def iterated(self):
        count = self.word_or_dword()
        blocks = self.word()
        if blocks == 0:
            n = self.byte()
            self.p += n
            return self.d[self.p - n:self.p] * count
        out = bytearray()
        for _ in range(blocks):
            out += self.iterated()
        return out * count


def modules(path):
    d = open(path, "rb").read()
    if d[0] != 0xF0:
        return [Module(d)]
    page = struct.unpack_from("<H", d, 1)[0] + 3
    out = []
    p = page
    while p < len(d) and d[p] != 0xF1:
        start = p
        while True:
            typ = d[p]
            ln, = struct.unpack_from("<H", d, p + 1)
            p += 3 + ln
            if typ in (0x8A, 0x8B):
                break
        out.append(Module(d[start:p]))
        p = (p + page - 1) // page * page
    return out


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "dump":
        sys.exit(__doc__)
    for m in modules(sys.argv[2]):
        print(f"module {m.name}")
        for i, s in enumerate(m.segments[1:], 1):
            print(f"  segment {i} {s.name} {s.cls} size {s.size:#x}, {len(s.fixups)} fixups")
            for off, name, _ in s.publics:
                print(f"    {off:#06x} {name}")


if __name__ == "__main__":
    main()
