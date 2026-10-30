"""Links the standalone DOS executable from build/obj/ with Watcom's wlink.

    link_le.py

Writes build/<name>_standalone.exe, a DOS/4GW LE executable that runs
without the original. The original's code and data that src/ does not
provide (Watcom's C library, the sound and video libraries, the 16-bit
keyboard handler and any data no module defines yet) are cut out of the
user's original at link time into OMF objects in build/link/; nothing
from the original is ever written outside build/.

Each module's segments are placed at their addresses in the original
(the code through config/symbols.csv, the data the way compare_le.py
places it). Every stretch of an object of the original that no module
covers becomes a segment of a generated "blob" module, which is linked
right after the module whose segment precedes it, under that segment's
name, so wlink lays it out where the original has it. The modules are
linked in the original's order, which their code addresses give.

The blobs carry the original's fixups as OMF fixups: a target in a blob
goes through that blob's segment or its label (__blob_<address>), a
target in a module through the nearest public in the same segment, with
a displacement. Relative calls and jumps out of a blob into other code
have no fixup in the original; they are found by their targets, which
must be function starts in config/symbols.csv. Every named symbol of
config/symbols.csv inside a blob becomes a public of it, which resolves
the modules' calls into the libraries.

The DOS stub, the entry point and the initial stack pointer are the
original's. The stack, a STACK segment wlink takes the initial stack
pointer from, is the end of the last object after the highest address
anything refers to or config/symbols.csv names.

The C library comes from the original too, not from CLIB3R.LIB: the
linker interleaved its modules with the sound and video libraries'.
"""
import csv, glob, os, struct, subprocess, sys

import compare_le
import omf
import project
from build_watcom import env, winpath
from le import LE
from project import ROOT, NAME, watcom

OUT = project.EXE
LINK = "build/link"


class Omf:
    """Writes a 32-bit OMF object module."""

    def __init__(self, name):
        self.recs = []
        self.lnames = [None]
        self.rec(0x80, self.str(name))

    @staticmethod
    def str(s):
        b = s.encode()
        return bytes([len(b)]) + b

    @staticmethod
    def idx(i):
        return bytes([i]) if i < 0x80 else bytes([0x80 | i >> 8, i & 0xFF])

    def rec(self, typ, body):
        self.recs.append(bytes([typ]) + struct.pack("<H", len(body) + 1) + body + b"\0")

    def lname(self, s):
        if s not in self.lnames:
            self.lnames.append(s)
        return self.lnames.index(s)

    def bytes(self):
        return b"".join(self.recs)


class Piece:
    """A stretch of the original no module provides."""

    def __init__(self, start, end, obj, seg, cls, after):
        self.start, self.end, self.obj = start, end, obj
        self.seg, self.cls, self.after = seg, cls, after
        self.label = f"__blob_{start:x}"
        self.module = None


def load_symbols():
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        return [(int(r["address"], 16), int(r["size"] or 0), r["name"], r["symbol"]) for r in csv.DictReader(f)]


def original_fixups(le):
    """Yields (source, kind, target) for every fixup of the original."""
    for o in le.objects:
        for k in range(o["npages"]):
            for srcoff, kind, obj, target in le.fixups(o["page"] - 1 + k):
                src = o["base"] + k * le.pagesize + srcoff
                yield src, kind, le.objects[obj - 1]["base"] + target


def place_modules(orig):
    """Returns [(path, module, {segment index: address})] in link order."""
    by_symbol, _ = compare_le.load_symbols()
    mods = []
    for path in sorted(glob.glob("build/obj/*.obj")):
        for mod in omf.modules(path):
            _, bases = compare_le.compare_module(mod, orig, by_symbol)
            bases = dict(bases)
            for seg, name, start, _ in mod.functions():
                si = mod.segments.index(seg)
                if si not in bases and name in by_symbol:
                    bases[si] = int(by_symbol[name]["address"], 16) - start
            missing = [s.name for i, s in enumerate(mod.segments) if s and s.size and i not in bases]
            if missing:
                sys.exit(f"error: {path}: no place in the original for {', '.join(missing)}")
            mods.append((path, mod, bases))
    mods.sort(key=lambda m: min((a for i, a in m[2].items() if m[1].segments[i].size), default=1 << 32))
    return mods


def find_pieces(le, mods):
    """Returns the pieces, and the covered regions as (start, end, module number, segment index)."""
    regions = sorted((a, a + mod.segments[si].size, n, si)
                     for n, (_, mod, bases) in enumerate(mods) for si, a in bases.items()
                     if mod.segments[si].size)
    for (a0, e0, n0, _), (a1, _, n1, _) in zip(regions, regions[1:]):
        if a1 < e0:
            print(f"warning: {mods[n0][0]} and {mods[n1][0]} overlap at {a1:#x}")
    pieces = []
    for oi, o in enumerate(le.objects):
        base, end = o["base"], o["base"] + o["size"]
        inside = [r for r in regions if base <= r[0] < end]
        at, prev = base, None
        for r in inside + [(end, end, None, None)]:
            if r[0] > at:
                if prev is None:  # Watcom's startup leads the code and DGROUP
                    head = {le.eip_obj - 1: ("BEGTEXT", "CODE"), le.esp_obj - 1: ("_NULL", "BEGDATA")}
                    seg, cls = head.get(oi, (f"OBJ{oi + 1}", "CODE" if o["flags"] & 4 else "DATA"))
                    after = None if oi in head else len(mods) - 1
                else:
                    s = mods[prev[2]][1].segments[prev[3]]
                    seg, cls, after = s.name, s.cls, prev[2]
                pieces.append(Piece(at, r[0], oi, seg, cls, after))
                pieces[-1].use32 = bool(o["flags"] & 0x2000)
                pieces[-1].dgroup = oi == le.esp_obj - 1
            if r[2] is not None:
                at, prev = max(at, r[1]), r
    return pieces, regions


def branch_fixups(image, piece, starts):
    """Finds the relative calls and jumps from piece to function starts outside it."""
    base, mem = image
    out = []
    lo, hi = piece.start - base, piece.end - base
    for i in range(lo, hi - 4):
        op = mem[i]
        if op in (0xE8, 0xE9):
            at = i + 1
        elif op == 0x0F and 0x80 <= mem[i + 1] <= 0x8F and i + 6 <= hi:
            at = i + 2
        else:
            continue
        if at + 4 > hi:
            continue
        t = base + at + 4 + struct.unpack_from("<i", mem, at)[0]
        if t in starts and not piece.start <= t < piece.end:
            out.append((base + at, 8, t))
    return out


def main():
    os.chdir(ROOT)
    le = LE(project.ORIGINAL)
    orig = compare_le.Original(compare_le.EXE)
    mods = place_modules(orig)
    pieces, regions = find_pieces(le, mods)
    images = [(base, mem) for base, mem, _ in le.image()[0]]
    symbols = load_symbols()
    starts = {a for a, size, _, _ in symbols if size and a < project.CODE[1]}

    # The stack: the end of the last object after its highest fixup target.
    last = max((p for p in pieces if p.obj == le.esp_obj - 1), key=lambda p: p.end)
    fixups = sorted(set(original_fixups(le)))
    esp = le.objects[le.esp_obj - 1]["base"] + le.esp
    assert esp == last.end, f"the stack pointer {esp:#x} is not at the end of the last blob"
    top = max(t for _, _, t in fixups if t < esp)
    top = max(top, max(a + s for a, s, _, _ in symbols if a < esp))
    low = (top + 0x10) & ~0xF
    pieces.append(Piece(low, esp, last.obj, "STACK", "STACK", len(mods) - 1))
    pieces[-1].use32, pieces[-1].dgroup = last.use32, last.dgroup
    last.end = low

    by_addr = sorted((p.start, p.end, p) for p in pieces)
    reg = sorted([(a, e, ("mod", n, si)) for a, e, n, si in regions] +
                 [(a, e, ("piece", p)) for a, e, p in by_addr])
    piece_fix = {}
    for src, kind, t in fixups:
        for a, e, p in by_addr:
            if a <= src < e:
                piece_fix.setdefault(id(p), []).append((src, kind, t))
                break
    for p in pieces:
        if p.cls == "CODE":
            img = next(i for i in images if i[0] <= p.start < i[0] + len(i[1]))
            piece_fix.setdefault(id(p), []).extend(branch_fixups(img, p, starts))

    # Blob modules: one before the first module, one after each that has pieces.
    groups = {}
    for p in pieces:
        groups.setdefault(p.after, []).append(p)

    def find_region(t):
        hit = [r for r in reg if r[0] <= t < r[1]] or [r for r in reg if r[1] == t]
        return hit[0] if hit else None

    errors = []

    def target(t, mod_pieces):
        """Returns ('seg', piece, disp) or ('ext', name, disp)."""
        r = find_region(t)
        if r is None:
            errors.append(f"no target at {t:#x}")
            return ("ext", "__none", 0)
        if r[2][0] == "piece":
            p = r[2][1]
            if p in mod_pieces:
                return ("seg", p, t - p.start)
            return ("ext", p.label, t - p.start)
        _, n, si = r[2]
        mod, base = mods[n][1], mods[n][2][si]
        pubs = [(off, name) for off, name, public in mod.segments[si].publics if public]
        if not pubs:
            errors.append(f"{t:#x} in {mods[n][0]} {mod.segments[si].name}: no public to reach it by")
            return ("ext", "__none", 0)
        off = t - base
        below = [pp for pp in pubs if pp[0] <= off]
        po, pn = below[-1] if below else pubs[0]
        return ("ext", pn, off - po)

    order = []
    plan = {}
    for after in [None] + list(range(len(mods))):
        if after is not None:
            order.append(mods[after][0])
        if after in groups:
            name = f"blob{len(plan):02d}"
            plan[name] = groups[after]
            for p in groups[after]:
                p.module = name
            order.append(os.path.join(LINK, name + ".obj"))

    # Every named symbol in a blob becomes a public of it (the first piece
    # holding it, a symbol of size 0 at a piece's end included).
    owned = {}
    for p in pieces:
        p.publics = {p.label: 0}
    for a, size, _, sym in symbols:
        if sym and sym not in owned:
            for p in pieces:
                if p.start <= a < p.end or (a == p.end and not size):
                    owned[sym] = p
                    p.publics[sym] = a - p.start
                    break
    entry = le.entry()
    holder = next(p for p in pieces if p.cls == "CODE" and p.start <= entry < p.end)
    holder.publics["__blob_entry"] = entry - holder.start

    # The modules' externals must all resolve. One no fixup uses only pulls
    # in a library module (__8087, _fltused_, __argc); the first blob defines it.
    defined = set(owned) | {p.label for p in pieces}
    for _, mod, _ in mods:
        defined |= {n for n, (si, _) in mod.publics.items()}
    used = {f.target[1] for _, mod, _ in mods for s in mod.segments[1:] for f in s.fixups if f.target[0] == "ext"}
    missing = sorted({e for _, mod, _ in mods for e in mod.externs[1:] if e not in defined})
    if [e for e in missing if e in used]:
        sys.exit(f"error: unresolved: {' '.join(e for e in missing if e in used)}")
    first = plan[next(iter(plan))][0]
    for e in missing:
        first.publics[e] = 0

    os.makedirs(LINK, exist_ok=True)
    for name, ps in plan.items():
        write_blob(name, ps, images, piece_fix, target)
    if errors:
        sys.exit("\n".join(f"error: {e}" for e in sorted(set(errors))[:20]))

    stub = le.data[:struct.unpack_from("<H", le.data, 2)[0] + (struct.unpack_from("<H", le.data, 4)[0] - 1) * 512]
    with open(os.path.join(LINK, "stub.exe"), "wb") as f:
        f.write(stub)
    lnk = [
        "format os2 le",
        "option osname='DOS/4G'",
        f"option stub={winpath(os.path.join(LINK, 'stub.exe'))}",
        "option start=__blob_entry",
        "option nodefaultlibs",
        "option quiet",
        f"option map={winpath(os.path.join(LINK, NAME + '.map'))}",
        f"name {winpath(OUT)}",
    ] + [f"file {winpath(p)}" for p in order]
    with open(os.path.join(LINK, NAME + ".lnk"), "w") as f:
        f.write("\n".join(lnk) + "\n")
    w = watcom()
    r = subprocess.run(["timeout", "120", "wine", os.path.join(w, "BINNT", "WLINK.EXE"), "@" + winpath(os.path.join(LINK, NAME + ".lnk"))],
                       env=env(w), capture_output=True, text=True, stdin=subprocess.DEVNULL)
    out = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if l.strip())
    if out:
        print(out)
    if r.returncode or not os.path.exists(OUT):
        sys.exit("error: wlink failed")
    print(f"{OUT}: {len(order)} objects, {len(plan)} of them blobs")


def write_blob(name, ps, images, piece_fix, target):
    o = Omf(name)
    segs = []  # (piece, index)
    lnames = []
    for p in ps:
        lnames += [p.seg, p.cls]
    for s in ["", "FLAT", "DGROUP"] + lnames:
        o.lname(s)
    o.rec(0x96, b"".join(o.str(s) for s in o.lnames[1:]))
    for i, p in enumerate(ps):
        size = p.end - p.start
        combine = 5 if p.cls == "STACK" else 2
        attr = (1 << 5) | (combine << 2) | int(p.use32)
        o.rec(0x99, bytes([attr]) + struct.pack("<I", size) + o.idx(o.lname(p.seg)) + o.idx(o.lname(p.cls)) + o.idx(1))
        segs.append((p, i + 1))
    data_segs = [i for p, i in segs if p.dgroup]
    o.rec(0x9A, o.idx(o.lname("DGROUP")) + b"".join(b"\xff" + o.idx(i) for i in data_segs))
    o.rec(0x9A, o.idx(o.lname("FLAT")))
    dgroup, flat = 1, 2
    externs = []

    def ext(n):
        if n not in externs:
            externs.append(n)
        return externs.index(n) + 1

    pubs = {si: p.publics for p, si in segs}

    # Fixups first, to know the externals.
    fixes = {}
    mod_pieces = set(ps)
    for p, si in segs:
        lst = []
        for src, kind, t in sorted(piece_fix.get(id(p), [])):
            lst.append((src - p.start, kind, target(t, mod_pieces)))
        fixes[si] = lst
    for lst in fixes.values():
        for _, _, tg in lst:
            if tg[0] == "ext":
                ext(tg[1])
    if externs:
        for k in range(0, len(externs), 40):
            o.rec(0x8C, b"".join(o.str(n) + b"\0" for n in externs[k:k + 40]))
    for si, d in pubs.items():
        items = sorted(d.items(), key=lambda kv: kv[1])
        for k in range(0, len(items), 20):
            grp = dgroup if segs[si - 1][0].dgroup else 0
            body = o.idx(grp) + o.idx(si)
            body += b"".join(o.str(n) + struct.pack("<I", off) + b"\0" for n, off in items[k:k + 20])
            o.rec(0x91, body)

    for p, si in segs:
        img = next(i for i in images if i[0] <= p.start <= i[0] + len(i[1]))
        mem = bytearray(img[1][p.start - img[0]:p.end - img[0]])
        mem += bytes(p.end - p.start - len(mem))
        lst = fixes[si]
        width = {7: 4, 8: 4, 6: 6, 2: 2, 5: 2, 3: 4}
        for off, kind, _ in lst:
            mem[off:off + width[kind]] = bytes(width[kind])
        if not any(mem):
            continue
        at = 0
        while at < len(mem):
            end = min(at + 1000, len(mem))
            for off, kind, _ in lst:  # no fixup may straddle two records
                if off < end < off + width[kind]:
                    end = off
            chunk = mem[at:end]
            mine = [f for f in lst if at <= f[0] < end]
            if any(chunk) or mine:
                o.rec(0xA1, o.idx(si) + struct.pack("<I", at) + bytes(chunk))
                if mine:
                    o.rec(0x9D, b"".join(fixup(o, f[0] - at, f[1], f[2], segs, ext, dgroup, flat) for f in mine))
            at = end
    o.rec(0x8A, b"\0")
    with open(os.path.join(LINK, name + ".obj"), "wb") as f:
        f.write(o.bytes())


def fixup(o, off, kind, tg, segs, ext, dgroup, flat):
    loc, m = {7: (9, 1), 8: (9, 0), 6: (11, 1), 2: (2, 1), 5: (1, 1), 3: (3, 1)}[kind]
    locat = bytes([0x80 | m << 6 | loc << 2 | off >> 8, off & 0xFF])
    if tg[0] == "seg":
        method, datum = 0, next(i for p, i in segs if p is tg[1])
    else:
        method, datum = 2, ext(tg[1])
    frame = dgroup if kind == 2 else flat
    return locat + bytes([1 << 4 | method]) + o.idx(frame) + o.idx(datum) + struct.pack("<i", tg[2])


if __name__ == "__main__":
    main()
