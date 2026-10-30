"""Compares the compiled functions with the original, byte for byte.

    compare.py [SYMBOL...]

Nothing is masked. Each fixup in an object must sit where the original
has one (a self-relative call has none in either) and must resolve to the
address the original uses: an external through config/symbols.csv, a
segment of the same module through that segment's place in the original,
which is worked out from its first use and must be the same for every
other, or failing that from the first pointer to it in a data segment;
its own code through the function that holds the target. The
CONST, CONST2 and _DATA bytes of each placed segment must then match the
original's too. A module's own public data is referenced by name, like
any external, so each data segment is also placed through its publics'
addresses in symbols.csv, which must all agree, and its bytes and
pointers are compared the same way.

Watcom puts a function's switch jump tables in the code segment right
before the function. They are compared with the code they sit in: the
bytes after a function's last public up to the next, and the bytes of a
segment before its first public with that first public. A function's
size, checked against config/symbols.csv, leaves out the jump tables
at its end.

Each function is checked at its own address, so one that does not match
yet can be left out of its module: references to it then go through
symbols.csv like any external, and the functions after it still match.
A module whose functions are not contiguous gets a warning.

A function listed in config/nonmatching.txt is decompiled but known not
to match yet: it is reported as `nonmatch` and does not fail the run,
until it matches, when it has to come off the list.

With SYMBOLs, shows a disassembly diff for each.
"""
import csv, difflib, glob, os, struct, subprocess, sys, tempfile

import le, omf, project

ROOT = project.ROOT
EXE = project.ORIGINAL
PADDING = (b"\x8d\x40\x00", b"\x8b\xc0", b"\x90")


class Original:
    def __init__(self, path):
        objs, fixups = le.LE(path).image()
        self.objs = [(base, bytes(m)) for base, m, _ in objs]
        self.fixups = {src: tgt for src, tgt, kind in fixups if kind != 8}
        self.kinds = {src: kind for src, tgt, kind in fixups}

    def width(self, addr):
        """The size of the original's fixup at addr: 6 for a 16:32 pointer,
        whose selector the loader fills in, otherwise 4."""
        return 6 if self.kinds.get(addr) == 6 else 4

    def read(self, addr, n):
        for base, m in self.objs:
            if base <= addr and addr + n <= base + len(m):
                return m[addr - base:addr - base + n]
        raise ValueError(f"{addr:#x}+{n} is outside the image")


def load_nonmatching():
    path = os.path.join(ROOT, "config/nonmatching.txt")
    if not os.path.exists(path):
        return set()
    return {l.strip() for l in open(path) if l.strip()}


def load_symbols():
    rows = list(csv.DictReader(open(os.path.join(ROOT, "config/symbols.csv"))))
    by_symbol = {r["symbol"]: r for r in rows if r["symbol"]}
    by_addr = {int(r["address"], 16): r for r in rows}
    return by_symbol, by_addr


class Result:
    def __init__(self, name, addr):
        self.name, self.addr = name, addr
        self.errors = []
        self.warning = None
        self.data = False
        self.ours = None
        self.size = 0

    def ok(self):
        return not self.errors


def strip_padding(b):
    for pad in PADDING:
        if b.endswith(pad) and len(b) > len(pad):
            return b[:-len(pad)]
    return b


def jump_tables(seg, si, start, end):
    """Returns the length of the jump tables at the end of seg.data[start:end]: dwords
    each under an absolute fixup into the same segment."""
    at = {f.offset: f for f in seg.fixups if start <= f.offset < end}
    n = 0
    while True:
        f = at.get(end - n - 4)
        if not f or f.size != 4 or f.rel or f.target != ("seg", si):
            return n
        n += 4


def code_owner(seg, off, by_symbol):
    """The address of offset off of a code segment, through the function that holds it.
    Bytes before the first function belong to it."""
    pubs = seg.publics
    if not pubs:
        return None
    holder = pubs[0]
    for p in pubs:
        if p[0] <= off:
            holder = p
    row = by_symbol.get(holder[1])
    return int(row["address"], 16) + off - holder[0] if row else None


def compare_module(mod, orig, by_symbol):
    results = []
    bases = {}
    layout = {}
    segs = mod.segments
    first = set()
    for seg, name, start, end in mod.functions():
        lead = 0
        if seg not in first:
            first.add(seg)
            lead, start = start, 0
        row = by_symbol.get(name)
        if not row:
            r = Result(name, None)
            r.errors.append("not in config/symbols.csv")
            results.append(r)
            continue
        addr = int(row["address"], 16)
        r = Result(row["name"], addr)
        results.append(r)
        addr -= lead
        si = segs.index(seg)
        layout.setdefault(si, []).append((start, end, addr))
        ours = bytearray(strip_padding(bytes(seg.data[start:end])))
        tables = jump_tables(seg, si, start, start + len(ours))
        try:
            theirs = orig.read(addr, len(ours))
        except ValueError as e:
            r.errors.append(str(e))
            continue
        fixed = set()
        for f in seg.fixups:
            if not start <= f.offset < end:
                continue
            at = addr + f.offset - start
            off = f.offset - start
            fixed.update(range(at, at + f.size))
            if f.size != orig.width(at):
                r.errors.append(f"{f.size}-byte fixup at {at:#x}, the original's is {orig.width(at)}-byte")
                continue
            inline, = struct.unpack_from("<i", ours, off)
            if f.rel:
                if at in orig.fixups:
                    r.errors.append(f"self-relative fixup at {at:#x}, the original's is absolute")
                    continue
                target = at + 4 + struct.unpack_from("<i", theirs, off)[0]
            else:
                if at not in orig.fixups:
                    r.errors.append(f"fixup at {at:#x}, the original has none")
                    continue
                target = orig.fixups[at]
            kind, what = f.target
            if kind == "ext":
                sym = by_symbol.get(what)
                if not sym:
                    r.errors.append(f"{what} is not in config/symbols.csv; the original uses "
                                    f"{target - f.disp - inline:#x}")
                    continue
                expect = int(sym["address"], 16) + f.disp + inline
            elif kind == "seg" and segs[what].is_code():
                off2 = f.disp + inline
                owner = code_owner(segs[what], off2, by_symbol)
                if owner is None:
                    r.errors.append(f"{segs[what].name}+{off2:#x} at {at:#x} is in no function of "
                                    f"config/symbols.csv; the original's is {target:#x}")
                    continue
                expect = owner
            elif kind == "seg":
                base = target - f.disp - inline
                placed = bases.setdefault(what, base)
                if placed != base:
                    r.errors.append(f"{segs[what].name}+{f.disp + inline:#x} at {at:#x} puts the segment at "
                                    f"{base:#x}, it is at {placed:#x}")
                    continue
                expect = placed + f.disp + inline
            else:
                r.errors.append(f"unsupported fixup target {f.target} at {at:#x}")
                continue
            if expect != target:
                r.errors.append(f"{what if kind == 'ext' else segs[what].name}+{f.disp + inline:#x} "
                                f"at {at:#x} is {expect:#x}, the original's is {target:#x}")
            val = expect - (at + 4) if f.rel else expect
            struct.pack_into("<I", ours, off, val & 0xFFFFFFFF)
        for at in range(addr, addr + len(ours)):
            if at in orig.fixups and at not in fixed:
                r.errors.append(f"the original has a fixup at {at:#x}, this has none")
        diff = [addr + i for i in range(len(ours)) if addr + i not in fixed and ours[i] != theirs[i]]
        if diff:
            r.errors.append(f"{len(diff)} bytes differ, first at {diff[0]:#x}")
        own = len(strip_padding(bytes(ours[:len(ours) - tables]))) - lead if tables else len(ours) - lead
        size = int(row["size"]) if row["size"] else 0
        if size and own != size:
            r.errors.append(f"{own} bytes, the original's is {size}")
        r.ours, r.size = bytes(ours[lead:]), own
    for si, placed in layout.items():
        base = placed[0][2] - placed[0][0]
        moved = [(start, addr) for start, end, addr in placed if addr - start != base]
        if moved:
            r = Result(f"layout of {segs[si].name} in {mod.name.replace(chr(92), '/').rsplit('/', 1)[-1]}", base + moved[0][0])
            r.warning = (f"{len(moved)} functions are not where a contiguous {segs[si].name} puts "
                         f"them, first at {moved[0][1]:#x} (a function between them is missing)")
            results.append(r)
    modname = mod.name.replace(chr(92), "/").rsplit("/", 1)[-1]
    misplaced = {}
    for si, seg in enumerate(segs[1:], 1):
        if seg.is_code():
            continue
        for off, name, _ in seg.publics:
            row = by_symbol.get(name)
            if not row:
                misplaced.setdefault(si, []).append(f"{name} is not in config/symbols.csv")
                continue
            want = int(row["address"], 16) - off
            placed = bases.setdefault(si, want)
            if placed != want:
                misplaced.setdefault(si, []).append(
                    f"{name} is at {want + off:#x}, {seg.name} puts it at {placed + off:#x}")
    done = set()
    while True:
        todo = sorted((si, base) for si, base in bases.items() if si not in done)
        if not todo:
            break
        si, base = todo[0]
        done.add(si)
        seg = segs[si]
        if seg.is_code() or not seg.size:
            continue
        r = Result(f"{seg.name} of {modname}", base)
        r.data = True
        results.append(r)
        r.errors += misplaced.get(si, [])
        try:
            theirs = orig.read(base, seg.size)
        except ValueError as e:
            r.errors.append(str(e))
            continue
        ours = bytearray(seg.data)
        fixed = set()
        for f in seg.fixups:
            at = base + f.offset
            fixed.update(range(at, at + f.size))
            if f.size != orig.width(at) or f.rel:
                r.errors.append(f"{f.size}-byte {'relative ' if f.rel else ''}fixup at {at:#x}, "
                                f"the original's is {orig.width(at)}-byte")
                continue
            if at not in orig.fixups:
                r.errors.append(f"fixup at {at:#x}, the original has none")
                continue
            target = orig.fixups[at]
            inline, = struct.unpack_from("<i", ours, f.offset)
            kind, what = f.target
            if kind == "ext":
                sym = by_symbol.get(what)
                expect = int(sym["address"], 16) + f.disp + inline if sym else None
                if expect is None:
                    r.errors.append(f"{what} is not in config/symbols.csv; the original uses "
                                    f"{target - f.disp - inline:#x}")
                    continue
            elif kind == "seg" and segs[what].is_code():
                expect = code_owner(segs[what], f.disp + inline, by_symbol)
            elif kind == "seg":
                expect = bases.setdefault(what, target - f.disp - inline) + f.disp + inline
            else:
                r.errors.append(f"unsupported fixup target {f.target} at {at:#x}")
                continue
            if expect != target:
                r.errors.append(f"pointer at {at:#x} is {expect if expect is None else hex(expect)}, "
                                f"the original's is {target:#x}")
            struct.pack_into("<I", ours, f.offset, (expect or 0) & 0xFFFFFFFF)
        for at in range(base, base + seg.size):
            if at in orig.fixups and at not in fixed:
                r.errors.append(f"the original has a fixup at {at:#x}, this has none")
        if seg.cls.upper() != "BSS":
            diff = [base + i for i in range(seg.size) if base + i not in fixed and ours[i] != theirs[i]]
            if diff:
                r.errors.append(f"{len(diff)} bytes differ, first at {diff[0]:#x}")
        r.ours, r.size = bytes(ours), seg.size
    return results, bases


def disasm(blob, addr):
    with tempfile.NamedTemporaryFile(suffix=".bin") as t:
        t.write(blob)
        t.flush()
        out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "intel",
                              f"--adjust-vma={addr:#x}", t.name], capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if l[:1] == " "]


def main():
    os.chdir(ROOT)
    orig = Original(EXE)
    by_symbol, _ = load_symbols()
    results = []
    for path in sorted(glob.glob("build/obj/*.obj")):
        for mod in omf.modules(path):
            results += compare_module(mod, orig, by_symbol)[0]
    wanted = sys.argv[1:]
    known = load_nonmatching()
    warnings = [r for r in results if r.warning]
    results = [r for r in results if not r.warning]
    failed = []
    for r in results:
        expected = r.name in known
        if r.ok() and expected:
            r.errors.append("matches now: remove it from config/nonmatching.txt")
            status = "MISMATCH"
        elif r.ok():
            status = "ok"
        else:
            status = "nonmatch" if expected else "MISMATCH"
        if status == "MISMATCH":
            failed.append(r)
        if wanted and r.name not in wanted:
            continue
        print(f"{status:8} {r.addr or 0:#010x} {r.name}")
        for e in r.errors if status == "MISMATCH" or wanted else r.errors[-1:]:
            print(f"         {e}")
        if wanted and r.ours is not None:
            a = disasm(r.ours, r.addr)
            b = disasm(orig.read(r.addr, max(len(r.ours), 1)), r.addr)
            for line in difflib.unified_diff(b, a, "original", "ours", lineterm=""):
                print(line)
    if not wanted:
        for r in warnings:
            print(f"warning  {r.addr:#010x} {r.name}: {r.warning}")
        funcs = [r for r in results if not r.data]
        data = [r for r in results if r.data]
        good = [r for r in funcs if r.ok() and r.addr]
        near = [r for r in funcs if not r.ok() and r.name in known]
        print(f"{len(good)} of {len(funcs)} match, {sum(r.size for r in good)} bytes"
              + (f", {len(near)} known not to" if near else "")
              + f"; {sum(r.ok() for r in data)} of {len(data)} data segments match")
    sys.exit(0 if not [r for r in failed if not wanted or r.name in wanted] else 1)

if __name__ == "__main__":
    main()
