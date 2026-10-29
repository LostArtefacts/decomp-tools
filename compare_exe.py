"""Compares the standalone build/<name>.exe with the original, section by
section, and the game's functions and globals by symbol.

    compare_exe.py [-v] [OURS [ORIGINAL]]

For the headers, the Rich header, each section and the imports it prints
the share of identical bytes (at the same file offset or address), the
size difference and the first divergence. Code is then aligned by
symbol: the link map (build/<name>_exe.map) gives each function's address in
our exe, config/symbols.csv its address in the original. For each
function it checks whether it sits at its original address and whether
its bytes are identical, raw and with addresses masked (a dword that is
an address inside both images, or a rel32 call/jump/jcc whose
target lies in both images' .text). Functions are grouped into regions
(game, CRT, other libraries) by the object or library our map puts them
in. The Rich header is compared when either exe has one: MSVC 5's
linker writes none. -v lists every function that moved or differs.
"""
import bisect, collections, csv, os, re, struct, sys

import project

ROOT = project.ROOT
OURS = project.EXE
ORIGINAL = project.ORIGINAL
MAP = project.EXE_MAP
SYMBOLS = "config/symbols.csv"

OPT_FIELDS = [  # (offset in the optional header, format, name)
    (0, "H", "Magic"), (2, "B", "MajorLinkerVersion"), (3, "B", "MinorLinkerVersion"),
    (4, "I", "SizeOfCode"), (8, "I", "SizeOfInitializedData"),
    (12, "I", "SizeOfUninitializedData"), (16, "I", "AddressOfEntryPoint"),
    (20, "I", "BaseOfCode"), (24, "I", "BaseOfData"), (28, "I", "ImageBase"),
    (32, "I", "SectionAlignment"), (36, "I", "FileAlignment"),
    (40, "H", "MajorOperatingSystemVersion"), (42, "H", "MinorOperatingSystemVersion"),
    (44, "H", "MajorImageVersion"), (46, "H", "MinorImageVersion"),
    (48, "H", "MajorSubsystemVersion"), (50, "H", "MinorSubsystemVersion"),
    (52, "I", "Win32VersionValue"), (56, "I", "SizeOfImage"), (60, "I", "SizeOfHeaders"),
    (64, "I", "CheckSum"), (68, "H", "Subsystem"), (70, "H", "DllCharacteristics"),
    (72, "I", "SizeOfStackReserve"), (76, "I", "SizeOfStackCommit"),
    (80, "I", "SizeOfHeapReserve"), (84, "I", "SizeOfHeapCommit"),
    (88, "I", "LoaderFlags"), (92, "I", "NumberOfRvaAndSizes"),
]
DIRS = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug",
        "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT",
        "DelayImport", "CLR", "Reserved"]
# Rich header product ids (MSVC 5 to 7.1), for the report. Id 0 counts
# the objects of tools that wrote no id, such as MSVC 5's compiler.
PRODIDS = {0: "Unmarked", 1: "Import0", 2: "Linker510", 3: "Cvtomf510", 4: "Linker600",
           5: "Cvtomf600", 6: "Cvtres500", 7: "Utc11_Basic", 8: "Utc11_C", 9: "Utc12_Basic",
           10: "Utc12_C", 11: "Utc12_CPP", 12: "AliasObj60", 14: "Masm613", 16: "Linker511",
           17: "Cvtomf511", 18: "Masm614", 19: "Linker512", 20: "Cvtomf512",
           25: "Implib700", 28: "Utc13_C", 29: "Utc13_CPP",
           37: "Linker620", 61: "Linker700", 64: "Masm700", 69: "Cvtres700",
           90: "Linker710", 93: "Implib710", 94: "Cvtres710", 95: "Utc1310_C",
           96: "Utc1310_CPP"}


class PE:
    def __init__(self, path):
        self.path = path
        self.data = d = open(path, "rb").read()
        self.pe = pe = struct.unpack_from("<I", d, 0x3C)[0]
        self.nsec, = struct.unpack_from("<H", d, pe + 6)
        self.optsz, = struct.unpack_from("<H", d, pe + 20)
        self.opt = pe + 24
        self.base, = struct.unpack_from("<I", d, self.opt + 28)
        self.sizeof_headers, = struct.unpack_from("<I", d, self.opt + 60)
        self.sizeof_image, = struct.unpack_from("<I", d, self.opt + 56)
        self.sections = {}
        self.order = []
        for i in range(self.nsec):
            h = self.opt + self.optsz + 40 * i
            name = d[h:h + 8].rstrip(b"\0").decode()
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, h + 8)
            self.sections[name] = (self.base + va, vsize, rawptr, rawsize)
            self.order.append(name)
        self.rich = self._rich()

    def _rich(self):
        d = self.data
        end = d.find(b"Rich", 0, self.pe)
        if end < 0:
            return None
        key, = struct.unpack_from("<I", d, end + 4)
        start = end - 4
        while struct.unpack_from("<I", d, start)[0] ^ key != 0x536E6144:  # DanS
            start -= 4
        entries = []
        for off in range(start + 16, end, 8):
            compid, count = (v ^ key for v in struct.unpack_from("<II", d, off))
            entries.append((compid >> 16, compid & 0xFFFF, count))
        return start, end + 8, key, entries

    def directory(self, i):
        return struct.unpack_from("<II", self.data, self.opt + 96 + 8 * i)

    def offset(self, addr):
        for va, vsize, rawptr, rawsize in self.sections.values():
            if va <= addr < va + max(vsize, rawsize):
                return rawptr + addr - va if addr - va < rawsize else None
        return None

    def read(self, addr, size):
        o = self.offset(addr)
        if o is None:
            return b""
        name = self.section_of(addr)
        va, _, rawptr, rawsize = self.sections[name]
        return self.data[o:min(o + size, rawptr + rawsize)]

    def section_of(self, addr):
        for name, (va, vsize, _, rawsize) in self.sections.items():
            if va <= addr < va + max(vsize, rawsize):
                return name
        return None

    def imports(self):
        """[(dll, IAT address, [function names])] in descriptor order."""
        rva, _ = self.directory(1)
        out = []
        o = self.offset(self.base + rva)
        while True:
            oft, _, _, name, ft = struct.unpack_from("<IIIII", self.data, o)
            if not name:
                return out
            dll = self.cstr(self.base + name)
            funcs, t = [], self.offset(self.base + (oft or ft))
            while (v := struct.unpack_from("<I", self.data, t)[0]):
                funcs.append(f"#{v & 0xFFFF}" if v & 0x80000000 else self.cstr(self.base + v + 2))
                t += 4
            out.append((dll, self.base + ft, funcs))
            o += 20

    def cstr(self, addr):
        o = self.offset(addr)
        return self.data[o:self.data.index(b"\0", o)].decode("latin-1")


def same(a, b):
    """Identical bytes at the same position, the length of the longer."""
    n = min(len(a), len(b))
    if a[:n] == b[:n]:
        return n
    return sum(x == y for x, y in zip(a, b))


def first_diff(a, b):
    n = min(len(a), len(b))
    if a[:n] == b[:n]:
        return None if len(a) == len(b) else n
    lo, hi = 0, n  # binary search on prefix equality
    while lo < hi:
        mid = (lo + hi) // 2
        if a[:mid + 1] == b[:mid + 1]:
            lo = mid + 1
        else:
            hi = mid
    return lo


def pct(n, total):
    return f"{100 * n / total:6.2f}%" if total else "   n/a "


def bytes_line(label, a, b, base=None):
    total = max(len(a), len(b))
    n = same(a, b)
    fd = first_diff(a, b)
    where = "identical" if fd is None else f"first divergence at +{fd:#x}" + (
        f" ({base + fd:#010x})" if base is not None else "")
    print(f"  {label:22s} {pct(n, total)} identical  ours {len(a):#9x}  orig {len(b):#9x}"
          f"  ({len(a) - len(b):+#x})  {where}")
    return n, total


def report_headers(ours, orig):
    print("Headers")
    # Without a Rich header the DOS stub runs up to the PE header.
    rich_o = ours.rich or (ours.pe, ours.pe)
    rich_r = orig.rich or (orig.pe, orig.pe)
    bytes_line("DOS header + stub", ours.data[:rich_o[0]], orig.data[:rich_r[0]])
    if ours.rich or orig.rich:
        bytes_line("Rich header", ours.data[rich_o[0]:rich_o[1]], orig.data[rich_r[0]:rich_r[1]])
    bytes_line("all headers", ours.data[:ours.sizeof_headers], orig.data[:orig.sizeof_headers])
    diffs = []
    for off, fmt, name in OPT_FIELDS:
        a, = struct.unpack_from("<" + fmt, ours.data, ours.opt + off)
        b, = struct.unpack_from("<" + fmt, orig.data, orig.opt + off)
        if a != b:
            diffs.append(f"{name} {a:#x}/{b:#x}")
    for i, name in enumerate(DIRS):
        a, b = ours.directory(i), orig.directory(i)
        if a != b:
            diffs.append(f"{name}Dir {a[0]:#x},{a[1]:#x}/{b[0]:#x},{b[1]:#x}")
    print("  optional header fields that differ (ours/orig):")
    for d in diffs:
        print("    " + d)
    print("  sections (ours/orig):")
    for name in sorted(set(ours.order) | set(orig.order), key=lambda n: orig.order.index(n) if n in orig.order else 99):
        a, b = ours.sections.get(name), orig.sections.get(name)
        fa = lambda s: f"va {s[0]:#x} vsize {s[1]:#x} raw {s[3]:#x}" if s else "missing"
        print(f"    {name:8s} {fa(a):42s} | {fa(b)}")


def report_rich(ours, orig):
    if not ours.rich and not orig.rich:
        return
    print("Rich header (prodid/build: count, ours vs orig; in header order)")
    ours_rich = ours.rich[3] if ours.rich else []
    orig_rich = orig.rich[3] if orig.rich else []
    o = {(p, b): c for p, b, c in ours_rich}
    r = {(p, b): c for p, b, c in orig_rich}
    for k in [e[:2] for e in orig_rich] + [e[:2] for e in ours_rich if e[:2] not in r]:
        p, b = k
        mark = "" if o.get(k) == r.get(k) else "   <-- differs"
        print(f"  {p:3d} {PRODIDS.get(p, '?'):11s} build {b:5d}: ours {o.get(k, '-')!s:>4} orig {r.get(k, '-')!s:>4}{mark}")
    print("  order ours: " + " ".join(f"{p}/{b}" for p, b, _ in ours_rich))
    print("  order orig: " + " ".join(f"{p}/{b}" for p, b, _ in orig_rich))


def report_sections(ours, orig):
    print("Sections (raw bytes at the same offset within the section)")
    totals = [0, 0]
    for name in orig.order:
        if name not in ours.sections:
            print(f"  {name}: missing in ours")
            continue
        va, vsize, rawptr, rawsize = ours.sections[name]
        vb, vsizeb, rawptrb, rawsizeb = orig.sections[name]
        # .data: only the initialized part (on disk) is compared.
        a = ours.data[rawptr:rawptr + min(vsize, rawsize)]
        b = orig.data[rawptrb:rawptrb + min(vsizeb, rawsizeb)]
        label = name + (" (initialized)" if vsize > rawsize or vsizeb > rawsizeb else "")
        n, t = bytes_line(label, a, b, vb)
        totals[0] += n
        totals[1] += t
        if vsize != vsizeb:
            print(f"  {'':22s} virtual size ours {vsize:#x} orig {vsizeb:#x} ({vsize - vsizeb:+#x})")
    n, t = same(ours.data, orig.data), max(len(ours.data), len(orig.data))
    print(f"  {'whole file':22s} {pct(n, t)} identical  ({t - n} bytes differ)")


def report_imports(ours, orig):
    print("Imports")
    io, ir = ours.imports(), orig.imports()
    print("  DLL order ours: " + " ".join(d for d, _, _ in io))
    print("  DLL order orig: " + " ".join(d for d, _, _ in ir))
    o = {d.upper(): (iat, f) for d, iat, f in io}
    for dll, iat, funcs in ir:
        if dll.upper() not in o:
            print(f"  {dll}: missing in ours")
            continue
        iat_o, f_o = o[dll.upper()]
        state = ("same functions, same order" if f_o == funcs else
                 "same functions, other order" if sorted(f_o) == sorted(funcs) else
                 f"different functions (+{sorted(set(f_o) - set(funcs))} -{sorted(set(funcs) - set(f_o))})")
        print(f"  {dll:12s} {len(funcs):3d} funcs  IAT ours {iat_o:#x} orig {iat:#x}  {state}")
    rva, size = orig.directory(1)
    rva_o, size_o = ours.directory(1)
    bytes_line("import directory", ours.read(ours.base + rva_o, size_o), orig.read(orig.base + rva, size))
    rva, size = orig.directory(12)
    rva_o, size_o = ours.directory(12)
    bytes_line("IAT", ours.read(ours.base + rva_o, size_o), orig.read(orig.base + rva, size))


def read_map():
    """{symbol: (address, object)} from the link map."""
    text = open(MAP, encoding="latin-1").read()
    if "Preferred load address is 00400000" not in text:
        sys.exit(f"{MAP} is not the exe's map: run `just exe`")
    syms = {}
    line_re = re.compile(r"^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s+(?:f\s+)?(?:i\s+)?(\S+)\s*$")
    for line in text.splitlines():
        m = line_re.match(line)
        if m:
            name, addr, obj = m.groups()
            syms.setdefault(name, (int(addr, 16), obj))
    return syms


def read_symbols():
    with open(SYMBOLS) as f:
        return [(int(r["address"], 16), int(r["size"] or 0), r["name"], r["symbol"].split())
                for r in csv.DictReader(f)]


CRT = ("libc:", "libcmt:", "msvcrt:")


def region_of(obj):
    if obj.startswith(CRT):
        return "CRT"
    if ":" in obj:
        return obj.split(":")[0]
    return "game"


def masked_same(ours, orig, a_addr, b_addr, a, b):
    """Whether a and b differ only inside address operands. Both are
    read on for 3 more bytes, so an operand cut off at the end counts."""
    size = min(len(a), len(b))
    a = a + ours.read(a_addr + len(a), 3)
    b = b + orig.read(b_addr + len(b), 3)
    ta, tb = ours.sections[".text"], orig.sections[".text"]
    lo_a, hi_a = ours.base, ours.base + ours.sizeof_image
    lo_b, hi_b = orig.base, orig.base + orig.sizeof_image
    in_text = lambda t, x: t[0] <= x < t[0] + t[1]
    n = min(len(a), len(b))
    masked = bytearray(n)
    for j in range(n - 3):
        if a[j:j + 4] == b[j:j + 4]:
            continue
        va, = struct.unpack_from("<I", a, j)
        vb, = struct.unpack_from("<I", b, j)
        ok = lo_a <= va < hi_a and lo_b <= vb < hi_b
        if not ok and j >= 1:
            rel = a[j - 1] in (0xE8, 0xE9) and a[j - 1] == b[j - 1]
            rel = rel or (j >= 2 and a[j - 2] == 0x0F == b[j - 2] and 0x80 <= a[j - 1] == b[j - 1] < 0x90)
            if rel:
                ta_ = (a_addr + j + 4 + struct.unpack_from("<i", a, j)[0]) & 0xFFFFFFFF
                tb_ = (b_addr + j + 4 + struct.unpack_from("<i", b, j)[0]) & 0xFFFFFFFF
                ok = in_text(ta, ta_) and in_text(tb, tb_)
        if ok:
            masked[j:j + 4] = b"\1\1\1\1"
    return all(x == y or masked[i] for i, (x, y) in enumerate(zip(a[:size], b[:size])))


def report_code(ours, orig, verbose):
    print("Functions by symbol (.text)")
    ourmap = read_map()
    text = orig.sections[".text"]
    rows = []
    unmatched = 0
    for addr, size, name, syms in read_symbols():
        if not (text[0] <= addr < text[0] + text[1]) or not size:
            continue
        cands = syms + [name, "_" + name, "_" + name.lstrip("_"), "__" + name.lstrip("_")]
        hit = next((ourmap[c] for c in cands if c in ourmap), None)
        rows.append((addr, size, name, hit))
        unmatched += hit is None
    rows.sort()
    # Region of each original function: its object in our map, else the
    # region of the preceding function that has one.
    region, last = [], "game"
    for addr, size, name, hit in rows:
        if hit:
            last = region_of(hit[1])
        region.append(last)
    stats = collections.defaultdict(lambda: collections.Counter())
    first = {}
    details = []
    for (addr, size, name, hit), reg in zip(rows, region):
        st = stats[reg]
        st["functions"] += 1
        st["bytes"] += size
        if not hit:
            st["no symbol"] += 1
            continue
        ours_addr = hit[0]
        a, b = ours.read(ours_addr, size), orig.read(addr, size)
        moved = ours_addr != addr
        raw = a == b
        masked = raw or masked_same(ours, orig, ours_addr, addr, a, b)
        st["at original address"] += not moved
        st["bytes at original address"] += size * (not moved)
        st["identical raw"] += raw
        st["identical masked"] += masked
        st["bytes identical masked"] += size * masked
        if moved and reg not in first:
            first[reg] = (addr, name, ours_addr)
        if moved or not masked:
            details.append(f"    {reg:6s} {addr:#010x} -> {ours_addr:#010x} ({ours_addr - addr:+#7x})"
                           f" {'raw' if raw else 'masked' if masked else 'DIFFERS'} {name}")
    spans = []
    for (addr, size, _, _), reg in zip(rows, region):
        if spans and spans[-1][0] == reg:
            spans[-1][2] = addr + size
        else:
            spans.append([reg, addr, addr + size])
    print("  original layout: " + ", ".join(f"{r} {a:#x}-{e:#x}" for r, a, e in spans))
    ours_spans = collections.defaultdict(lambda: [1 << 32, 0])
    for name, (addr, obj) in ourmap.items():
        if ours.section_of(addr) == ".text":
            s = ours_spans[region_of(obj)]
            s[0], s[1] = min(s[0], addr), max(s[1], addr)
    print("  our layout (min-max symbol): " + ", ".join(
        f"{r} {a:#x}-{e:#x}" for r, (a, e) in sorted(ours_spans.items(), key=lambda kv: kv[1][0])))
    print(f"  {unmatched} of {len(rows)} named original functions have no symbol in our map")
    for reg, st in stats.items():
        n = st["functions"] - st["no symbol"]
        print(f"  {reg:6s} {st['functions']:4d} functions ({st['bytes']:#x} bytes), {st['no symbol']} without symbol;"
              f" of {n}: {st['at original address']} at original address,"
              f" {st['identical raw']} identical raw, {st['identical masked']} identical with addresses masked"
              f" ({pct(st['bytes identical masked'], st['bytes'])} of bytes)")
        if reg in first:
            a, nm, o = first[reg]
            print(f"         first moved: {nm} at {a:#x} (ours {o:#x}, {o - a:+#x})")
    report_chunks(ours, orig, ourmap, {a: n for a, _, n, _ in rows},
                  {s: a for a, _, _, syms in read_symbols() for s in syms})
    if verbose:
        print("  moved or different:")
        print("\n".join(details))


def report_chunks(ours, orig, ourmap, orig_names, orig_syms):
    """Library code by object: each object's run of .text in our exe
    (from its first public to the next object's), placed in the original
    by any of its publics that symbols.csv knows."""
    text = sorted((a, obj, n) for n, (a, obj) in ourmap.items() if ours.section_of(a) == ".text")
    chunks = []
    for a, obj, n in text:
        if chunks and chunks[-1][1] == obj:
            chunks[-1][2].append((a, n))
        else:
            chunks.append([a, obj, [(a, n)]])
    va, vsize = ours.sections[".text"][:2]
    stats = collections.defaultdict(collections.Counter)
    for i, (start, obj, syms) in enumerate(chunks):
        end = chunks[i + 1][0] if i + 1 < len(chunks) else va + vsize
        reg = region_of(obj)
        st = stats[reg]
        st["objects"] += 1
        st["bytes"] += end - start
        delta = None
        for a, n in syms:
            cands = [n, n[1:], n.lstrip("_")]
            hit = next((orig_syms[c] for c in cands if c in orig_syms), None)
            if hit is None:
                hit = next((x for x, nm in orig_names.items() if nm in cands), None)
            if hit is not None:
                delta = hit - a
                break
        if delta is None:
            found = find_code(ours, orig, start, end - start)
            if found is not None:
                delta = found - start
                st["placed by content"] += 1
        if delta is None:
            st["not placed"] += 1
            continue
        a, b = ours.read(start, end - start), orig.read(start + delta, end - start)
        st["placed"] += 1
        st["placed bytes"] += end - start
        st["at original address"] += delta == 0
        if a == b or masked_same(ours, orig, start, start + delta, a, b):
            st["identical masked"] += 1
            st["identical bytes"] += end - start
    print("  by object (our runs of .text, placed in the original by a known public):")
    for reg, st in stats.items():
        print(f"  {reg:8s} {st['objects']:3d} objects ({st['bytes']:#x} bytes), {st['placed']} placed;"
              f" ({st['placed by content']} by content); {st['at original address']} at original address;"
              f" {st['identical masked']} identical with addresses masked"
              f" ({pct(st['identical bytes'], st['placed bytes'])} of placed bytes)")


def find_code(ours, orig, addr, size):
    """The address in the original's .text of the code at `addr` in ours,
    by its first bytes with address operands as wildcards, if unique."""
    a = ours.read(addr, min(size, 96))
    wild = bytearray(len(a))
    for j in range(len(a) - 3):
        v, = struct.unpack_from("<I", a, j)
        if ours.base <= v < ours.base + ours.sizeof_image or (j and a[j - 1] in (0xE8, 0xE9)) \
                or (j > 1 and a[j - 2] == 0x0F and 0x80 <= a[j - 1] < 0x90):
            wild[j:j + 4] = b"\1\1\1\1"
    if sum(not w for w in wild) < 24:
        return None
    pat = re.compile(b"".join(b"." if w else re.escape(bytes([c])) for c, w in zip(a, wild)), re.S)
    va, vsize, rawptr, _ = orig.sections[".text"]
    hits = [m.start() for m in pat.finditer(orig.data, rawptr, rawptr + vsize)]
    if len(hits) != 1:
        return None
    return va + hits[0] - rawptr


def report_data(ours, orig, verbose):
    print("Globals by symbol (.rdata, .data)")
    ourmap = read_map()
    stats = collections.defaultdict(collections.Counter)
    for addr, size, name, syms in read_symbols():
        sec = orig.section_of(addr)
        if sec not in (".rdata", ".data"):
            continue
        hit = next((ourmap[c] for c in syms if c in ourmap), None)
        st = stats[sec]
        st["globals"] += 1
        if not hit:
            st["not in map"] += 1
            continue
        st["at original address"] += hit[0] == addr
        if size:
            a, b = ours.read(hit[0], size), orig.read(addr, size)
            if a or b:
                st["initialized"] += 1
                st["identical"] += a == b
    for sec, st in stats.items():
        print(f"  {sec:7s} {st['globals']} globals in symbols.csv, {st['not in map']} not in our map;"
              f" {st['at original address']} at original address;"
              f" {st['identical']} of {st['initialized']} initialized ones identical (raw)")


def main():
    os.chdir(ROOT)
    args = [a for a in sys.argv[1:] if a != "-v"]
    verbose = "-v" in sys.argv[1:]
    ours = PE(args[0] if args else OURS)
    orig = PE(args[1] if len(args) > 1 else ORIGINAL)
    print(f"{ours.path} ({len(ours.data)} bytes) vs {orig.path} ({len(orig.data)} bytes)")
    report_headers(ours, orig)
    report_rich(ours, orig)
    report_sections(ours, orig)
    report_imports(ours, orig)
    report_code(ours, orig, verbose)
    report_data(ours, orig, verbose)


if __name__ == "__main__":
    main()
