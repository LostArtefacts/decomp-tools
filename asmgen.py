"""Writes MASM source for functions of the original exe that no compiler
wrote, such as hand-written patches, from the exe's own bytes.

    asmgen.py NAME... > FILE.s

Each function becomes a `proc` named by its symbol in config/symbols.csv,
in the order given. Branches inside the given functions go to labels,
calls and jumps out of them name their target's symbol, and addresses in
the code become symbols: import slots `__imp__NAME@N` (from the import
libraries in build.lib), rows of config/symbols.csv (with an offset into
a data row), or labels on the bytes after a function up to the next row,
for strings kept in the code; those bytes go in .data, so the functions
keep their sizes, under public labels, so each piece ends where the next
begins. An address none of these
covers stops the run; add a row for it to config/symbols.csv.

Instructions are written out as MASM mnemonics, then assembled, and any
whose bytes differ from the original's (MASM picks other encodings for
some) are written as the original's bytes instead, with the symbols kept
where the code has relocations, until every function matches.
"""
import csv, glob, os, re, struct, subprocess, sys, tempfile

import build, coff, compare, project

ROOT = project.ROOT
os.chdir(ROOT)
EXE = os.path.join(ROOT, compare.EXE)
LOW, HIGH = 0x400000, 0x1000000
BRANCH = re.compile(r"^(j\w+|call|loop\w*|jecxz)$")


def rows():
    with open("config/symbols.csv") as f:
        return list(csv.DictReader(f))


def imports():
    """{import slot address: name} from the exe's import table."""
    data = open(EXE, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    base = struct.unpack_from("<I", data, opt + 28)[0]
    secs = [struct.unpack_from("<IIII", data, opt + optsz + 40 * n + 8) for n in range(nsec)]

    def off(rva):
        for vsz, va, rsz, rptr in secs:
            if va <= rva < va + max(vsz, rsz):
                return rva - va + rptr
    out, o = {}, off(struct.unpack_from("<I", data, opt + 104)[0])
    while True:
        oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, o)
        if not name_rva:
            return {k + base: v for k, v in out.items()}
        t, slot = off(oft or ft), ft
        while (v := struct.unpack_from("<I", data, t)[0]):
            if not v & 0x80000000:
                out[slot] = data[off(v) + 2:].split(b"\0")[0].decode()
            t, slot = t + 4, slot + 4
        o += 20


def import_symbols(names):
    """{name: its __imp__ symbol} from the import libraries."""
    found = {}
    for d in project.config["build"]["lib"]:
        for lib in glob.glob(os.path.join(build.host(d).replace("\\", "/") if build.NATIVE else
                                          os.path.join(ROOT, ".wine/drive_c", d[3:].replace("\\", "/")), "*.[lL][iI][bB]")):
            data = open(lib, "rb").read()
            for name in names - set(found):
                m = re.search(rb"__imp__" + re.escape(name.encode()) + rb"(@\d+)?\0", data)
                if m:
                    found[name] = m.group(0)[:-1].decode()
    return found


def disasm(code, addr):
    """(address, bytes, mnemonic, operands) of each instruction."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(code)
    out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "intel", f"--adjust-vma={addr:#x}",
                          f.name], capture_output=True, text=True, check=True).stdout
    os.remove(f.name)
    ins = []
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*(?:\t(\S+)\s*(.*))?$", line)
        if not m:
            continue
        at, raw = int(m[1], 16), bytes.fromhex(m[2])
        if m[3] is None:
            ins[-1] = (ins[-1][0], ins[-1][1] + raw, ins[-1][2], ins[-1][3])
        else:
            ins.append((at, raw, m[3], m[4].strip()))
    return ins


REG_SIZE = {**{r: "byte" for r in "al cl dl bl ah ch dh bh".split()},
            **{r: "word" for r in "ax cx dx bx sp bp si di".split()},
            **{r: "dword" for r in "eax ecx edx ebx esp ebp esi edi".split()}}


class Writer:
    def __init__(self, names):
        self.rows = rows()
        self.by_name = {r["name"]: r for r in self.rows}
        self.starts = sorted((int(r["address"], 16), r) for r in self.rows)
        self.slots = imports()
        self.funcs = []
        for name in names:
            r = self.by_name[name]
            if not r["symbol"]:
                sys.exit(f"{name} has no symbol in config/symbols.csv; give it one, e.g. _{name}")
            addr, size = int(r["address"], 16), int(r["size"])
            ins = disasm(coff.Image(EXE).read(addr, size), addr)
            cut = [at for at, raw, mnem, ops in ins if mnem.startswith(".") or mnem == "(bad)"]
            if cut:
                sys.exit(f"{name}: its size in config/symbols.csv ({size}) cuts the instruction at {cut[0]:#x}")
            self.funcs.append((name, r["symbol"].split()[0], addr, size, ins))
        self.raw = set()

    def next_row(self, addr):
        return min((a for a, _ in self.starts if a > addr), default=addr + 256)

    def label(self, v):
        for name, sym, addr, size, ins in self.funcs:
            if v == addr:
                return sym
            if addr <= v < addr + size:
                return f"L{v:x}"
        for name, sym, addr, size, ins in self.funcs:
            if addr + size <= v < self.next_row(addr):
                return f"D{v:x}"

    def symbol(self, v, used):
        local = self.label(v)
        if local:
            return local
        if v in self.slots:
            used["imports"].add(self.slots[v])
            return "\0imp:" + self.slots[v]
        best = None
        for a, r in self.starts:
            if a > v:
                break
            best = (a, r)
        if best and r_covers(best, v):
            a, r = best
            sym = r["symbol"].split()[0] if r["symbol"] else None
            if not sym:
                sys.exit(f"{v:#x} is in {r['name']}, which has no symbol in config/symbols.csv")
            used["externs"].add((sym, is_code(r)))
            return sym if v == a else f"{sym}+{v - a}"
        sys.exit(f"{v:#x}: no row in config/symbols.csv covers it; add one")

    def operands(self, text, used, mnem):
        text = text.replace("DWORD PTR", "dword ptr").replace("WORD PTR", "word ptr").replace("BYTE PTR", "byte ptr")
        text = text.replace("QWORD PTR", "qword ptr").replace("TBYTE PTR", "tbyte ptr")

        def addr(m):
            v = int(m.group(2), 16)
            if LOW <= v < HIGH:
                sym = self.symbol(v, used)
                return f"[{sym}]" if m.group(1) else f"offset {sym}"
            return f"0{v:x}h" if m.group(1) is None else f"ds:[0{v:x}h]"
        text = re.sub(r"(ds:)?0x([0-9a-f]+)", addr, text)
        text = re.sub(r"\[([^\]]*?)0x([0-9a-f]+)([^\]]*)\]", lambda m: f"[{m[1]}0{m[2]}h{m[3]}]", text)
        parts = [p.strip() for p in split_operands(text)]
        if len(parts) == 2 and parts[0].startswith("[") and parts[1] in REG_SIZE:
            parts[0] = f"{REG_SIZE[parts[1]]} ptr {parts[0]}"
        if len(parts) == 2 and parts[1].startswith("[") and parts[0] in REG_SIZE and mnem not in ("lea",):
            parts[1] = f"{REG_SIZE[parts[0]]} ptr {parts[1]}"
        return ", ".join(parts)

    def source(self):
        used = {"imports": set(), "externs": set()}
        body, data = [], []
        targets = {int(t, 16) for _, _, _, _, ins in self.funcs for _, _, m, o in ins
                   if BRANCH.match(m) for t in re.findall(r"^0x([0-9a-f]+)$", o)}
        data_refs = {int(v, 16) for _, _, _, _, ins in self.funcs for _, _, _, ops in ins
                     for v in re.findall(r"0x([0-9a-f]+)", ops)
                     if (self.label(int(v, 16)) or "").startswith("D")}
        for name, sym, addr, size, ins in self.funcs:
            body.append(f"{sym} proc public")
            for at, raw, mnem, ops in ins:
                if at in targets and at != addr:
                    body.append(f"L{at:x}:")
                body.append(self.instruction(at, raw, mnem, ops, used, data_refs))
            body.append(f"{sym} endp")
            body.append("")
            refs = sorted(v for v in data_refs if addr + size <= v < self.next_row(addr))
            if refs:
                end = self.next_row(addr)
                blob = coff.Image(EXE).read(addr + size, end - addr - size)
                cuts = sorted(set(refs) | {addr + size, end})
                for a, b in zip(cuts, cuts[1:]):
                    data.append(f"    public D{a:x}")
                    data.append(f"D{a:x} label byte")
                    data.extend(data_lines(blob[a - addr - size:b - addr - size]))
        imps = import_symbols(used["imports"])
        missing = used["imports"] - set(imps)
        if missing:
            sys.exit(f"no import library defines {', '.join(sorted(missing))}")
        if data:
            body += ["    .data", ""] + data
        text = "\n".join(body)
        text = re.sub(r"\0imp:(\w+)", lambda m: imps[m[1]], text)
        local = {sym for _, sym, _, _, _ in self.funcs}
        head = ["    .486", "    .model flat", ""]
        head += [f"    extern {s}:{'near' if code else 'byte'}" for s, code in sorted(used["externs"]) if s not in local]
        head += [f"    extern {imps[n]}:dword" for n in sorted(used["imports"])]
        return "\n".join(head + ["", "    .code", "", text]).rstrip() + "\n\n    end\n"

    def instruction(self, at, raw, mnem, ops, used, data_refs):
        for v in re.findall(r"0x([0-9a-f]+)", ops):
            if self.label(int(v, 16)) and self.label(int(v, 16)).startswith("D"):
                data_refs.add(int(v, 16))
        if at in self.raw:
            return self.bytes_of(at, raw, ops, used)
        if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
            target = self.symbol(int(ops, 16), used)
            if mnem == "call":
                return f"    call {target}"
            size = "short" if len(raw) == 2 else "near ptr"
            return f"    {mnem} {size} {target}"
        return f"    {mnem} {self.operands(ops, used, mnem)}".rstrip()

    def bytes_of(self, at, raw, ops, used):
        """The instruction as its bytes, with a dd of the symbol where it
        holds an address."""
        for v in re.findall(r"0x([0-9a-f]+)", ops):
            v = int(v, 16)
            if LOW <= v < HIGH:
                k = raw.find(struct.pack("<I", v))
                if k >= 0:
                    sym = self.symbol(v, used)
                    parts = []
                    if k:
                        parts.append("    db " + ", ".join(f"0{b:02x}h" for b in raw[:k]))
                    parts.append(f"    dd {sym}")
                    if raw[k + 4:]:
                        parts.append("    db " + ", ".join(f"0{b:02x}h" for b in raw[k + 4:]))
                    return "\n".join(parts)
        return "    db " + ", ".join(f"0{b:02x}h" for b in raw)


def data_lines(blob):
    """`db` lines for bytes: runs of printable text as strings, the rest
    as hex, 16 to a line."""
    lines, items, k = [], [], 0
    while k < len(blob):
        j = k
        while j < len(blob) and 0x20 <= blob[j] < 0x7f and blob[j] != 0x22:
            j += 1
        if j - k >= 3:
            items.append('"' + blob[k:j].decode() + '"')
            k = j
        else:
            items.append(f"0{blob[k]:02x}h")
            k += 1
        if len(items) >= 16 or items[-1].startswith('"'):
            lines.append("    db " + ", ".join(items))
            items = []
    if items:
        lines.append("    db " + ", ".join(items))
    return lines


def r_covers(best, v):
    a, r = best
    return v < a + max(int(r["size"] or 0), 1)


def text_range():
    data = open(EXE, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
    for n in range(nsec):
        h = pe + 24 + optsz + 40 * n
        vsz, va = struct.unpack_from("<II", data, h + 8)
        if struct.unpack_from("<I", data, h + 36)[0] & 0x20:
            return base + va, base + va + vsz
    return 0, 0


TEXT = text_range()


def is_code(r):
    return TEXT[0] <= int(r["address"], 16) < TEXT[1]


def split_operands(text):
    out, depth, cur = [], 0, ""
    for ch in text:
        depth += ch == "["
        depth -= ch == "]"
        if ch == "," and not depth:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    return out + [cur] if cur or out else []


def assemble(text):
    """Our bytes for each function: {address: bytes}, or None if ml fails."""
    work = os.path.join(ROOT, "build", "asmgen")
    os.makedirs(work, exist_ok=True)
    src, obj = os.path.join(work, "gen.s"), os.path.join(work, "gen.obj")
    open(src, "w", newline="\r\n").write(text)
    code, out = build.run_tool("ml", *project.config["build"]["asflags"], "/Fo" + build.win(obj), build.win(src))
    if code:
        print(out, file=sys.stderr)
        return None
    return coff.Object(obj)


def main():
    names = sys.argv[1:]
    if not names:
        sys.exit(__doc__)
    w = Writer(names)
    for _ in range(200):
        text = w.source()
        obj = assemble(text)
        if obj is None:
            sys.exit("ml failed on the generated source")
        mismatch = first_mismatch(w, obj)
        if mismatch is None:
            print(text, end="")
            return 0
        if mismatch in w.raw:
            sys.exit(f"{mismatch:#x} still differs as bytes")
        w.raw.add(mismatch)
    sys.exit("gave up after 200 rounds")


def first_mismatch(w, obj):
    """The address of the first instruction whose assembled bytes differ
    from the original's, outside relocations, or None."""
    text = next(s for s in obj.sections if s.name.startswith(".text"))
    starts = {}
    for sym in obj.symbols:
        if sym is not None and sym.section > 0 and obj.sections[sym.section - 1] is text:
            starts[sym.name] = sym.value
    relocated = set()
    for off, *_ in text.relocs:
        relocated.update(range(off, off + 4))
    for name, sym, addr, size, ins in w.funcs:
        base = starts.get(sym)
        if base is None:
            return ins[0][0]
        for at, raw, mnem, ops in ins:
            k = base + at - addr
            ours = text.data[k:k + len(raw)]
            if any(ours[i] != raw[i] for i in range(len(raw)) if k + i not in relocated) or len(ours) < len(raw):
                return at
    return None


if __name__ == "__main__":
    sys.exit(main())
