"""Writes a stretch of the original LE exe as source MASM: every
instruction a mnemonic, as a person writes it, where asmgen_le.py falls
back to the original's bytes.

    asmclean_le.py [--keep src/MODULE.asm] [--code ADDR]... [--cpu .486p]
                   KIND=START-END... > src/MODULE.asm

The ranges are asmgen_le.py's. The code is found by following it from
the functions of config/symbols.csv in the code range, from every
address a fixup outside an instruction (a jump table's entry) holds,
from the --code addresses, and from any stretch nothing reaches that
is not zeros or the assembler's alignment fill. The rest of the code
range is data: dwords, words and bytes typed by the instructions that
access them, `dword offset SYM` at fixups, and `align N` for runs of
MASM's fill (90, 8b c0, 2e 8b c0) up to an aligned address. The data
ranges are typed the same way where the code reads them, at fixups and
in runs of zeros; the rest of them stays bytes and strings. A jump
table read from a base before it (the table less its smallest index
times 4) is written `[reg*4+TABLE-INDEXh*4]`.

Labels keep the names --keep's module gives their addresses (read from
its MASM listing), so a module renamed by hand can be regenerated; the
rest are config/symbols.csv's symbols, or Lxxxxx for code and Dxxxxx
for data. Each function row is a proc; code outside the rows is under
plain labels, as compare_le.py takes a proc for a function with a row.

Each instruction is tried in its spellings (MASM's own branch sizing
first, then `short` or `near ptr`; swapped operands; the string,
iretd and pushfd forms) until the assembled line has the original's
bytes, checked line by line from ml's listing, so a wrong length does
not cascade. An instruction no spelling reproduces is reported with
both encodings and nothing is written: the module stays a stand-in
until it is solved by hand. The whole module is then checked as
asmgen_le.py checks it.
"""
import argparse, atexit, os, re, shutil, struct, subprocess, sys

import asmgen_le, omf, project
from asmgen import BRANCH, disasm
from asmgen_le import SEGMENTS, parse_range
from build_watcom import env, winpath

ROOT = project.ROOT
WORK = os.path.join(ROOT, "build", "asmclean", str(os.getpid()))
atexit.register(shutil.rmtree, WORK, True)
STOP = {"jmp", "ret", "retf", "retn", "iret", "iretd"}
SIZES = {"byte": 1, "word": 2, "dword": 4, "fword": 6, "qword": 8, "tbyte": 10}
TYPES = {1: "byte", 2: "word", 4: "dword"}
CPU486 = {"bswap", "cmpxchg", "xadd", "invd", "wbinvd", "invlpg"}
CPU586 = {"cpuid", "rdtsc", "rdmsr", "wrmsr", "cmpxchg8b"}
STRING = re.compile(r"^(rep\w* )?(movs|stos|lods|scas|cmps|ins|outs)$")


def fill(n):
    """MASM 6.11's alignment fill of n bytes in code."""
    return b"\x2e\x8b\xc0" * (n // 3) + (b"", b"\x90", b"\x8b\xc0")[n % 3]


class Clean(asmgen_le.Module):
    def __init__(self, ranges, keep=None, seeds=(), cpu=None):
        self.seeds, self.kept = list(seeds), {}
        self.choice = {}
        super().__init__(ranges)
        mnems = {mnem for raw, mnem, ops in self.ins.values()}
        self.cpu = cpu or (".586p" if mnems & CPU586 else ".486p" if mnems & CPU486 else ".386p")
        if keep:
            self.kept = read_names(keep, ranges)
            self.labels.update(self.kept)

    def split_code(self):
        """self.ins {address: (bytes, mnemonic, operands)} of the code and
        self.datarefs {address: access size} of the data the code reads."""
        self.ins, self.within, self.datarefs, self.tables = {}, {}, {}, set()
        self.datarefs_out, self.data_tables, self.data_plain = {}, set(), set()
        self.spans = []
        code = self.range("code")
        if not code:
            self.starts = set()
            return
        cs, ce = code
        work = [r[0] for r in self.funcs] + self.seeds
        while True:
            while work:
                a = work.pop()
                if a in self.ins or not cs <= a < ce:
                    continue
                if a in self.within:
                    sys.exit(f"{a:#x}: a branch or table enters the instruction at {self.within[a]:#x}")
                self.trace(a, work)
            gaps = self.gaps()

            def new(s):
                t = self.fix[s][0]
                return cs <= t < ce and t not in self.ins and t not in self.datarefs and t not in self.within

            for s in self.table_entries():
                if new(s):
                    work.append(self.fix[s][0])
            if not work:
                loose = [s for s in sorted(self.fix) if cs <= s < ce and s not in self.ins
                         and s not in self.within and new(s)]
                work += [self.fix[s][0] for s in loose[:1]]
            if not work:
                for a, b in gaps:
                    if any(x in self.datarefs or x in self.fix or x in self.inside_refs() for x in range(a, b)):
                        continue
                    for p, q in self.pieces(a, b):
                        if any(self.read(p, q)) and not self.is_fill(p, q):
                            work.append(p)
                            break
            if not work:
                break
        self.starts = set(self.ins)

    def trace(self, a, work):
        cs, ce = self.range("code")
        while True:
            end = min(a + 512, ce)
            for at, raw, mnem, ops in disasm(self.read(a, end), a):
                if at + 16 > end and end < ce:
                    a = at
                    break
                if at in self.ins:
                    return
                if mnem == "(bad)" or mnem.startswith(".") or at + len(raw) > ce:
                    sys.exit(f"{at:#x}: the code reached from {a:#x} does not disassemble")
                if any(i in self.ins or i in self.within for i in range(at, at + len(raw))):
                    sys.exit(f"{at:#x}: the instruction overlaps another")
                self.ins[at] = (raw, mnem, ops)
                for i in range(at + 1, at + len(raw)):
                    self.within[i] = at
                if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
                    work.append(int(ops, 16))
                for s in range(at, at + len(raw)):
                    if s in self.fix and self.kind_of(self.fix[s][0]) and "[" in ops:
                        t = self.fix[s][0]
                        m = re.search(r"(\w+) PTR", ops)
                        size = SIZES.get(m[1].lower(), 0) if m and mnem != "lea" else 0
                        if not cs <= t < ce:
                            self.datarefs_out[t] = max(self.datarefs_out.get(t, 0), size)
                            (self.data_tables if mnem in ("jmp", "call") else self.data_plain).add(t)
                            continue
                        self.datarefs[t] = max(self.datarefs.get(t, 0), size)
                        if mnem in ("jmp", "call"):
                            self.tables.add(t)
                if mnem in STOP:
                    return
            else:
                return

    def table_start(self, t):
        """The first entry of the jump table an indexed jmp or call with
        base t reads: t, or the first one after it, for a base inside
        other code (the table less the smallest index)."""
        s = t
        while s - t < 1024 and (s in self.ins or s in self.within or s not in self.fix):
            s += 4
        return s

    def table_entries(self):
        """The fixups of the jump tables an indexed jmp or call reads,
        each the run of code addresses from its start."""
        out = []
        for t in sorted(self.tables):
            s = self.table_start(t)
            while s in self.fix and s not in self.ins and s not in self.within:
                out.append(s)
                s += 4
        return out

    def inside_refs(self):
        """The addresses the module's fixups point at."""
        if not hasattr(self, "_targets"):
            self._targets = {t for t, k in self.fix.values()}
        return self._targets

    def gaps(self):
        cs, ce = self.range("code")
        out, at = [], cs
        while at < ce:
            if at in self.ins:
                at += len(self.ins[at][0])
                continue
            b = at
            while b < ce and b not in self.ins:
                b += 1
            out.append((at, b))
            at = b
        return out

    def is_fill(self, p, q):
        return any(q % n == 0 and q - p < n for n in (4, 8, 16)) and self.read(p, q) == fill(q - p)

    def pieces(self, a, b):
        """The gap a-b cut at labels, fixups and alignment fill."""
        cuts = {a, b} | {x for x in range(a + 1, b) if (x in self.datarefs or x in self.fix
                         or x in getattr(self, "labels", {}) or x in self.kept) and self.fixup_at(x) is None}
        for x in range(a + 1, b + 1):
            if x % 4 == 0:
                for k in range(min(15, x - a), 0, -1):
                    if self.read(x - k, x) == fill(k) and x % next(n for n in (4, 8, 16) if n > k) == 0:
                        cuts |= {x - k, x}
                        break
        cuts = sorted(cuts)
        return list(zip(cuts, cuts[1:]))

    def fixup_at(self, x):
        """The start of the fixup whose dword x is inside (not its first
        byte), or None."""
        return next((x - k for k in (1, 2, 3) if x - k in self.fix), None)

    def find_labels(self):
        labels = {}
        for a, s, n, sym in self.rows:
            if self.kind_of(a) and sym:
                labels.setdefault(a, sym)
        refs = set(self.datarefs)
        for kind, start, end in self.ranges:
            for src in range(start, end):
                if src in self.fix:
                    refs.add(self.fix[src][0])
        for at, (raw, mnem, ops) in self.ins.items():
            if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
                refs.add(int(ops, 16))
        self.based = {}
        for t in self.tables:
            s = self.table_start(t)
            if s != t and s in self.fix and t not in labels:
                self.based[t] = s
                refs = (refs - {t}) | {s}
        for t in self.data_tables - self.data_plain:
            s = next((s for s in range(t, t + 1024, 4) if s in self.fix), None)
            if s is not None and s != t and t not in labels:
                self.based[t] = s
                refs = (refs - {t}) | {s}
        self.inside = {}
        for t in refs:
            if t in self.within and t not in labels:
                self.inside[t] = self.within[t]
                refs = refs | {self.within[t]}
            elif t not in self.ins and t not in labels and self.kind_of(t) and self.fixup_at(t) is not None:
                self.inside[t] = self.fixup_at(t)
                refs = refs | {self.inside[t]}
        for t in refs:
            k = self.kind_of(t)
            if k and t not in labels and t not in self.inside:
                labels[t] = f"{'L' if t in self.ins else 'B' if k == 'bss' else 'D'}{t:x}"
        return labels

    def symbol(self, v, used):
        if v in getattr(self, "based", {}) and v not in self.labels:
            s = self.based[v]
            n = f"{(s - v) // 4:x}h"
            return f"{self.symbol(s, used)}-{'0' if n[0] > '9' else ''}{n}*4" if (s - v) % 4 == 0 else f"{self.symbol(s, used)}-{s - v}"
        return super().symbol(v, used)

    def variants(self, at, used):
        raw, mnem, ops = self.ins[at]
        if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
            target = int(ops, 16)
            if not self.kind_of(target) and not any(target == r[0] and r[3] for r in self.rows):
                sys.exit(f"{at:#x}: {mnem} {target:#x} goes to no function start with a symbol")
            t = self.symbol(target, used)
            if mnem == "call" or mnem.startswith("loop") or mnem == "jecxz":
                return [f"{mnem} {t}"]
            return [f"{mnem} {t}", f"{mnem} {'short' if len(raw) == 2 else 'near ptr'} {t}"]
        m = STRING.match(mnem)
        if m:
            size = re.match(r"(\w+) PTR", ops)
            letter = {"BYTE": "b", "WORD": "w", "DWORD": "d"}[size[1]] if size else "b"
            return [f"{m[1] or ''}{m[2]}{letter}"]
        if mnem in ("iret", "pushf", "popf", "pusha", "popa"):
            return [mnem + "d", mnem] if mnem.startswith("iret") else [mnem, mnem + "d"]
        if mnem == "xlat":
            return ["xlatb"]
        text = self.operands(at, raw, mnem, ops, used)
        out = [f"{mnem} {text}".rstrip()]
        parts = [p.strip() for p in text.split(",")]
        if mnem in ("xchg", "test") and len(parts) == 2:
            out.append(f"{mnem} {parts[1]}, {parts[0]}")
        return out

    def data_lines(self, p, q, used, named, before_fill=False):
        """Lines for the data p-q in code, the first named `named`. MASM
        fills an `align` after a `dup` with zeros, so before a fill the
        last item is written out of its dup."""
        out, at = [], p
        size = self.datarefs.get(p) or 0
        if size not in TYPES:
            size = next(n for n in (4, 2, 1) if (q - p) % n == 0)
        while at < q:
            if at in self.fix:
                t, kind = self.fix[at]
                if kind != 7:
                    sys.exit(f"{at:#x}: fixup kind {kind} is not supported yet")
                out.append((at, f"dword offset {self.symbol(t, used)}"))
                at += 4
                continue
            nxt = next((s for s in range(at, q) if s in self.fix), q)
            n = size if (nxt - at) >= size else next(k for k in (4, 2, 1) if (nxt - at) >= k)
            count = (nxt - at) // n
            blob = self.read(at, at + count * n)
            vals = [int.from_bytes(blob[i:i + n], "little") for i in range(0, len(blob), n)]
            last = before_fill and nxt == q
            if not any(vals) and count > 1 + last:
                out.append((at, f"{TYPES[n]} {count - last} dup(0)"))
                if last:
                    out.append((at + (count - 1) * n, f"{TYPES[n]} 0"))
            else:
                for i in range(0, len(vals), 8):
                    out.append((at + i * n, f"{TYPES[n]} " + ", ".join(f"0{v:x}h" if v else "0" for v in vals[i:i + 8])))
            at += count * n
        lines = []
        for i, (a, text) in enumerate(out):
            lines.append((a, f"{named} {text}" if i == 0 and named else f"    {text}"))
        return lines

    def data(self, start, end, used, bss=False):
        """The data range start-end, typed as data_lines types the data
        in code where the code reads it, all-zero runs and the stretches
        with fixups; the rest as asmgen_le.py writes it (strings)."""
        if bss:
            return super().data(start, end, used, bss)
        refs = self.datarefs_out
        cuts = sorted({start, end} | {a for a in self.labels if start < a < end}
                      | {a for a in refs if start < a < end})
        out = []
        for a, b in zip(cuts, cuts[1:]):
            name = self.labels.get(a)
            if a in refs or any(s in self.fix for s in range(a, b)) or not any(self.read(a, b)):
                saved, self.datarefs = self.datarefs, refs
                try:
                    out += [text for _, text in self.data_lines(a, b, used, name)]
                finally:
                    self.datarefs = saved
            else:
                if name:
                    out.append(f"{name} label byte")
                out.append(self.bytes_of(a, b, used))
        return out

    def source(self):
        """(text, items): items [(line number, address, kind)] of the code."""
        used, body, items = set(), [], []
        code = self.range("code")
        explicit = code and code[0] % 16 == 0 or any(k.startswith("obj") or s % 4 for k, s, e in self.ranges)
        publics = [sym for a, sym in sorted(self.labels.items()) if any(sym == r[3] for r in self.rows)]
        for kind, start, end in self.ranges:
            seg = SEGMENTS[kind][0]
            if explicit:
                body += ["", f"{seg} segment"]
            else:
                body += ["", "    " + {"code": ".code", "data": ".data", "bss": ".data?", "const": ".const"}[kind]]
            if kind != "code":
                body += self.data(start, end, used, kind == "bss")
            else:
                body += self.code_lines(start, end, used, items, len(body))
            if explicit:
                body.append(f"{seg} ends")
        head = [f"    {self.cpu}"]
        if explicit:
            head.append("")
            for kind, start, end in self.ranges:
                seg, cls = SEGMENTS[kind]
                align = next(n for k, n in asmgen_le.ALIGNS
                             if start % k == 0 and (k <= 4 or kind == "code" or kind.startswith("obj")))
                head += [f"{seg} segment {align} public use32 '{cls}'", f"{seg} ends"]
            head += ["", "    assume cs:FLAT, ds:FLAT, es:FLAT, ss:FLAT"]
        else:
            head.append("    .model flat")
        head.append("")
        local = set(self.labels.values())
        ext = [f"    extrn {s}:{'near' if c else 'byte'}" for s, c in sorted(used) if s not in local]
        head += ext + ([""] if ext else [])
        head += [f"    public {s}" for s in publics]
        items = [(n + len(head), a, k) for n, a, k in items]
        return "\n".join(head + body + ["", "    end"]) + "\n", items

    def code_lines(self, start, end, used, items, base):
        out, at, proc = [], start, None
        ends = {r[0] + r[1]: r for r in self.funcs}
        heads = {r[0]: r for r in self.funcs}

        def emit(text, a=None, kind=None):
            if a is not None:
                items.append((base + len(out) + 1, a, kind))
            out.append(text)

        gaps = dict(self.gaps())
        while at < end:
            if at in ends and proc:
                emit(f"{proc[3]} endp")
                proc = None
            if at in heads:
                proc = heads[at]
                emit(f"{proc[3]} proc near")
            name = self.labels.get(at)
            if at in self.ins:
                if name and not (proc and at == proc[0]):
                    emit(f"{name}{'::' if proc else ':'}")
                vs = self.variants(at, used)
                emit("    " + vs[min(self.choice.get(at, 0), len(vs) - 1)], at, "ins")
                at += len(self.ins[at][0])
                continue
            b = gaps[at]
            parts = self.pieces(at, b)
            for i, (p, q) in enumerate(parts):
                name = self.labels.get(p)
                if p in ends and proc and p != at:
                    emit(f"{proc[3]} endp")
                    proc = None
                if self.is_fill(p, q) and not name:
                    emit(f"    align {next(n for n in (4, 8, 16) if n > q - p)}", p, "fill")
                    continue
                if proc and p == proc[0]:
                    name = None
                after = parts[i + 1] if i + 1 < len(parts) else None
                follows = bool(after and self.is_fill(*after) and not self.labels.get(after[0]))
                for a, text in self.data_lines(p, q, used, name, follows):
                    emit(text, a, "data")
            at = b
        if proc:
            emit(f"{proc[3]} endp")
        return out


def listing(path):
    """(offset or None, source line) of each line of ml's listing at path.
    The source starts at column 32, right after the offset of a line
    whose label reaches past it, or right after the bytes of a line ml
    wrote without its tabs (it does that to a line now and then)."""
    for line in open(path, errors="replace"):
        line = line.rstrip("\r\n")
        m = re.match(r"^ ([0-9A-F]{8})(.*)$", line)
        bare = m and "\t" not in line and re.match(r"^  [0-9A-F]{2,8}(?: [0-9A-F]{2,8})*( {2,}\S.*)$", m[2])
        if m and m[2] and not m[2][0].isspace():
            yield int(m[1], 16), m[2]
        elif bare:
            yield int(m[1], 16), bare[1]
        elif line.startswith("\t\t\t\t") or m:
            yield (int(m[1], 16) if m else None), line.expandtabs(8)[32:]


def read_names(path, ranges):
    """{address: label} of the MASM module at path, from its listing."""
    work = WORK
    os.makedirs(work, exist_ok=True)
    lst = os.path.join(work, "keep.lst")
    r = subprocess.run(["wine", os.path.join(project.masm(), "ML.EXE"), *project.config["build"]["asflags"],
                        "/Sa", "/Sl255", "/Sp255", "/Fl" + winpath(lst), "/Fo" + winpath(os.path.join(work, "keep.obj")),
                        winpath(os.path.abspath(path))], env=env(project.watcom()), capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.abspath(path)))
    if r.returncode:
        sys.exit(f"ml failed on {path}:\n{r.stdout}")
    starts = {k: s for k, s, e in ranges}
    kinds = {SEGMENTS[k][0]: k for k in SEGMENTS}
    dirs = {".code": "code", ".data": "data", ".data?": "bss", ".const": "const"}
    names, seg = {}, None
    for offset, field in listing(lst):
        field = field.split(";")[0]
        text = field.strip()
        low = text.lower()
        sm = re.match(r"(\w+)\s+segment\b", text, re.I)
        if sm:
            seg = kinds.get(sm[1].upper())
            continue
        if re.match(r"\w+\s+ends\b", low):
            seg = None
            continue
        if low in dirs:
            seg = dirs[low]
            continue
        if offset is None or seg not in starts:
            continue
        lm = not field[:1].isspace() and re.match(r"^(\w+)(?:::?|\s+(?:label|proc|byte|word|dword|fword|qword|db|dw|dd|df|dq)\b)", text, re.I)
        if lm and lm[1].lower() not in SIZES and lm[1].lower() not in ("align",):
            names.setdefault(starts[seg] + offset, lm[1])
    return names


def assemble(text):
    """(module, {line: offset}, errors) of the generated source."""
    work = WORK
    os.makedirs(work, exist_ok=True)
    src, obj, lst = (os.path.join(work, "gen" + x) for x in (".asm", ".obj", ".lst"))
    marked = "\n".join(f"{line} ;@{n}" if line.strip() else line for n, line in enumerate(text.split("\n"), 1))
    with open(src, "w", newline="\r\n") as f:
        f.write(marked)
    for p in (obj, lst):
        if os.path.exists(p):
            os.remove(p)
    r = subprocess.run(["wine", os.path.join(project.masm(), "ML.EXE"), *project.config["build"]["asflags"],
                        "/Sa", "/Sl255", "/Sp255", "/Fl" + winpath(lst), "/Fo" + winpath(obj), winpath(src)],
                       env=env(project.watcom()), capture_output=True, text=True)
    out = r.stdout + r.stderr
    errors = {int(m[1]): m[2] for m in re.finditer(r"gen\.asm\((\d+)\) ?: (?:error|warning) (.*)", out)}
    if r.returncode or not os.path.exists(obj):
        return None, {}, errors or {0: out}
    offsets = {}
    for offset, field in listing(lst):
        m = re.search(r";@(\d+)\s*$", field)
        if m and offset is not None:
            offsets[int(m[1])] = offset
    return omf.Module(open(obj, "rb").read()), offsets, errors


def bad_items(m, mod, items, offsets):
    """Addresses of the code lines whose bytes are not the original's."""
    start, end = m.range("code")
    seg = next(s for s in mod.segments[1:] if s.name == "_TEXT")
    ours = set()
    for f in seg.fixups:
        ours.update(range(f.offset, f.offset + 4))
    theirs = {s + k for s in m.fix if start <= s < end for k in range(m.width(s))}
    bad = set()
    for i, (line, a, kind) in enumerate(items):
        if kind != "ins":
            continue
        raw = m.ins[a][0]
        o = offsets.get(line)
        nxt = next((offsets[l] for l, _, _ in items[i + 1:] if l in offsets), seg.size)
        if o is None:
            bad.add(a)
            continue
        mine = seg.data[o:o + len(raw)]
        filled = any(k == "fill" for l, _, k in items[i + 1:i + 2])
        if nxt - o != len(raw) and not (filled and nxt - o > len(raw)):
            bad.add(a)
            continue
        mnem = m.ins[a][1]
        keep = len(raw)
        if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", m.ins[a][2]):
            keep = 1 if raw[0] != 0x0f else 2
        for k in range(keep):
            if (a + k) in theirs or (o + k) in ours:
                continue
            if mine[k] != raw[k]:
                bad.add(a)
                break
    return bad


def differences(m, mod):
    """Where the module's segments differ from the original's, fixups
    masked (a branch to another module has a fixup only in ours)."""
    out = []
    for kind, start, end in m.ranges:
        name = SEGMENTS[kind][0]
        seg = next((s for s in mod.segments[1:] if s.name == name), None)
        if seg is None or seg.size != end - start:
            out.append(f"{name} is {seg.size if seg else 0:#x} bytes, the range {end - start:#x}")
            continue
        masked = {s - start + k for s in m.fix if start <= s < end for k in range(m.width(s))}
        for f in seg.fixups:
            masked.update(range(f.offset, f.offset + 4))
        theirs = {s - start for s in m.fix if start <= s < end}
        ours = {f.offset for f in seg.fixups if not (f.rel and f.target[0] == "ext")}
        orig = m.read(start, end)
        diff = [o for o in range(end - start) if o not in masked and (o >= len(seg.data) or seg.data[o] != orig[o])]
        diff += sorted(ours ^ theirs)
        if diff:
            out.append(f"{name} at " + ", ".join(f"{start + o:#x}" for o in sorted(diff)[:8]))
    return out


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--keep", help="an existing module whose label names to keep")
    p.add_argument("--code", action="append", default=[], help="an address that is code (hex)")
    p.add_argument("--cpu", help="the CPU directive (default: the least the instructions need, from .386p)")
    p.add_argument("ranges", nargs="+")
    args = p.parse_args(argv)
    m = Clean([parse_range(r) for r in args.ranges], args.keep, [int(c, 16) for c in args.code], args.cpu)
    tried = set()
    for _ in range(12):
        text, items = m.source()
        mod, offsets, errors = assemble(text)
        if mod is None:
            lines = dict((n, a) for n, a, k in items)
            bad = {lines[n] for n in errors if n in lines}
            if not bad:
                sys.exit("ml failed on the generated source:\n" + "\n".join(f"{n}: {e}" for n, e in errors.items()))
        else:
            bad = bad_items(m, mod, items, offsets)
            if not bad:
                left = differences(m, mod)
                if left:
                    sys.exit("the module differs: " + "; ".join(left))
                print(text, end="")
                return 0
        stuck = []
        for a in sorted(bad):
            n = len(m.variants(a, set()))
            if m.choice.get(a, 0) + 1 >= n:
                stuck.append(a)
            else:
                m.choice[a] = m.choice.get(a, 0) + 1
        if stuck:
            for a in stuck:
                raw, mnem, ops = m.ins[a]
                why = next((e for n, x, k in items if x == a for e in [errors.get(n)] if e), None)
                print(f"{a:#x}: {raw.hex(' ')}  {mnem} {ops}: no spelling of "
                      f"{m.variants(a, set())} assembles to it" + (f" ({why})" if why else ""), file=sys.stderr)
            sys.exit(1)
    sys.exit("the spellings did not settle")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
