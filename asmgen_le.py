"""asmgen.py's LE backend: writes a MASM module for a stretch of the
original LE exe (a library module no source exists for) from its bytes.

    asmgen.py KIND=START-END... > src/MODULE.asm

Each KIND=START-END is one segment of the module: `code` (_TEXT),
`data` (_DATA), `const` (CONST), `const2` (CONST2), `bss` (_BSS), or
`obj3`/`obj4` for a segment that is an object of its own (OBJn, of the
class link_le gives that object of the original),
with addresses in the flattened image (hex, 0x optional), the end
exclusive. A segment aligns to the largest of 16, 4, 2 and 1 its start
is a multiple of (data at most 4, as Watcom and MASM align it), so wlink places it where the original has it after the
module before it; the zeros before the start are wlink's padding.

The code's functions are the rows of config/symbols.csv in the code
range; each becomes a public `proc` under its symbol, which every row
needs. The bytes between them (padding, Watcom's jump tables) are data,
as are tables of code addresses inside a function that an indexed jump
reads (`jmp [ebx*4+table]`). A row with a symbol in a data or BSS range,
or one of size 0 in code (a table other modules index), becomes a public
label there. Every other address the module's
fixups or branches reach inside it gets a local label: Lxxxx in code,
Dxxxx in data, Bxxxx in BSS. Addresses outside the module name their
row's symbol, plus an offset into it, as an extern. Which values are
addresses comes from the original's fixup table, not from their values;
an address in data is a `dd offset SYM`.

Instructions are written as MASM mnemonics, assembled, and any whose
bytes or relocations differ from the original's (or that ml rejects) are
written as the original's bytes instead, with the symbols kept at the
relocations, until the module's every segment matches the original.
"""
import csv, os, re, struct, subprocess, sys

import compare_le, omf, project
from asmgen import BRANCH, REG_SIZE, data_lines, disasm, split_operands
from build_watcom import env, winpath

ROOT = project.ROOT
SEGMENTS = {  # kind: (segment, class)
    "code": ("_TEXT", "CODE"),
    "data": ("_DATA", "DATA"),
    "const": ("CONST", "DATA"),
    "const2": ("CONST2", "DATA"),
    "bss": ("_BSS", "BSS"),
    # An object of its own (link_le's name and class for one).
    "obj3": ("OBJ3", "OBJ3DATA"),
    "obj4": ("OBJ4", "OBJ4DATA"),
}
ALIGNS = ((16, "para"), (4, "dword"), (2, "word"), (1, "byte"))
PREFIX = {"code": "L", "bss": "B"}


def parse_range(arg):
    m = re.fullmatch(r"(\w+)=(?:0x)?([0-9a-fA-F]+)-(?:0x)?([0-9a-fA-F]+)", arg)
    if not m or m[1] not in SEGMENTS:
        sys.exit(f"{arg}: expected KIND=START-END, KIND one of {', '.join(SEGMENTS)}")
    start, end = int(m[2], 16), int(m[3], 16)
    if end <= start:
        sys.exit(f"{arg}: empty range")
    return m[1], start, end


class Module:
    def __init__(self, ranges):
        kinds = [k for k, _, _ in ranges]
        if len(set(kinds)) != len(kinds):
            sys.exit("one range per kind")
        self.ranges = ranges
        self.orig = compare_le.Original(compare_le.EXE)
        self.fix = {s: (t, self.orig.kinds[s]) for s, t in self.orig.fixups.items()}
        with open(os.path.join(ROOT, "config/symbols.csv")) as f:
            self.rows = sorted(((int(r["address"], 16), int(r["size"] or 0), r["name"], r["symbol"].split()[0]
                                 if r["symbol"] else "") for r in csv.DictReader(f)), key=lambda r: (r[0], -r[1]))
        self.raw = set()
        for kind, start, end in ranges:
            for src in range(start - 3, end):
                if src in self.fix and not (start <= src and src + self.width(src) <= end):
                    sys.exit(f"the fixup at {src:#x} straddles {kind}={start:#x}-{end:#x}")
        self.funcs = []
        code = self.range("code")
        if code:
            self.funcs = [(a, s, n, sym) for a, s, n, sym in self.rows if code[0] <= a < code[1] and s]
            for a, s, n, sym in self.funcs:
                if not sym:
                    sys.exit(f"{n} ({a:#x}) has no symbol in config/symbols.csv; give it one, e.g. {n}_")
                if a + s > code[1]:
                    sys.exit(f"{n} ({a:#x}+{s}) runs past the end of the code range")
        self.split_code()
        self.labels = self.find_labels()

    def range(self, kind):
        return next(((s, e) for k, s, e in self.ranges if k == kind), None)

    def kind_of(self, v):
        return next((k for k, s, e in self.ranges if s <= v < e), None)

    def width(self, src):
        return 6 if self.fix[src][1] == 6 else 4

    def read(self, start, end):
        return self.orig.read(start, end - start)

    def split_code(self):
        """self.spans: [(start, end, is_code, func row or None)] over the code range."""
        code = self.range("code")
        self.spans, self.ins = [], {}
        if not code:
            return
        tables = set()
        for _ in range(20):
            spans, at = [], code[0]
            for row in self.funcs:
                a, s = row[0], row[1]
                if a > at:
                    spans.append((at, a, False, None))
                cuts = sorted(t for t in tables if a <= t < a + s)
                pos = a
                for t in cuts:
                    end = t
                    while end in self.fix and self.width(end) == 4 and self.kind_of(self.fix[end][0]) == "code":
                        end += 4
                    if t > pos:
                        spans.append((pos, t, True, row if pos == a else None))
                    spans.append((t, min(end, a + s), False, row if t == a else None))
                    pos = min(end, a + s)
                if pos < a + s:
                    spans.append((pos, a + s, True, row if pos == a else None))
                at = max(at, a + s)
            if at < code[1]:
                spans.append((at, code[1], False, None))
            ins, found = {}, set(tables)
            for start, end, is_code, _ in spans:
                if not is_code:
                    continue
                ins[start] = disasm(self.read(start, end), start)
            within = {i for lst in ins.values() for a, raw, m, o in lst for i in range(a + 1, a + len(raw))}
            for start, end, is_code, _ in spans:
                if not is_code:
                    continue
                for at_, raw, mnem, ops in ins[start]:
                    for v in re.findall(r"\[[^\]]*[a-z]+[^\]]*0x([0-9a-f]+)\]", ops):
                        t = int(v, 16)
                        if self.kind_of(t) == "code" and t in self.fix and t not in within and not any(
                                t == r[0] for r in self.funcs):
                            found.add(t)
            if found == tables:
                self.spans, self.ins = spans, ins
                for start, end, is_code, _ in spans:
                    if is_code:
                        cut = [a for a, raw, m, o in ins[start] if a + len(raw) > end or m == "(bad)" or m.startswith(".")]
                        if cut:
                            sys.exit(f"the code at {start:#x}-{end:#x} does not disassemble to its end "
                                     f"({cut[0]:#x}); check the sizes in config/symbols.csv")
                return
            tables = found
        sys.exit("the jump tables did not settle")

    def find_labels(self):
        labels = {}
        for a, s, n, sym in self.rows:
            k = self.kind_of(a)
            if k and sym:
                labels.setdefault(a, sym)
        refs = set()
        for kind, start, end in self.ranges:
            for src in range(start, end):
                if src in self.fix:
                    refs.add(self.fix[src][0])
        for lst in self.ins.values():
            for at, raw, mnem, ops in lst:
                if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
                    refs.add(int(ops, 16))
        # A target inside an address the module holds (a jump table's
        # base before its first entry) is an offset from that dword.
        self.inside = {}
        within = {}
        for lst in self.ins.values():
            for at, raw, mnem, ops in lst:
                for i in range(at + 1, at + len(raw)):
                    within[i] = at
        for t in refs:
            s = within.get(t)
            if s is None:
                s = next((s for s in range(t - 3, t) if s in self.fix and self.kind_of(s)), None)
            if s is not None and t not in labels:
                self.inside[t] = s
                refs = refs | {s}
        for t in refs:
            k = self.kind_of(t)
            if k and t not in labels and t not in self.inside:
                labels[t] = f"{PREFIX.get(k, 'D')}{t:x}"
        return labels

    def symbol(self, v, used):
        if v in self.labels:
            return self.labels[v]
        if v in self.inside:
            return f"{self.labels[self.inside[v]]}+{v - self.inside[v]}"
        if self.kind_of(v):
            sys.exit(f"{v:#x}: no label")  # find_labels labels every target
        best = None
        for row in self.rows:
            if row[0] > v:
                break
            if v < row[0] + max(row[1], 1) or best is None or v >= best[0] + max(best[1], 1):
                best = row
        if not best or v >= best[0] + max(best[1], 1):
            sys.exit(f"{v:#x}: no row in config/symbols.csv covers it; add one")
        a, s, n, sym = best
        if not sym:
            sys.exit(f"{v:#x} is in {n}, which has no symbol in config/symbols.csv")
        used.add((sym, project.CODE[0] <= a < project.CODE[1]))
        return sym if v == a else f"{sym}+{v - a}"

    def operands(self, at, raw, mnem, ops, used):
        addrs = {self.fix[s][0] for s in range(at, at + len(raw)) if s in self.fix}
        text = ops
        for w in ("QWORD", "TBYTE", "DWORD", "FWORD", "WORD", "BYTE"):
            text = text.replace(f"{w} PTR", f"{w.lower()} ptr")

        def addr(m):
            v = int(m[2], 16)
            if v in addrs:
                sym = self.symbol(v, used)
                return f"[{sym}]" if m[1] else f"offset {sym}"
            return f"ds:[0{v:x}h]" if m[1] else f"0{v:x}h"

        def inner(m):
            def one(n):
                v = int(n[1], 16)
                return self.symbol(v, used) if v in addrs else f"0{v:x}h"
            return "[" + re.sub(r"0x([0-9a-f]+)", one, m[1]) + "]"
        text = re.sub(r"\[([^\]]*)\]", inner, text)
        text = re.sub(r"(ds:)?0x([0-9a-f]+)", addr, text)
        parts = [p.strip() for p in split_operands(text)]
        if len(parts) == 2 and parts[0].startswith("[") and parts[1] in REG_SIZE:
            parts[0] = f"{REG_SIZE[parts[1]]} ptr {parts[0]}"
        if len(parts) == 2 and parts[1].startswith("[") and parts[0] in REG_SIZE and mnem not in ("lea",):
            parts[1] = f"{REG_SIZE[parts[0]]} ptr {parts[1]}"
        return ", ".join(parts)

    def instruction(self, at, raw, mnem, ops, used):
        if at in self.raw:
            return self.bytes_of(at, at + len(raw), used)
        if BRANCH.match(mnem) and re.fullmatch(r"0x[0-9a-f]+", ops):
            target = int(ops, 16)
            if not self.kind_of(target) and not any(target == r[0] and r[3] for r in self.rows):
                sys.exit(f"{at:#x}: {mnem} {target:#x} goes to no function start with a symbol")
            target = self.symbol(target, used)
            if mnem == "call":
                return f"    call {target}"
            if mnem.startswith("loop") or mnem == "jecxz":
                return f"    {mnem} {target}"
            return f"    {mnem} {'short' if len(raw) == 2 else 'near ptr'} {target}"
        return f"    {mnem} {self.operands(at, raw, mnem, ops, used)}".rstrip()

    def bytes_of(self, start, end, used):
        """Lines for the original's bytes start-end, with `dd offset SYM` at fixups."""
        out, at, blob = [], start, self.read(start, end)
        while at < end:
            nxt = next((s for s in range(at, end) if s in self.fix), end)
            if nxt > at:
                out += data_lines(blob[at - start:nxt - start])
                at = nxt
            if at < end:
                t, kind = self.fix[at]
                if kind != 7:
                    sys.exit(f"{at:#x}: fixup kind {kind} is not supported yet")
                inline, = struct.unpack_from("<I", blob, at - start)
                if inline != t:
                    sys.exit(f"{at:#x}: the bytes hold {inline:#x}, the fixup {t:#x}")
                out.append(f"    dd offset {self.symbol(t, used)}")
                at += 4
        return "\n".join(out)

    def data(self, start, end, used, bss=False):
        cuts = sorted({start, end} | {a for a in self.labels if start < a < end})
        out = []
        for a, b in zip(cuts, cuts[1:]):
            if a in self.labels:
                out.append(f"{self.labels[a]} label byte")
            if bss:
                if any(self.read(a, b)) or any(s in self.fix for s in range(a, b)):
                    sys.exit(f"the bss range {a:#x}-{b:#x} is not all zeros")
                out.append(f"    db {b - a} dup(?)")
            else:
                out.append(self.bytes_of(a, b, used))
        return out

    def source(self):
        used = set()
        self.lines = {}  # index in body, later line number in the source: instruction address
        body = []
        publics = [sym for a, sym in sorted(self.labels.items()) if not re.fullmatch(r"[LDB][0-9a-f]+", sym)]
        for kind, start, end in self.ranges:
            seg = SEGMENTS[kind][0]
            body += ["", f"{seg} segment"]
            if kind == "code":
                for s, e, is_code, row in self.spans:
                    if row:
                        body.append(f"{row[3]} proc near")
                    if is_code:
                        for at, raw, mnem, ops in self.ins[s]:
                            if at in self.labels and not (row and at == s):
                                body.append(f"{self.labels[at]}::")
                            self.lines[len(body)] = at
                            body.append(self.instruction(at, raw, mnem, ops, used))
                    else:
                        cuts = sorted({s, e} | {a for a in self.labels if s < a < e})
                        for a, b in zip(cuts, cuts[1:]):
                            if a in self.labels and not (row and a == s):
                                body.append(f"{self.labels[a]} label byte")
                            body.append(self.bytes_of(a, b, used))
                    if self.closes(s, e):
                        body.append(f"{self.func_at(s)[3]} endp")
            else:
                body += self.data(start, end, used, kind == "bss")
            body.append(f"{seg} ends")
        head = ["    .586p", ""]
        for kind, start, end in self.ranges:
            seg, cls = SEGMENTS[kind]
            align = next(n for k, n in ALIGNS if start % k == 0 and (k <= 4 or kind == "code" or kind.startswith("obj")))
            head += [f"{seg} segment {align} public use32 '{cls}'", f"{seg} ends"]
        head += ["", "    assume cs:FLAT, ds:FLAT, es:FLAT, ss:FLAT", ""]
        local = set(self.labels.values())
        head += [f"    extrn {s}:{'near' if code else 'byte'}" for s, code in sorted(used) if s not in local]
        if used:
            head.append("")
        head += [f"    public {s}" for s in publics]
        text = head + body + ["", "    end"]
        line, first = len(head) + 1, []
        for item in body:  # an item of raw bytes can be several lines
            first.append(line)
            line += item.count("\n") + 1
        self.lines = {first[i]: a for i, a in self.lines.items()}
        return "\n".join(text) + "\n"

    def func_at(self, s):
        return next(r for r in self.funcs if r[0] <= s < r[0] + r[1])

    def closes(self, s, e):
        """Whether the span s-e is the last of its function."""
        row = next((r for r in self.funcs if r[0] <= s < r[0] + r[1]), None)
        return row is not None and e == row[0] + row[1]


def assemble(text):
    """(module, {line: error}) of the generated source, module None if ml failed."""
    work = os.path.join(ROOT, "build", "asmgen")
    os.makedirs(work, exist_ok=True)
    src, obj = os.path.join(work, "gen.asm"), os.path.join(work, "gen.obj")
    with open(src, "w", newline="\r\n") as f:
        f.write(text)
    if os.path.exists(obj):
        os.remove(obj)
    w = project.watcom()
    r = subprocess.run(["wine", os.path.join(project.masm(), "ML.EXE"), *project.config["build"]["asflags"],
                        "/Fo" + winpath(obj), winpath(src)], env=env(w), capture_output=True, text=True)
    out = r.stdout + r.stderr
    errors = {int(m[1]): m[2] for m in re.finditer(r"gen\.asm\((\d+)\) ?: (?:error|warning) (.*)", out)}
    if r.returncode or not os.path.exists(obj):
        return None, errors or {0: out}
    return omf.Module(open(obj, "rb").read()), errors


def mismatches(m, mod):
    """Addresses of the instructions whose bytes or relocations differ."""
    bad = set()
    for kind, start, end in m.ranges:
        name = SEGMENTS[kind][0]
        seg = next((s for s in mod.segments[1:] if s.name == name), None)
        if seg is None or seg.size != end - start:
            size = seg.size if seg else 0
            if kind != "code":
                sys.exit(f"{name} is {size:#x} bytes, the range {end - start:#x}")
        # A relative branch to another module has a fixup only in ours:
        # the original's link resolved it within the code object.
        branches = {f.offset for f in (seg.fixups if seg else []) if f.rel and f.target[0] == "ext"}
        ours = {f.offset for f in (seg.fixups if seg else [])} - branches
        theirs = {s - start for s in range(start, end) if s in m.fix}
        masked = set()
        for o in ours | theirs | branches:
            masked.update(range(o, o + 4))
        orig = m.read(start, end)
        data = seg.data if seg else b""
        diff = [o for o in range(end - start) if o not in masked and (o >= len(data) or data[o] != orig[o])]
        diff += sorted(ours ^ theirs)
        if kind == "bss" and diff:
            sys.exit(f"_BSS differs at {start + min(diff):#x}")
        for o in diff:
            a = start + o
            if kind != "code":
                sys.exit(f"{name} differs at {a:#x}")
            bad.add(instruction_at(m, a))
            if len(bad) > 50:
                break
        if kind == "code" and seg and seg.size != end - start and not diff:
            sys.exit(f"_TEXT is {seg.size:#x} bytes, the range {end - start:#x}")
    return bad - {None}


def instruction_at(m, a):
    for lst in m.ins.values():
        for at, raw, _, _ in lst:
            if at <= a < at + len(raw):
                return at
    # A difference in data shifts nothing; the first instruction after it
    # whose bytes moved is the culprit, found next round.
    return None


def main(args):
    m = Module([parse_range(a) for a in args])
    for _ in range(300):
        text = m.source()
        mod, errors = assemble(text)
        if mod is None:
            bad = {m.lines[n] for n in errors if n in m.lines}
            if not bad or bad <= m.raw:
                sys.exit("ml failed on the generated source:\n" + "\n".join(f"{n}: {e}" for n, e in errors.items()))
        else:
            bad = mismatches(m, mod)
            if not bad:
                print(text, end="")
                return 0
        if bad <= m.raw:
            sys.exit(f"{min(bad):#x} still differs as bytes")
        m.raw |= bad
    sys.exit("gave up after 300 rounds")
