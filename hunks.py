"""Groups the differences of the functions that don't match yet into
families that may share a cause.

    hunks.py                    every function hooks.allow_diff lists,
                                but those of hooks.permute_skip
    hunks.py NAME...            only these
    hunks.py --level a|b|c      how far apart two instructions may be
                                and still align (default b)
    hunks.py --top N            the N best clusters (default 20)
    hunks.py --min N            clusters of at least N functions
                                (default 2)
    hunks.py -v                 every hunk of each cluster, not just one
    hunks.py --lines            also our source lines, from a /Zd compile
    hunks.py --kind K           only clusters whose kind starts with K
    hunks.py --exact            the exact groups, without fuzzy merging
    hunks.py --min-ins N        hunks of at least N instructions, both
                                sides counted (default 2)
    hunks.py --gap N            hunks fewer than N aligned instructions
                                apart join (default 2)
    hunks.py --fuzz R           the difflib ratio that merges groups
                                (default 0.75)
    hunks.py --anchored R       ... of groups before the same call
                                (default 0.5)

It reads the objects in build/obj, as compare.py does, so build first
(`just build`). For each function, our instructions are aligned with the
original's (difflib over normalized instructions, as redtriage.py
compares them) and each run of instructions that doesn't align is a
hunk. The levels normalize an instruction for the alignment:

    a   registers as placeholders by width (reg32, reg16, reg8, st):
        register choice alone makes no hunk
    b   as a, and displacements off esp and ebp and the immediates that
        move esp masked: stack slots in another order make none either
    c   as b, and every other number masked but small immediates (under
        16): globals, displacements and constants make none

Addresses symbols.csv knows read as their names (a data symbol with a
size as name+offset), call targets at every level; branches inside the
function read as L, its switch tables as T and a field compare.py masks
as D. ebp is a stack register only where the function sets it up as a
frame pointer. The switch tables after the code and the nop and int3
padding are left out.

Each hunk gets a kind, the first that fits:

    frame    only the immediate of the esp adjustment differs
    slot     the same instructions but for stack displacements
    global   ... but for the addresses of globals
    disp     ... but for displacements off other registers
    imm      ... but for other numbers
    extra    instructions only ours has
    missing  instructions only the original has
    moved    as extra or missing, but the other side has the same
             instructions elsewhere in the function
    sched    the same instructions in another order
    bias     (instead of disp, sched or replace) the instructions that
             are the same at level c differ in displacements off
             registers, and most by the same amount: a pointer that
             walks biased to a field
    replace  anything else

and a signature: the kind and both sides' instructions as level c
writes them (a bias: the kind alone). Hunks with the same signature
form a group. Groups whose kinds differ in what they compare (numbers
or instructions) never merge; others merge into one cluster when their
instructions are close (a difflib ratio of --fuzz, signatures of more
than FUZZY_MIN instructions), or less close (--anchored) when a hunk of
each comes before the same call: an argument list evaluated in another
order, say. A cluster's score is the number of its functions times the
bytes its hunks cover (the larger side of each); clusters of a single
function are left out unless --min 1. --lines compiles each file
involved again with /Zd for our line numbers.
"""
import argparse, bisect, collections, csv, difflib, os, re, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

import capstone

import build, compare, project, redtriage

ROOT = project.ROOT
LEVELS = "abc"
CONTEXT = 2
FUZZY_MIN = 4  # instructions of both sides a signature needs to merge with others
NUMBER = re.compile(r"-?\b(?:0x[0-9a-f]+|\d+)\b")
BRACKET = re.compile(r"\[[^\]]*\]")
# Within the image: what reads as a symbol's address.
IMAGE = range(0x400000, 0x1000000)
# A symbol's name in an operand, with an offset; not a register, a size
# or the masks.
NAME = re.compile(r"\b(?!(?:reg32|reg16|reg8|st|esp|byte|word|dword|qword|tbyte|xword|ptr|S|L|N|D|T)\b)"
                  r"[A-Za-z_][\w@?$]*(?:\+0x[0-9a-f]+)?")
ESP = re.compile(r"\b(esp)( [+-] (?:0x[0-9a-f]+|\d+))?(?=\])")
OPERAND = re.compile(r"\[[^\]]*\]|[^,\s]+")


class Names:
    """symbols.csv's addresses as names: functions and data, a data
    symbol with a size covering the bytes after it too."""

    def __init__(self):
        rows = []
        with open(os.path.join(ROOT, "config/symbols.csv")) as f:
            for r in csv.DictReader(f):
                rows.append((int(r["address"], 16), int(r["size"] or 0), r["name"]))
        rows.sort()
        self.starts = [r[0] for r in rows]
        self.rows = rows

    def __call__(self, addr):
        k = bisect.bisect_right(self.starts, addr) - 1
        if k < 0:
            return None
        start, size, name = self.rows[k]
        if addr == start:
            return name
        if addr < start + size:
            return f"{name}+{addr - start:#x}"
        return None


class Side:
    """One function's instructions, each normalized at the three levels,
    with its offset and size."""

    def __init__(self, code, addr, mask, names):
        self.whole = range(addr, addr + len(code))
        code = code[:tables(code, addr)]
        self.listing = redtriage.Listing(code, addr, mask)
        self.addr = addr
        # Alignment padding is no instruction of the function's.
        kept = [(n, i) for n, i in enumerate(self.listing.ins) if i.mnemonic not in ("nop", "int3")]
        self.offsets = [i.address - addr for _, i in kept]
        self.sizes = [i.size for _, i in kept]
        self.raw = [f"{i.mnemonic} {i.op_str}".strip() for _, i in kept]
        # Without a frame pointer ebp is a register like the others.
        framed = any((i.mnemonic, i.op_str) == ("mov", "ebp, esp") for i in self.listing.ins[:8])
        self.stack = None if framed else ESP
        self.keys = {lv: [] for lv in LEVELS}
        for n, i in kept:
            for lv, key in zip(LEVELS, self.normalize(n, i, names)):
                self.keys[lv].append(key)

    def normalize(self, n, i, names):
        listing = self.listing
        mnemonic, ops = i.mnemonic, i.op_str
        target = listing.target(i)
        if target is not None:
            if listing.addr <= target < listing.end and capstone.CS_GRP_CALL not in i.groups:
                ops = "L"
            else:
                ops = names(target) or "F"
        else:
            masked = listing.masked[n]

            def address(m):
                v = int(m[0], 0)
                if masked and abs(v) >= 0x10000:
                    return "D"
                if v in self.whole:
                    return "T"  # a switch's table
                if v in IMAGE:
                    return names(v) or "D"
                return m[0]
            ops = NUMBER.sub(address, ops)
        a = f"{mnemonic} {registers(ops)}".strip()
        # Level b: stack displacements and the esp adjustments masked,
        # as redtriage.py's SLOT does.
        if mnemonic in ("sub", "add") and i.op_str.startswith("esp, "):
            b = "sub esp, S" if mnemonic == "sub" else "add esp, S"
        elif n == 0 and (mnemonic, i.op_str) == ("push", "ecx"):
            b = "sub esp, S"
        elif (mnemonic, i.op_str) == ("pop", "ecx") and n + 1 < len(listing.ins) \
                and listing.ins[n + 1].mnemonic == "ret":
            b = "add esp, S"
        else:
            b = f"{mnemonic} {registers((self.stack or redtriage.STACK).sub(r'\1 + S', ops))}".strip()
        if target is not None:
            return a, b, b
        # Level c: data names and other numbers masked, but small
        # immediates.
        pieces = []
        for piece in re.split(r"(\[[^\]]*\])", b[len(mnemonic):]):
            if piece.startswith("["):
                piece = NAME.sub("N", piece)
                piece = NUMBER.sub("N", piece).replace(" - N", " + N")
            else:
                piece = NAME.sub("G", piece)
                piece = NUMBER.sub(lambda m: m[0] if abs(int(m[0], 0)) < 16 else "N", piece)
            pieces.append(piece)
        return a, b, mnemonic + "".join(pieces)


def tables(code, addr):
    """Where the switch tables after a function's code start: the lowest
    address inside it that an instruction reads with an index."""
    end = len(code)
    for i in redtriage.CS.disasm(code, addr):
        if i.address - addr >= end:
            break
        for m in re.finditer(r"\[[^\]]*\b(0x[0-9a-f]+)\]", i.op_str):
            if "*" in m[0] or i.mnemonic in ("mov", "movzx") and "byte" in i.op_str:
                v = int(m[1], 16) - addr
                if 0 < v < end:
                    end = v
    return end


def registers(ops):
    for pattern, placeholder in redtriage.REGISTERS:
        ops = pattern.sub(placeholder, ops)
    return ops


class Hunk:
    def __init__(self, func, ours, theirs, i1, i2, j1, j2):
        self.func, self.ours, self.theirs = func, ours, theirs
        self.i1, self.i2, self.j1, self.j2 = i1, i2, j1, j2
        self.kind = None
        self.bias = None
        self.line = None

    def keys(self, side, level):
        if side == "ours":
            return self.ours.keys[level][self.i1:self.i2]
        return self.theirs.keys[level][self.j1:self.j2]

    @property
    def bytes(self):
        return max(sum(self.ours.sizes[self.i1:self.i2]), sum(self.theirs.sizes[self.j1:self.j2]))

    @property
    def offset(self):
        side, k = (self.ours, self.i1) if self.i1 < len(self.ours.offsets) else (self.theirs, self.j1)
        return side.offsets[k] if k < len(side.offsets) else len(side.offsets) and side.offsets[-1]

    def signature(self):
        if self.kind == "bias":
            # Whatever the instructions: the bias is the cause.
            return (self.kind, (), ())
        return (self.kind, tuple(self.keys("ours", "c")), tuple(self.keys("theirs", "c")))

    @property
    def anchor(self):
        """The first call in the original's hunk or the CONTEXT
        instructions after it: what the hunk feeds, often."""
        keys = self.theirs.keys["c"][self.j1:self.j2 + CONTEXT]
        return next((k for k in keys if k.startswith("call ")), None)


def hunks(func, ours, theirs, level, gap):
    """The hunks of one function, aligned at `level`; runs of fewer than
    `gap` aligned instructions between two hunks join them."""
    a, b = ours.keys[level], theirs.keys[level]
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    spans = [op[1:] for op in sm.get_opcodes() if op[0] != "equal"]
    joined = []
    for s in spans:
        if joined and s[0] - joined[-1][1] < gap and s[2] - joined[-1][3] < gap:
            joined[-1] = (joined[-1][0], s[1], joined[-1][2], s[3])
        else:
            joined.append(s)
    out = [Hunk(func, ours, theirs, *s) for s in joined]
    # Instructions inserted in one place and deleted in another: moved.
    added = collections.Counter(k for h in out for k in h.keys("ours", "c"))
    removed = collections.Counter(k for h in out for k in h.keys("theirs", "c"))
    for h in out:
        h.kind = kind(h, added, removed)
        h.bias = bias(h)
        if h.bias is not None and h.kind not in ("slot", "frame", "global"):
            h.kind = "bias"
    return out


def displacement(op):
    """The displacement of a memory operand off registers, or None for
    one off the stack, of a symbol or not one at all."""
    if not op.startswith("[") or NAME.search(op) or "S" in op or "D" in op or "T" in op:
        return None
    total, sign, base = 0, 1, False
    for t in re.split(r"\s*([+-])\s*", op[1:-1]):
        if t in "+-":
            sign = 1 if t == "+" else -1
        elif NUMBER.fullmatch(t):
            total += sign * int(t, 0)
        else:
            base = True
    return total if base else None


def bias(h):
    """The difference of the displacements, the original's less ours, in
    the instructions that are the same at level c, when one difference
    covers most and at least two: a pointer walking with a bias."""
    # Without displacements: [reg32] and [reg32 + N] pair too.
    a = [re.sub(r" \+ N(?=\])", "", k) for k in h.keys("ours", "c")]
    b = [re.sub(r" \+ N(?=\])", "", k) for k in h.keys("theirs", "c")]
    ka, kb = h.keys("ours", "b"), h.keys("theirs", "b")
    deltas = collections.Counter()
    for m in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks():
        for k in range(m.size):
            x, y = ka[m.a + k], kb[m.b + k]
            if x == y:
                continue
            for p, q in zip(OPERAND.findall(x), OPERAND.findall(y)):
                dp, dq = displacement(p), displacement(q)
                if p != q and dp is not None and dq is not None:
                    deltas[dq - dp] += 1
    if not deltas:
        return None
    delta, count = deltas.most_common(1)[0]
    h.bias_count = count
    return delta if count >= 2 and count * 3 >= 2 * sum(deltas.values()) else None


def kind(h, added, removed):
    ours = {lv: h.keys("ours", lv) for lv in LEVELS}
    theirs = {lv: h.keys("theirs", lv) for lv in LEVELS}
    if ours["a"] and len(ours["a"]) == len(theirs["a"]):
        if ours["b"] == theirs["b"]:
            raw = [(x, y) for x, y in zip(h.ours.raw[h.i1:h.i2], h.theirs.raw[h.j1:h.j2]) if x != y]
            if all(re.match(r"(sub|add) esp, |(push|pop) ecx$", x) for x, _ in raw):
                return "frame"
            return "slot"
        if ours["c"] == theirs["c"]:
            # Which numbers differ: of globals, of displacements, other.
            kinds = set()
            for x, y in zip(ours["b"], theirs["b"]):
                for p, q in zip(OPERAND.findall(x), OPERAND.findall(y)):
                    if p == q:
                        continue
                    if NAME.search(p) or NAME.search(q) or "D" in (p, q):
                        kinds.add("global")
                    elif p.startswith("["):
                        kinds.add("disp")
                    else:
                        kinds.add("imm")
            return min(kinds, key=["global", "disp", "imm"].index) if kinds else "imm"
    if not ours["a"] or not theirs["a"]:
        mine, other = (ours["c"], removed) if ours["a"] else (theirs["c"], added)
        if not collections.Counter(mine) - other:
            return "moved"
        return "extra" if ours["a"] else "missing"
    if collections.Counter(ours["c"]) == collections.Counter(theirs["c"]):
        return "sched"
    return "replace"


def collect(wanted, level, gap):
    """(name, size, hunks) for each function of `wanted` that differs."""
    symbols, plain, names = compare.read_symbols(), redtriage.names(), Names()
    out = []
    for symbol, ok, code, mask, orig, data in compare.results(symbols):
        name = plain.get(symbol, symbol)
        if name not in wanted or ok:
            continue
        addr = symbols[symbol][0]
        # Masked bytes read as the original's, as compare.py shows them.
        shown = bytes(b if m and i < len(orig) else a
                      for i, (a, m, b) in enumerate(zip(code, mask, orig + bytes(len(code)))))
        ours, theirs = Side(shown, addr, mask, names), Side(orig, addr, None, names)
        found = hunks(name, ours, theirs, level, gap)
        out.append((name, symbol, len(orig), found))
    return out


# Kinds that may merge: the numbers differ, or the instructions do.
FAMILY = {"frame": "n", "slot": "n", "global": "n", "disp": "n", "imm": "n"}


def fuzzy(groups, ratio, anchored):
    """Merges groups whose instructions are close: of one family of
    kinds (FAMILY), by a difflib ratio of `ratio`, or of `anchored` when
    a hunk of each comes before the same call. A list of lists of
    signatures."""
    sigs = list(groups)
    parent = list(range(len(sigs)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    seqs = [list(s[1]) + ["|"] + list(s[2]) for s in sigs]

    def close(kx, ky, least):
        lx, ly = len(seqs[kx]), len(seqs[ky])
        if find(kx) == find(ky) or 2 * min(lx, ly) / (lx + ly) < least:
            return False
        sm = difflib.SequenceMatcher(None, seqs[kx], seqs[ky], autojunk=False)
        return sm.real_quick_ratio() >= least and sm.quick_ratio() >= least and sm.ratio() >= least

    def merge(members, least):
        members = sorted(members, key=lambda k: len(seqs[k]))
        for x, kx in enumerate(members):
            for ky in members[x + 1:]:
                lx, ly = len(seqs[kx]), len(seqs[ky])
                if 2 * lx / (lx + ly) < least:
                    break
                if close(kx, ky, least):
                    parent[find(ky)] = find(kx)

    by_family = collections.defaultdict(list)
    by_anchor = collections.defaultdict(list)
    for k, s in enumerate(sigs):
        family = FAMILY.get(s[0], "i")
        # Short ones only merge when they are the same.
        if len(seqs[k]) > FUZZY_MIN:
            by_family[family].append(k)
        if s[0] == "bias":
            continue  # one group already, whatever the instructions
        for a in {h.anchor for h in groups[s]} - {None}:
            by_anchor[family, a].append(k)
    for members in by_family.values():
        merge(members, ratio)
    for members in by_anchor.values():
        merge(members, anchored)
    merged = collections.defaultdict(list)
    for k, s in enumerate(sigs):
        merged[find(k)].append(s)
    return list(merged.values())


def source_lines(rows):
    """Sets our source line of each hunk of `rows`, from the line numbers
    a /Zd compile of the function's file records (/Zd keeps the code)."""
    import permute
    where = {}
    for src, obj in build.sources():
        if not os.path.exists(os.path.join(ROOT, obj)):
            continue
        o = compare.coff.Object(os.path.join(ROOT, obj))
        rel = os.path.relpath(src, "src").replace("\\", "/")
        for s in o.symbols:
            if s and s.section > 0:
                where.setdefault(s.name, src)
                if s.storage == compare.STATIC:
                    where[f"{rel}:{s.name}"] = src
    by_src = collections.defaultdict(list)
    for _, symbol, _, found in rows:
        if symbol in where and found:
            by_src[where[symbol]].append((symbol, found))
    with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, "build")) as tmp:
        def lines(job):
            k, (src, funcs) = job
            obj = os.path.join(tmp, f"{k}.obj")
            converted = build.win(os.path.join(build.CONVERTED, os.path.relpath(src, "src")))
            code, _ = build.run_tool("cl", "/c", *build.file_flags(src, build.CFLAGS), "/Zd",
                                     "/I" + build.win(build.CONVERTED), "/Fo" + build.win(obj), converted)
            if code or not os.path.exists(obj):
                return
            for symbol, found in funcs:
                table = permute.coff_lines(obj, [symbol.split(":")[-1]])
                for h in found:
                    if h.i1 < len(h.ours.offsets):
                        at = h.ours.offsets[h.i1]
                        h.line = max((n for va, n in table if va <= at), default=None)
                        h.src = src

        with ThreadPoolExecutor(build.JOBS) as pool:
            list(pool.map(lines, enumerate(by_src.items())))


def show(h, out):
    """A hunk side by side, original left, with CONTEXT instructions
    around it."""
    i0, j0 = max(0, h.i1 - CONTEXT), max(0, h.j1 - CONTEXT)
    i3, j3 = min(len(h.ours.raw), h.i2 + CONTEXT), min(len(h.theirs.raw), h.j2 + CONTEXT)
    where = f"  {h.func} +{h.offset:#x} {h.kind}, {h.bytes} bytes"
    if h.line is not None:
        where += f", {os.path.relpath(h.src, 'src')}:{h.line}"
    out.append(where)
    out.append(f"    {'original':<52}| ours")

    def text(side, k, inside):
        return ("* " if inside else "  ") + side.keys["a"][k]

    left = [text(h.theirs, k, h.j1 <= k < h.j2) for k in range(j0, j3)]
    right = [text(h.ours, k, h.i1 <= k < h.i2) for k in range(i0, i3)]
    # Align the context: the hunks' tops at the same row.
    pad = (h.j1 - j0) - (h.i1 - i0)
    if pad > 0:
        right = [""] * pad + right
    elif pad < 0:
        left = [""] * -pad + left
    for x, y in zip(left + [""] * (len(right) - len(left)), right + [""] * (len(left) - len(right))):
        out.append(f"    {x[:51]:<52}| {y}")


def describe(sig):
    kind_, ours, theirs = sig
    def ops(seq):
        # Mnemonics, a call with its target.
        return " ".join(k.replace("call ", "call:", 1) if k.startswith("call ") else k.split(" ", 1)[0]
                        for k in seq) or "-"
    return f"{kind_}: {ops(theirs)} / {ops(ours)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*")
    parser.add_argument("--level", choices=list(LEVELS), default="b")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--min", type=int, default=2, help="the fewest functions a cluster lists")
    parser.add_argument("--min-ins", type=int, default=2,
                        help="the fewest instructions of both sides a signature has")
    parser.add_argument("--gap", type=int, default=2, help="join hunks fewer aligned instructions apart")
    parser.add_argument("--fuzz", type=float, default=0.75, help="difflib ratio that merges groups")
    parser.add_argument("--anchored", type=float, default=0.5,
                        help="difflib ratio that merges groups before the same call")
    parser.add_argument("--exact", action="store_true", help="no fuzzy merging")
    parser.add_argument("--kind", help="only clusters of kinds that start with this")
    parser.add_argument("--lines", action="store_true", help="our source line of each hunk shown")
    parser.add_argument("-v", action="store_true", help="every hunk of each cluster")
    args = parser.parse_args()
    os.chdir(ROOT)
    hooks = project.config["hooks"]
    wanted = set(args.names) or set(hooks["allow_diff"]) - set(hooks.get("permute_skip", []))
    rows = collect(wanted, args.level, args.gap)
    groups = collections.defaultdict(list)
    for _, _, _, found in rows:
        for h in found:
            if len(h.keys("ours", "a")) + len(h.keys("theirs", "a")) >= args.min_ins:
                groups[h.signature()].append(h)
    clusters = [[s] for s in groups] if args.exact else fuzzy(groups, args.fuzz, args.anchored)
    ranked = []
    for sigs in clusters:
        members = [h for s in sigs for h in groups[s]]
        funcs = sorted({h.func for h in members})
        if len(funcs) < args.min or args.kind and not sigs[0][0].startswith(args.kind):
            continue
        covered = sum(h.bytes for h in members)
        ranked.append((len(funcs) * covered, funcs, covered, sigs, members))
    ranked.sort(key=lambda r: (-r[0], r[1]))
    ranked = ranked[:args.top]
    if args.lines:
        source_lines([r for r in rows if any(r[0] in c[1] for c in ranked)])
    out = []
    total = sum(len(f) for *_, f in rows)
    out.append(f"{len(rows)} functions, {total} hunks at level {args.level}, "
               f"{len(groups)} signatures, {len(clusters)} clusters")
    for n, (score, funcs, covered, sigs, members) in enumerate(ranked, 1):
        common = collections.Counter(h.signature() for h in members).most_common(1)[0][0]
        out.append("")
        what = describe(common)
        if common[0] == "bias":
            # The instructions each bias covers, the strongest first.
            per = collections.defaultdict(collections.Counter)
            for h in members:
                per[h.func][h.bias] += h.bias_count
            funcs.sort(key=lambda f: (-per[f].most_common(1)[0][1], f))
            what = "bias: displacements off a register shifted by (instructions) " + ", ".join(
                f"{f} {d:+#x} ({c})" for f in funcs for d, c in per[f].most_common(1))
        out.append(f"#{n} score {score}: {len(funcs)} functions, {len(members)} hunks, {covered} bytes;"
                   f" {what}")
        out.append("  " + ", ".join(funcs))
        if common[0] == "bias":
            first = max((h for h in members if h.func == funcs[0]), key=lambda h: h.bias_count)
        else:
            first = next(h for h in members if h.signature() == common)
        shown = members if args.v else [first]
        for h in shown:
            show(h, out)
        if args.lines and not args.v:
            lines = collections.defaultdict(set)
            for h in members:
                if h.line is not None:
                    lines[h.func].add(f"{os.path.relpath(h.src, 'src')}:{h.line}")
            for f in funcs:
                if lines[f]:
                    out.append(f"    {f}: {', '.join(sorted(lines[f], key=lambda s: int(s.rsplit(':', 1)[1])))}")
    print("\n".join(out))


if __name__ == "__main__":
    sys.exit(main())
