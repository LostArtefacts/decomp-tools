"""Sorts the functions that differ from the original by how far apart
they are.

    redtriage.py [NAME...]        the bucket of each function hooks.allow_diff
                                  lists (default) or of each NAME
    redtriage.py --all            of every compiled function that differs
    redtriage.py -v NAME...       also the first differing instructions
    redtriage.py --markdown FILE  also write the table and the names per
                                  bucket to FILE

It reads the objects in build/obj, as compare.py does, so build first
(`just build`). Each function gets the first bucket that fits:

    SAME     the bytes match: the function needn't be in hooks.allow_diff
    DATA     the code matches, data it points at (constants, strings) doesn't
    REGONLY  the same instructions at the same offsets and of the same
             sizes, once every register is a placeholder by its width
             (reg8, reg16, reg32; st for the x87 stack)
    SLOT     as REGONLY, once displacements off esp and ebp and the
             immediates that move esp are masked too: stack slots in
             another order (frame: the frame sizes, when they differ)
    SCHED    as SLOT, but each basic block may hold its instructions in
             another order
    LAYOUT   the same blocks, in another order: unconditional jumps
             inside the function are left out and conditional ones lose
             their condition, so inverted branches count too
             (tail: the same set of blocks, but some appear more often in
             one, such as a merged or a duplicated epilogue)
    MOTION   the same instructions as LAYOUT compares them, but some in
             other blocks: code moved across branches
    STRUCT   anything else (note: the instruction counts, the edits that
             turn one listing into the other and the instructions only
             one of them has, as LAYOUT and MOTION compare them)

A field compare.py masks (a relocation to a target symbols.csv doesn't
know) makes its instruction compare with the original's with every
number left out. Branches inside the function compare by the index of
the instruction they go to. Each row also gives the size, the compiled
size, the number of differing bytes (counting the bytes one has past
the other's end) and the first differing offset.
"""
import argparse, collections, difflib, os, re, sys

import capstone

import compare, project

ROOT = project.ROOT
BUCKETS = ["SAME", "DATA", "REGONLY", "SLOT", "SCHED", "LAYOUT", "MOTION", "STRUCT"]

CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
CS.detail = True
CS.skipdata = True

REGISTERS = [(re.compile(r"\b(?:e[abcd]x|e[sd]i|e[bs]p)\b"), "reg32"),
             (re.compile(r"\b(?:[abcd]x|[sd]i|[bs]p)\b"), "reg16"),
             (re.compile(r"\b[abcd][lh]\b"), "reg8"),
             (re.compile(r"\bst\(\d\)|\bst\b"), "st")]
STACK = re.compile(r"\b(e[bs]p)( [+-] (?:0x[0-9a-f]+|\d+))?(?=\])")
NUMBER = re.compile(r"\b(?:0x[0-9a-f]+|\d+)\b")


def names():
    """symbols.csv's symbol -> name."""
    import csv
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        return {s: r["name"] for r in csv.DictReader(f) for s in r["symbol"].split()}


def differing(code, mask, orig):
    """The offsets of the bytes that differ, masked fields left out."""
    diff = [i for i in range(min(len(code), len(orig))) if not mask[i] and code[i] != orig[i]]
    return diff + list(range(min(len(code), len(orig)), max(len(code), len(orig))))


class Listing:
    """A function's instructions: their offsets, sizes, whether one holds
    a masked field, and where the basic blocks start."""

    def __init__(self, code, addr, mask=None):
        self.ins = list(CS.disasm(code, addr))
        self.addr, self.end = addr, addr + len(code)
        self.index = {i.address: n for n, i in enumerate(self.ins)}
        self.masked = [bool(mask) and any(mask[i.address - addr:i.address - addr + i.size])
                       for i in self.ins]
        starts = {0}
        for n, i in enumerate(self.ins):
            if self.branch(i):
                starts.add(n + 1)
                target = self.target(i)
                if target in self.index:
                    starts.add(self.index[target])
        self.starts = sorted(s for s in starts if s < len(self.ins))

    @staticmethod
    def branch(i):
        return any(g in (capstone.CS_GRP_JUMP, capstone.CS_GRP_RET) for g in groups(i))

    def target(self, i):
        """The address a direct branch or call goes to, else None."""
        if (capstone.CS_GRP_JUMP in groups(i) or capstone.CS_GRP_CALL in groups(i)) \
                and NUMBER.fullmatch(i.op_str):
            return int(i.op_str, 0)
        return None

    def blocks(self):
        bounds = self.starts + [len(self.ins)]
        return [range(a, b) for a, b in zip(bounds, bounds[1:])]

    def tokens(self, stack=False, layout=False):
        """Each instruction as (text, text without numbers, masked), the
        registers as placeholders; `stack` masks frame displacements,
        `layout` drops jumps inside the function and branch conditions."""
        out = []
        for n, i in enumerate(self.ins):
            ops, mnemonic = i.op_str, i.mnemonic
            target = self.target(i)
            if target is not None and self.addr <= target < self.end:
                ops = "L" if layout else f"L{self.index.get(target, f'?{target - self.addr:x}')}"
                if layout and mnemonic == "jmp":
                    continue
                if layout and capstone.CS_GRP_JUMP in groups(i) and mnemonic != "jmp":
                    mnemonic = "jcc"
            if stack:
                ops = STACK.sub(r"\1 + S", ops)
                if mnemonic in ("sub", "add") and ops.startswith("esp, "):
                    ops = "esp, S"
                # ecx is the caller's to save: pushing it first makes a
                # 4-byte frame, and popping it before a return drops one.
                elif n == 0 and (mnemonic, ops) == ("push", "ecx"):
                    mnemonic, ops = "sub", "esp, S"
                elif (mnemonic, ops) == ("pop", "ecx") and n + 1 < len(self.ins) \
                        and self.ins[n + 1].mnemonic == "ret":
                    mnemonic, ops = "add", "esp, S"
            for pattern, placeholder in REGISTERS:
                ops = pattern.sub(placeholder, ops)
            text = f"{mnemonic} {ops}".strip()
            out.append((text, NUMBER.sub("N", text), self.masked[n]))
        return out

    def frame(self):
        """The immediate of the first `sub esp, N`, the frame's size."""
        if self.ins and (self.ins[0].mnemonic, self.ins[0].op_str) == ("push", "ecx"):
            return 4
        for i in self.ins[:16]:
            m = re.fullmatch(r"esp, (0x[0-9a-f]+|\d+)", i.op_str)
            if i.mnemonic == "sub" and m:
                return int(m[1], 0)
        return 0


def groups(i):
    """An instruction's capstone groups; none for undecodable bytes."""
    return () if i.mnemonic == ".byte" else i.groups


def same(a, b):
    """Whether two tokens match; a masked one by its numberless text."""
    return a[1] == b[1] if a[2] or b[2] else a[0] == b[0]


def unmatched(ours, theirs):
    """How many tokens of each list the other lacks, in any order. Only
    `ours` has masked fields: those tokens compare by their numberless
    text with what the others leave of `theirs`."""
    exact = collections.Counter(t[0] for t in theirs)
    loose = collections.Counter()
    extra = 0
    for t in ours:
        if t[2]:
            loose[t[1]] += 1
        elif exact[t[0]]:
            exact[t[0]] -= 1
        else:
            extra += 1
    rest = collections.Counter(NUMBER.sub("N", t) for t, n in exact.items() for _ in range(n))
    return extra + sum((loose - rest).values()), sum((rest - loose).values())


def same_multiset(ours, theirs):
    """Whether two lists of tokens hold the same tokens, in any order."""
    return len(ours) == len(theirs) and unmatched(ours, theirs) == (0, 0)


def classify(code, mask, orig, addr, data_diffs=()):
    """The bucket of one compiled function, with what it found."""
    diff = differing(code, mask, orig)
    row = {"size": len(orig), "compiled": len(code), "diff": len(diff),
           "first": diff[0] if diff else None, "note": ""}
    if not diff:
        row["bucket"] = "DATA" if data_diffs else "SAME"
        return row
    ours, theirs = Listing(code, addr, mask), Listing(orig, addr)
    shape = [(i.address, i.size) for i in ours.ins] == [(i.address, i.size) for i in theirs.ins]
    for bucket, stack in (("REGONLY", False), ("SLOT", True)):
        a, b = ours.tokens(stack), theirs.tokens(stack)
        if len(a) == len(b) and all(map(same, a, b)) and (shape or bucket == "SLOT"):
            row["bucket"] = bucket
            if bucket == "SLOT" and ours.frame() != theirs.frame():
                row["note"] = f"frame {ours.frame():#x}/{theirs.frame():#x}"
            return row
    a, b = ours.tokens(True), theirs.tokens(True)
    if ours.starts == theirs.starts and all(same_multiset(a[r.start:r.stop], b[r.start:r.stop])
                                            for r in ours.blocks()):
        row["bucket"] = "SCHED"
        return row
    a, b = ours.tokens(True, True), theirs.tokens(True, True)

    def blocks(listing, tokens):
        # Token n belongs to the block of the instruction it came from;
        # dropped jumps leave holes, so walk the instructions again.
        kept = iter(tokens)
        out = []
        for r in listing.blocks():
            block = []
            for n in r:
                i = listing.ins[n]
                t = listing.target(i)
                if i.mnemonic == "jmp" and t is not None and listing.addr <= t < listing.end:
                    continue
                block.append(next(kept))
            if block:
                out.append(block)
        return out

    def loose(block):
        return tuple(sorted(t[1] for t in block))

    def pair(ba, bb, reuse):
        # Whether each block of ba has a block of bb with the same
        # instructions, a different one each unless `reuse`.
        free = collections.defaultdict(list)
        for block in bb:
            free[loose(block)].append(block)
        for block in ba:
            found = next((k for k, other in enumerate(free[loose(block)])
                          if same_multiset(block, other)), None)
            if found is None:
                return False
            if not reuse:
                free[loose(block)].pop(found)
        return True

    ba, bb = blocks(ours, a), blocks(theirs, b)
    if len(ba) == len(bb) and pair(ba, bb, False):
        row["bucket"] = "LAYOUT"
        return row
    if pair(ba, bb, True) and pair(bb, ba, True):
        row["bucket"] = "LAYOUT"
        row["note"] = "tail"
        return row
    extra, missing = unmatched(a, b)
    if (extra, missing) == (0, 0):
        row["bucket"] = "MOTION"
        return row
    row["bucket"] = "STRUCT"
    row["delta"] = extra + missing
    a, b = ours.tokens(True), theirs.tokens(True)
    matcher = difflib.SequenceMatcher(None, [t[1] for t in a], [t[1] for t in b], autojunk=False)
    edits = len(a) + len(b) - 2 * sum(m.size for m in matcher.get_matching_blocks())
    row["edits"] = edits
    row["note"] = f"{len(a)}/{len(b)} ins, {edits} edits, {row['delta']} not in the other"
    return row


def triage(wanted=None, verbose=False):
    """Yields (name, row) for each function that differs, or each in
    `wanted` (names), compiled or not."""
    symbols, plain = compare.read_symbols(), names()
    seen = set()
    for symbol, ok, code, mask, orig, data in compare.results(symbols):
        name = plain.get(symbol, symbol)
        if wanted is not None and name not in wanted or wanted is None and ok:
            continue
        seen.add(name)
        row = classify(code, mask, orig, symbols[symbol][0], data)
        row["address"] = symbols[symbol][0]
        if verbose and row["first"] is not None:
            shown = bytes(b if m and i < len(orig) else a
                          for i, (a, m, b) in enumerate(zip(code, mask, orig + bytes(len(code)))))
            row["listing"] = (compare.disasm(shown, row["address"]), compare.disasm(orig, row["address"]))
        yield name, row
    for name in sorted((wanted or set()) - seen):
        yield name, None


def markdown(rows):
    counts = collections.Counter(r["bucket"] for _, r in rows)
    lines = ["| bucket | functions | diff bytes | size |", "|---|---:|---:|---:|"]
    for b in BUCKETS:
        group = [r for _, r in rows if r["bucket"] == b]
        if group:
            lines.append(f"| {b} | {len(group)} | {sum(r['diff'] for r in group)} |"
                         f" {sum(r['size'] for r in group)} |")
    lines.append(f"| total | {len(rows)} | {sum(r['diff'] for _, r in rows)} |"
                 f" {sum(r['size'] for _, r in rows)} |")
    for b in BUCKETS:
        group = [n for n, r in rows if r["bucket"] == b]
        if group:
            lines += ["", f"{b} ({counts[b]}): " + ", ".join(group)]
    lines += ["", "| function | address | bucket | size | compiled | diff | first | note |",
              "|---|---|---|---:|---:|---:|---:|---|"]
    for n, r in rows:
        first = "" if r["first"] is None else f"{r['first']:#x}"
        lines.append(f"| {n} | {r['address']:08x} | {r['bucket']} | {r['size']} | {r['compiled']} |"
                     f" {r['diff']} | {first} | {r['note']} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*")
    parser.add_argument("--all", action="store_true", help="every compiled function that differs")
    parser.add_argument("-v", action="store_true", help="show the first differing instructions")
    parser.add_argument("--markdown", metavar="FILE")
    args = parser.parse_args()
    os.chdir(ROOT)
    wanted = None if args.all else set(args.names or project.config["hooks"]["allow_diff"])
    rows, missing = [], []
    for name, row in triage(wanted, args.v):
        if row is None:
            missing.append(name)
            continue
        rows.append((name, row))
        first = "-" if row["first"] is None else f"{row['first']:#x}"
        print(f"{row['bucket']:<7} {row['address']:08x} {row['size']:5d}/{row['compiled']:<5d}"
              f" diff {row['diff']:5d} first {first:>6} {name} {row['note']}".rstrip())
        if "listing" in row:
            ours, theirs = row["listing"]
            n = next((k for k, (a, b) in enumerate(zip(ours, theirs)) if a != b), min(len(ours), len(theirs)))
            print(f"    {'original':<50} | compiled")
            for a, b in zip(ours[n:n + 8], theirs[n:n + 8]):
                print(f"    {b:<50} | {a}")
    for name in missing:
        print(f"MISSING {name}: not compiled")
    counts = collections.Counter(r["bucket"] for _, r in rows)
    print(", ".join(f"{b} {counts[b]} ({sum(r['diff'] for _, r in rows if r['bucket'] == b)} bytes)"
                    for b in BUCKETS if counts[b]))
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(markdown(rows))


if __name__ == "__main__":
    sys.exit(main())
