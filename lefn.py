"""One function of an LE game (game.format = "le"): fn.py and permute.py
use this module for their LE side, it has no command line of its own.

    fn.py NAME|ADDR        its status, the module that has it (src/X.c or
                           the stand-in src/X.asm), its neighbours there
    fn.py NAME|ADDR -d     builds, then diffs the compiled function with
                           the original's: first with registers, stack
                           offsets ([esp+N], [ebp-N]) and jump targets
                           masked, then unmasked, each a unified diff of
                           normalized lines (+offset, instruction)
    fn.py NAME|ADDR -d -a  the same without a cap on the diff's length
    fn.py NAME|ADDR -g     Ghidra's decompilation (as for pe)
    fn.py --next [N]       the first N functions of progress.compiled
                           modules still in assembly, by address

The function is placed as compare_le.py places it: through the module
in build/obj/ that defines its symbol, with every fixup resolved to the
original's target, so only real differences show. Scorer compiles a
variant of one src/ file alone with wcc386 (under Wine, the file's
build.file_cflags) and scores the function in it for permute.py: 0 is a
byte match; otherwise ten per masked diff line plus one per unmasked
one, plus 1000 per other function of the file that stops matching and
500 when the function outgrows its slot (its size up to the next
function in config/symbols.csv), which would move the code after it.
"""
import csv, difflib, glob, os, re, shutil, subprocess, sys, tempfile, threading

import build_watcom, compare_le, omf, project

ROOT = project.ROOT
REG = re.compile(r"\b(?:e?(?:[abcd]x|si|di)|[abcd][lh])\b")
STACK = re.compile(r"\b(e[bs]p)([+-]0x[0-9a-f]+)?\b")
TARGET = re.compile(r"^(j\w+|call|loop\w*)\s+0x([0-9a-f]+)")
_orig = []


def original():
    if not _orig:
        _orig.append(compare_le.Original(compare_le.EXE))
    return _orig[0]


def rows():
    return list(csv.DictReader(open(os.path.join(ROOT, "config/symbols.csv"))))


def slot(addr):
    """The bytes from addr to the next function in symbols.csv."""
    after = [int(r["address"], 16) for r in rows() if int(r["address"], 16) > addr and r["size"] not in ("", "0")]
    return min(after) - addr if after else None


def module_of(symbol):
    """(object, stem, public symbols in order) of the build/obj module
    that defines `symbol`, or None."""
    for path in sorted(glob.glob(os.path.join(ROOT, "build/obj/*.obj"))):
        for mod in omf.modules(path):
            names = [n for seg in mod.segments[1:] if seg.is_code() for _, n, _ in seg.publics]
            if symbol in names:
                return path, os.path.splitext(os.path.basename(path))[0], names
    return None


def source_of(stem):
    for ext in (".c", ".asm"):
        path = os.path.join("src", stem + ext)
        if os.path.exists(os.path.join(ROOT, path)):
            return path
    return None


def results(obj, by_symbol):
    out = []
    for mod in omf.modules(obj):
        out += compare_le.compare_module(mod, original(), by_symbol)[0]
    return out


def lines(blob, addr, masked):
    """The disassembly of blob at addr as normalized lines: the offset
    from addr and the instruction, or with `masked` the instruction alone
    with registers, stack offsets and jump targets replaced."""
    out = []
    for l in compare_le.disasm(blob, addr):
        parts = l.split("\t")
        if len(parts) < 3:
            continue
        at, ins = int(parts[0].strip().rstrip(":"), 16), " ".join(parts[2].split())
        m = TARGET.match(ins)
        if m and addr <= int(m[2], 16) < addr + len(blob):
            ins = f"{m[1]} " + ("L" if masked else f"+{int(m[2], 16) - addr:#x}")
        if masked:
            ins = REG.sub("R", STACK.sub(lambda m: m[1] + ("+N" if m[2] else ""), ins))
            out.append(ins)
        else:
            out.append(f"+{at - addr:04x} {ins}")
    return out


def diff(r, masked, context=3):
    theirs = original().read(r.addr, max(len(r.ours), 1))
    a, b = lines(theirs, r.addr, masked), lines(r.ours, r.addr, masked)
    return list(difflib.unified_diff(a, b, "original", "compiled", n=context, lineterm=""))


def changed(d):
    return sum(1 for l in d[2:] if l[:1] in "+-")


def status(r, known):
    if r.ok():
        return "MISMATCH (matches now: take it off config/nonmatching.txt)" if r.name in known else "ok"
    return "nonmatch (config/nonmatching.txt)" if r.name in known else "MISMATCH"


def find_row(key):
    rs = rows()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{5,8}", key):
        hit = [r for r in rs if int(r["address"], 16) == int(key, 16)]
    else:
        hit = [r for r in rs if r["name"] == key] or [r for r in rs if r["name"].lower() == key.lower()]
    if not hit:
        sys.exit(f"{key}: not in config/symbols.csv")
    return hit[0]


def build():
    r = subprocess.run([sys.executable, os.path.join(project.TOOLS, "build_watcom.py")],
                       capture_output=True, text=True, cwd=ROOT)
    if r.returncode:
        print("BUILD FAILED\n" + (r.stdout + r.stderr).strip()[-3000:])
        return False
    return True


def info(row, show_diff, full):
    if show_diff and not build():
        return 1
    symbol = row["symbol"].split()[0] if row["symbol"] else ""
    addr = int(row["address"], 16)
    print(f"{row['name']} {row['address']} size {row['size']} symbol {symbol}")
    found = module_of(symbol) if symbol else None
    if not found:
        print("in no module of build/obj (just build); pick the src/ file by its neighbours' addresses")
        return 0
    obj, stem, names = found
    src = source_of(stem)
    i = names.index(symbol)
    near = ", ".join(w for w in (f"after {names[i - 1]}" if i else "", f"before {names[i + 1]}"
                                 if i + 1 < len(names) else "") if w)
    kind = "stand-in assembly" if src and src.endswith(".asm") else "C"
    print(f"module: {src or stem} ({kind}), function {i + 1} of {len(names)}{': ' + near if near else ''}")
    if src and src.endswith(".asm") and stem in project.config["progress"]["compiled"]:
        print(f"  {stem} was C in the original (progress.compiled): it goes to src/{stem}.c, whole module at once")
    by_symbol, _ = compare_le.load_symbols()
    r = next((x for x in results(obj, by_symbol) if x.name == row["name"]), None)
    if r is None:
        print("status: not compared")
        return 0
    print(f"status: {status(r, compare_le.load_nonmatching())}, compiled {r.size} bytes"
          + (f", slot {slot(addr)}" if slot(addr) else ""))
    for e in r.errors[:12]:
        print("  " + e)
    if not show_diff or r.ok() or r.ours is None:
        return 0
    cap = None if full else 150
    for masked in (True, False):
        d = diff(r, masked)
        print(f"--- {'masked (registers, stack offsets, jump targets)' if masked else 'unmasked'}: "
              f"{changed(d)} lines differ")
        print("\n".join(d[2:cap]))
        if cap and len(d) > cap:
            print(f"... {len(d) - cap} more diff lines (-a shows all)")
    return 0


def show_next(n):
    compiled = set(project.config["progress"]["compiled"])
    by_addr = {int(r["address"], 16): r for r in rows()}
    todo = []
    for path in sorted(glob.glob(os.path.join(ROOT, "build/obj/*.obj"))):
        stem = os.path.splitext(os.path.basename(path))[0]
        if stem not in compiled or not (source_of(stem) or "").endswith(".asm"):
            continue
        for mod in omf.modules(path):
            for seg, name, start, end in mod.functions():
                r = next((r for r in by_addr.values() if r["symbol"] == name), None)
                if r:
                    todo.append((int(r["address"], 16), stem, r))
    for addr, stem, r in sorted(todo)[:n]:
        print(f"{addr:#010x} {r['size']:>5} {stem:10} {r['name']}")
    return 0


def main(args):
    os.chdir(ROOT)
    if args[0] == "--next":
        return show_next(int(args[1]) if len(args) > 1 else 10)
    row = find_row(args[0])
    if "-g" in args:
        import fn
        return fn.ghidra(int(row["address"], 16))
    return info(row, "-d" in args, "-a" in args)


class Scorer:
    """permute.py's scorer for an LE game; see the module docstring."""

    def __init__(self, name, src, text, start, end):
        self.name, self.src, self.text, self.start, self.end = name, src, text, start, end
        row = find_row(name)
        self.symbol = row["symbol"].split()[0]
        self.addr = int(row["address"], 16)
        self.slot = slot(self.addr)
        self.flags = build_watcom.cflags(src)
        self.by_symbol, _ = compare_le.load_symbols()
        self.watcom = project.watcom()
        self.tmp = tempfile.mkdtemp(prefix="permute", dir=os.path.join(ROOT, "build"))
        self.lock = threading.Lock()
        self.n = 0
        self.matched = None
        original()

    def variant(self, body):
        return (self.text[:self.start], body, self.text[self.end:])

    def compile(self, variant, extra=()):
        with self.lock:
            self.n += 1
            k = self.n
        c, obj = os.path.join(self.tmp, f"{k}.c"), os.path.join(self.tmp, f"{k}.obj")
        open(c, "w", encoding="utf-8", newline="\n").write("".join(variant))
        cmd = ["wine", os.path.join(self.watcom, "BINNT", "WCC386.EXE"), *self.flags, *extra,
               "-fo=" + build_watcom.winpath(obj), build_watcom.winpath(c)]
        code, out = build_watcom.run(cmd, self.watcom, cwd=self.tmp)
        os.remove(c)
        if os.path.exists(c[:-2] + ".err"):
            os.remove(c[:-2] + ".err")
        if code or not os.path.exists(obj):
            self.why = "wcc386 failed:\n" + "\n".join(l for l in out.splitlines()
                                                       if "rror" in l)[:1500]
            if os.path.exists(obj):
                os.remove(obj)
            return None
        return obj

    def result(self, variant):
        obj = self.compile(variant)
        if obj is None:
            return None, []
        try:
            every = results(obj, self.by_symbol)
        finally:
            os.remove(obj)
        mine = next((r for r in every if r.name == self.name), None)
        if mine is None:
            self.why = f"compiled, but the object doesn't define {self.symbol}"
        return mine, every

    def score(self, variant):
        if isinstance(variant, str):
            variant = self.variant(variant)
        r, every = self.result(variant)
        if r is None or r.ours is None:
            return None
        matched = {x.name for x in every if x.ok() and x.name != self.name}
        if self.matched is None:
            self.matched = matched
        penalty = 1000 * len(self.matched - matched) + (500 if self.slot and r.size > self.slot else 0)
        if r.ok():
            return penalty
        unmasked = changed(diff(r, False, 0))
        return penalty + 10 * changed(diff(r, True, 0)) + unmasked + (not unmasked)

    def hot_lines(self, variant):
        return set()
