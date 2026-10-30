"""Predicts how wcc386 lays out each module's _BSS and checks it against
the original's addresses in config/symbols.csv.

    bss.py [-v] [MODULE...]

wcc386 10.6 does not lay out uninitialized globals in definition order.
It sorts them by

1. size class, descending: a multiple of 8 bytes, then of 4, then other
   even sizes above 2, then 2 bytes, then odd sizes above 1, then 1;
2. symbol table block, newest first. The front end's symbol entries come
   in blocks of 25, the first of which holds 20 of its own. A variable's
   entry is made where it is first declared: an extern in a header
   counts, not where it is defined. Typedefs, prototypes, function
   definitions, their parameters and every block-scope declaration take
   an entry each; struct tags, members and enum constants do not;
3. name hash, ascending: hashpjw below, modulo 241;
4. the later entry first.

There is no padding between them. So the order of the externs in the
headers decides the order of the variables, and a declaration added to
a header can move another module's variables into the next block.

The source is preprocessed with wcc386 and parsed with pycparser. With
-v, prints every variable with its block and hash.
"""
import csv, glob, os, re, subprocess, sys

import build_watcom as build
from pycparser import c_ast, c_parser

ROOT = build.ROOT
FIRST = 20
BLOCK = 25
KEYWORDS = r"\b(__far|__near|__huge|__cdecl|__pascal|__watcall|__interrupt|__loadds|__saveregs|__export|_Packed)\b"


def hashpjw(name):
    s = [ord(c) for c in name] + [0]
    i, h = 1, s[0]
    if h:
        c, i = s[i], i + 1
        if c:
            h = (h << 4) + c
            while True:
                h &= 0x0FFF
                c, i = s[i], i + 1
                if not c:
                    break
                h = ((h << 4) + c) ^ (((h << 4) + c) >> 12)
                h &= 0x0FFF
                c, i = s[i], i + 1
                if not c:
                    break
                h = (h << 4) + c
                h ^= h >> 12
    return h % 241


def preprocess(src):
    w = build.watcom()
    r = subprocess.run(["wine", os.path.join(w, "BINNT", "WCC386.EXE"), *build.CFLAGS, "-p",
                        build.winpath(src)], env=build.env(w), capture_output=True, text=True)
    out, cont = [], False
    for line in r.stdout.split("\n"):
        if cont or line.startswith("#"):
            cont = line.rstrip().endswith("\\")
            line = ""
        out.append(line)
    return re.sub(KEYWORDS, "", "\n".join(out))


def entries(text):
    """Returns the file-scope names in the order of their symbol entries
    (None for a block-scope entry) and the uninitialized definitions."""
    order, seen, defs = [], set(), []

    def add(name):
        if name and name not in seen:
            seen.add(name)
            order.append(name)

    class Body(c_ast.NodeVisitor):
        def visit_Decl(self, node):
            if "extern" in node.storage:
                add(node.name)
            elif node.name:
                order.append(None)
            self.generic_visit(node)

        def visit_FuncCall(self, node):
            if isinstance(node.name, c_ast.ID):
                add(node.name.name)
            self.generic_visit(node)

    for e in c_parser.CParser().parse(text).ext:
        if isinstance(e, c_ast.FuncDef):
            add(e.decl.name)
            for p in e.decl.type.args.params if e.decl.type.args else []:
                if getattr(p, "name", None):
                    order.append(None)
            Body().visit(e.body)
        elif isinstance(e, (c_ast.Typedef, c_ast.Decl)):
            add(e.name)
            if isinstance(e, c_ast.Decl) and e.name and e.init is None \
                    and "extern" not in e.storage and not isinstance(e.type, c_ast.FuncDecl):
                defs.append(e.name)
    return order, defs


def size_class(size):
    return min(size & -size, 8) * 2 + (size > 2)


def main():
    args = sys.argv[1:]
    verbose = "-v" in args
    mods = [a for a in args if a != "-v"] or \
        [os.path.basename(p)[:-2] for p in sorted(glob.glob(os.path.join(ROOT, "src", "*.c")))]
    syms = {}
    for r in csv.reader(open(os.path.join(ROOT, "config", "symbols.csv"))):
        if r[3].startswith("_") and r[1].isdigit():
            syms[r[3][1:]] = (int(r[0], 16), int(r[1]))
    bad = 0
    for mod in mods:
        order, defs = entries(preprocess(os.path.join(ROOT, "src", mod + ".c")))
        index = {n: i for i, n in enumerate(order) if n}
        block = lambda n: (index[n] + FIRST) // BLOCK
        missing = [d for d in defs if d not in syms]
        known = [d for d in defs if d in syms]
        key = lambda n: (-size_class(syms[n][1]), -block(n), hashpjw(n), -index[n])
        ours = sorted(known, key=key)
        orig = sorted(known, key=lambda n: syms[n][0])
        ok = ours == orig and not missing
        bad += not ok
        print(f"{mod:10} {'ok' if ok else 'DIFFERS'}" + (f", not in symbols.csv: {' '.join(missing)}" if missing else ""))
        if verbose or not ok:
            for n in orig:
                print(f"    {syms[n][0]:#x} {n:24} size {syms[n][1]:5} block {block(n):3} hash {hashpjw(n):3}"
                      + ("" if ours.index(n) == orig.index(n) else f"  ours at {ours.index(n)}"))
    sys.exit(bad and 1)


if __name__ == "__main__":
    main()
