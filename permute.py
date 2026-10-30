"""Searches source variants of one function for a byte match.

    permute.py NAME [-j JOBS] [-t SECONDS] [-s SEED]
    permute.py NAME --decls [-j JOBS] [--limit N]

NAME must already be defined in src/ and build. The permuter takes its
definition, applies random rewrites (reordering local declarations,
swapping the operands of commutative operators, comparisons, && and ||,
swapping adjacent statements, flipping if/else, writing `x += y` as
`x = x + y` and `x = e; return x;` as `return e;`, and back), and
compiles each variant on its own with the build's flags, without
linking. A variant is scored by the instructions that differ from the
original, and the search climbs towards lower scores until it finds 0
or runs out of time. A rewrite may change the meaning (swapping
dependent statements, or && operands with side effects); a variant that
matches byte for byte is proven correct by the match itself.

--decls searches the local declarations only, exhaustively: every order
of the declaration lines at the top of the function, times every order
of the names within each line (sampled down to --limit candidates). VC5
orders the terms of a sum, and often register choice, by a key built
from the order its locals are declared in (all of them, used or not),
which the random search rarely hits; this mode does.

src/ is never written. The best variant goes to
build/permute/NAME.c, and the change is printed as a diff to apply by
hand; run the full compare after applying it, since a change can flip
other functions.
"""
import argparse, difflib, os, random, re, shutil, sys, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor

import build, coff, compare, project

ROOT = project.ROOT
os.chdir(ROOT)

OUT = "build/permute"
COMPARE_LOCK = threading.Lock()  # results() reads build.sources, patched per call
COMMUTATIVE = ["+", "*", "&", "|", "^", "==", "!="]
FLIPPED = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}


def find_function(name):
    """(path, text, start, end) of `name`'s definition in src/."""
    for path in sorted(build.sources()):
        src = path[0]
        if src.lower().endswith(build.ASM_EXTS) or "/dll/" in src.replace("\\", "/"):
            continue
        text = open(src, encoding="utf-8").read()
        m = re.search(r"^[^\n;{}()#]*\b" + re.escape(name) + r"\s*\([^;{]*\)\s*\{", text, re.M)
        if not m:
            continue
        depth, k = 0, m.end() - 1
        while k < len(text):
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            k += 1
            if depth == 0:
                break
        return src, text, m.start(), k
    sys.exit(f"{name}: no definition in src/")


OPERAND = r"[A-Za-z_][\w]*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\[\]]*\])*|\d+|0x[0-9a-fA-F]+"
LEFT_EDGE = r"(?<=[(\[,=?:])\s*|(?<=return )|(?<=&& )|(?<=\|\| )"


def swap_operands(body, rng):
    """Swaps the two operands of one commutative operator, or flips one
    comparison, where both are simple and bounded by low-precedence
    tokens."""
    ops = "|".join(re.escape(o) for o in sorted(COMMUTATIVE + list(FLIPPED), key=len, reverse=True))
    pat = re.compile(r"(?:" + LEFT_EDGE + r")(" + OPERAND + r") (" + ops + r") (" + OPERAND + r")(?=\s*[)\],;?:]|\s*&&|\s*\|\|)")
    hits = list(pat.finditer(body))
    if not hits:
        return None
    m = rng.choice(hits)
    a, op, b = m.group(1), m.group(2), m.group(3)
    op = FLIPPED.get(op, op)
    return body[:m.start(1)] + f"{b} {op} {a}" + body[m.end(3):]


def reorder_declarations(body, rng):
    """Shuffles the names in one multi-name declaration, or swaps two
    adjacent declaration lines at the top of the function."""
    lines = body.split("\n")
    decl = re.compile(r"^(\s+)((?:const |unsigned |signed |static |register )*[A-Za-z_]\w*\s+)([^;=(){}]+);$")
    top = []
    for i, line in enumerate(lines[2:], 2):
        if decl.match(line):
            top.append(i)
        elif line.strip():
            break
    if not top:
        return None
    if len(top) > 1 and rng.random() < 0.5:
        i = rng.choice(top[:-1])
        if i + 1 in top:
            lines[i], lines[i + 1] = lines[i + 1], lines[i]
            return "\n".join(lines)
    i = rng.choice(top)
    m = decl.match(lines[i])
    names = [n.strip() for n in m.group(3).split(",")]
    if len(names) < 2:
        return None
    rng.shuffle(names)
    lines[i] = f"{m.group(1)}{m.group(2)}{', '.join(names)};"
    return "\n".join(lines)


SIMPLE = re.compile(r"^(\s+)[^\s{}][^{}]*;$")
CONTROL = re.compile(r"^\s*(if|else|for|while|do|switch|case|default|return|break|continue|goto)\b")


def swap_statements(body, rng):
    """Swaps two adjacent simple statements at the same indent."""
    lines = body.split("\n")
    pairs = [i for i in range(1, len(lines) - 1)
             if SIMPLE.match(lines[i]) and SIMPLE.match(lines[i + 1])
             and not CONTROL.match(lines[i]) and not CONTROL.match(lines[i + 1])
             and SIMPLE.match(lines[i]).group(1) == SIMPLE.match(lines[i + 1]).group(1)
             and not re.match(r"^\s+[A-Za-z_][\w\s\*]*\s\**[A-Za-z_]\w*(\s*,\s*\**\w+)*;$", lines[i])]
    if not pairs:
        return None
    i = rng.choice(pairs)
    lines[i], lines[i + 1] = lines[i + 1], lines[i]
    return "\n".join(lines)


def flip_if(body, rng):
    """Turns `if (c) A else B` into `if (!(c)) B else A` for one-line
    branches."""
    pat = re.compile(r"(\n(\s+)if \()([^\n]*)(\)\n\2    ([^\n]+;)\n\2else\n\2    ([^\n]+;)\n)")
    hits = list(pat.finditer(body))
    if not hits:
        return None
    m = rng.choice(hits)
    ind = m.group(2)
    cond = m.group(3)
    neg = cond[2:-1] if cond.startswith("!(") and cond.endswith(")") else f"!({cond})"
    new = f"\n{ind}if ({neg})\n{ind}    {m.group(6)}\n{ind}else\n{ind}    {m.group(5)}\n"
    return body[:m.start()] + new + body[m.end():]


def swap_logical(body, rng):
    """Swaps the two sides of one && or || between parentheses."""
    side = r"[^()&|\n]+(?:\([^()\n]*\))?[^()&|\n]*"
    pat = re.compile(r"\((" + side + r") (&&|\|\|) (" + side + r")\)")
    hits = list(pat.finditer(body))
    if not hits:
        return None
    m = rng.choice(hits)
    return body[:m.start()] + f"({m.group(3).strip()} {m.group(2)} {m.group(1).strip()})" + body[m.end():]


def compound(body, rng):
    """Writes `x op= y;` as `x = x op y;`, or the other way round."""
    lv = r"[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\[\]]*\])*"
    short = re.compile(r"(?m)^(\s+)(" + lv + r") ([-+*&|^]|<<|>>)= ([^;]+);$")
    long = re.compile(r"(?m)^(\s+)(" + lv + r") = (" + lv + r") ([-+*&|^]|<<|>>) ([^;]+);$")
    hits = [("s", m) for m in short.finditer(body)] + [("l", m) for m in long.finditer(body) if m.group(2) == m.group(3)]
    if not hits:
        return None
    kind, m = rng.choice(hits)
    if kind == "s":
        new = f"{m.group(1)}{m.group(2)} = {m.group(2)} {m.group(3)} {m.group(4)};"
    else:
        new = f"{m.group(1)}{m.group(2)} {m.group(4)}= {m.group(5)};"
    return body[:m.start()] + new + body[m.end():]


def shuffle_declarations(body, rng):
    """Shuffles every declaration line at the top of the function."""
    lines = body.split("\n")
    decl = re.compile(r"^\s+(?:const |unsigned |signed |static |register )*[A-Za-z_]\w*\s+[^;=(){}]+;$")
    top = []
    for i, line in enumerate(lines[2:], 2):
        if decl.match(line):
            top.append(i)
        elif line.strip():
            break
    if len(top) < 2:
        return None
    picked = [lines[i] for i in top]
    rng.shuffle(picked)
    for i, line in zip(top, picked):
        lines[i] = line
    return "\n".join(lines)


def inline_return(body, rng):
    """Writes `x = e; return x;` as `return e;`, or the other way round
    through the variable a return's value was last stored in."""
    stored = re.compile(r"(?m)^(\s+)([A-Za-z_]\w*) = ([^;]+);\n\1return \2;$")
    direct = re.compile(r"(?m)^(\s+)return ([^;]+);$")
    hits = [("s", m) for m in stored.finditer(body)]
    names = re.findall(r"(?m)^\s+(?:[A-Za-z_]\w*\s+)+\**([A-Za-z_]\w*)(?:, \**[A-Za-z_]\w*)*;$", body)
    params = re.findall(r"([A-Za-z_]\w*)\s*[,)]", body.split("{", 1)[0])
    hits += [("d", m) for m in direct.finditer(body) if names or params]
    if not hits:
        return None
    kind, m = rng.choice(hits)
    if kind == "s":
        new = f"{m.group(1)}return {m.group(3)};"
    else:
        var = rng.choice(names + params)
        new = f"{m.group(1)}{var} = {m.group(2)};\n{m.group(1)}return {var};"
    return body[:m.start()] + new + body[m.end():]


MUTATIONS = [swap_operands, swap_operands, reorder_declarations, shuffle_declarations, swap_statements,
             flip_if, swap_logical, compound, inline_return]


class Scorer:
    def __init__(self, name, src, text, start, end):
        self.name, self.src, self.text, self.start, self.end = name, src, text, start, end
        self.symbols = compare.read_symbols()
        row = next(r for r in compare_rows() if r["name"] == name)
        self.symbol_names = row["symbol"].split()
        self.symbol = self.symbol_names[0]
        self.addr, self.size = self.symbols[self.symbol]
        self.orig = coff.Image(os.path.join(ROOT, compare.EXE)).read(self.addr, self.size)
        self.orig_asm = compare.disasm(self.orig, self.addr)
        self.flags = build.file_flags(src, build.CFLAGS)
        self.tmp = tempfile.mkdtemp(prefix="permute", dir=os.path.join(ROOT, "build"))
        self.lock = threading.Lock()
        self.n = 0

    def source(self, body):
        return self.text[:self.start] + body + self.text[self.end:]

    def score(self, body):
        with self.lock:
            self.n += 1
            k = self.n
        rel = os.path.relpath(self.src, "src")
        conv = os.path.join(build.CONVERTED, os.path.dirname(rel), f"_perm{k}_{os.path.basename(rel)}")
        obj = os.path.join(self.tmp, f"{k}.obj")
        text = self.source(body)
        if build.CRLF:
            text = text.replace("\n", "\r\n")
        with open(conv, "wb") as f:
            f.write(build.encode(text))
        try:
            code, out = build.run_tool("cl", "/c", *self.flags, "/I" + build.win(build.CONVERTED),
                                     "/Fo" + build.win(obj), build.win(conv))
        finally:
            os.remove(conv)
        if code or not os.path.exists(obj):
            self.why = "cl failed:\n" + "\n".join(l for l in out.splitlines() if "error" in l)[:1500]
            return None
        with COMPARE_LOCK:
            saved = build.sources
            try:
                build.sources = lambda *a, **kw: [(self.src, obj)]
                res = [r for r in compare.results(self.symbols) if r[0] in self.symbol_names]
            finally:
                build.sources = saved
                os.remove(obj)
        if not res:
            self.why = (f"compiled, but the object defines none of {' '.join(self.symbol_names)} (symbols.csv's "
                        f"symbols for {self.name}): check the function's linkage, extern \"C\" or C++")
            return None
        _, same, code_bytes, mask, orig, diffs = res[0]
        if same:
            return 0
        shown = bytes(b if m and i < len(orig) else a
                      for i, (a, m, b) in enumerate(zip(code_bytes, mask, orig + bytes(len(code_bytes)))))
        ours = compare.disasm(shown, self.addr)
        sm = difflib.SequenceMatcher(None, ours, self.orig_asm, autojunk=False)
        return len(ours) + len(self.orig_asm) - 2 * sum(b.size for b in sm.get_matching_blocks()) + len(diffs)


DECL = re.compile(r"^(\s+)((?:const |unsigned |signed |static |register |struct |enum )*[A-Za-z_]\w*[\s\*]+)([^;=(){}]+);$")


def declaration_orders(body, limit, rng):
    """Orders of the top declaration lines and of the names in each, the
    original first: all of them when there are at most `limit`, otherwise
    `limit` drawn at random. Memory stays proportional to `limit`."""
    import itertools, math
    lines = body.split("\n")
    top = []
    for i, line in enumerate(lines[2:], 2):
        m = DECL.match(line)
        if m and m.group(2).split()[0] not in ("return", "goto", "case", "else", "do"):
            top.append(i)
        elif line.strip() or top:
            break
    if not top:
        return []
    parts = []
    for i in top:
        m = DECL.match(lines[i])
        parts.append((m.group(1), m.group(2).rstrip(), [n.strip() for n in m.group(3).split(",")]))

    def render(order, names):
        block = [f"{parts[i][0]}{parts[i][1]}{'' if parts[i][1].endswith('*') else ' '}{', '.join(ns)};"
                 for i, ns in zip(order, names)]
        return "\n".join(lines[:top[0]] + block + lines[top[-1] + 1:])

    total = math.factorial(len(parts)) * math.prod(math.factorial(len(p[2])) for p in parts)
    if total <= limit:
        out = []
        for order in itertools.permutations(range(len(parts))):
            for names in itertools.product(*[itertools.permutations(parts[i][2]) for i in order]):
                out.append(render(order, names))
        return out
    out, seen = [body], set()
    tries = 0
    while len(out) < limit and tries < limit * 20:
        tries += 1
        order = list(range(len(parts)))
        rng.shuffle(order)
        names = []
        for i in order:
            ns = list(parts[i][2])
            rng.shuffle(ns)
            names.append(tuple(ns))
        key = (tuple(order), tuple(names))
        if key in seen:
            continue
        seen.add(key)
        out.append(render(order, names))
    return out


def compare_rows():
    import csv
    return list(csv.DictReader(open("config/symbols.csv")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("-j", type=int, default=max(2, build.JOBS))
    ap.add_argument("-t", type=float, default=600)
    ap.add_argument("-s", type=int, default=None)
    ap.add_argument("--decls", action="store_true", help="search declaration orders exhaustively")
    ap.add_argument("--limit", type=int, default=3000, help="--decls: most candidates to try")
    args = ap.parse_args()
    build.compile_all()
    src, text, start, end = find_function(args.name)
    s = Scorer(args.name, src, text, start, end)
    base = text[start:end]
    first = s.score(base)
    if first is None:
        sys.exit("the function doesn't build as it is: " + getattr(s, "why", "unknown reason"))
    print(f"{args.name}: {src}, score {first} as written", flush=True)
    if first == 0:
        print("already matches")
        return 0
    rng = random.Random(args.s)
    best, best_score = base, first
    cur, cur_score = base, first
    deadline = time.time() + args.t
    tried = 0

    if args.decls:
        cands = declaration_orders(base, args.limit, rng)[1:]
        print(f"{len(cands)} declaration orders to try", flush=True)
        step = args.j * 4
        with ThreadPoolExecutor(args.j) as pool:
            for i in range(0, len(cands), step):
                chunk = cands[i:i + step]
                for body, sc in zip(chunk, pool.map(s.score, chunk)):
                    tried += 1
                    if sc is not None and sc < best_score:
                        best, best_score = body, sc
                        print(f"  {tried:5d} tries: score {sc}", flush=True)
                if best_score == 0:
                    break
        deadline = 0

    def candidate(seed_body, r):
        body = seed_body
        for _ in range(r.choice([1, 1, 1, 2, 3])):
            new = r.choice(MUTATIONS)(body, r)
            if new:
                body = new
        return body

    with ThreadPoolExecutor(args.j) as pool:
        while time.time() < deadline and best_score:
            bodies = [candidate(cur, random.Random(rng.random())) for _ in range(args.j)]
            for body, sc in zip(bodies, pool.map(s.score, bodies)):
                tried += 1
                if sc is None:
                    continue
                if sc < best_score:
                    best, best_score = body, sc
                    print(f"  {tried:5d} tries: score {sc}", flush=True)
                if sc <= cur_score or rng.random() < 0.05:
                    cur, cur_score = body, sc
            if rng.random() < 0.02:
                cur, cur_score = best, best_score
    shutil.rmtree(s.tmp, ignore_errors=True)
    os.makedirs(OUT, exist_ok=True)
    out = os.path.join(OUT, f"{args.name}.c")
    open(out, "w").write(best)
    print(f"{tried} tries, best score {best_score}{' (MATCH)' if best_score == 0 else ''}; written to {out}")
    if best != base:
        sys.stdout.writelines(difflib.unified_diff(base.splitlines(True), best.splitlines(True),
                                                   "as written", "best variant", n=1))
    return 0 if best_score == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
