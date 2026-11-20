"""Searches source variants of one function for a byte match.

    permute.py NAME [-j JOBS] [-t SECONDS] [-s SEED]
    permute.py NAME --decls [-j JOBS] [--limit N]
    permute.py NAME --order [-j JOBS] [-t SECONDS]
    permute.py --all [--budget SECONDS] [-j JOBS] [-p PARALLEL] [--names FILE]

--start FILE searches from the variant in FILE instead, when it builds
and scores better than the definition in src/.

--sweep enumerates instead of sampling, around the lines whose code
differs (from /Zd line numbers): every declaration order, every
combination of swapped operands in those lines, every order of each
run of independent stores (those lines' first), every single
application of the other rewrites there, and with --file every place
a top-level declaration before the function can move to. It keeps the
best two variants and goes again from them until a whole pass finds
nothing better, then prints "sweep exhausted".

NAME must already be defined in src/ and build. The permuter takes its
definition, applies random rewrites (reordering local declarations,
swapping the operands of commutative operators, comparisons, && and ||,
swapping adjacent statements, flipping if/else, writing `x += y` as
`x = x + y` and `x = e; return x;` as `return e;`, and back, and the
statement and scope shapes of tools/docs/vc6-c2.md's "Quick levers for
a red function", each both ways: a for header's pointer increment
moved before each continue and to the bottom of the body (rule V1), a
local declared in the innermost block holding its uses, or a copy in
each run that sets it afresh or each switch arm, a local re-spelled as
its initializer at each use or a repeated `a[i]` cached in one, a
ternary call argument selected into a local by if/else, a call
argument used twice (or holding a call) named in a local, a run of
independent stores reordered, `x = constant;` moved above an early
return, and the statements after an if/else chain moved into each
arm), and compiles each variant on its own with the build's flags, without
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

--pad looks for a declaration that only needs to move. It first puts
N dummy declarations right before the function, for N below --limit
(default 32 here), to see whether some shift of the symbol IDs makes it
match. If none does, it searches every local declaration order (as
--decls) at the three shifts that come closest, and prints the shift and
order that match. If one does, it tries every real change that shifts them: each
top-level declaration line moved from after the function to right
before it or from before it to right after it, and each prototype
before it with its parameter names dropped. A change counts only when
the function matches and every other function in the file still does;
the file goes to build/permute/NAME.file.

--plan does the same for every function in NAME's file at once. It
finds which shifts below --limit (default 64) make each function match
when the extra declarations go right before it, then the number of
declarations to add before each function, never fewer than before the
one above it, that makes the most of them match, and prints that plan.
Only the count matters to VC5, so the plan can be met with any real
declarations.

--order climbs over statement orders only: it moves one simple
statement within its run of statements at one indent, past only
statements it is independent of (neither calls a function, neither
mentions what the other assigns), scores -j such moves a round and
takes the best when it is no worse, and returns to the best order after
20 rounds without progress. It suits functions whose instructions
match but are scheduled differently, such as a block of stores.

--all runs a search on every function of hooks.allow_diff but those
hooks.permute_skip lists (or on those --names lists, one a line), each
in a permute.py of its own for --budget seconds (default 300): a sweep
for up to half of it, then a random search from its best. -j is the
compiles in all, shared by -p functions at a time (default -j / 4);
a function whose search fails (cl times out under load) gets a second
search afterwards, alone with all -j compiles. A
match goes to build/permute/batch/NAME.match.c, a lower score to
NAME.better.c, and summary.txt tabulates the score as written, the
best, and the time of each; the logs are in build/permute/batch/work.
--hybrid is that search for one function, --base FILE starts it from
the body in FILE as if src/ had it, and --out DIR writes the best
variant, and NAME.json with the scores, to DIR.

With game.format = "le", lefn.py's Scorer compiles each variant with
wcc386 under Wine, with the file's flags (build.file_cflags), and
scores it as `fn.py NAME -d` diffs it: ten per masked diff line, one per
unmasked one, 0 for a byte match, plus 1000 per other function of the
file that stops matching and 500 when the function outgrows its slot.
--pad, --plan and --sweep are pe only.

src/ is never written, not even by --all. The best variant goes to
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
LE = project.config["game"]["format"] == "le"
COMPARE_LOCK = threading.Lock()  # results() reads build.sources, patched per call
FILE_MODE = [False, None]  # --file, and the text around the function in src/
COMMUTATIVE = ["+", "*", "&", "|", "^", "==", "!="]
FLIPPED = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}


def keep(name, variant):
    """Writes the best variant so far, so a stopped search keeps it: the
    function's body as NAME.c and, when the rest of the file changed too,
    the whole file as NAME.file."""
    before, body, after = variant
    os.makedirs(OUT, exist_ok=True)
    open(os.path.join(OUT, f"{name}.c"), "w", encoding="utf-8", newline="\n").write(body)
    whole = os.path.join(OUT, f"{name}.file")
    if FILE_MODE[0] and (before, after) != FILE_MODE[1]:
        open(whole, "w", encoding="utf-8", newline="\n").write(before + body + after)
    elif os.path.exists(whole):
        os.remove(whole)


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


def operand_pattern():
    ops = "|".join(re.escape(o) for o in sorted(COMMUTATIVE + list(FLIPPED), key=len, reverse=True))
    return re.compile(r"(?:" + LEFT_EDGE + r")(" + OPERAND + r") (" + ops + r") (" + OPERAND
                      + r")(?=\s*[)\],;?:]|\s*&&|\s*\|\|)")


def swap_operands(body, rng):
    """Swaps the two operands of one commutative operator, or flips one
    comparison, where both are simple and bounded by low-precedence
    tokens."""
    hits = list(operand_pattern().finditer(body))
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


LVALUE = r"[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\[\]]*\])*"


def condition_form(body, rng):
    """Writes one test as `!x` or `x == 0`, or `if (x)` as `if (x != 0)`,
    and back."""
    forms = [
        (re.compile(r"(?<=[(\s])!(" + OPERAND + r")(?=[)\s])"), lambda m: f"{m.group(1)} == 0"),
        (re.compile(r"(?<=\()(" + OPERAND + r") == 0(?=\))|(?<=[&|] )(" + OPERAND + r") == 0(?=[)\s])"),
         lambda m: f"!{m.group(1) or m.group(2)}"),
        (re.compile(r"(?:(?<=\bif \()|(?<=\bwhile \())(" + OPERAND + r")(?=\))"), lambda m: f"{m.group(1)} != 0"),
        (re.compile(r"(?:(?<=\bif \()|(?<=\bwhile \())(" + OPERAND + r") != 0(?=\))"), lambda m: m.group(1)),
    ]
    hits = [(m, f) for pat, f in forms for m in pat.finditer(body)]
    if not hits:
        return None
    m, f = rng.choice(hits)
    return body[:m.start()] + f(m) + body[m.end():]


def increment_form(body, rng):
    """Writes the statement `x++;` as `++x;` or `x += 1;`, and back."""
    pat = re.compile(r"(?m)^(\s+)(?:(" + LVALUE + r")(\+\+|--)|(\+\+|--)(" + LVALUE + r")|(" + LVALUE
                     + r") ([-+])= 1);$")
    hits = list(pat.finditer(body))
    if not hits:
        return None
    m = rng.choice(hits)
    ind = m.group(1)
    if m.group(2):
        x, op = m.group(2), m.group(3)
    elif m.group(5):
        x, op = m.group(5), m.group(4)
    else:
        x, op = m.group(6), m.group(7) * 2
    forms = [f"{x}{op};", f"{op}{x};", f"{x} {op[0]}= 1;"]
    forms.remove(m.group(0)[len(ind):])
    return body[:m.start()] + ind + rng.choice(forms) + body[m.end():]


def ternary_form(body, rng):
    """Writes `x = c ? a : b;` as an if/else of two assignments, and back."""
    tern = re.compile(r"(?m)^(\s+)(" + LVALUE + r") = \(?([^;?\n]+?)\)? \? ([^;:\n]+) : ([^;\n]+);$")
    ifelse = re.compile(r"(?m)^(\s+)if \(([^\n]*)\)\n\1    (" + LVALUE + r") = ([^\n;]+);\n\1else\n\1    \3 = ([^\n;]+);$")
    hits = [("t", m) for m in tern.finditer(body)] + [("i", m) for m in ifelse.finditer(body)]
    if not hits:
        return None
    kind, m = rng.choice(hits)
    ind = m.group(1)
    if kind == "t":
        new = (f"{ind}if ({m.group(3)})\n{ind}    {m.group(2)} = {m.group(4)};\n"
               f"{ind}else\n{ind}    {m.group(2)} = {m.group(5)};")
    else:
        new = f"{ind}{m.group(3)} = ({m.group(2)}) ? {m.group(4)} : {m.group(5)};"
    return body[:m.start()] + new + body[m.end():]


def block_end(lines, i):
    """The line closing the block that line `i` opens, or None."""
    ind = re.match(r"\s*", lines[i]).group(0)
    for j in range(i + 1, len(lines)):
        if lines[j] == ind + "}":
            return j
        if lines[j].strip() and not lines[j].startswith(ind + " ") and lines[j] != ind + "}":
            return None
    return None


def loop_form(body, rng):
    """Writes `for (a; c; s) {...}` as `a; while (c) {...; s;}`, and back,
    for loops with no continue."""
    lines = body.split("\n")
    hits = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s+)for \(([^;]*); ([^;]+); ([^)]*)\) \{$", line)
        if m:
            j = block_end(lines, i)
            if j and not any("continue" in l for l in lines[i:j]):
                hits.append(("f", i, j, m))
        m = re.match(r"^(\s+)while \((.+)\) \{$", line)
        if m and i > 0:
            j = block_end(lines, i)
            init = re.match(r"^" + m.group(1) + r"([^\s{}][^{};]*);$", lines[i - 1])
            step = j and re.match(r"^" + m.group(1) + r"    ([^\s{}][^{};]*);$", lines[j - 1])
            if j and init and step and not CONTROL.match(lines[i - 1]) and not CONTROL.match(lines[j - 1]) \
                    and not any("continue" in l for l in lines[i:j]):
                hits.append(("w", i, j, (m, init.group(1), step.group(1))))
    if not hits:
        return None
    kind, i, j, m = rng.choice(hits)
    if kind == "f":
        ind, init, cond, step = m.group(1), m.group(2), m.group(3), m.group(4)
        new = ([f"{ind}{init};"] if init.strip() else []) + [f"{ind}while ({cond}) {{"] + lines[i + 1:j]
        new += ([f"{ind}    {step};"] if step.strip() else []) + [f"{ind}}}"]
        return "\n".join(lines[:i] + new + lines[j + 1:])
    w, init, step = m
    ind = w.group(1)
    new = [f"{ind}for ({init}; {w.group(2)}; {step}) {{"] + lines[i + 1:j - 1] + [f"{ind}}}"]
    return "\n".join(lines[:i - 1] + new + lines[j + 1:])


def address_form(body, rng):
    """Writes `&a[i]` as `a + i`, and back."""
    amp = re.compile(r"&([A-Za-z_]\w*)\[([^\[\]]+)\](?![\[.]|->)")
    plus = re.compile(r"(?<=[(=,] )([A-Za-z_]\w*) \+ (" + OPERAND + r")(?=[);,])|(?<=\()([A-Za-z_]\w*) \+ (" + OPERAND
                      + r")(?=\))")
    hits = [("a", m) for m in amp.finditer(body)] + [("p", m) for m in plus.finditer(body)]
    if not hits:
        return None
    kind, m = rng.choice(hits)
    if kind == "a":
        return body[:m.start()] + f"{m.group(1)} + {m.group(2)}" + body[m.end():]
    a, i = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
    return body[:m.start()] + f"&{a}[{i}]" + body[m.end():]


def move_statement(body, rng):
    """Moves one simple statement up or down past up to three others at
    the same indent."""
    lines = body.split("\n")

    def simple(i):
        m = SIMPLE.match(lines[i])
        return m and not CONTROL.match(lines[i]) and not re.match(r"^\s+[A-Za-z_][\w\s\*]*\s\**[A-Za-z_]\w*(\s*,\s*\**\w+)*;$",
                                                                    lines[i]) and m.group(1)
    runs, i = [], 1
    while i < len(lines):
        ind = simple(i)
        j = i
        while ind and j + 1 < len(lines) and simple(j + 1) == ind:
            j += 1
        if j - i >= 2:
            runs.append((i, j))
        i = j + 1
    if not runs:
        return None
    a, b = rng.choice(runs)
    i = rng.randint(a, b)
    k = min(b, max(a, i + rng.choice([-3, -2, 2, 3])))
    if k == i:
        return None
    line = lines.pop(i)
    lines.insert(k, line)
    return "\n".join(lines)


def default_case(body, rng):
    """Adds `default: break;` to a switch without a default, at its start
    or its end, or removes an empty one."""
    lines = body.split("\n")
    hits = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)switch \(.*\) \{$", line)
        if not m:
            continue
        ind = m.group(1)
        j = i + 1
        while j < len(lines) and lines[j] != ind + "}":
            if lines[j].strip() and not lines[j].startswith((ind + " ", ind + "case ", ind + "default:")):
                j = None
                break
            j += 1
        if j is None or j == len(lines):
            continue
        empty = [k for k in range(i + 1, j - 1) if lines[k] == ind + "default:" and lines[k + 1] == ind + "    break;"
                 and (lines[k + 2] == ind + "}" or lines[k + 2].startswith(ind + "case "))]
        if empty:
            hits.append(("del", empty[0], ind))
        elif not any(lines[k] == ind + "default:" for k in range(i + 1, j)):
            hits += [("add", j, ind), ("add", i + 1, ind)]
    if not hits:
        return None
    kind, k, ind = rng.choice(hits)
    if kind == "del":
        del lines[k:k + 2]
    else:
        lines[k:k] = [ind + "default:", ind + "    break;"]
    return "\n".join(lines)



# The rewrites below change the shape of statements and scopes, which
# moves registers and frame slots without changing what the function
# does: tools/docs/vc6-c2.md's "Quick levers for a red function". They
# read the function as formatted in src/ (one statement a line, K&R
# braces, four spaces an indent) through these helpers.


def indent(line):
    return len(line) - len(line.lstrip(" "))


def ident(name):
    """A pattern for `name` as a variable, not a field or a longer name."""
    return re.compile(r"(?<![\w.>])" + re.escape(name) + r"(?!\w)")


def blocks(lines):
    """(open, close) line pairs of every block that spans lines, by the
    braces outside string and character literals."""
    out, stack = [], []
    for i, line in enumerate(lines):
        for ch in re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', line):
            if ch == "{":
                stack.append(i)
            elif ch == "}" and stack:
                o = stack.pop()
                if o != i:
                    out.append((o, i))
    return sorted(out)


def body_block(lines, bl):
    """The function body's block."""
    return next(((o, c) for o, c in bl if lines[o] == "{"), bl[0] if bl else None)


def innermost(bl, at):
    """The innermost block holding every line of `at` strictly inside."""
    lo, hi = min(at), max(at)
    inside = [(o, c) for o, c in bl if o < lo and c > hi]
    return max(inside) if inside else None


def is_switch(line):
    return re.match(r"^\s*switch \(.*\) \{$", line) is not None


def is_label(line):
    return re.match(r"^\s*(case\b.*|default):(?: \{)?$", line) is not None


def units(lines, block):
    """The statements directly inside `block`, as (first, last) line
    pairs: a statement runs on over deeper lines and its own `} else`
    lines. Case labels and blank lines belong to none."""
    o, c = block
    inner = indent(lines[o]) + 4
    out, i = [], o + 1
    while i < c:
        line = lines[i]
        if not line.strip() or is_label(line) or indent(line) != inner:
            i += 1
            continue
        j = i
        while j + 1 < c:
            nxt = lines[j + 1]
            if nxt.strip() and indent(nxt) < inner:
                break
            if nxt.strip() and indent(nxt) == inner and not nxt.lstrip().startswith(("}", "else")):
                break
            if not nxt.strip() and lines[j].lstrip().startswith("}") and indent(lines[j]) == inner:
                break
            j += 1
        while not lines[j].strip():
            j -= 1
        out.append((i, j))
        i = j + 1
    return out


def unit_at(us, line):
    return next((k for k, (a, b) in enumerate(us) if a <= line <= b), None)


def arms(lines, block):
    """The arms of a switch block: (label line, first, last) with the
    statement lines each label heads, the last of a run of labels."""
    o, c = block
    ind = indent(lines[o])
    labels = [i for i in range(o + 1, c) if indent(lines[i]) == ind and is_label(lines[i])]
    out = []
    for k, i in enumerate(labels):
        end = labels[k + 1] - 1 if k + 1 < len(labels) else c - 1
        if end > i:
            out.append((i, i + 1, end))
    return out


KEYWORDS = {"return", "goto", "case", "else", "do", "break", "continue", "static", "typedef", "extern"}
DECLARATOR = re.compile(r"^(\**)\s*([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)$")
DECL_LINE = re.compile(r"^(\s+)((?:(?:const|unsigned|signed|register|struct|enum|volatile)\s+)*[A-Za-z_]\w*)\s+"
                       r"([^;=(){}]+);$")


def parse_decl(line):
    """(indent, base type, [(stars, name, array)]) of a declaration line,
    or None."""
    m = DECL_LINE.match(line)
    if not m or m[2].split()[0] in KEYWORDS:
        return None
    out = []
    for d in m[3].split(","):
        dm = DECLARATOR.match(d.strip())
        if not dm:
            return None
        out.append((dm[1], dm[2], dm[3]))
    return m[1], m[2], out


def render_decl(ind, base, decls):
    return f"{ind}{base} {', '.join(s + n + a for s, n, a in decls)};"


def block_decls(lines, block):
    """The declaration lines at the top of `block`."""
    out = []
    for i in range(block[0] + 1, block[1]):
        if parse_decl(lines[i]):
            out.append(i)
        elif lines[i].strip() or out:
            break
    return out


def declared(lines, bl):
    """{name: (decl line, block, (stars, name, array), base)} of the locals."""
    out = {}
    for b in bl:
        for i in block_decls(lines, b):
            ind, base, decls = parse_decl(lines[i])
            for d in decls:
                out.setdefault(d[1], (i, b, d, base))
    return out


def drop_names(lines, i, names):
    """Removes `names` from declaration line i; the edit as a list of
    replacement lines (empty when the line goes, with the blank line after
    a run of declarations that ends with it)."""
    ind, base, decls = parse_decl(lines[i])
    rest = [d for d in decls if d[1] not in names]
    if rest:
        return [render_decl(ind, base, rest)]
    return []


def apply_edits(lines, edits):
    """Applies (first, last, replacement lines) edits, last first; the
    ranges must not overlap. first > last inserts before first."""
    for a, b, new in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        lines[a:b + 1] = new
    return lines


def tidy(lines):
    """Drops a blank line left right after an opening brace or before a
    closing one, and doubled blank lines."""
    out = []
    for line in lines:
        if not line.strip() and out and (not out[-1].strip() or out[-1].endswith("{")):
            continue
        if line.lstrip().startswith("}") and out and not out[-1].strip():
            out.pop()
        out.append(line)
    return out


def add_top_decl(lines, bl, base, decl, rng=None):
    """Declares `decl` of type `base` at the top of the function body,
    joining a declaration line of the same type when rng says so."""
    top = body_block(lines, bl)
    at = block_decls(lines, top)
    same = [i for i in at if parse_decl(lines[i])[1] == base]
    if same and rng and rng.random() < 0.5:
        i = rng.choice(same)
        ind, b, decls = parse_decl(lines[i])
        lines[i] = render_decl(ind, b, decls + [decl])
        return lines
    new = render_decl(" " * (indent(lines[top[0]]) + 4), base, [decl])
    if at:
        k = rng.randint(at[0], at[-1] + 1) if rng else at[-1] + 1
        lines.insert(k, new)
    else:
        lines[top[0] + 1:top[0] + 1] = [new, ""]
    return lines


def fresh(body, stem):
    for n in [stem] + [f"{stem}{k}" for k in range(1, 99)]:
        if not ident(n).search(body):
            return n
    return None


def temp_types(natural=None):
    types = list(project.config["hooks"].get("permute_types") or ["int", "short", "unsigned int"])
    return ([natural] if natural and natural not in types else []) + types


def braceless_parent(lines, i):
    """The control line whose braceless body is line i, or None."""
    k = i - 1
    while k >= 0 and not lines[k].strip():
        k -= 1
    if k < 0 or indent(lines[k]) != indent(lines[i]) - 4:
        return None
    s = lines[k].strip()
    if s.endswith(("{", ";", "}", ":")) or not (re.match(r"^(\} )?(if|else|for|while)\b", s)):
        return None
    return k


def insert_before(lines, i, new):
    """Edits that put the lines `new` (unindented) before the statement at
    line i, at its indent, with braces when i is a braceless body."""
    ind = " " * indent(lines[i])
    k = braceless_parent(lines, i)
    if k is None:
        return [(i, i - 1, [ind + l if l else l for l in new])]
    end = i
    while end + 1 < len(lines) and lines[end + 1].strip() and indent(lines[end + 1]) > indent(lines[i]):
        end += 1
    outer = " " * indent(lines[k])
    return [(k, k, [lines[k] + " {"]), (i, i - 1, [ind + l if l else l for l in new]),
            (end + 1, end, [outer + "}"])]


def v1_split(body, rng):
    """Moves a pointer increment out of a for header to before each of the
    loop's continues and to the bottom of its body, or back (rule V1)."""
    lines = body.split("\n")
    bl = blocks(lines)
    loops = [b for b in bl if re.match(r"^\s*(for|while) \(.*\) \{$|^\s*do \{$", lines[b[0]])]
    step = r"[A-Za-z_]\w*(?:\+\+|--)|(?:\+\+|--)[A-Za-z_]\w*|[A-Za-z_]\w* [-+]= \w+"

    def own(o, c):
        out = []
        for k in range(o + 1, c):
            if lines[k].strip() == "continue;":
                inner = max((b for b in loops if b[0] < k < b[1]), default=None)
                if inner == (o, c):
                    out.append(k)
        return out
    hits = []
    for o, c in loops:
        m = re.match(r"^(\s*)for \(([^;]*); ([^;]*); (.*)\) \{$", lines[o])
        if not m:
            continue
        steps = [s.strip() for s in m[4].split(",")] if m[4].strip() else []
        conts = own(o, c)
        for k, s in enumerate(steps):
            if re.fullmatch(step, s):
                hits.append(("split", o, c, m, steps, k, conts))
        last = lines[c - 1].strip()
        if re.fullmatch(f"(?:{step});", last) and indent(lines[c - 1]) == indent(lines[o]) + 4 \
                and all(lines[k - 1].strip() == last for k in conts):
            hits.append(("join", o, c, m, steps, last, conts))
    if not hits:
        return None
    kind, o, c, m, steps, k, conts = rng.choice(hits)
    edits = []
    if kind == "split":
        s = steps[k]
        rest = steps[:k] + steps[k + 1:]
        edits.append((o, o, [f"{m[1]}for ({m[2]}; {m[3]}; {', '.join(rest)}) {{"]))
        for n in conts:
            edits += insert_before(lines, n, [s + ";"])
        if lines[c - 1].strip() != "continue;":
            edits.append((c, c - 1, [" " * (indent(lines[o]) + 4) + s + ";"]))
    else:
        s = k[:-1]
        edits.append((o, o, [f"{m[1]}for ({m[2]}; {m[3]}; {', '.join(steps + [s])}) {{"]))
        edits.append((c - 1, c - 1, []))
        for n in conts:
            p = n - 1
            opener, closer = p - 1, n + 1
            if lines[opener].endswith(" {") and re.match(r"^\s*(if|\} else)\b", lines[opener]) \
                    and lines[closer].strip() == "}" and indent(lines[closer]) == indent(lines[opener]):
                edits += [(opener, opener, [lines[opener][:-2]]), (p, p, []), (closer, closer, [])]
            else:
                edits.append((p, p, []))
    return "\n".join(apply_edits(lines, edits))


def regions(lines, block, name):
    """The runs of `block`'s statements that use `name`, as lists of line
    numbers of its uses, split where a statement assigns it afresh
    (`name = e;` without name in e) or, in a switch, by arm."""
    pat = ident(name)
    if is_switch(lines[block[0]]):
        out = []
        for _, a, b in arms(lines, block):
            at = [i for i in range(a, b + 1) if pat.search(lines[i]) and not parse_decl(lines[i])]
            if at:
                out.append(at)
        return out
    us = units(lines, block)
    out, cur = [], None
    for k, (a, b) in enumerate(us):
        at = [i for i in range(a, b + 1) if pat.search(lines[i]) and not parse_decl(lines[i])]
        if not at:
            continue
        m = re.match(r"^\s*" + re.escape(name) + r" = (.*);$", lines[a])
        kill = a == b and m and not pat.search(m[1])
        if cur is None or kill:
            cur = []
            out.append(cur)
        cur.extend(at)
    return out


def scope_local(body, rng):
    """Moves local declarations into the innermost block that holds their
    uses, a copy into each run of statements (or switch arm) that sets
    them afresh, wrapping the run in a block when none holds it; or moves
    a block's declaration up to the function's, merging the copies and
    dropping a bare block left without declarations."""
    lines = body.split("\n")
    bl = blocks(lines)
    if not bl:
        return None
    top = body_block(lines, bl)
    decl = declared(lines, bl)
    sink = rng.random() < 0.6
    for attempt in (sink, not sink):
        new = (scope_in if attempt else scope_out)(lines, bl, top, decl, rng)
        if new:
            return "\n".join(tidy(new))
    return None


def scope_in(lines, bl, top, decl, rng):
    cands = []
    for name, (i, b, d, base) in decl.items():
        at = [k for k in range(b[0] + 1, b[1]) if k != i and ident(name).search(lines[k])]
        if not at:
            continue
        inner = innermost(bl, at)
        regs = regions(lines, inner, name)
        if inner != b or len(regs) > 1:
            cands.append((name, inner, regs))
    if not cands:
        return None
    name, inner, regs = rng.choice(cands)
    i, b, d, base = decl[name]
    group = {name: (d, base)}
    spans = [[min(r), max(r)] for r in regs]
    if rng.random() < 0.7:
        changed = True
        while changed:
            changed = False
            for other, (j, ob, od, obase) in decl.items():
                if other in group or ob != b:
                    continue
                at = [k for k in range(b[0] + 1, b[1]) if k != j and ident(other).search(lines[k])]
                if not at or innermost(bl, at) != inner:
                    continue
                oregs = [[min(r), max(r)] for r in regions(lines, inner, other)]
                if rng.random() < (0.7 if len(oregs) < 2 else 0.4):
                    continue
                if all(any(r[0] <= s[1] and s[0] <= r[1] for s in spans) for r in oregs):
                    group[other] = (od, obase)
                    for r in oregs:
                        for s in spans:
                            if r[0] <= s[1] and s[0] <= r[1]:
                                s[0], s[1] = min(s[0], r[0]), max(s[1], r[1])
                    changed = True
            merged = []
            for s in sorted(spans):
                if merged and s[0] <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], s[1])
                else:
                    merged.append(s)
            spans = merged
    pats = {n: ident(n) for n in group}
    edits = []
    us = units(lines, inner)
    switch = is_switch(lines[inner[0]])
    for lo, hi in spans:
        used = [n for n in group if any(pats[n].search(lines[k]) for k in range(lo, hi + 1))]
        at = [k for k in range(lo, hi + 1) if any(pats[n].search(lines[k]) for n in used)]
        by_type = {}
        for n in sorted(used, key=lambda n: (decl[n][0], [x[1] for x in parse_decl(lines[decl[n][0]])[2]].index(n))):
            by_type.setdefault(group[n][1], []).append(group[n][0])
        new = [render_decl("", t, ds) for t, ds in by_type.items()]
        if rng.random() < 0.5:
            new.reverse()
        if switch:
            arm = next(a for a in arms(lines, inner) if a[1] <= lo <= a[2])
            first, last = arm[1], arm[2]
        else:
            ua, ub = unit_at(us, lo), unit_at(us, hi)
            if ua is None or ub is None:
                return None
            first, last = us[ua][0], us[ub][1]
        holder = innermost([x for x in bl if x[0] >= first and x[1] <= last], at)
        if holder is None and len(spans) == 1 and inner != decl[name][1] and not switch:
            holder = inner
        if holder is not None:
            ind = " " * (indent(lines[holder[0]]) + 4)
            ds = block_decls(lines, holder)
            k = ds[-1] + 1 if ds else holder[0] + 1
            edits.append((k, k - 1, [ind + l for l in new] + ([] if ds else [""])))
        elif switch:
            label = arm[0]
            while last > first and not lines[last].strip():
                last -= 1
            ind = " " * (indent(lines[label]) + 4)
            edits.append((label, label, [lines[label] + " {"] + [ind + l for l in new] + [""]))
            edits.append((last + 1, last, [" " * indent(lines[label]) + "}"]))
        else:
            ind = " " * indent(lines[first])
            moved = [("    " + l if l.strip() else l) for l in lines[first:last + 1]]
            edits.append((first, last, [ind + "{"] + [ind + "    " + l for l in new] + [""] + moved + [ind + "}"]))
    by_line = {}
    for n in group:
        by_line.setdefault(decl[n][0], set()).add(n)
    for j, names in by_line.items():
        edits.append((j, j, drop_names(lines, j, names)))
    return apply_edits(list(lines), edits)


def scope_out(lines, bl, top, decl, rng):
    cands = []
    for b in bl:
        if b == top:
            continue
        for i in block_decls(lines, b):
            for d in parse_decl(lines[i])[2]:
                cands.append((i, b, d))
    if not cands:
        return None
    i, b, d = rng.choice(cands)
    base = parse_decl(lines[i])[1]
    names = [x[1] for x in parse_decl(lines[i])[2]] if rng.random() < 0.5 else [d[1]]
    for j in block_decls(lines, top):
        if any(x[1] in names for x in parse_decl(lines[j])[2]):
            return None
    edits = []
    for bb in bl:
        if bb == top:
            continue
        ds = block_decls(lines, bb)
        left = 0
        for j in ds:
            _, bbase, xs = parse_decl(lines[j])
            drop = {x[1] for x in xs if x[1] in names and bbase == base}
            new = drop_names(lines, j, drop) if drop else [lines[j]]
            left += bool(new)
            if drop:
                edits.append((j, j, new))
        if not ds or left or len(edits) == 0 or not any(e[0] in ds for e in edits):
            continue
        o, c = bb
        after = ds[-1] + 1
        if after < c and not lines[after].strip():
            edits.append((after, after, []))
        if lines[o].strip() == "{":
            edits.append((o, o, []))
            edits.append((c, c, []))
            touched = {e[0] for e in edits}
            for k in range(o + 1, c):
                if k not in touched and k != after and lines[k].startswith("    "):
                    edits.append((k, k, [lines[k][4:]]))
        elif is_label(lines[o]) and lines[o].endswith(": {"):
            edits.append((o, o, [lines[o][:-2]]))
            edits.append((c, c, []))
    lines = apply_edits(list(lines), edits)
    by = {x[1]: x for x in decl_names(cands, names)}
    for n in names:
        lines = add_top_decl(lines, blocks(lines), base, by[n], rng)
    return lines


def decl_names(cands, names):
    out, seen = [], set()
    for _, _, d in cands:
        if d[1] in names and d[1] not in seen:
            seen.add(d[1])
            out.append(d)
    return out


def call_args(line):
    """(start, end) offsets of every argument of every call in `line`."""
    out = []
    for m in re.finditer(r"\b[A-Za-z_]\w*\(", line):
        if m.group(0)[:-1] in ("if", "while", "for", "switch", "return", "sizeof"):
            continue
        depth, k, start = 1, m.end(), m.end()
        args = []
        while k < len(line) and depth:
            ch = line[k]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
                if depth == 0:
                    args.append((start, k))
            elif ch == "," and depth == 1:
                args.append((start, k))
                start = k + 1
            k += 1
        for a, b in args:
            while a < b and line[a] == " ":
                a += 1
            if a < b:
                out.append((a, b))
    return out


def top_ternary(text):
    """(c, a, b) when `text` is `c ? a : b` at its own top level."""
    depth, q, colon = 0, None, None
    for k, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch == "?":
            if q is not None:
                return None
            q = k
        elif depth == 0 and ch == ":" and q is not None and colon is None:
            colon = k
    if q is None or colon is None:
        return None
    c, a, b = text[:q].strip(), text[q + 1:colon].strip(), text[colon + 1:].strip()
    if c.startswith("(") and c.endswith(")") and top_ternary(c[1:-1]) is None and c.count("(") == 1:
        c = c[1:-1]
    return c, a, b


def select_form(body, rng):
    """Writes a ternary call argument `f(.., c ? a : b)` as
    `if (c) t = a; else t = b;` into a new local before the call, or
    back."""
    lines = body.split("\n")
    bl = blocks(lines)
    hits = []
    for i, line in enumerate(lines):
        if not SIMPLE.match(line) or CONTROL.match(line):
            continue
        for a, b in call_args(line):
            t = top_ternary(line[a:b])
            if t:
                hits.append(("t", i, a, b, t))
    decl = declared(lines, bl)
    for i in range(len(lines) - 4):
        m = re.match(r"^(\s*)if \((.*)\)$", lines[i])
        if not m:
            continue
        ind = m[1]
        a = re.match("^" + ind + r"    ([A-Za-z_]\w*) = ([^;]+);$", lines[i + 1])
        if not a or lines[i + 2] != ind + "else" or a[1] not in decl:
            continue
        b = re.match("^" + ind + r"    " + a[1] + r" = ([^;]+);$", lines[i + 3])
        if not b:
            continue
        pat = ident(a[1])
        users = [k for k, l in enumerate(lines) if pat.search(l) and k not in (i + 1, i + 3, decl[a[1]][0])]
        if users == [i + 4] and len(pat.findall(lines[i + 4])) == 1:
            hits.append(("i", i, a[1], (m[2], a[2], b[1])))
    if not hits:
        return None
    hit = rng.choice(hits)
    if hit[0] == "t":
        _, i, a, b, (c, x, y) = hit
        name = fresh(body, rng.choice(["t", "sel", "v"]))
        natural = None
        typ = rng.choice(temp_types(natural))
        line = lines[i]
        lines[i] = line[:a] + name + line[b:]
        new = [f"if ({c})", f"    {name} = {x};", "else", f"    {name} = {y};"]
        lines = apply_edits(lines, insert_before(lines, i, new))
        return "\n".join(add_top_decl(lines, blocks(lines), typ, ("", name, ""), rng))
    _, i, name, (c, x, y) = hit
    use = lines[i + 4]
    m = ident(name).search(use)
    inner = f"{c} ? {x} : {y}"
    in_args = any(a == m.start() and b == m.end() for a, b in call_args(use))
    lines[i + 4] = use[:m.start()] + (inner if in_args else f"({inner})") + use[m.end():]
    j = decl[name][0]
    del lines[i:i + 4]
    lines[j:j + 1] = drop_names(lines, j, {name})
    lines = unwrap_single(lines)
    return "\n".join(tidy(lines))


def unwrap_single(lines):
    """Drops the braces of an `if (...) {` block left holding one
    one-line statement, when no else follows."""
    for o, c in reversed(blocks(lines)):
        if c - o == 2 and re.match(r"^\s*(if|for|while) \(.*\) \{$", lines[o]) and lines[c].strip() == "}" \
                and SIMPLE.match(lines[o + 1]) and not parse_decl(lines[o + 1]) and \
                not (c + 1 < len(lines) and lines[c + 1].strip().startswith("else")):
            lines[o:c + 1] = [lines[o][:-2], lines[o + 1]]
    return lines


def written_names(text):
    return set(re.findall(r"(?<![\w.>])([A-Za-z_]\w*)\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)", text)) | \
        set(re.findall(r"(?<![\w.>])([A-Za-z_]\w*)\s*(?:\+\+|--)", text)) | \
        set(re.findall(r"(?:\+\+|--)\s*([A-Za-z_]\w*)", text))


def names_in(expr):
    return set(re.findall(r"(?<![\w.>])([A-Za-z_]\w*)(?!\w)(?!\s*\()", expr))


def top_terms(expr):
    """Spans of the terms of `expr` split at its top-level binary + and -,
    each with the span inside the parentheses around a whole term."""
    spans, depth, start = [], 0, 0
    for k, ch in enumerate(expr):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch in "+-" and depth == 0 and k > 0 and expr[k - 1] == " " and expr[k + 1:k + 2] == " ":
            spans.append((start, k))
            start = k + 1
    spans.append((start, len(expr)))
    out = []
    for c, d in spans:
        while c < d and expr[c] == " ":
            c += 1
        while d > c and expr[d - 1] == " ":
            d -= 1
        inner = (c + 1, d - 1) if expr[c:c + 1] == "(" and expr[d - 1:d] == ")" and balanced(expr[c + 1:d - 1]) \
            else (c, d)
        out.append((c, d) + inner)
    return out if len(out) > 1 else []


def balanced(text):
    depth = 0
    for ch in text:
        depth += ch in "(["
        depth -= ch in ")]"
        if depth < 0:
            return False
    return depth == 0


def named_temp(body, rng):
    """Hoists a call argument used more than once (or holding a call) in a
    run of statements into a new local, set before the first of them or
    as early as its operands allow; or the call-free term of an argument
    that holds a call (`(-f >> 10) - (rand() & 1) + 16`), which retail
    then evaluates before the argument pushes."""
    lines = body.split("\n")
    bl = blocks(lines)
    decl = declared(lines, bl)
    groups, terms = {}, set()
    for i, line in enumerate(lines):
        if not SIMPLE.match(line) or line.lstrip().startswith(("return", "case", "else")):
            continue
        for a, b in call_args(line):
            arg = line[a:b]
            neg = arg.startswith("-") and not re.match(r"-\s*\d+$", arg)
            expr = arg[1:] if neg else arg
            if re.fullmatch(OPERAND, expr) or top_ternary(expr) or expr.startswith(("&", '"')) or '"' in expr \
                    or "=" in expr.replace("==", "").replace("<=", "").replace(">=", "").replace("!=", ""):
                continue
            groups.setdefault(expr, []).append((i, a, b, neg))
            if not neg and CALL.search(expr):
                for c, d, e, f in top_terms(expr):
                    term = expr[e:f]
                    if not CALL.search(term) and not re.fullmatch(OPERAND, term) \
                            and not re.fullmatch(r"\(?\s*-?\s*\d+\s*\)?", term):
                        groups.setdefault(term, []).append((i, a + c, a + d, False))
                        terms.add(term)
    cands = [(e, occ) for e, occ in groups.items() if len(occ) > 1 or CALL.search(e) or e in terms]
    if not cands:
        return None
    expr, occ = rng.choice(cands)
    at = sorted({o[0] for o in occ})
    block = innermost(bl, at)
    if block is None:
        return None
    us = units(lines, block)
    if any(unit_at(us, k) is None for k in at):
        return None
    first = unit_at(us, at[0])
    ops = names_in(expr)
    pure = not CALL.search(expr) and all(n in decl for n in ops)
    if CALL.search(expr) and any(us[unit_at(us, k)][0] != k for k in at):
        return None
    k = first
    if pure:
        while k > 0:
            a, b = us[k - 1]
            text = "\n".join(lines[a:b + 1])
            if ops & written_names(text) or any(parse_decl(lines[x]) for x in range(a, b + 1)):
                break
            k -= 1
        k = rng.randint(k, first)
    natural = next((decl[n][3] for n in ops if n in decl and not decl[n][2][0] and not decl[n][2][2]), None)
    typ = rng.choice(temp_types(natural))
    name = fresh(body, rng.choice(["t", "tmp", "val"]))
    at_line = us[k][0]
    if k == first and at[0] != us[first][0] and rng.random() < 0.5:
        at_line = at[0]
    for i, a, b, neg in sorted(occ, reverse=True):
        lines[i] = lines[i][:a] + ("-" if neg else "") + name + lines[i][b:]
    lines = apply_edits(lines, insert_before(lines, at_line, [f"{name} = {expr};"]))
    return "\n".join(add_top_decl(lines, blocks(lines), typ, ("", name, ""), rng))


def cache_vs_respell(body, rng):
    """Writes each use of a local that is set once and only read as its
    initializer (`r->x` as `room[n].x` for `r = &room[n];`), or caches a
    repeated `a[i]` in a new pointer local."""
    lines = body.split("\n")
    bl = blocks(lines)
    decl = declared(lines, bl)
    hits = []
    for name, (j, b, d, base) in decl.items():
        pat = ident(name)
        uses = [k for k in range(b[0] + 1, b[1]) if k != j and pat.search(lines[k])]
        sets = [k for k in uses if re.match(r"^\s*" + re.escape(name) + r" = [^;]+;$", lines[k])]
        if len(sets) != 1 or d[2] or re.search(r"(?<!&)&\s*" + re.escape(name) + r"\b", body) or name in written_names(
                "\n".join(lines[k] for k in uses if k != sets[0])):
            continue
        s = sets[0]
        expr = lines[s].split(" = ", 1)[1][:-1]
        home = innermost(bl, [s])
        if CALL.search(expr) or braceless_parent(lines, s) is not None or \
                not all(k > s and home[0] < k < home[1] for k in uses if k != s):
            continue
        rest = [k for k in uses if k != s]
        if not rest or names_in(expr) & written_names("\n".join(lines[s + 1:max(rest) + 1])):
            continue
        hits.append(("respell", name, j, s, expr, rest))
    found = {}
    for k, line in enumerate(lines):
        for m in re.finditer(r"(?<![\w.>])(&?)([A-Za-z_]\w*)\[([^\[\]]+)\]((?:\.|->)?)", line):
            if m[1] or m[4] == ".":
                found.setdefault((m[2], m[3]), []).append(k)
    for (arr, idx), at in found.items():
        if len(at) > 1 and not CALL.search(idx):
            hits.append(("cache", arr, idx, at))
    if not hits:
        return None
    hit = rng.choice(hits)
    if hit[0] == "respell":
        _, name, j, s, expr, rest = hit
        amp = re.fullmatch(r"&(" + LVALUE + r")", expr)
        simple = re.fullmatch(OPERAND, expr)
        for k in rest:
            line = lines[k]
            if amp:
                line = re.sub(r"(?<![\w.>])" + re.escape(name) + r"->", lambda _: amp[1] + ".", line)
            line = ident(name).sub(lambda _: expr if simple or amp else f"({expr})", line)
            lines[k] = line
        return "\n".join(tidy(apply_edits(lines, [(s, s, []), (j, j, drop_names(lines, j, {name}))])))
    _, arr, idx, at = hit
    typ = element_type(arr, decl)
    if not typ or names_in(idx) & written_names("\n".join(lines[at[0]:at[-1] + 1])):
        return None
    block = innermost(bl, at)
    if block is None:
        return None
    us = units(lines, block)
    first = unit_at(us, at[0])
    if first is None:
        return None
    name = fresh(body, typ[0].lower() if typ[0].isalpha() else "p")
    spelled = re.compile(r"(?<![\w.>])(&?)" + re.escape(arr) + r"\[" + re.escape(idx) + r"\](\.)?")
    for k in at:
        lines[k] = spelled.sub(lambda m: name if m[1] else (name + "->" if m[2] else "*" + name), lines[k])
    lines = apply_edits(lines, insert_before(lines, us[first][0], [f"{name} = &{arr}[{idx}];"]))
    return "\n".join(add_top_decl(lines, blocks(lines), typ, ("*", name, ""), rng))


ELEMENT_TYPES = {}


def element_type(name, decl):
    """The type of `name`'s elements: a local's, or a global's from the
    declarations in src/'s files."""
    if name in decl:
        _, _, d, base = decl[name]
        if d[0] == "*" and not d[2] or d[2] and not d[0]:
            return base
        return None
    if not ELEMENT_TYPES:
        import glob
        pat = re.compile(r"(?m)^(?:extern\s+)?(?:struct\s+)?([A-Za-z_]\w*)\s+(\*?)\s*([A-Za-z_]\w*)\s*"
                         r"(\[[^\]]*\])?\s*[;=]")
        for path in glob.glob(os.path.join(ROOT, "src", "**", "*.[ch]"), recursive=True):
            for m in pat.finditer(open(path, encoding="utf-8", errors="replace").read()):
                if bool(m[2]) != bool(m[4]) and m[1] not in KEYWORDS:
                    ELEMENT_TYPES.setdefault(m[3], m[1])
        ELEMENT_TYPES.setdefault("\0", None)
    return ELEMENT_TYPES.get(name)


STORE = re.compile(r"^(\s+)(" + LVALUE + r") = ([^;]+);$")


def store_runs(body):
    """Runs (first, last) of consecutive stores to fields of one base (or
    to plain variables) whose values read none of the run's targets and
    call nothing."""
    lines = body.split("\n")
    out, i = [], 0

    def base(lv):
        m = re.match(r"^(.*?)(?:\.|->|\[)[^.\[>]*$", lv)
        return m[1] if m else ""

    while i < len(lines):
        m = STORE.match(lines[i])
        prev = lines[i - 1].strip() if i else "{"
        if not m or CALL.search(m[3]) or not (prev.endswith((";", "{", "}")) or is_label(lines[i - 1])):
            i += 1
            continue
        run, targets = [i], [m[2]]
        j = i + 1
        while j < len(lines):
            n = STORE.match(lines[j])
            if not n or n[1] != m[1] or CALL.search(n[3]) or base(n[2]) != base(m[2]) or n[2] in targets:
                break
            vals = [STORE.match(lines[k])[3] for k in run] + [n[3]]
            if any(mentions(t, v) for t in targets + [n[2]] for v in vals):
                break
            run.append(j)
            targets.append(n[2])
            j += 1
        if len(run) > 1:
            out.append((run[0], run[-1]))
        i = j
    return out


def store_run_permute(body, rng):
    """Reorders one run of independent stores (store_runs): shuffles,
    reverses or swaps two of them."""
    runs = store_runs(body)
    if not runs:
        return None
    a, b = rng.choice(runs)
    lines = body.split("\n")
    part = lines[a:b + 1]
    r = rng.random()
    if r < 0.4:
        rng.shuffle(part)
    elif r < 0.6:
        part.reverse()
    else:
        i, j = rng.sample(range(len(part)), 2)
        part[i], part[j] = part[j], part[i]
    if part == lines[a:b + 1]:
        return None
    lines[a:b + 1] = part
    return "\n".join(lines)


def zero_memset(body, rng):
    """Turns two to four consecutive `L = 0;` stores to fields of one base
    (a run of store_runs) into one `memset(&L1, 0, sizeof(L1) + ...);`.
    c2 expands a constant memset late: its stores share one alias tag, so
    the first gets a memory edge to the next, which moves the stores (and
    a pending `add esp`) in the schedule. The result only means the same
    when the fields are adjacent; a byte match proves it."""
    lines = body.split("\n")
    cands = []
    for a, b in store_runs(body):
        i = a
        while i <= b:
            j = i
            while j <= b and STORE.match(lines[j])[3].strip() == "0":
                j += 1
            if j - i >= 2:
                cands.append((i, j))
            i = j + 1
    if not cands:
        return None
    i, j = rng.choice(cands)
    n = rng.randint(2, min(4, j - i))
    k = rng.randint(i, j - n)
    run = [STORE.match(lines[x]) for x in range(k, k + n)]
    first = run[0][2]
    m = re.match(r"^\*\s*\([^()]*\*\s*\)\s*&(.+)$", first)
    addr = "&" + m[1] if m else "&" + first
    size = " + ".join(f"sizeof({r[2]})" for r in run)
    lines[k:k + n] = [f"{run[0][1]}memset({addr}, 0, {size});"]
    return "\n".join(lines)


def store_orders(body, limit):
    """Every order of each run of store_runs, up to `limit` a run."""
    import itertools
    out = []
    lines = body.split("\n")
    for a, b in store_runs(body):
        part = lines[a:b + 1]
        for k, perm in enumerate(itertools.permutations(part)):
            if k > limit:
                break
            if list(perm) != part:
                out.append("\n".join(lines[:a] + list(perm) + lines[b + 1:]))
    return out


def hoist_init(body, rng):
    """Moves `x = constant;` above an early exit (`if (...) return ...;`)
    before it that doesn't mention x, or back below one."""
    lines = body.split("\n")
    bl = blocks(lines)
    hits = []
    const = r"-?(?:0x[0-9A-Fa-f]+|\d+)|[A-Z_][A-Z0-9_]*"
    for b in bl:
        us = units(lines, b)
        for k, (a, e) in enumerate(us):
            m = re.match(r"^\s*([A-Za-z_]\w*) = (" + const + r");$", lines[a])
            if a != e or not m:
                continue
            pat = ident(m[1])

            def exit_(u):
                text = "\n".join(lines[u[0]:u[1] + 1])
                return lines[u[0]].lstrip().startswith("if (") and re.search(r"\breturn\b", text) \
                    and not pat.search(text)
            if k > 0 and exit_(us[k - 1]) and us[k - 1][1] == a - 1:
                hits.append(("up", us[k - 1], a))
            if k + 1 < len(us) and exit_(us[k + 1]) and us[k + 1][0] == a + 1:
                hits.append(("down", us[k + 1], a))
    if not hits:
        return None
    kind, (s, e), a = rng.choice(hits)
    line = lines[a]
    if kind == "up":
        lines[s:a + 1] = [line] + lines[s:a]
    else:
        lines[a:e + 1] = lines[a + 1:e + 1] + [line]
    return "\n".join(lines)


def if_chains(lines, bl):
    """if/else-if/else chains of braced arms: (first, last, [(open,
    close)], has a final else)."""
    out = []
    by_open = {o: c for o, c in bl}
    for o, c in bl:
        if not re.match(r"^\s*if \(.*\) \{$", lines[o]) or (o > 0 and lines[o].lstrip().startswith("}")):
            continue
        chain = [(o, c)]
        while lines[chain[-1][1]].strip() != "}" and chain[-1][1] in by_open:
            nxt = chain[-1][1]
            if not re.match(r"^\s*\} else(?: if \(.*\))? \{$", lines[nxt]):
                break
            chain.append((nxt, by_open[nxt]))
        if lines[chain[-1][1]].strip() != "}":
            continue
        final = re.match(r"^\s*\} else \{$", lines[chain[-1][0]]) is not None
        out.append((o, chain[-1][1], chain, final))
    return out


JUMP = re.compile(r"^\s*(return\b|break;|continue;|goto\b)")


def arm_returns(body, rng):
    """Moves the statements after an if/else chain (up to a return) to the
    end of each of its arms, or the statements every arm ends with to
    after the chain."""
    lines = body.split("\n")
    bl = blocks(lines)
    hits = []
    for first, last, chain, final in if_chains(lines, bl):
        if not final:
            continue
        outer = innermost(bl, [first])
        if outer is None:
            continue
        us = units(lines, outer)
        k = unit_at(us, first)
        if k is None:
            continue
        tail = []
        for a, e in us[k + 1:]:
            if a != e or not SIMPLE.match(lines[a]) or parse_decl(lines[a]):
                break
            tail.append(a)
            if JUMP.match(lines[a]):
                break
        if tail:
            hits.append(("in", chain, tail))
        ends = []
        for o, c in chain:
            tail = []
            for a, e in reversed(units(lines, (o, c))):
                if a != e:
                    break
                tail.insert(0, lines[a].strip())
            ends.append(tail)
        common = 0
        while all(len(e) > common for e in ends) and len({e[-1 - common] for e in ends}) == 1 \
                and SIMPLE.match(" " + ends[0][-1 - common]):
            common += 1
        if common:
            hits.append(("out", chain, common))
    if not hits:
        return None
    kind, chain, arg = rng.choice(hits)
    edits = []
    if kind == "in":
        m = rng.randint(1, len(arg))
        moved = [lines[a].strip() for a in arg[:m]]
        for o, c in chain:
            aus = units(lines, (o, c))
            if aus and JUMP.match(lines[aus[-1][0]]):
                continue
            ind = " " * (indent(lines[o]) + 4)
            edits.append((c, c - 1, [ind + s for s in moved]))
        if not edits:
            return None
        edits.append((arg[0], arg[m - 1], []))
    else:
        m = rng.randint(1, arg)
        moved = None
        for o, c in chain:
            aus = units(lines, (o, c))
            gone = [a for a, e in aus[-m:]]
            moved = [lines[a].strip() for a in gone]
            edits.append((gone[0], gone[-1], []))
        ind = " " * indent(lines[chain[0][0]])
        end = chain[-1][1]
        edits.append((end + 1, end, [ind + s for s in moved]))
    return "\n".join(tidy(apply_edits(lines, edits)))


TOP_DECL = re.compile(r"^(?!\}|#|typedef struct|struct |union |enum )[A-Za-z_][^\n{}]*;$")


def lift(line, cpp):
    """`line`, taken out of an extern "C" block, as a top-level line."""
    if cpp and not line.startswith('extern "C"'):
        return 'extern "C" ' + line
    return line


def top_lines(text):
    """(index, line, in extern "C" block) of the top-level declaration
    lines in text.split("\\n")."""
    out, depth, extern_block = [], 0, False
    for i, line in enumerate(text.split("\n")):
        top = depth == 0 or (depth == 1 and extern_block)
        if top and TOP_DECL.match(line):
            out.append((i, line, depth == 1))
        if depth == 0:
            extern_block = line.startswith('extern "C" {')
        depth += line.count("{") - line.count("}")
    return out


def unnamed(line):
    """A prototype line with its parameter names dropped, or None."""
    m = re.match(r"^(.*\()(.*)(\)\s*;)$", line)
    if not m or "(" in m[2] or not m[2].strip() or m[2].strip() == "void":
        return None
    params = []
    for p in m[2].split(","):
        q = re.match(r"^(.*?[\s*&])([A-Za-z_]\w*)(\s*\[[^\]]*\])?\s*$", p.strip())
        if not q or not q[1].strip():
            return None
        params.append(q[1].rstrip() + (q[3] or "").strip())
    new = m[1] + ", ".join(params) + m[3]
    return None if new == line else new


def pad_moves(variant, cpp):
    """Every real change of the number of declarations before the
    function: (description, variant)."""
    before, body, after = variant
    out = []
    blines, alines = before.split("\n"), after.split("\n")
    for i, line, inside in top_lines(before):
        rest = blines[:i] + blines[i + 1:]
        moved = lift(line, cpp) if inside else line
        out.append((f"move below: {line}", ("\n".join(rest), body, after[:1] + moved + "\n" + after[1:]
                                            if after.startswith("\n") else "\n" + moved + "\n" + after)))
        new = unnamed(line)
        if new:
            out.append((f"drop the names: {line}", ("\n".join(blines[:i] + [new] + blines[i + 1:]), body, after)))
    for i, line, inside in top_lines(after):
        rest = alines[:i] + alines[i + 1:]
        moved = lift(line, cpp) if inside else line
        out.append((f"move above: {line}", (before + moved + "\n", body, "\n".join(rest))))
    return out


def pad(s, base, limit, jobs):
    """--pad: the variant that matches, or None."""
    cpp = s.src.lower().endswith((".cpp", ".cc", ".cxx"))
    before, body, after = base
    pads = [(before + "".join(f"extern int Pad{i};\n" for i in range(n)), body, after) for n in range(limit)]
    with ThreadPoolExecutor(jobs) as pool:
        scores = list(pool.map(s.score, pads))
    hits = [n for n, sc in enumerate(scores) if sc is not None and sc % 1000 == 0]
    print("shifts: " + " ".join(f"{n}:{'-' if sc is None else sc % 1000}" for n, sc in enumerate(scores)), flush=True)
    if not hits:
        print("no shift of the symbol IDs makes it match", flush=True)
        ranked = sorted((sc % 1000, n) for n, sc in enumerate(scores) if sc is not None)[:3]
        for sc, n in ranked:
            orders = declaration_orders(body, 3000, random.Random(n))[1:]
            print(f"with {n} more declarations (score {sc}): {len(orders)} local declaration orders", flush=True)
            cands = [(pads[n][0], b, after) for b in orders]
            with ThreadPoolExecutor(jobs) as pool:
                for cand, got in zip(cands, pool.map(s.score, cands)):
                    if got is not None and got % 1000 == 0:
                        print(f"MATCH with {n} more declarations before it and this local order:", flush=True)
                        sys.stdout.writelines(difflib.unified_diff(body.splitlines(True), cand[1].splitlines(True),
                                                                   "as written", "matching", n=0))
                        keep(s.name, (before, cand[1], after))
                        return None
        return None
    print(f"it matches with {', '.join(map(str, hits))} more declarations before it", flush=True)
    moves = pad_moves(base, cpp)
    print(f"{len(moves)} declaration changes to try", flush=True)
    with ThreadPoolExecutor(jobs) as pool:
        for (what, variant), sc in zip(moves, pool.map(lambda m: s.score(m[1]), moves)):
            if sc == 0:
                print(f"MATCH: {what}", flush=True)
                return variant
    print("no single declaration change does it")
    return None


def plan(src, text, limit, jobs):
    """--plan: prints how many declarations to add before each function
    in `src` to match the most of them."""
    rows = {r["name"] for r in compare_rows()}
    import reorder
    names = []
    for kind, item in reorder.items(text):
        n = reorder.fn_name(item) if kind == "fn" else None
        if n in rows and n not in names:
            names.append(n)
    hits = {}
    for name in names:
        try:
            _, t, start, end = find_function(name)
            s = Scorer(name, src, t, start, end)
        except (SystemExit, StopIteration, KeyError):
            continue
        before, body, after = s.variant(t[start:end])
        pads = [(before + "".join(f"extern int Pad{i};\n" for i in range(n)), body, after) for n in range(limit)]
        with ThreadPoolExecutor(jobs) as pool:
            scores = list(pool.map(s.score, pads))
        shutil.rmtree(s.tmp, ignore_errors=True)
        hits[name] = {n for n, sc in enumerate(scores) if sc is not None and sc % 1000 == 0}
        print(f"{name}: {' '.join(map(str, sorted(hits[name]))) or '-'}", flush=True)
    order = [n for n in names if n in hits]
    best = [[0] * limit for _ in order]
    for j, name in enumerate(order):
        run = 0
        for c in range(limit):
            if j:
                run = max(run, best[j - 1][c])
            best[j][c] = run + (c in hits[name])
    c = max(range(limit), key=lambda c: best[-1][c]) if order else 0
    chosen = []
    for j in range(len(order) - 1, -1, -1):
        chosen.append(c)
        if j:
            c = max(range(c + 1), key=lambda k: best[j - 1][k])
    chosen.reverse()
    now = sum(0 in hits[n] for n in order)
    print(f"as written {now} of {len(order)} match; with this plan {best[-1][chosen[-1]] if order else 0}:")
    prev = 0
    for name, c in zip(order, chosen):
        mark = "ok" if c in hits[name] else "--"
        print(f"  {mark} {name}: {c}" + (f"  (+{c - prev} before it)" if c != prev else ""))
        prev = c


def declaration_runs(text):
    """Runs of adjacent top-level declaration lines (externs and
    prototypes, also inside extern "C" blocks), as (first, last) line
    indices into text.split("\\n")."""
    lines, runs, first = text.split("\n"), [], None
    depth, extern_block = 0, False
    for i, line in enumerate(lines):
        top = depth == 0 or (depth == 1 and extern_block)
        if top and TOP_DECL.match(line):
            first = i if first is None else first
        else:
            if first is not None and i - first >= 2:
                runs.append((first, i - 1))
            first = None
        if depth == 0:
            extern_block = line.startswith('extern "C" {')
        depth += line.count("{") - line.count("}")
    if first is not None and len(lines) - first >= 2:
        runs.append((first, len(lines) - 1))
    return runs


def file_order(variant, rng):
    """Moves one top-level declaration line before or after the function
    to another place in its run of declarations."""
    before, body, after = variant
    sides = [(k, part, declaration_runs(part)) for k, part in ((0, before), (1, after))]
    sides = [x for x in sides if x[2]]
    if not sides:
        return None
    k, part, runs = rng.choice(sides)
    a, b = rng.choice(runs)
    lines = part.split("\n")
    i, j = rng.randint(a, b), rng.randint(a, b)
    if i == j:
        return None
    lines.insert(j, lines.pop(i))
    part = "\n".join(lines)
    return (part, body, after) if k == 0 else (before, body, part)


GLOBAL_REWRITES = {"reorder_declarations", "shuffle_declarations", "file_order"}


def changed_lines(old, new):
    """The range of lines of `new` that differ from `old`, by common prefix
    and suffix."""
    a, b = old.split("\n"), new.split("\n")
    p = 0
    while p < min(len(a), len(b)) and a[p] == b[p]:
        p += 1
    s = 0
    while s < min(len(a), len(b)) - p and a[-1 - s] == b[-1 - s]:
        s += 1
    return p, len(b) - s


def classify(old, new):
    """The kinds of rewrite that turn body `old` into `new`, roughly, by
    looking at the lines that differ."""
    a, b = old.split("\n"), new.split("\n")
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    kinds = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        gone, came = a[i1:i2], b[j1:j2]
        if any(l.strip() in {x.strip() for x in a} for l in came) and tag == "insert" or tag == "delete":
            kinds.add("move_statement")
        for x, y in zip(gone, came):
            if DECL.match(x) and DECL.match(y):
                kinds.add("reorder_declarations")
            elif sorted(re.findall(r"\w+|\S", x)) == sorted(re.findall(r"\w+|\S", y)):
                kinds.add("swap_logical" if "&&" in x or "||" in x else "swap_operands")
        text_gone, text_came = "\n".join(gone), "\n".join(came)
        for kind, pat in (("compound", r"[-+*&|^]= "), ("increment_form", r"\+\+|--|[-+]= 1;"),
                          ("condition_form", r"== 0|!= 0|\(!"), ("ternary_form", r" \? "),
                          ("loop_form", r"\b(?:for|while) \("), ("address_form", r"&\w+\["),
                          ("inline_return", r"\breturn\b"), ("default_case", r"default:"),
                          ("flip_if", r"\belse\b"), ("v1_split", r"\bcontinue;"),
                          ("arm_returns", r"\breturn\b"), ("select_form", r"\bif \("),
                          ("zero_memset", r"\bmemset\(")):
            if len(re.findall(pat, text_gone)) != len(re.findall(pat, text_came)):
                kinds.add(kind)
    if set(a) == set(b) and a != b and not kinds:
        kinds.add("swap_statements")
    return kinds


def load_stats(name):
    """Tries and wins per rewrite: build/permute/_prior.json, which farm.py
    --learn writes, then this function's own NAME.stats.json."""
    import json
    stats = {}
    for path in (os.path.join("build/permute", "_prior.json"), os.path.join(OUT, f"{name}.stats.json")):
        try:
            for k, (tries, wins) in json.load(open(path)).items():
                old = stats.get(k, [0, 0])
                stats[k] = [old[0] + tries, old[1] + wins]
        except (OSError, ValueError):
            pass
    return stats


def save_stats(name, stats, prior):
    import json
    own = {k: [v[0] - prior.get(k, [0, 0])[0], v[1] - prior.get(k, [0, 0])[1]] for k, v in stats.items()}
    os.makedirs(OUT, exist_ok=True)
    json.dump(own, open(os.path.join(OUT, f"{name}.stats.json"), "w"))


def weight(stats, kind):
    tries, wins = stats.get(kind, [0, 0])
    return 1 + 50 * wins / (tries + 50)


SWEEP_FORMS = ["condition_form", "increment_form", "ternary_form", "address_form", "compound", "inline_return",
               "flip_if", "swap_logical", "default_case", "loop_form", "move_statement", "swap_statements",
               "v1_split", "scope_local", "cache_vs_respell", "select_form", "named_temp", "store_run_permute",
               "hoist_init", "arm_returns", "zero_memset"]


def line_of(body, offset):
    return body.count("\n", 0, offset)


def sweep_dimensions(variant, hot, limit):
    """The neighbourhoods --sweep enumerates around `variant`, as
    (name, candidates): every order of the declarations, every place each
    top-level declaration before the function can move to in its run,
    every combination of swapped operands in the hot lines, and every
    single application of the other rewrites that touches them."""
    before, body, after = variant
    near = lambda lo, hi: not hot or any(lo <= n < max(hi, lo + 1) for n in hot)
    out = [("declaration orders", [(before, b, after) for b in declaration_orders(body, limit, random.Random(0))[1:]])]
    lines, moved = before.split("\n"), []
    for a, b in (declaration_runs(before)[-3:] if FILE_MODE[0] else []):
        for i in range(a, b + 1):
            for j in range(a, b + 1):
                if i != j:
                    copy = list(lines)
                    copy.insert(j, copy.pop(i))
                    moved.append(("\n".join(copy), body, after))
    out.append(("extern orders", moved[:limit]))
    hits = [m for m in operand_pattern().finditer(body) if near(line_of(body, m.start()), line_of(body, m.end()) + 1)]
    hits = hits[:12]
    combos = []
    for mask in range(1, 1 << len(hits)):
        text = body
        for k in reversed(range(len(hits))):
            if mask >> k & 1:
                m = hits[k]
                a, op, b = m.group(1), FLIPPED.get(m.group(2), m.group(2)), m.group(3)
                text = text[:m.start(1)] + f"{b} {op} {a}" + text[m.end(3):]
        combos.append((before, text, after))
    out.append((f"operand orders ({len(hits)} operators)", combos))
    stores = sorted(store_orders(body, 120), key=lambda b: not near(*changed_lines(body, b)))
    out.append(("store orders", [(before, b, after) for b in stores[:limit]]))
    forms, seen = [], {body}
    for name in SWEEP_FORMS:
        f = globals()[name]
        for seed in range(64):
            new = f(body, random.Random(seed))
            if new and new not in seen and near(*changed_lines(body, new)):
                seen.add(new)
                forms.append((before, new, after))
    out.append(("rewrites at the hot lines", forms))
    return out


def sweep(s, best, best_score, args, keep_best):
    """Beam search over sweep_dimensions until a whole pass finds nothing
    better: returns the best variant and score, and whether it got that
    far (`exhausted`) within the time."""
    beam, seen = [(best_score, best)], {"".join(best)}
    deadline = time.time() + args.t
    passes = 0
    with ThreadPoolExecutor(args.j) as pool:
        while best_score and time.time() < deadline:
            passes += 1
            better = False
            for score, variant in list(beam):
                hot = s.hot_lines(variant)
                hot |= {n + d for n in hot for d in (-1, 1)}
                for name, cands in sweep_dimensions(variant, hot, args.limit):
                    cands = [c for c in cands if "".join(c) not in seen]
                    seen.update("".join(c) for c in cands)
                    if not cands:
                        continue
                    print(f"  sweep {passes}: {name}, {len(cands)} variants from score {score}", flush=True)
                    done, step, mark = 0, args.j * 4, 0.25
                    for i in range(0, len(cands), step):
                        chunk = cands[i:i + step]
                        for c, sc in zip(chunk, pool.map(s.score, chunk)):
                            if sc is None:
                                continue
                            beam.append((sc, c))
                            if sc < best_score:
                                best, best_score, better = c, sc, True
                                print(f"  {len(seen):5d} tries: score {sc}", flush=True)
                                keep_best(best)
                        done += len(chunk)
                        if done / len(cands) >= mark and len(cands) >= 200:
                            print(f"    {done}/{len(cands)}", flush=True)
                            mark += 0.25
                        if not best_score or time.time() > deadline:
                            return best, best_score, False
                    beam = sorted(beam, key=lambda x: x[0])[:2]
            if not better:
                print(f"sweep exhausted after {passes} passes, {len(seen)} variants, best score {best_score}",
                      flush=True)
                return best, best_score, True
    return best, best_score, False


MUTATIONS = [swap_operands, swap_operands, reorder_declarations, shuffle_declarations, swap_statements,
             flip_if, swap_logical, compound, inline_return, condition_form, increment_form,
             ternary_form, loop_form, address_form, move_statement, default_case, v1_split, scope_local,
             cache_vs_respell, select_form, named_temp, store_run_permute, hoist_init, arm_returns,
             zero_memset]


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
        self.matched = None

    def variant(self, body):
        return (self.text[:self.start], body, self.text[self.end:])

    def compile(self, variant, extra=()):
        """Compiles `variant` alone; the object's path, or None (see
        self.why). The caller removes the object."""
        with self.lock:
            self.n += 1
            k = self.n
        rel = os.path.relpath(self.src, "src")
        conv = os.path.join(build.CONVERTED, os.path.dirname(rel), f"_perm{os.getpid()}_{k}_{os.path.basename(rel)}")
        obj = os.path.join(self.tmp, f"{k}.obj")
        text = "".join(variant)
        if build.CRLF:
            text = text.replace("\n", "\r\n")
        with open(conv, "wb") as f:
            f.write(build.encode(text))
        try:
            code, out = build.run_tool("cl", "/c", *self.flags, *extra, "/I" + build.win(build.CONVERTED),
                                     "/Fo" + build.win(obj), build.win(conv))
        finally:
            os.remove(conv)
        if code or not os.path.exists(obj):
            self.why = "cl failed:\n" + "\n".join(l for l in out.splitlines() if "error" in l)[:1500]
            if os.path.exists(obj):
                os.remove(obj)
            return None
        return obj

    def results(self, obj):
        with COMPARE_LOCK:
            saved = build.sources
            try:
                build.sources = lambda *a, **kw: [(self.src, obj)]
                return list(compare.results(self.symbols))
            finally:
                build.sources = saved

    def ours(self, res):
        """Our instructions, with the original's bytes where only
        relocations differ."""
        _, same, code_bytes, mask, orig, diffs = res
        shown = bytes(b if m and i < len(orig) else a
                      for i, (a, m, b) in enumerate(zip(code_bytes, mask, orig + bytes(len(code_bytes)))))
        return compare.disasm(shown, self.addr)

    def score(self, variant):
        if isinstance(variant, str):
            variant = self.variant(variant)
        obj = self.compile(variant)
        if obj is None:
            return None
        try:
            every = self.results(obj)
        finally:
            os.remove(obj)
        res = [r for r in every if r[0] in self.symbol_names]
        matched = {r[0] for r in every if r[1] and r[0] not in self.symbol_names}
        if self.matched is None:
            self.matched = matched
        broken = len(self.matched - matched)
        if not res:
            self.why = (f"compiled, but the object defines none of {' '.join(self.symbol_names)} (symbols.csv's "
                        f"symbols for {self.name}): check the function's linkage, extern \"C\" or C++")
            return None
        _, same, code_bytes, mask, orig, diffs = res[0]
        if same:
            return 1000 * broken
        ours = self.ours(res[0])
        sm = difflib.SequenceMatcher(None, ours, self.orig_asm, autojunk=False)
        return (len(ours) + len(self.orig_asm) - 2 * sum(b.size for b in sm.get_matching_blocks()) + len(diffs)
                + 1000 * broken)


    def hot_lines(self, variant):
        """The lines of `variant`'s body, counted from 0, that compile to
        instructions differing from the original's, from the line
        numbers /Zd records. /Zd doesn't change the code, but its .bf and
        .lf symbols confuse the sizes coff.py reads, so the code comes
        from a plain compile."""
        obj = self.compile(variant)
        if obj is None:
            return set()
        try:
            res = [r for r in self.results(obj) if r[0] in self.symbol_names]
        finally:
            os.remove(obj)
        obj = self.compile(variant, ["/Zd"])
        if obj is None:
            return set()
        try:
            table = coff_lines(obj, self.symbol_names)
        finally:
            os.remove(obj)
        if not res or not table or res[0][1]:
            return set()
        ours = self.ours(res[0])
        sm = difflib.SequenceMatcher(None, ours, self.orig_asm, autojunk=False)
        kept = set()
        for b in sm.get_matching_blocks():
            kept.update(range(b.a, b.a + b.size))
        offset, bad = 0, []
        for i, line in enumerate(ours):
            if i not in kept:
                bad.append(offset)
            offset += len(line.split("\t", 1)[0].split())
        first = variant[0].count("\n")
        lines = set()
        for at in bad:
            line = max((n for va, n in table if va <= at), default=None)
            if line is not None:
                lines.add(line - 1 - first)
        return {n for n in lines if n >= 0}


def coff_lines(path, symbols):
    """(offset, source line) pairs of the first of `symbols` in the COFF
    object at `path`, from its line number table."""
    import struct
    d = open(path, "rb").read()
    _, nsec, _, symptr, nsym, opt, _ = struct.unpack_from("<HHIIIHH", d, 0)
    strtab = symptr + nsym * 18
    names, i, bf = {}, 0, {}
    while i < nsym:
        o = symptr + i * 18
        raw = d[o:o + 8]
        if raw[:4] == b"\0\0\0\0":
            at = strtab + struct.unpack_from("<I", raw, 4)[0]
            name = d[at:d.index(b"\0", at)].decode("latin-1")
        else:
            name = raw.rstrip(b"\0").decode("latin-1")
        sec, aux = struct.unpack_from("<h", d, o + 12)[0], d[o + 17]
        names.setdefault(name, (i, sec))
        if name == ".bf" and aux:
            bf[sec] = struct.unpack_from("<H", d, o + 18 + 4)[0]
        i += 1 + aux
    hit = next((names[s] for s in symbols if s in names), None)
    if not hit:
        return []
    index, sec = hit
    o = 20 + opt + (sec - 1) * 40
    ptr, = struct.unpack_from("<I", d, o + 28)
    count, = struct.unpack_from("<H", d, o + 34)
    base = bf.get(sec, 0)
    out = []
    for k in range(count):
        va, line = struct.unpack_from("<IH", d, ptr + 6 * k)
        if line:
            out.append((va, base + line))
    return sorted(out)


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


LOCAL_DECL = re.compile(r"^\s+[A-Za-z_][\w\s\*]*\s\**[A-Za-z_]\w*(\s*,\s*\**\w+)*;$")
CALL = re.compile(r"\b(?!sizeof\b|if\b|while\b|for\b|switch\b|return\b)[A-Za-z_]\w*\s*\(")
WRITE = re.compile(r"^\s*(?:(\+\+|--)\s*)?([^=;]+?)\s*(?:(?:[-+*/%&|^]|<<|>>)?=(?!=)|\+\+|--|;)")


def order_runs(body):
    """Runs (first, last) of body's lines that are simple statements at
    one indent, not a braceless if/else/loop body, not declarations."""
    lines = body.split("\n")

    def simple(i):
        m = SIMPLE.match(lines[i])
        if not m or CONTROL.match(lines[i]) or LOCAL_DECL.match(lines[i]):
            return None
        prev = lines[i - 1].strip() if i else "{"
        if not prev.endswith((";", "{", "}")) and not prev.startswith(("case ", "default")):
            return None
        return m.group(1)
    runs, i = [], 1
    while i < len(lines):
        ind = simple(i)
        j = i
        while ind and j + 1 < len(lines) and simple(j + 1) == ind:
            j += 1
        if ind and j > i:
            runs.append((i, j))
        i = j + 1
    return lines, runs


def written(stmt):
    """The lvalue a simple statement assigns, or None (a call, or a form
    this doesn't know): such a statement never moves past another."""
    if CALL.search(stmt):
        return None
    m = WRITE.match(stmt)
    return m and m[2].strip()


def mentions(path, stmt):
    return re.search(r"(?<![\w.>])" + re.escape(path) + r"(?!\w)", stmt) or (
        "[" in path and mentions(path.split("[", 1)[0], stmt))


def independent(a, b):
    wa, wb = written(a), written(b)
    return wa and wb and not mentions(wa, b) and not mentions(wb, a)


def order_move(body, rng):
    """Moves one statement of a run to another place in it, past only
    statements it is independent of (see written())."""
    lines, runs = order_runs(body)
    if not runs:
        return None
    a, b = rng.choice(runs)
    i = rng.randint(a, b)
    k = rng.randint(a, b) if rng.random() < 0.5 else min(b, max(a, i + rng.choice([-1, 1])))
    if k == i:
        return None
    lo, hi = (i + 1, k + 1) if k > i else (k, i)
    if not all(independent(lines[i], lines[n]) for n in range(lo, hi)):
        return None
    lines.insert(k, lines.pop(i))
    return "\n".join(lines)


def order_climb(s, best, best_score, args, keep_best):
    """Hill climb over statement orders (--order): each round scores -j
    moves of one statement from the current order and takes the best of
    them when it is no worse; a sideways step is taken, so the climb can
    cross plateaus, and after 20 rounds without progress it goes back
    to the best."""
    rng = random.Random(args.s)
    cur, cur_score = best, best_score
    deadline, tried, stale = time.time() + args.t, 0, 0
    _, runs = order_runs(best[1])
    print(f"{sum(b - a + 1 for a, b in runs)} statements in {len(runs)} runs", flush=True)
    with ThreadPoolExecutor(args.j) as pool:
        while time.time() < deadline and best_score:
            made = []
            for _ in range(args.j * 20):
                body = order_move(cur[1], rng)
                if body and body not in made:
                    made.append(body)
                if len(made) == args.j:
                    break
            if not made:
                break
            scored = [(sc, b) for b, sc in zip(made, pool.map(lambda b: s.score((cur[0], b, cur[2])), made))
                      if sc is not None]
            tried += len(made)
            if not scored:
                continue
            sc, body = min(scored)
            stale += 1
            if sc <= cur_score:
                cur, cur_score = (cur[0], body, cur[2]), sc
            if sc < best_score:
                best, best_score, stale = cur, sc, 0
                print(f"  {tried:5d} tries: score {sc}", flush=True)
                keep_best(best)
            if stale >= 20:
                cur, cur_score, stale = best, best_score, 0
    return best, best_score, tried


def report(args, first, best, tried, began):
    """With --out, NAME.json: the scores as written and at the end, for
    --all."""
    if args.out:
        import json
        json.dump({"start": first, "best": best, "tries": tried, "seconds": round(time.time() - began)},
                  open(os.path.join(OUT, f"{args.name}.json"), "w"))


def compare_rows():
    import csv
    return list(csv.DictReader(open("config/symbols.csv")))


def batch(args):
    """--all: searches each function of hooks.allow_diff (or of --names)
    but hooks.permute_skip in a permute.py of its own, for --budget
    seconds, and sorts what they find into build/permute/batch."""
    if args.names:
        names = [l.split()[0] for l in open(args.names) if l.strip() and not l.startswith("#")]
    else:
        skip = set(project.config["hooks"].get("permute_skip") or [])
        names = [n for n in project.config["hooks"]["allow_diff"] if n not in skip]
    out = os.path.join(OUT, "batch")
    work = os.path.join(out, "work")
    os.makedirs(work, exist_ok=True)
    if LE:
        import lefn
        if not lefn.build():
            return 1
    else:
        build.compile_all()
    procs = max(1, min(args.p or args.j // 4, len(names)))
    jobs = max(1, args.j // procs)
    print(f"{len(names)} functions, {args.budget:g} s each, {procs} at a time with {jobs} compiles each "
          f"(about {len(names) * args.budget / procs / 60:.0f} minutes)", flush=True)
    rows = {}

    def one(name):
        for kind in ("match", "better"):
            for ext in (".c", ".file"):
                path = os.path.join(out, f"{name}.{kind}{ext}")
                if os.path.exists(path):
                    os.remove(path)
        for ext in (".c", ".file", ".json"):
            path = os.path.join(work, name + ext)
            if os.path.exists(path):
                os.remove(path)
        cmd = [sys.executable, os.path.abspath(__file__), name, "-j", str(jobs), "-t", str(args.budget),
               "--hybrid", "--out", work, "--no-build"] + (["-s", str(args.s)] if args.s is not None else [])
        t = time.time()
        with open(os.path.join(work, f"{name}.log"), "w") as log:
            import subprocess
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
        took = time.time() - t
        try:
            import json
            res = json.load(open(os.path.join(work, f"{name}.json")))
        except (OSError, ValueError):
            rows[name] = (None, None, took)
            print(f"{name}: failed, see {work}/{name}.log", flush=True)
            return
        rows[name] = (res["start"], res["best"], took)
        kind = "match" if res["best"] == 0 else "better" if res["best"] < res["start"] else None
        if kind:
            for ext in (".c", ".file"):
                if os.path.exists(os.path.join(work, name + ext)):
                    shutil.copy(os.path.join(work, name + ext), os.path.join(out, f"{name}.{kind}{ext}"))
        print(f"{name}: {res['start']} -> {res['best']}{' MATCH' if kind == 'match' else ''} ({took:.0f} s)",
              flush=True)

    with ThreadPoolExecutor(procs) as pool:
        list(pool.map(one, names))
    again = [n for n in names if rows[n][0] is None]
    if again:
        print(f"again, one at a time: {' '.join(again)}", flush=True)
        jobs = args.j
        for name in again:
            one(name)
    table = [f"{'name':32} {'start':>7} {'best':>7} {'delta':>7}  match  seconds"]
    for name in names:
        start, best, took = rows.get(name, (None, None, 0))
        if start is None:
            table.append(f"{name:32} {'-':>7} {'-':>7} {'-':>7}  {'-':5}  {took:7.0f}")
        else:
            match = "yes" if best == 0 else "no"
            table.append(f"{name:32} {start:7d} {best:7d} {best - start:7d}  {match:5}  {took:7.0f}")
    open(os.path.join(out, "summary.txt"), "w").write("\n".join(table) + "\n")
    print("\n".join(table))
    done = [rows[n] for n in names if rows.get(n, (None,))[0] is not None]
    print(f"{sum(1 for r in done if r[1] == 0)} matches, {sum(1 for r in done if 0 < r[1] < r[0])} improvements;"
          f" written to {out}")
    return 0


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("name", nargs="?")
    ap.add_argument("-j", type=int, default=max(2, build.JOBS))
    ap.add_argument("-t", type=float, default=600)
    ap.add_argument("-s", type=int, default=None)
    ap.add_argument("--decls", action="store_true", help="search declaration orders exhaustively")
    ap.add_argument("--limit", type=int, default=3000, help="--decls: most candidates to try")
    ap.add_argument("--fitness", choices=("raw", "relocations"), default="raw",
                    help="opt-in COFF literal/instruction ranking (PE; requires Capstone)")
    ap.add_argument("--start", help="a variant to search from, such as an earlier run's best")
    ap.add_argument("--sweep", action="store_true",
                    help="enumerate the neighbourhoods of the diff's lines, beam search, until nothing helps")
    ap.add_argument("--pad", action="store_true",
                    help="look for a shift of the symbol IDs, then a declaration move that makes it")
    ap.add_argument("--plan", action="store_true",
                    help="plan how many declarations to add before each function in the file")
    ap.add_argument("--order", action="store_true",
                    help="hill climb over the order of independent statements only")
    ap.add_argument("--file", action="store_true",
                    help="also reorder the file's top-level declarations, keeping its other functions matching")
    ap.add_argument("--base", help="search from the body in this file, as if src/ had it")
    ap.add_argument("--hybrid", action="store_true",
                    help="sweep for up to half of -t, then a random search from its best for the rest")
    ap.add_argument("--out", help="where to write the best variant (default build/permute)")
    ap.add_argument("--no-build", action="store_true", help="don't build src/ first")
    ap.add_argument("--all", action="store_true", help="search every function of hooks.allow_diff in turn")
    ap.add_argument("--budget", type=float, default=300, help="--all: seconds for each function")
    ap.add_argument("--names", help="--all: the functions to search, one a line, instead")
    ap.add_argument("-p", type=int, default=0, help="--all: functions at a time (default -j / 4)")
    args = ap.parse_args()
    if args.out:
        OUT = args.out
    if args.all:
        return batch(args)
    if not args.name:
        ap.error("NAME is required without --all")
    if args.fitness == "relocations" and (LE or args.pad or args.plan):
        ap.error("--fitness relocations requires PE and cannot be used with --pad or --plan")
    FILE_MODE[0] = args.file or args.pad
    if LE:
        import lefn
        if args.pad or args.plan or args.sweep:
            sys.exit("--pad, --plan and --sweep are pe only (VC5's symbol IDs, COFF line numbers)")
        if not args.no_build and not lefn.build():
            return 1
    elif not args.no_build:
        build.compile_all()
    src, text, start, end = find_function(args.name)
    if args.plan:
        plan(src, text, args.limit if args.limit != 3000 else 64, args.j)
        return 0
    s = (lefn.Scorer if LE else Scorer)(args.name, src, text, start, end)
    if args.fitness == "relocations":
        from relocation_fitness import RelocationScorer
        s = RelocationScorer(s)
    base = s.variant(text[start:end])
    if args.base:
        base = s.variant(open(args.base, encoding="utf-8").read())
    FILE_MODE[1] = (base[0], base[2])
    began = time.time()
    first = s.score(base)
    if first is None:
        sys.exit("the function doesn't build as it is: " + getattr(s, "why", "unknown reason"))
    print(f"{args.name}: {src}, score {first} as written", flush=True)
    if first == 0 and not args.pad:
        print("already matches")
        report(args, first, 0, 0, began)
        return 0
    rng = random.Random(args.s)
    best, best_score = base, first
    if args.start and os.path.exists(args.start):
        seed = s.variant(open(args.start, encoding="utf-8").read())
        whole = os.path.splitext(args.start)[0] + ".file"
        if args.file and os.path.exists(whole):
            full = open(whole, encoding="utf-8").read()
            at = full.find(seed[1])
            if at >= 0:
                seed = (full[:at], seed[1], full[at + len(seed[1]):])
        score = s.score(seed)
        if score is not None and score < best_score:
            best, best_score = seed, score
            print(f"starting from {args.start}, score {score}", flush=True)
    cur, cur_score = best, best_score
    deadline = time.time() + args.t if best_score else 0
    tried = 0

    if args.pad:
        found = pad(s, best, args.limit if args.limit != 3000 else 32, args.j)
        if found:
            best, best_score = found, 0
        keep(args.name, best)
        deadline = 0
    elif args.hybrid and best_score and not LE:
        whole = args.t
        args.t = whole / 2
        best, best_score, _ = sweep(s, best, best_score, args, lambda v: keep(args.name, v))
        args.t = whole
        cur, cur_score = best, best_score
        deadline = began + whole if best_score else 0
    elif args.sweep and best_score:
        best, best_score, _ = sweep(s, best, best_score, args, lambda v: keep(args.name, v))
        tried = 0
        deadline = 0
    elif args.order and best_score:
        best, best_score, tried = order_climb(s, best, best_score, args, lambda v: keep(args.name, v))
        deadline = 0
    elif args.decls and best_score:
        cands = [(best[0], b, best[2]) for b in declaration_orders(best[1], args.limit, rng)[1:]]
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
                        keep(args.name, best)
                if best_score == 0:
                    break
        deadline = 0

    stats = load_stats(args.name)
    prior = load_stats("\0")
    hot = set()

    def focus(variant):
        nonlocal hot
        hot = s.hot_lines(variant)
        hot |= {n + d for n in hot for d in (-1, 1)}

    def pick(r):
        kinds = sorted(set(MUTATIONS), key=lambda f: f.__name__)
        return r.choices(kinds, [weight(stats, f.__name__) for f in kinds])[0]

    def candidate(seed, r):
        before, body, after = seed
        used = []
        for _ in range(r.choice([1, 1, 1, 2, 3])):
            if args.file and r.random() < 0.3 * weight(stats, "file_order") / weight(stats, "swap_operands"):
                new = file_order((before, body, after), r)
                if new:
                    before, body, after = new
                    used.append("file_order")
                continue
            for _ in range(8):
                f = pick(r)
                new = f(body, r)
                if not new:
                    continue
                lo, hi = changed_lines(body, new)
                if not hot or f.__name__ in GLOBAL_REWRITES or r.random() < 0.25 \
                        or any(lo <= n < max(hi, lo + 1) for n in hot):
                    body = new
                    used.append(f.__name__)
                    break
        return (before, body, after), used

    if deadline:
        focus(best)
    with ThreadPoolExecutor(args.j) as pool:
        while time.time() < deadline and best_score:
            made = [candidate(cur, random.Random(rng.random())) for _ in range(args.j)]
            bodies = [m[0] for m in made]
            for (body, used), sc in zip(made, pool.map(s.score, bodies)):
                tried += 1
                for kind in used:
                    stats.setdefault(kind, [0, 0])[0] += 1
                if sc is None:
                    continue
                if sc < cur_score:
                    for kind in used:
                        stats[kind][1] += 1
                if sc < best_score:
                    best, best_score = body, sc
                    print(f"  {tried:5d} tries: score {sc}", flush=True)
                    keep(args.name, best)
                    save_stats(args.name, stats, prior)
                    if best_score:
                        focus(best)
                if sc <= cur_score or rng.random() < 0.05:
                    cur, cur_score = body, sc
            if rng.random() < 0.02:
                cur, cur_score = best, best_score
    if tried:
        save_stats(args.name, stats, prior)
    shutil.rmtree(s.tmp, ignore_errors=True)
    os.makedirs(OUT, exist_ok=True)
    keep(args.name, best)
    out = os.path.join(OUT, f"{args.name}.c")
    print(f"{tried} tries, best score {best_score}{' (MATCH)' if best_score == 0 else ''}; written to {out}")
    report(args, first, best_score, tried, began)
    if best != base:
        sys.stdout.writelines(difflib.unified_diff("".join(base).splitlines(True), "".join(best).splitlines(True),
                                                   "as written", "best variant", n=1))
    return 0 if best_score == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
