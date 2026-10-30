"""Everything about one function, in one call.

    fn.py NAME|ADDR        where it goes in src/, the reference's definition
                           (comments stripped), and what it uses that src/
                           doesn't declare yet
    fn.py NAME|ADDR -d     build, then the compare status and a short diff
                           of that function only
    fn.py NAME|ADDR -g     Ghidra's decompilation (build/decomp), FUN_ and
                           DAT_ names replaced from config/symbols.csv
    fn.py NAME|ADDR -a     the reference's definition from where probe.py
                           compiled it, even when a reference.prefer
                           directory has one
    fn.py --next [N]       the next N functions to do: probe.py's matches,
                           then the lowest scores, then the ones only a
                           reference.prefer directory defines, by size

The reference is reference.source. Its definitions come from the file
probe.py compiled (reference.probe), or from a reference.prefer
directory first when that has one, since those are the closest to the
target. reference.layout maps the reference's top directories to src/'s
to say which file a function goes in; reference.skip leaves stale
copies out. Functions already matching are the ones HEAD's
docs/progress.svg shows.
"""
import csv, difflib, glob, os, re, subprocess, sys, tempfile

import project

ROOT = project.ROOT
REF = project.config["reference"]
SOURCE = os.path.join(ROOT, REF["source"]) if REF["source"] else ""
KEYWORDS = set("""auto break case char const continue default do double else enum extern float
for goto if int long register return short signed sizeof static struct switch typedef union
unsigned void volatile while NULL __cdecl __fastcall __stdcall __inline inline TRUE FALSE
true false bool class new delete this public private""".split())
SOURCE_EXTS = (".c", ".cpp")


def symbols():
    return list(csv.DictReader(open("config/symbols.csv")))


def probe():
    path = REF["probe"]
    return {int(r["address"], 16): r for r in csv.DictReader(open(path))} if os.path.exists(path) else {}


def lookup(key):
    rows = symbols()
    if re.fullmatch(r"(0x)?[0-9a-fA-F]{6,8}", key):
        want = int(key, 16)
        hit = [r for r in rows if int(r["address"], 16) == want]
    else:
        hit = [r for r in rows if r["name"] == key] or [r for r in rows if r["name"].lower() == key.lower()]
    if not hit:
        sys.exit(f"{key}: not in config/symbols.csv")
    return hit[0]


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m[0].count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def read(path):
    return open(path, encoding="latin-1").read()


def extract(text, name):
    """The definition of `name` in `text`, comments stripped, or None."""
    text = strip_comments(text)
    for m in re.finditer(r"^[^\n;{}()#]*\b" + re.escape(name) + r"\s*\(", text, re.M):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        j = i
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != "{":
            continue
        depth, k = 0, j
        while k < len(text):
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            k += 1
            if depth == 0:
                break
        body = "\n".join(l.rstrip() for l in text[m.start():k].splitlines())
        return re.sub(r"\n\n\n+", "\n\n", body)
    return None


def skipped(path):
    rel = os.path.relpath(path, SOURCE).replace("\\", "/").lower()
    return any(rel.startswith(s.lower().rstrip("/") + "/") for s in REF["skip"])


def reference_files(exts):
    if not SOURCE:
        return []
    return sorted(p for p in glob.glob(os.path.join(SOURCE, "**", "*"), recursive=True)
                  if p.lower().endswith(exts) and not skipped(p))


def resolve(rel):
    """`rel` in the reference, matching case-insensitively."""
    cur = SOURCE
    for part in rel.split("/"):
        names = {n.lower(): n for n in os.listdir(cur)}
        if part.lower() not in names:
            return None
        cur = os.path.join(cur, names[part.lower()])
    return cur


def reference_file(addr, name):
    """The reference file probe.py compiled `name` from, or any that
    defines it."""
    row = probe().get(addr)
    if row and row["file"]:
        path = resolve(row["file"])
        if path:
            return path
    for path in reference_files(SOURCE_EXTS):
        text = read(path)
        if name in text and extract(text, name):
            return path
    return None


def preferred_file(name, near=None):
    """The reference.prefer file that defines `name`: the one named like
    `near` first."""
    files = [p for d in REF["prefer"] if resolve(d)
             for p in sorted(glob.glob(os.path.join(resolve(d), "*"))) if p.lower().endswith(SOURCE_EXTS)]
    if near:
        same = [f for f in files if os.path.basename(f).lower() == os.path.basename(near).lower()]
        files = same + [f for f in files if f not in same]
    for path in files:
        text = read(path)
        if name in text and extract(text, name):
            return path
    return None


def preferred_names():
    names = set()
    for d in REF["prefer"]:
        if resolve(d):
            for p in glob.glob(os.path.join(resolve(d), "*")):
                if p.lower().endswith(SOURCE_EXTS):
                    names |= defined_in(p)
    return names


def src_target(path):
    """The src/ file a reference file's functions go in."""
    if not path:
        return None
    parts = os.path.relpath(path, SOURCE).replace("\\", "/").split("/")
    layout = {k.lower(): v for k, v in REF["layout"].items()}
    folder = layout.get(parts[0].lower(), "/".join(parts[:-1]).lower()) if len(parts) > 1 else ""
    return os.path.join("src", folder, parts[-1].lower()).replace("\\", "/")


def src_text():
    return "\n".join(read(p) for p in glob.glob("src/**/*.[ch]*", recursive=True))


def defined_in(path):
    if not os.path.exists(path):
        return set()
    text = strip_comments(read(path))
    return set(re.findall(r"^[\w \t\*]*?\b(\w+)\s*\([^;{]*\)\s*\{", text, re.M))


def placement(addr, target):
    if not target:
        return "no reference file; pick the src/ file by its neighbours' addresses"
    rows = sorted(symbols(), key=lambda r: int(r["address"], 16))
    have = defined_in(target)
    before = [r for r in rows if int(r["address"], 16) < addr and r["name"] in have]
    after = [r for r in rows if int(r["address"], 16) > addr and r["name"] in have]
    where = []
    if before:
        where.append(f"after {before[-1]['name']}")
    if after:
        where.append(f"before {after[0]['name']}")
    state = "exists" if os.path.exists(target) else "new file"
    return f"{target} ({state}){': ' + ', '.join(where) if where else ''}"


def definition(ident, first=None):
    """A one-line definition of `ident` from the reference's headers, or
    None."""
    pats = [r"#define\s+" + ident + r"\b", r"\}\s*" + ident + r"\s*;", r"typedef\b[^;]*\b" + ident + r"\s*;",
            r"\bextern\b[^;]*\b" + ident + r"\b", r"^\s*\w[\w \t\*]*\b" + ident + r"\s*\([^;{]*\)\s*;"]
    for path in ([first] if first else []) + reference_files((".h", ".hpp")):
        text = strip_comments(read(path))
        for p in pats:
            m = re.search(p, text, re.M)
            if m:
                line = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.end())].strip()
                if line.startswith("}"):
                    line += "   (struct; see the header)"
                return f"{os.path.relpath(path, SOURCE)}: {line[:150]}"
    return None


def missing(body, name, path):
    have = set(re.findall(r"\w+", strip_comments(src_text())))
    used = set(re.findall(r"(?<![.>\w])([A-Za-z_]\w*)", body)) - {name}
    return [f"  {ident:28s} {definition(ident, path) or '?'}" for ident in sorted(used - have - KEYWORDS)]


def matched_at_head():
    import render_progress
    shown = subprocess.run(["git", "show", "HEAD:docs/progress.svg"], capture_output=True, text=True)
    with tempfile.NamedTemporaryFile("w", suffix=".svg") as f:
        f.write(shown.stdout)
        f.flush()
        return {a for a, same in render_progress.built_from_svg(f.name).items() if same}


def todo():
    done = matched_at_head()
    pr = probe()
    preferred = preferred_names()
    rows = [r for r in symbols() if r["size"] and int(r["address"], 16) not in done
            and int(r["address"], 16) < project.GAME_END]
    rank = {"match": 0, "size": 1, "differ": 1}

    def key(r):
        a = int(r["address"], 16)
        p = pr.get(a)
        if not p or p["status"] == "missing":
            return (2 if r["name"] in preferred else 3, int(r["size"]), a)
        return (rank.get(p["status"], 3), int(p["score"] or r["size"]), a)

    return sorted(rows, key=key), pr, preferred


def show_next(n):
    rows, pr, preferred = todo()
    tag = "/".join(REF["prefer"]) or "-"
    for r in rows[:n]:
        p = pr.get(int(r["address"], 16), {})
        where = p.get("file") or (tag if r["name"] in preferred else "")
        print(f"{r['address']} {r['name']:32s} {r['size']:>5s}B {p.get('status', '?'):7s}"
              f" score={p.get('score') or '-':4s} {where}")


def diff(row):
    built = subprocess.run([sys.executable, os.path.join(project.TOOLS, "build.py")],
                           capture_output=True, text=True)
    if built.returncode:
        errs = [l for l in (built.stdout + built.stderr).splitlines() if re.search(r"error|fatal|unresolved", l, re.I)]
        print("BUILD FAILED\n" + "\n".join(errs[:25]))
        return 1
    import compare
    syms = compare.read_symbols()
    names = row["symbol"].split()
    others = 0
    for name, same, code, mask, orig, diffs in compare.results(syms):
        if name not in names:
            others += not same
            continue
        addr, size = syms[name]
        print(f"{'OK' if same else 'DIFF'} {addr:#x} size {size} compiled {len(code)}")
        for pos, at, first, ours, theirs in diffs:
            print(f"  data at {addr + pos:#x} -> {at:#x}+{first:#x}: compiled {ours[first:first + 16].hex()}"
                  f" original {theirs[first:first + 16].hex()}")
        if not same:
            shown = bytes(b if m and i < len(orig) else a
                          for i, (a, m, b) in enumerate(zip(code, mask, orig + bytes(len(code)))))
            lines = list(difflib.unified_diff(compare.disasm(orig, addr), compare.disasm(shown, addr),
                                              "original", "compiled", n=1, lineterm=""))
            print("\n".join(lines[2:120]))
            if len(lines) > 122:
                print(f"... {len(lines) - 122} more diff lines")
        break
    else:
        print("not compiled: no definition of", row["name"], "in src/")
    if others:
        print(f"note: {others} other function(s) DIFF")
    return 0


def ghidra(addr):
    path = f"build/decomp/{addr:08x}.c"
    if not os.path.exists(path):
        print(f"{path} missing: just decompile {addr:#x}")
        return 0
    names = {int(r["address"], 16): r["name"] for r in symbols()}
    print(re.sub(r"\b(?:FUN|DAT|PTR|LAB)_([0-9a-f]{8})\b", lambda m: names.get(int(m[1], 16), m[0]), read(path)))
    return 0


def main():
    os.chdir(ROOT)
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    if args[0] == "--next":
        show_next(int(args[1]) if len(args) > 1 else 10)
        return 0
    row = lookup(args[0])
    addr = int(row["address"], 16)
    if "-d" in args:
        return diff(row)
    if "-g" in args:
        return ghidra(addr)
    p = probe().get(addr, {})
    print(f"{row['name']} {row['address']} size {row['size']} symbol {row['symbol']}")
    print(f"probe: {p.get('status', '?')} score {p.get('score') or '-'} ratio {p.get('ratio') or '-'}")
    if not SOURCE:
        print("no reference.source; use -g for Ghidra's")
        return 0
    path = reference_file(addr, row["name"])
    pref = None if "-a" in args else preferred_file(row["name"], path)
    print("goes in:", placement(addr, src_target(path or pref)))
    if pref:
        if path:
            print(f"(the probe compiled another version: fn.py {row['name']} -a)")
        path = pref
    body = extract(read(path), row["name"]) if path else None
    if not body:
        print("the reference has no definition; use -g for Ghidra's")
        return 0
    print(f"--- {os.path.relpath(path, ROOT)}, comments stripped")
    print(body.strip())
    gone = missing(body, row["name"], path)
    if gone:
        print("--- not declared in src/ yet")
        print("\n".join(gone))
    return 0


if __name__ == "__main__":
    sys.exit(main())
