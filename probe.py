"""Compiles a reference source tree as its Visual C++ project builds it,
and compares each of its functions with the original.

    probe.py [-j N]

reference.source is copied to build/reference, and every source file
that reference.dsp's reference.dsp_config builds is compiled there with
build.cflags and reference.defines (assembly with ml). Each function an
object defines is looked up in config/symbols.csv by its symbol or name
and compared with the original's bytes, every relocation masked: whether
the function matches up to what it refers to. Writes reference.probe
(address, size, name, file, compiled size, status, symbol, score, ratio)
and prints a summary. score is the number of instructions that differ
(an edit distance over the two disassemblies, relocated operands taken
as the original's), ratio how alike the two are, 0 to 1: the functions
to start with are the ones with the lowest score. Statuses:

    match      the same bytes, relocations aside
    size       the same size, different bytes
    differ     a different size
    missing    the original has it, the reference's build doesn't

Files that don't compile are listed with their first errors.
"""
import collections, csv, difflib, os, re, shutil, sys
from concurrent.futures import ThreadPoolExecutor

import build, coff, compare, project

ROOT = project.ROOT
REF = project.config["reference"]
SOURCE = os.path.join(ROOT, REF["source"])
OUT = os.path.join(ROOT, "build/reference")
LABEL = 6


def project_sources():
    """The project file's source files that its configuration builds."""
    text = open(os.path.join(SOURCE, REF["dsp"]), encoding="latin-1").read()
    config = '"' + REF["dsp_config"] + '"'
    for block in text.split("# Begin Source File")[1:]:
        block = block.split("# End Source File")[0]
        path = re.search(r"SOURCE=(\S+)", block)[1].replace("\\", "/").lstrip("./")
        m = re.search(r'!IF\s+"\$\(CFG\)" == ' + re.escape(config) + r"(.*?)(!ELSEIF|!ENDIF)", block, re.S)
        if m and "Exclude_From_Build 1" in m[1]:
            continue
        if path.lower().endswith((".c", ".cpp") + build.ASM_EXTS):
            yield path


def find(path):
    """`path` in the copy, matching case-insensitively."""
    cur = OUT
    for part in path.split("/"):
        names = {n.lower(): n for n in os.listdir(cur)}
        if part.lower() not in names:
            return None
        cur = os.path.join(cur, names[part.lower()])
    return cur


def compile_one(path):
    src = find(path)
    if not src:
        return path, None, "not in the tree"
    obj = os.path.join(OUT, "obj", re.sub(r"[/\\]", "_", path).rsplit(".", 1)[0] + ".obj")
    rel = build.win(os.path.relpath(src, ROOT))
    out_flag = "/Fo" + build.win(os.path.relpath(obj, ROOT))
    if path.lower().endswith(build.ASM_EXTS):
        code, out = build.run_tool("ml", *build.BUILD["asflags"], out_flag, rel)
    else:
        code, out = build.run_tool("cl", "/c", *build.CFLAGS, *REF["defines"], out_flag, rel)
    return path, obj if code == 0 and os.path.exists(obj) else None, out


def score(code, mask, orig, addr):
    """The instructions that differ, and how alike the two are."""
    shown = bytes(orig[i] if i in mask and i < len(orig) else b for i, b in enumerate(code))
    ours, theirs = compare.disasm(shown, addr), compare.disasm(orig, addr)
    m = difflib.SequenceMatcher(None, ours, theirs, autojunk=False)
    same = sum(b.size for b in m.get_matching_blocks())
    return len(ours) + len(theirs) - 2 * same, m.ratio()


def plain(symbol):
    """The function name inside a decorated symbol."""
    if symbol.startswith("?"):
        return symbol[1:].split("@")[0]
    return symbol.lstrip("_@").split("@")[0]


def main():
    os.chdir(ROOT)
    if not REF["source"] or not REF["dsp"]:
        sys.exit("probe.py needs reference.source and reference.dsp in project.toml")
    jobs = build.JOBS
    if sys.argv[1:3] and sys.argv[1] == "-j":
        jobs = int(sys.argv[2])
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    shutil.copytree(SOURCE, OUT, symlinks=False,
                    ignore=shutil.ignore_patterns("*.OBJ", "*.obj", "*.PDB", "*.pdb"))
    os.makedirs(os.path.join(OUT, "obj"))
    sources = list(project_sources())
    with ThreadPoolExecutor(jobs) as pool:
        results = list(pool.map(compile_one, sources))

    rows = list(csv.DictReader(open("config/symbols.csv")))
    by_symbol = {s: r for r in rows for s in r["symbol"].split()}
    by_name = {}
    for r in rows:
        by_name.setdefault(r["name"].lower(), r)
    exe = coff.Image(project.ORIGINAL)
    found, failed = {}, []
    for path, obj, out in results:
        if not obj:
            failed.append((path, out.splitlines()[:3]))
            continue
        o = coff.Object(obj)
        for sym in o.externals():
            if sym.section <= 0 or not o.sections[sym.section - 1].flags & coff.CODE:
                continue
            row = by_symbol.get(sym.name) or by_name.get(plain(sym.name).lower())
            if not row or not row["size"] or int(row["address"], 16) >= project.GAME_END:
                continue
            addr, size = int(row["address"], 16), int(row["size"])
            sec = o.sections[sym.section - 1]
            starts = sorted(s.value for s in o.symbols if s and s.section == sym.section
                            and s.value > sym.value and s.storage != LABEL)
            end = starts[0] if starts else len(sec.data)
            code = bytearray(sec.data[sym.value:end])
            while len(code) > size and code[-1] in (0x90, 0xCC):
                code.pop()
            mask = {off - sym.value + i for off, _, _ in sec.relocs for i in range(4)
                    if sym.value <= off < end}
            orig = exe.read(addr, size)
            if len(code) != size:
                status = "differ"
            elif all(i in mask or code[i] == orig[i] for i in range(size)):
                status = "match"
            else:
                status = "size"
            diff, ratio = (0, 1.0) if status == "match" else score(code, mask, orig, addr)
            found[addr] = (row["name"], size, path, len(code), status, sym.name, diff, ratio)

    os.makedirs(os.path.dirname(REF["probe"]) or ".", exist_ok=True)
    with open(REF["probe"], "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["address", "size", "name", "file", "compiled", "status", "symbol", "score", "ratio"])
        game = [r for r in rows if r["size"] and int(r["address"], 16) < project.GAME_END]
        for r in sorted(game, key=lambda r: int(r["address"], 16)):
            addr = int(r["address"], 16)
            if addr in found:
                name, size, path, n, status, symbol, diff, ratio = found[addr]
                w.writerow([f"{addr:#x}", size, name, path, n, status, symbol, diff, f"{ratio:.3f}"])
            else:
                w.writerow([f"{addr:#x}", r["size"], r["name"], "", "", "missing", "", "", ""])
    counts = collections.Counter(v[4] for v in found.values())
    sizes = collections.Counter()
    for v in found.values():
        sizes[v[4]] += v[1]
    print(f"{len(sources)} sources, {len(failed)} failed to compile")
    for path, lines in failed:
        print(f"  {path}: {' | '.join(lines)}")
    for status in ("match", "size", "differ"):
        print(f"{status:7s} {counts[status]:5d} functions {sizes[status]:7d} bytes")
    print(f"missing {len(game) - len(found):5d} functions")
    near = collections.Counter()
    for v in found.values():
        if v[4] != "match":
            near["1-2" if v[6] <= 2 else "3-5" if v[6] <= 5 else "6-10" if v[6] <= 10 else "11+"] += 1
    print("instructions that differ: " + "  ".join(f"{k}: {near[k]}" for k in ("1-2", "3-5", "6-10", "11+")))


if __name__ == "__main__":
    main()
