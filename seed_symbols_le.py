"""Adds every function of the original to config/symbols.csv.

    seed_symbols.py [FUNCTIONS]

Functions come from the Ghidra analysis (ghidra.functions in
project.toml), with a placeholder name, FuncXXXXX. Library functions are
recognized by searching the original past game.game_end for each public
of symbols.libs, Watcom's CLIB3R.LIB and MATH387R.LIB, with the bytes
under their fixups as wildcards; one found at exactly one address gets
the library's name and symbol.

Existing rows are never changed.
"""
import csv, os, re, sys

import le, omf, project

ROOT = project.ROOT
LIBS = project.config["symbols"]["libs"]
GAME_END = project.GAME_END


def library_functions(w, code, base):
    found = {}
    for lib in LIBS:
        for m in omf.modules(os.path.join(w, lib)):
            for s, name, a, b in m.functions():
                if b - a < 8:
                    continue
                wild = set()
                for f in s.fixups:
                    wild.update(range(f.offset, f.offset + f.size))
                pat = b"".join(b"." if i in wild else re.escape(s.data[i:i + 1]) for i in range(a, b))
                hits = [x.start() for x in re.finditer(pat, code, re.S)]
                if len(hits) == 1 and base + hits[0] >= GAME_END:
                    found[base + hits[0]] = (name, b - a)
    return found


def main():
    os.chdir(ROOT)
    src = sys.argv[1] if len(sys.argv) > 1 else project.config["ghidra"]["functions"]
    path = "config/symbols.csv"
    rows = {int(r["address"], 16): r for r in csv.DictReader(open(path))} if os.path.exists(path) else {}
    objs, _ = le.LE(project.ORIGINAL).image()
    base, code, _ = objs[0]
    lib = library_functions(project.watcom(), bytes(code), base)
    added = named = 0
    for f in csv.DictReader(open(src)):
        addr = int(f["address"], 16)
        if addr in rows or not base <= addr < base + len(code):
            continue
        name, symbol = f"Func{addr:x}", ""
        if addr in lib:
            symbol = lib[addr][0]
            name = symbol.rstrip("_")
            named += 1
        rows[addr] = {"address": f"0x{addr:08x}", "size": f["size"], "name": name, "symbol": symbol}
        added += 1
    for addr, (symbol, size) in lib.items():
        if addr not in rows:
            rows[addr] = {"address": f"0x{addr:08x}", "size": str(size), "name": symbol.rstrip("_"),
                          "symbol": symbol}
            added += 1
            named += 1
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["address", "size", "name", "symbol"], lineterminator="\n")
        w.writeheader()
        for addr in sorted(rows):
            w.writerow({k: rows[addr].get(k) or "" for k in w.fieldnames})
    print(f"{added} functions added to {path}, {named} of them library functions, {len(rows)} rows")


if __name__ == "__main__":
    main()
