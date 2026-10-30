"""Adds every function and import of the original to config/symbols.csv.

    seed_symbols.py [FUNCTIONS]

FUNCTIONS is Ghidra's function list, by default ghidra.functions in
project.toml.

Functions come from the Ghidra analysis. New rows get a placeholder name,
FuncXXXXXX. In the library code after the game code, names that Ghidra's
function ID recognized are kept; in the game code they are false
positives.

Imports are the executable's import address table slots, with the
decorated `__imp__` names from the SDK import libraries, so decompiled
code calls through the game's own imports and `just compare` checks
which import each call uses.

Of existing rows, only an empty size is filled in, from Ghidra's.
With game.format = "le", seed_symbols_le.py seeds instead.
"""
import csv, glob, os, re, struct, subprocess, sys

import project

ROOT = project.ROOT
GAME_END = project.GAME_END  # the game's code ends here; libraries follow
EXE = project.ORIGINAL
LIBS = project.config["symbols"]["import_libs"]


def imports(path):
    """Yields (dll, function name, IAT slot address) for imports by name."""
    d = open(path, "rb").read()
    pe, = struct.unpack_from("<I", d, 0x3C)
    nsec, = struct.unpack_from("<H", d, pe + 6)
    optsz, = struct.unpack_from("<H", d, pe + 20)
    opt = pe + 24
    base, = struct.unpack_from("<I", d, opt + 28)
    secs = [struct.unpack_from("<IIII", d, opt + optsz + i * 40 + 8) for i in range(nsec)]

    def off(rva):
        for vsize, va, rawsize, rawptr in secs:
            if va <= rva < va + max(vsize, rawsize):
                return rawptr + rva - va
        raise ValueError(hex(rva))

    def cstr(rva):
        o = off(rva)
        return d[o:d.index(b"\0", o)].decode()

    desc = off(struct.unpack_from("<I", d, opt + 104)[0])
    while True:
        ilt, _, _, name, iat = struct.unpack_from("<IIIII", d, desc)
        if not name:
            break
        dll = cstr(name)
        i = 0
        while True:
            thunk, = struct.unpack_from("<I", d, off((ilt or iat) + i * 4))
            if not thunk:
                break
            if not thunk & 0x80000000:
                yield dll, cstr(thunk + 2), base + iat + i * 4
            i += 1
        desc += 20


def import_symbols(dlls):
    """Maps undecorated names to `__imp__` symbols from the import libraries."""
    wanted = {d.split(".")[0].lower() for d in dlls}
    out = {}
    for lib in sorted(sum((glob.glob(os.path.join(p, "*")) for p in LIBS), [])):
        if os.path.basename(lib).split(".")[0].lower() not in wanted:
            continue
        syms = subprocess.run(["objdump", "-t", lib], capture_output=True, text=True).stdout
        for sym in re.findall(r" (__imp__\S+)$", syms, re.M):
            out.setdefault(re.sub(r"@\d+$", "", sym[len("__imp__"):]), sym)
    return out


def main():
    if project.FORMAT == "le":
        import seed_symbols_le
        return seed_symbols_le.main()
    os.chdir(ROOT)
    src = sys.argv[1] if len(sys.argv) > 1 else project.config["ghidra"]["functions"]
    path = "config/symbols.csv"
    rows = {int(r["address"], 16): r for r in csv.DictReader(open(path))}
    added = sized = 0
    for f in csv.DictReader(open(src)):
        addr = int(f["address"], 16)
        if addr in rows:
            if not rows[addr]["size"]:
                rows[addr]["size"] = f["size"]
                sized += 1
            continue
        name = f["name"]
        if addr < GAME_END or name.startswith("FUN_"):
            name = f"Func{addr:x}"
        rows[addr] = {"address": f"0x{addr:08x}", "size": f["size"], "name": name, "symbol": ""}
        added += 1

    found = list(imports(EXE))
    decorated = import_symbols({dll for dll, _, _ in found})
    added_imports = missing = 0
    for dll, name, addr in found:
        if addr in rows:
            continue
        if name not in decorated:
            if decorated:
                print(f"warning: no import library symbol for {dll}!{name}", file=sys.stderr)
            missing += 1
            continue
        rows[addr] = {"address": f"0x{addr:08x}", "size": "4", "name": name, "symbol": decorated[name]}
        added_imports += 1

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["address", "size", "name", "symbol"], lineterminator="\n")
        w.writeheader()
        for addr in sorted(rows):
            w.writerow({k: rows[addr].get(k) or "" for k in w.fieldnames})
    print(f"{added} functions and {added_imports} imports added to {path}, {sized} sized,"
          f" {len(rows)} rows" + (f"; {missing} imports without a symbol" if missing else "")
          + ("" if decorated else f" (no import libraries in {', '.join(LIBS)})"))


if __name__ == "__main__":
    main()
