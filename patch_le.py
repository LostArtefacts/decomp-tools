"""Builds a copy of the original with the compiled functions hooked in.

    patch_exe.py [OUT]

Every function of build/obj that config/symbols.csv names goes into a
new object at build.hook_base, and the original's first instruction
becomes a jump to it, so the game runs our code whether or not it
matches yet. A function with less than 5 bytes before the next one, such
as an empty function on another one's ret, has no room for the jump and
stays the original's. Calls and references from it resolve as in
compare.py: externals through symbols.csv, the module's own data
segments to where the original has them once compare.py has placed
them, or else into the new object too. OUT defaults to game.hooked in
build/game; both settings are in project.toml.
"""
import glob, os, struct, sys

import compare_le as compare, le, omf, project

ROOT = project.ROOT
BASE = project.config["build"]["hook_base"]
FLAGS = 0x2047


def patch(out):
    exe = le.LE(compare.EXE)
    orig = compare.Original(compare.EXE)
    by_symbol, by_addr = compare.load_symbols()
    blob = bytearray()
    placed = []
    for path in sorted(glob.glob("build/obj/*.obj")):
        for mod in omf.modules(path):
            _, bases = compare.compare_module(mod, orig, by_symbol)
            where = {}
            for i, seg in enumerate(mod.segments[1:], 1):
                if seg.is_code() or i not in bases:
                    blob += bytes(-len(blob) % 16)
                    where[i] = BASE + len(blob)
                    blob += seg.data
                else:
                    where[i] = bases[i]
            placed.append((mod, where))
    patch = le.Patch(exe)
    patch.add_object(BASE, bytes(blob) or bytes(1), FLAGS)
    hooked = 0
    starts = sorted(by_addr)
    room = {a: b - a for a, b in zip(starts, starts[1:])}
    for mod, where in placed:
        for i, seg in enumerate(mod.segments[1:], 1):
            if not where[i] >= BASE:
                continue
            for f in seg.fixups:
                at = where[i] + f.offset
                inline, = struct.unpack_from("<i", seg.data, f.offset)
                kind, what = f.target
                if kind == "ext":
                    sym = by_symbol.get(what)
                    if not sym:
                        sys.exit(f"error: {what} is not in config/symbols.csv")
                    target = int(sym["address"], 16) + f.disp + inline
                elif kind == "seg":
                    target = where[what] + f.disp + inline
                else:
                    sys.exit(f"error: unsupported fixup target {f.target} in {mod.name}")
                if f.size != 4:
                    sys.exit(f"error: {f.size}-byte fixup in {mod.name}")
                patch.add_fixup(at, 8 if f.rel else 7, target)
        for seg, name, start, end in mod.functions():
            sym = by_symbol.get(name)
            if not sym:
                continue
            addr = int(sym["address"], 16)
            if room.get(addr, 5) < 5:
                continue
            patch.remove_fixups(addr, addr + 5)
            patch.write(addr, b"\xe9\0\0\0\0")
            patch.add_fixup(addr + 1, 8, where[mod.segments.index(seg)] + start)
            hooked += 1
    os.makedirs(os.path.dirname(out), exist_ok=True)
    patch.save(out)
    print(f"{hooked} functions hooked into {out}, {len(blob)} bytes at {BASE:#x}")


def main():
    os.chdir(ROOT)
    patch(sys.argv[1] if len(sys.argv) > 1 else project.HOOKED)


if __name__ == "__main__":
    main()
