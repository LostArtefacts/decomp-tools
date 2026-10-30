"""Lists the functions of the flattened executable.

    functions.py [ELF] > build/functions.csv

ELF defaults to build/<game.name>.elf, and game.code in project.toml is
the range that holds code.

A function starts at a direct call target or at a fixup that points into
code, such as a function pointer in a table or stored by an instruction.
Switch tables in code are runs of adjacent fixups; those point into the
middle of a function and are left out, as are targets of fixups in code
that are not 4-byte aligned right after a return or padding. A function
nothing refers to starts at an aligned address after a return and
padding, which may also be zeros between modules, unless something
jumps there: code after a return in the same function is only reached
by a jump. It ends where the next one
starts, less the alignment padding Watcom puts between functions.
"""
import os, re, subprocess, sys

from project import CODE, ELF

PADDING = (b"\x8d\x40\x00", b"\x8b\xc0", b"\x90")


def main():
    elf = sys.argv[1] if len(sys.argv) > 1 else ELF
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", elf],
                         capture_output=True, text=True, check=True).stdout
    starts = set()
    for m in re.finditer(r"\scall\s+0x([0-9a-f]+)", dis):
        starts.add(int(m.group(1), 16))
    fixups = {}
    for line in open(elf + ".fixups"):
        src, tgt = (int(x, 16) for x in line.split(",")[:2])
        fixups[src] = tgt
    data = open(elf, "rb").read()
    off = 0x1000 - CODE[0]
    for src, tgt in fixups.items():
        if not CODE[0] <= tgt < CODE[1] or tgt in fixups:
            continue
        if CODE[0] <= src < CODE[1]:
            if src - 4 in fixups or src + 4 in fixups or tgt % 4:
                continue
            before = data[tgt + off - 3:tgt + off]
            if not (before[2] == 0xC3 or before == bytes(3) or before[0] == 0xC2 or before.endswith(PADDING)):
                continue
        starts.add(tgt)
    jumps = {int(m.group(1), 16) for m in re.finditer(r"\sj[a-z]+\s+0x([0-9a-f]+)", dis)}
    jumps.update(t for src, t in fixups.items() if CODE[0] <= src < CODE[1])
    for m in re.finditer(r"^\s*([0-9a-f]+):\s+ret\b", dis, re.M):
        a = int(m.group(1), 16) + (1 if data[int(m.group(1), 16) + off] == 0xC3 else 3)
        pad = re.match(rb"(?:\x8d\x40\x00|\x8b\xc0|\x90|\x00+)?", data[a + off:a + off + 16]).end()
        a += pad
        if a % 4 or a in jumps or not CODE[0] <= a < CODE[1] or a in fixups:
            continue
        if data[a + off:a + off + 4] == bytes(4):
            continue
        starts.add(a)
    starts = sorted(a for a in starts if CODE[0] <= a < CODE[1])
    print("address,size")
    for i, a in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else CODE[1]
        body = data[a + off:end + off]
        for pad in PADDING:
            if body.endswith(pad) and len(body) > len(pad):
                end -= len(pad)
                break
        print(f"0x{a:08x},{end - a}")


if __name__ == "__main__":
    main()
