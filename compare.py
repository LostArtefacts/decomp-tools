"""Compares compiled functions with the original executable.

    compare.py            report every function in src/ that symbols.csv lists
    compare.py SYMBOL...  also show a disassembly diff of these functions

Relocations whose target has a known address (symbols.csv, or the same
function) are filled in and compared. The others are masked in the code;
when they point at data the object defines, such as float constants and
string literals, that data is compared with what the original points at.

With game.format = "le", compare_le.py compares instead.
"""
import csv, os, re, subprocess, sys, tempfile, shutil

import build, coff, project

ROOT = project.ROOT
EXE = project.ORIGINAL


LABEL = 6  # IMAGE_SYM_CLASS_LABEL
UNINITIALIZED = 0x80  # IMAGE_SCN_CNT_UNINITIALIZED_DATA


def target_data(obj, target, addend):
    """The bytes a reference to `target` + `addend` reads, as far as the
    next symbol, with a mask over the pointers in them; None for code and
    uninitialized data."""
    sec = obj.sections[target.section - 1]
    if sec.flags & (coff.CODE | UNINITIALIZED):
        return None
    start = target.value + addend
    ends = [s.value for s in obj.symbols
            if s and s.section == target.section and s.value > start]
    end = min(ends) if ends else len(sec.data)
    # Leave out the padding after string literals and constants.
    if target.name.startswith("$SG"):
        end = min(end, sec.data.index(b"\0", start) + 1)
    elif target.name.startswith("__real@"):
        # MSVC 5 and 6 write __real@<size>@<80-bit hex>, 7 and later
        # __real@<hex of the constant>.
        size = re.match(r"__real@(\d+)@", target.name)
        end = min(end, start + (int(size[1]) if size else len(target.name[7:]) // 2))
    mask = bytearray(end - start)
    for off, _, _ in sec.relocs:
        for i in range(off, off + 4):
            if start <= i < end:
                mask[i - start] = 1
    return sec.data[start:end], bytes(mask)


def compiled_functions(symbols):
    """Yields (name, bytes, mask, data) for each function src/ defines,
    data listing (offset, addend, bytes, mask) for the data references
    masked in the code."""
    # Objects of the current sources only: a renamed file leaves its old
    # object behind. They are read in link order: of an inline function
    # several objects define, the linker keeps the first copy.
    seen = set()
    for _, path in build.sources():
        if os.path.basename(path).startswith(build.GLUE_PREFIX):
            continue  # the DLL's own code
        obj = coff.Object(os.path.join(ROOT, path))
        for sym in obj.externals():
            if sym.section <= 0 or sym.name not in symbols or sym.name in seen:
                continue
            seen.add(sym.name)
            sec = obj.sections[sym.section - 1]
            # Labels (storage class 6) are case targets inside a function;
            # a switch's jump table starts at a static symbol after it.
            starts = sorted(s.value for s in obj.symbols
                            if s and s.section == sym.section and s.value > sym.value
                            and s.storage != LABEL)
            end = starts[0] if starts else len(sec.data)
            addr = symbols[sym.name][0]
            code = bytearray(sec.data[sym.value:end])
            mask = bytearray(len(code))
            data = []
            for off, index, typ in sec.relocs:
                if not sym.value <= off < end:
                    continue
                pos = off - sym.value
                target = obj.symbols[index]
                if target.name in symbols:
                    to = symbols[target.name][0]
                elif target.section == sym.section and sym.value <= target.value < end:
                    to = addr + target.value - sym.value
                else:
                    mask[pos:pos + 4] = b"\1" * 4
                    if typ == coff.DIR32 and target.section > 0:
                        addend = int.from_bytes(code[pos:pos + 4], "little")
                        found = target_data(obj, target, addend)
                        if found:
                            data.append((pos, addend) + found)
                    continue
                addend = int.from_bytes(code[pos:pos + 4], "little")
                value = to + addend - (addr + pos + 4 if typ == coff.REL32 else 0)
                code[pos:pos + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")
            while len(code) > symbols[sym.name][1] and code[-1] in (0x90, 0xCC):
                code.pop()
            yield sym.name, bytes(code), bytes(mask), data


def disasm(code, addr):
    if not shutil.which("objdump"):
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        return [f"{i.bytes.hex(' ')}\t{i.mnemonic} {i.op_str}".rstrip()
                for i in cs.disasm(code, addr)]
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        f.write(code)
        f.flush()
        out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386", "-M", "intel",
                              f"--adjust-vma={addr:#x}", f.name],
                             capture_output=True, text=True, check=True).stdout
    return [l.split("\t", 1)[1] for l in out.splitlines() if l[:2] == "  " and "\t" in l]


def read_symbols():
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        return {s: (int(r["address"], 16), int(r["size"] or 0))
                for r in csv.DictReader(f) for s in r["symbol"].split()}


def data_diffs(exe, orig, data):
    """Lists the data references whose data differs from the original's."""
    diffs = []
    for pos, addend, ours, mask in data:
        if pos + 4 > len(orig):
            continue
        at = int.from_bytes(orig[pos:pos + 4], "little")
        try:
            theirs = exe.read(at, len(ours))
        except ValueError:
            theirs = b""
        bad = [i for i, (a, m) in enumerate(zip(ours, mask))
               if not m and (i >= len(theirs) or a != theirs[i])]
        if bad:
            diffs.append((pos, at, bad[0], ours, theirs))
    return diffs


def results(symbols):
    """Yields (name, same, code, mask, original, data diffs) for each
    compiled function."""
    exe = coff.Image(os.path.join(ROOT, EXE))
    for name, code, mask, data in compiled_functions(symbols):
        addr, size = symbols[name]
        orig = exe.read(addr, size)
        same = len(code) == size and all(m or a == b for a, b, m in zip(code, orig, mask))
        diffs = data_diffs(exe, orig, data) if same else []
        yield name, same and not diffs, code, mask, orig, diffs


def main():
    if project.FORMAT == "le":
        import compare_le
        return compare_le.main()
    os.chdir(ROOT)
    symbols = read_symbols()
    show = set(sys.argv[1:])
    matched = total = matched_bytes = 0
    for name, same, code, mask, orig, diffs in results(symbols):
        addr, size = symbols[name]
        total += 1
        matched += same
        matched_bytes += size if same else 0
        print(f"{'OK  ' if same else 'DIFF'} {addr:08x} {size:5d}/{len(code):<5d} {name}", flush=True)
        for pos, at, first, ours, theirs in diffs:
            print(f"     data at {addr + pos:08x} -> {at:08x}+{first:#x}:"
                  f" compiled {ours[first:first + 16].hex()}, original {theirs[first:first + 16].hex()}")
        if name in show:
            # Show masked bytes as the original's so they don't show up as diffs.
            shown = bytes(b if m and i < len(orig) else a
                          for i, (a, m, b) in enumerate(zip(code, mask, orig + bytes(len(code)))))
            ours, theirs = disasm(shown, addr), disasm(orig, addr)
            with tempfile.TemporaryDirectory() as tmp:
                for fn, lines in (("original", theirs), ("compiled", ours)):
                    open(os.path.join(tmp, fn), "w").write("\n".join(lines) + "\n")
                subprocess.run(["diff", "-u", "original", "compiled"], cwd=tmp)
    print(f"{matched}/{total} functions match, {matched_bytes} bytes")
    return 0 if matched == total else 1


if __name__ == "__main__":
    sys.exit(main())
