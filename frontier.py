"""A ratchet on the functions that don't match yet: none of the bytes of
one that matched the original may stop matching.

    frontier.py [NAME...]            check every function the baseline
                                     records, or each NAME
    frontier.py --fn NAME            the same, for NAME (repeatable)
    frontier.py --update [NAME...]   record what improved, add the
                                     functions hooks.allow_diff lists that
                                     the baseline doesn't, drop those that
                                     match or aren't compiled any more
    frontier.py --rebaseline NAME... record NAME as it is now, even if
                                     bytes stopped matching
    frontier.py -v ...               show the instructions that stopped
                                     matching

It builds src/ first, as `just build` does, unless --no-build. The
baseline is config/frontier.toml: for each function, its address, its
size and compiled size, and the ranges of offsets (hex, inclusive) whose
bytes match the original's, a field compare.py masks counting as
matching. Offsets compare in place, so a byte inserted early makes the
rest stop matching: the check then fails, and a change that moves code
on purpose is recorded with --rebaseline. Nothing is written without
--update or --rebaseline; neither writes over a regression of another
function. The check exits 1 when a byte stopped matching.
"""
import argparse, contextlib, io, os, sys, tomllib

import build, compare, project, redtriage

ROOT = project.ROOT
BASELINE = os.path.join(ROOT, "config/frontier.toml")
HEADER = """\
# The functions that don't match yet, and the byte offsets (hex,
# inclusive ranges) at which each matches the original; checked by
# `just frontier`. Written by tools/frontier.py --update or --rebaseline,
# not by hand."""


def ranges(offsets):
    """Sorted offsets as ["A-B", "C", ...] in hex."""
    out, start, prev = [], None, None
    for value in sorted(offsets) + [None]:
        if start is not None and value == prev + 1:
            prev = value
            continue
        if start is not None:
            out.append(f"{start:X}" if start == prev else f"{start:X}-{prev:X}")
        start = prev = value
    return out


def offsets(items):
    found = set()
    for item in items:
        low, _, high = item.partition("-")
        found.update(range(int(low, 16), int(high or low, 16) + 1))
    return found


def load():
    if not os.path.exists(BASELINE):
        return {}
    with open(BASELINE, "rb") as f:
        return tomllib.load(f).get("frontier", {})


def save(entries):
    lines = [HEADER]
    for name, e in sorted(entries.items(), key=lambda item: item[1]["address"]):
        lines += ["", f"[frontier.{name}]", f"address = {e['address']:#010x}",
                  f"size = {e['size']}", f"compiled = {e['compiled']}",
                  f"matching = {e['matching']}"]
        parts = [f'"{r}"' for r in e["match"]]
        row, rows = "match = [", []
        for p in parts:
            if len(row) + len(p) > 98:
                rows.append(row.rstrip())
                row = "    "
            row += p + ", "
        rows.append(row.rstrip(", ") + "]")
        lines += rows
    with open(BASELINE, "w") as f:
        f.write("\n".join(lines) + "\n")


def measure(wanted):
    """name -> (address, size, compiled size, matching offsets, ok, code,
    mask, original) for each compiled function in `wanted`."""
    symbols, plain = compare.read_symbols(), redtriage.names()
    found = {}
    for symbol, ok, code, mask, orig, data in compare.results(symbols):
        name = plain.get(symbol, symbol)
        if name not in wanted:
            continue
        differ = set(redtriage.differing(code, mask, orig))
        match = set(range(len(orig))) - differ
        found[name] = (symbols[symbol][0], len(orig), len(code), match, ok, code, mask, orig)
    return found


def entry(m):
    addr, size, compiled, match = m[:4]
    return {"address": addr, "size": size, "compiled": compiled, "matching": len(match),
            "match": ranges(match)}


def show(m, lost):
    """The original's instructions that hold a byte that stopped matching."""
    addr, _, _, _, _, code, mask, orig = m
    ours = {i.address: i for i in redtriage.CS.disasm(code, addr)}
    shown = 0
    for i in redtriage.CS.disasm(orig, addr):
        if any(i.address - addr + k in lost for k in range(i.size)):
            mine = ours.get(i.address)
            text = f"{mine.mnemonic} {mine.op_str}" if mine else "(not an instruction start)"
            print(f"    +{i.address - addr:04x} original {i.mnemonic} {i.op_str:<36} compiled {text}")
            shown += 1
            if shown == 20:
                print("    ...")
                return


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*")
    parser.add_argument("--fn", action="append", default=[], metavar="NAME")
    parser.add_argument("--update", action="store_true", help="record improvements and new functions")
    parser.add_argument("--rebaseline", action="store_true", help="record NAMEs as they are, even worse")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("-v", action="store_true", help="show the instructions that stopped matching")
    args = parser.parse_args()
    os.chdir(ROOT)
    names = args.names + args.fn
    if args.rebaseline and not names:
        sys.exit("--rebaseline needs the functions to record")
    if not args.no_build:
        # The compiler's warnings only matter when it fails.
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                build.compile_all()
        except SystemExit:
            print(out.getvalue(), end="")
            raise
    baseline = load()
    listed = set(project.config["hooks"]["allow_diff"])
    wanted = set(names) if names else set(baseline) | (listed if args.update else set())
    found = measure(wanted)
    entries = dict(baseline)
    regressed = improved = 0
    for name in sorted(wanted, key=lambda n: (n not in found, found[n][0] if n in found else 0, n)):
        old = baseline.get(name)
        m = found.get(name)
        if m is None:
            print(f"GONE      {name}: not compiled")
            if args.update and old:
                del entries[name]
            continue
        addr, size, compiled, match, ok = m[:5]
        label = f"{addr:08x} {name}: {len(match)}/{size} bytes match, compiled {compiled}"
        if old is None:
            print(f"NEW       {label}" + ("" if args.update or args.rebaseline else " (--update records it)"))
            if args.update or args.rebaseline:
                entries[name] = entry(m)
            continue
        before = offsets(old["match"])
        lost, gained = before - match, match - before
        if ok:
            print(f"MATCHES   {label}: take it off hooks.allow_diff;"
                  + (" dropped" if args.update else " --update drops it"))
            if args.update:
                del entries[name]
        elif lost:
            regressed += 1
            print(f"REGRESSED {label}: {len(lost)} stopped matching ({', '.join(ranges(lost)[:8])}"
                  + (", ..." if len(ranges(lost)) > 8 else "") + f"), {len(gained)} started")
            if args.v:
                show(m, lost)
            if args.rebaseline:
                entries[name] = entry(m)
        elif gained or compiled != old["compiled"]:
            improved += 1
            print(f"IMPROVED  {label}: {len(gained)} started matching ({', '.join(ranges(gained)[:8])}"
                  + (", ..." if len(ranges(gained)) > 8 else "") + ")")
            if args.update or args.rebaseline:
                entries[name] = entry(m)
        else:
            print(f"SAME      {label}")
    if regressed and args.update and not args.rebaseline:
        print(f"{regressed} regressed: nothing recorded (--rebaseline NAME records one as it is)")
        return 1
    if (args.update or args.rebaseline) and entries != baseline:
        save(entries)
        print(f"recorded {os.path.relpath(BASELINE, ROOT)}")
    elif improved and not args.update:
        print(f"{improved} improved: --update records them")
    if args.rebaseline:
        return 0
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
