"""Names config/symbols.csv's functions and globals from a TRX symbol
manifest (TRX's docs/symbols/tr*.txt).

    manifest.py [-n] [MANIFEST]

MANIFEST is symbols.manifest in project.toml by default. -n only prints
what would change. Its lines are

    0xADDR d NAME TYPE   a global variable
    0xADDR + NAME PROTO  a function; a row that already has a name keeps it
    0xADDR ! NAME PROTO  a function whose name replaces the row's
    0xADDR x             not a function: the row is removed
    0xADDR -             not identified yet

and everything else (comments, typedefs) is skipped. A row has a name
when it isn't a placeholder (FuncXXXXXX, FUN_XXXXXX, DataXXXXXX).

The symbol column gets the MSVC decoration of a C name: _Name for
__cdecl and data, _Name@N for __stdcall and @Name@N for __fastcall, N
the bytes of the arguments. A function without a prototype is taken to
be __cdecl. Rows the manifest names that symbols.csv lacks are added; a
function's size comes from the Ghidra analysis, a global's from its type
when that is a scalar, a pointer or an array of either.

The manifest's `# sha256` line, when there is one, must match the
original executable.
"""
import csv, hashlib, os, re, sys

import project

ROOT = project.ROOT
PATH = "config/symbols.csv"
FIELDS = ["address", "size", "name", "symbol"]
PLACEHOLDER = re.compile(r"(Func|FUN_|Data|DAT_)[0-9a-fA-F]+$")
LINE = re.compile(r"0x([0-9a-fA-F]+)\s+([d+!x-])(?:\s+(\S+)(?:\s+(.*))?)?$")
CONVENTIONS = ("__cdecl", "__stdcall", "__fastcall", "__thiscall")

SCALARS = {
    "char": 1, "signed char": 1, "unsigned char": 1, "int8_t": 1, "uint8_t": 1, "BYTE": 1,
    "bool": 1, "__int8": 1,
    "short": 2, "unsigned short": 2, "int16_t": 2, "uint16_t": 2, "__int16": 2, "WORD": 2,
    "SHORT": 2, "USHORT": 2, "WCHAR": 2,
    "int": 4, "unsigned int": 4, "long": 4, "unsigned long": 4, "int32_t": 4, "uint32_t": 4,
    "__int32": 4, "DWORD": 4, "LONG": 4, "ULONG": 4, "UINT": 4, "BOOL": 4, "float": 4,
    "HRESULT": 4, "HWND": 4, "HINSTANCE": 4, "HANDLE": 4, "LPVOID": 4, "LPSTR": 4,
    "LPTSTR": 4, "LPCTSTR": 4, "LPCSTR": 4, "LPBYTE": 4, "LPDDS": 4, "size_t": 4,
    "double": 8, "int64_t": 8, "uint64_t": 8, "__int64": 8, "LONGLONG": 8,
}
WIDE_ARGS = ("double", "int64_t", "uint64_t", "__int64", "LONGLONG", "ULONGLONG")


def split_args(text):
    """The comma-separated arguments of `text`, at the top nesting level."""
    args, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


def arg_bytes(arg):
    """The stack bytes one argument takes: 4, or 8 for a double or a
    64-bit integer passed by value."""
    if arg in ("void", "") or arg == "...":
        return 0
    if "*" in arg or "[" in arg:
        return 4
    words = arg.replace("const ", "").split()
    return 8 if any(w in WIDE_ARGS for w in words) else 4


def decorate_function(name, proto):
    """The decorated symbol of a function from its prototype, or None for
    a __thiscall, which C code can't define."""
    if not proto or "(" not in proto:
        return "_" + name
    head, _, rest = proto.partition("(")
    convention = next((c for c in CONVENTIONS if c in head.split()), "__cdecl")
    if convention == "__thiscall":
        return None
    if convention == "__cdecl":
        return "_" + name
    size = sum(arg_bytes(a) for a in split_args(rest.rsplit(")", 1)[0]))
    return f"_{name}@{size}" if convention == "__stdcall" else f"@{name}@{size}"


def data_size(name, decl):
    """A global's size from its declaration (`__int16 TrackIDs[16]`), or ""
    when its type isn't a scalar or a pointer."""
    if not decl:
        return ""
    m = re.match(r"(.*?)\b" + re.escape(name) + r"((?:\s*\[\s*\w+\s*\])*)\s*$", decl)
    if not m:
        return ""
    base, dims = m[1].strip(), re.findall(r"\[\s*(\w+)\s*\]", m[2])
    base = re.sub(r"\b(const|volatile|static|extern)\b", "", base).strip()
    if base.endswith("*"):
        size = 4
    elif base in SCALARS:
        size = SCALARS[base]
    else:
        return ""
    for d in dims:
        if not d.isdigit():
            return ""
        size *= int(d)
    return str(size)


def read_manifest(path):
    """Yields (address, kind, name, rest) for each entry, and checks its
    sha256 line against the original."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    for line in lines[:5]:
        m = re.match(r"#\s*sha256\s+([0-9a-f]{64})", line)
        if m:
            with open(project.ORIGINAL, "rb") as f:
                ours = hashlib.sha256(f.read()).hexdigest()
            if ours != m[1]:
                sys.exit(f"{path} is for sha256 {m[1]}, the original is {ours}")
    for line in lines:
        m = LINE.match(line.strip())
        if m:
            yield int(m[1], 16), m[2], m[3], (m[4] or "").strip()


def functions_sizes():
    path = project.config["ghidra"]["functions"]
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return {int(r["address"], 16): r["size"] for r in csv.DictReader(f)}


def main():
    os.chdir(ROOT)
    args = sys.argv[1:]
    dry = "-n" in args
    args = [a for a in args if a != "-n"]
    src = args[0] if args else project.config["symbols"]["manifest"]
    if not src:
        sys.exit("no manifest: set symbols.manifest in project.toml or name one")
    with open(PATH) as f:
        rows = {int(r["address"], 16): r for r in csv.DictReader(f)}
    sizes = functions_sizes()
    counts = dict(named=0, added=0, removed=0, kept=0, thiscall=0)
    for addr, kind, name, rest in read_manifest(src):
        row = rows.get(addr)
        if kind == "-":
            continue
        if kind == "x":
            if row and not row["symbol"]:
                del rows[addr]
                counts["removed"] += 1
            continue
        if kind == "d":
            symbol, size = "_" + name, data_size(name, rest)
        else:
            symbol, size = decorate_function(name, rest), sizes.get(addr, "")
            if symbol is None:
                counts["thiscall"] += 1
                symbol = ""
        if row is None:
            rows[addr] = dict(address=f"0x{addr:08x}", size=size, name=name, symbol=symbol)
            counts["added"] += 1
            continue
        unnamed = not row["name"] or PLACEHOLDER.match(row["name"])
        if kind == "!" or unnamed:
            if row["name"] != name or row["symbol"] != symbol:
                row["name"], row["symbol"] = name, symbol
                counts["named"] += 1
            if not row["size"]:
                row["size"] = size
        else:
            counts["kept"] += 1
            if not row["size"]:
                row["size"] = size
    names = {}
    for addr, row in rows.items():
        for s in row["symbol"].split():
            if s in names:
                print(f"warning: {s} at both 0x{names[s]:08x} and 0x{addr:08x}", file=sys.stderr)
            names[s] = addr
    if not dry:
        with open(PATH, "w", newline="") as f:
            w = csv.DictWriter(f, FIELDS, lineterminator="\n")
            w.writeheader()
            for addr in sorted(rows):
                w.writerow({k: rows[addr].get(k) or "" for k in FIELDS})
    print(f"{counts['named']} named, {counts['added']} added, {counts['removed']} removed,"
          f" {counts['kept']} kept their names; {len(rows)} rows"
          + (f"; {counts['thiscall']} __thiscall without a symbol" if counts["thiscall"] else "")
          + (" (dry run)" if dry else ""))


if __name__ == "__main__":
    main()
