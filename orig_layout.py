"""Links the standalone exe in the original's layout.

A project's build.hook can call link() from its link_exe() to link the
recovered objects with every function and global at the address that
config/symbols.csv records for it:

1. Code. The exe's objects are compiled with /Gy, so each function is a
   COMDAT the linker can place on its own. place_code() orders them by
   their original addresses (an /ORDER file) and pads each one with NOPs
   up to the next function, so a function no larger than the original's
   lands where it was. A larger one pushes its neighbours along until a
   gap absorbs the difference; build/layout/code.json lists them. Code
   sections of assembled files (.s, .asm) are promoted to COMDATs keyed
   by their first function, so they can be ordered too. A static function
   gets a unique external name the order file can give. A function the
   original's linker folded into an identical one (a symbols.csv row with
   several symbols) becomes an alias of the row's first. Every placed
   function is kept (/INCLUDE), referenced or not, and none is folded
   (/OPT:NOICF), so each keeps its slot.

2. Data. bind_data() writes an object whose one .data section spans the
   original's data section, with every symbols.csv global in it that the
   game's objects use but neither they nor the libraries define. It is
   linked first, so it starts the exe's .data after the runtime's
   initializer tables, and the compiled objects' own data follows it.
   With initial_data="original" the section holds the original's
   initialized bytes, and every word there that is the address of a
   recovered function becomes a relocation to it: a stand-in for the
   initializers the sources do not recover yet.

3. Layout. The link is repeated, with filler after .text and .rdata and
   room for the runtime's tables, until the bound globals sit at their
   original addresses.

Intermediate files and reports go to build/layout/.
"""
from __future__ import annotations

import collections
import contextlib
import csv
import dataclasses
import json
import os
import struct

import build
import coff
import compare_exe
import project

LAYOUT = "build/layout"
PLACED = "build/obj_placed"
COMDAT = 0x1000  # IMAGE_SCN_LNK_COMDAT
ALIGN_MASK = 0x00F00000
ALIGN_1 = 0x00100000
DATA_FLAGS = 0x40 | 0x40000000 | 0x80000000 | 0x00300000  # initialized, read, write, align 4
CODE_FILL = 0x90
NOP_FLAGS = 0x00100A00  # an empty, removed .drectve-like section


def read_rows():
    """[(address, size, [symbols])] from config/symbols.csv."""
    with open(os.path.join(project.ROOT, "config/symbols.csv")) as f:
        return [(int(r["address"], 16), int(r["size"] or 0), r["symbol"].split())
                for r in csv.DictReader(f)]


def lib_path(name):
    """The host path of a library named in exe.libs, searched like LIB."""
    if os.path.exists(name):
        return name
    for folder in build.BUILD["lib"]:
        local = folder
        if folder[:3].upper() == "C:\\":
            local = os.path.join(project.ROOT, ".wine", "drive_c", folder[3:].replace("\\", "/"))
        if not os.path.isdir(local):
            continue
        for entry in os.listdir(local):
            if entry.lower() == name.lower():
                return os.path.join(local, entry)
    return None


def archive_symbols(path):
    """The public symbols an archive (.lib) defines, from its first linker member."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"!<arch>\n":
        return set()
    size = int(data[8 + 48:8 + 58])
    body = data[68:68 + size]
    count = struct.unpack_from(">I", body, 0)[0]
    names = body[4 + 4 * count:].split(b"\0")[:count]
    return {n.decode("latin-1") for n in names}


def section_symbol(obj, number):
    """The index of section `number`'s own (static, same-name) symbol."""
    name = obj.sections[number - 1].name
    for index, sym in enumerate(obj.symbols):
        if sym and sym.section == number and sym.storage == 3 and sym.name == name and sym.value == 0:
            return index
    return None


def key_symbol(obj, number):
    """The index and symbol of the function that starts code section `number`."""
    name = obj.sections[number - 1].name
    for index, sym in enumerate(obj.symbols):
        if (sym and sym.section == number and sym.value == 0 and sym.storage in (2, 3)
                and sym.name != name and not sym.name.startswith("$")):
            return index, sym
    return None, None


@dataclasses.dataclass
class Piece:
    path: str
    section: int
    key: str  # its symbols.csv name
    name: str  # its symbol's name in the placed object
    index: int  # its symbol's index
    static: bool
    data: bytes
    relocs: list


class Rewriter:
    """Edits a COFF object's section headers, contents and symbol table in place."""

    def __init__(self, path):
        self.raw = open(path, "rb").read()
        self.nsec = struct.unpack_from("<H", self.raw, 2)[0]
        self.symptr, self.nsym = struct.unpack_from("<II", self.raw, 8)
        self.headers = bytearray(self.raw[:20 + self.nsec * 40])
        self.symtab = bytearray(self.raw[self.symptr:self.symptr + self.nsym * 18])
        self.strtab = bytearray(self.raw[self.symptr + self.nsym * 18:])
        self.data = {}  # section number: new contents
        self.relocs = {}  # section number: new relocation records

    def header(self, number):
        return 20 + (number - 1) * 40

    def flags(self, number):
        return struct.unpack_from("<I", self.headers, self.header(number) + 36)[0]

    def set_flags(self, number, flags):
        struct.pack_into("<I", self.headers, self.header(number) + 36, flags)

    def set_name(self, number, name):
        at = self.header(number)
        self.headers[at:at + 8] = name.encode().ljust(8, b"\0")

    def section_data(self, number):
        if number in self.data:
            return self.data[number]
        size, ptr = struct.unpack_from("<II", self.raw, self.header(number) + 16)
        return self.raw[ptr:ptr + size] if ptr else b""

    def section_relocs(self, number):
        if number in self.relocs:
            return self.relocs[number]
        at = self.header(number)
        ptr = struct.unpack_from("<I", self.raw, at + 24)[0]
        count = struct.unpack_from("<H", self.raw, at + 32)[0]
        return bytearray(self.raw[ptr:ptr + count * 10])

    def set_aux_length(self, sym_index, length):
        struct.pack_into("<I", self.symtab, (sym_index + 1) * 18, length)

    def rename_symbol(self, index, name):
        raw = name.encode("latin-1")
        if len(raw) <= 8:
            self.symtab[index * 18:index * 18 + 8] = raw.ljust(8, b"\0")
        else:
            struct.pack_into("<II", self.symtab, index * 18, 0, len(self.strtab))
            self.strtab += raw + b"\0"

    def add_symbol(self, name, value, section):
        """Appends an external symbol defined in `section`."""
        self.symtab += bytes(18)
        self.nsym += 1
        self.rename_symbol(self.nsym - 1, name)
        struct.pack_into("<IhHBB", self.symtab, (self.nsym - 1) * 18 + 8, value, section, 0x20,
                         coff.CLASS_EXTERNAL, 0)

    def swap_symbols(self, a, b):
        """Swaps two plain symbol records, and every relocation to them."""
        sa, sb = self.symtab[a * 18:a * 18 + 18], self.symtab[b * 18:b * 18 + 18]
        self.symtab[a * 18:a * 18 + 18], self.symtab[b * 18:b * 18 + 18] = sb, sa
        for number in range(1, self.nsec + 1):
            records = self.section_relocs(number)
            for r in range(len(records) // 10):
                target = struct.unpack_from("<I", records, r * 10 + 4)[0]
                if target in (a, b):
                    struct.pack_into("<I", records, r * 10 + 4, b if target == a else a)
            if records:
                self.relocs[number] = records

    def write(self, path):
        body = bytearray()
        start = len(self.headers)
        for number in range(1, self.nsec + 1):
            at = self.header(number)
            size, ptr, _, lineptr, _, nline = struct.unpack_from("<IIIIHH", self.raw, at + 16)
            data = self.section_data(number)
            relocs = self.section_relocs(number)
            if ptr or number in self.data:
                struct.pack_into("<II", self.headers, at + 16, len(data), start + len(body) if data else 0)
                body += data
            struct.pack_into("<I", self.headers, at + 24, start + len(body) if relocs else 0)
            struct.pack_into("<H", self.headers, at + 32, len(relocs) // 10)
            body += relocs
            if nline and number not in self.data:
                struct.pack_into("<I", self.headers, at + 28, start + len(body))
                body += self.raw[lineptr:lineptr + nline * 6]
            else:
                struct.pack_into("<I", self.headers, at + 28, 0)
                struct.pack_into("<H", self.headers, at + 34, 0)
        struct.pack_into("<II", self.headers, 8, start + len(body), self.nsym)
        struct.pack_into("<I", self.strtab, 0, len(self.strtab))
        with open(path, "wb") as f:
            f.write(self.headers + body + self.symtab + self.strtab)


def source_paths():
    """{object stem: source path relative to src/} for the exe's objects."""
    return {os.path.splitext(os.path.basename(obj))[0]: os.path.relpath(src, "src").replace(os.sep, "/")
            for src, obj in build.sources(build.EXE)}


def place_code(objects, code_start, code_end):
    """Rewrites the objects into build/obj_placed with their functions padded
    to their original addresses; returns the new paths and the /ORDER names."""
    symbols, primary = {}, {}
    for address, _, names in read_rows():
        for name in names:
            symbols.setdefault(name, address)
        primary.setdefault(address, names)
    stems = source_paths()
    pieces = collections.defaultdict(list)  # address: [Piece]
    asm = collections.defaultdict(set)  # path: promoted section numbers
    unknown = []
    for path in objects:
        obj = coff.Object(path)
        stem = os.path.splitext(os.path.basename(path))[0]
        rel = stems.get(stem, "")
        for number, sec in enumerate(obj.sections, 1):
            if not sec.flags & coff.CODE or not sec.data:
                continue
            index, sym = key_symbol(obj, number)
            if sym is None:
                unknown.append((path, number, None))
                continue
            key = sym.name if sym.name in symbols else f"{rel}:{sym.name}"
            address = symbols.get(key)
            if address is None or not code_start <= address < code_end:
                unknown.append((path, number, sym.name))
                continue
            if not sec.flags & COMDAT:
                if rel.lower().endswith(build.ASM_EXTS) and section_symbol(obj, number) is not None:
                    asm[path].add(number)
                else:
                    unknown.append((path, number, sym.name))
                    continue
            data = sec.data
            # The compiler fills a function section's tail with NOPs to its
            # alignment; keep every byte a symbol or relocation covers.
            floor = max([s.value + 1 for s in obj.symbols if s and s.section == number]
                        + [off + 4 for off, _, _ in sec.relocs])
            while len(data) > floor and data[-1] == CODE_FILL:
                data = data[:-1]
            name = sym.name
            if sym.storage == 3:
                # A static's name is not unique: give it one the order file can name.
                name = f"_layout_{stem}_{sym.name.lstrip('_')}"
            pieces[address].append(Piece(path, number, key, name, index, sym.storage == 3, data,
                                         [(o, obj.symbols[i].name, t) for o, i, t in sec.relocs]))

    # One function per address, the symbols.csv row's first that the objects
    # define (with every copy of it: an inline function each object emits).
    # A folded function identical to it becomes an alias of its symbol.
    addresses = sorted(pieces)
    chosen, aliases, removed = {}, collections.defaultdict(list), set()
    for address in addresses:
        group = pieces[address]
        rank = {n: i for i, n in enumerate(primary.get(address, []))}
        best = min(group, key=lambda p: (rank.get(p.key, len(rank)), -len(p.data)))
        chosen[address] = [p for p in group if p.key == best.key]
        for piece in group:
            if piece.key == best.key or (piece.path, piece.section) in removed:
                continue
            if piece.data == best.data and piece.relocs == best.relocs and not piece.static:
                removed.add((piece.path, piece.section))
                aliases[best.path, best.section].append(piece.name)
            else:
                unknown.append((piece.path, piece.section, piece.name))
    order, moved, pads, renames = [], [], {}, {}
    cursor = code_start
    for i, address in enumerate(addresses):
        group = chosen[address]
        size = max(len(p.data) for p in group)
        if cursor != address:
            moved.append((group[0].name, address, cursor))
        start = max(cursor, address)
        if i + 1 < len(addresses):
            end = max(addresses[i + 1], start + size)
        else:
            end = start + size + (-(start + size) % 16)
        for piece in group:
            pads[piece.path, piece.section] = piece.data + bytes([CODE_FILL]) * (end - start - len(piece.data))
            if piece.static:
                renames[piece.path, piece.section] = piece.name
        order.append(group[0].name)
        cursor = end
    if code_start not in pieces:
        moved.insert(0, ("(start)", code_start, min(addresses) if addresses else code_start))

    os.makedirs(PLACED, exist_ok=True)
    placed = []
    for path in objects:
        rewriter = Rewriter(path)
        obj = coff.Object(path)
        for number in sorted(asm.get(path, ())):
            if (path, number) not in pads:
                continue
            index = section_symbol(obj, number)
            if not rewriter.symtab[index * 18 + 17]:
                raise ValueError(f"{path}: section {number} has no auxiliary record")
            # The COMDAT's key is the first of its section's symbols after
            # the section's own.
            key, _ = key_symbol(obj, number)
            follow = next(i for i, s in enumerate(obj.symbols)
                          if i > index + 1 and s and s.section == number)
            if key != follow:
                if any(rewriter.symtab[i * 18 + 17] for i in (key, follow)):
                    raise ValueError(f"{path}: section {number}'s symbols have auxiliary records")
                rewriter.swap_symbols(key, follow)
            rewriter.set_name(number, ".text")
            rewriter.symtab[index * 18:index * 18 + 8] = b".text\0\0\0"
            rewriter.set_flags(number, rewriter.flags(number) | COMDAT)
            rewriter.symtab[(index + 1) * 18 + 14] = 2  # IMAGE_COMDAT_SELECT_ANY
        for number in range(1, len(obj.sections) + 1):
            index = section_symbol(obj, number)
            if (path, number) in removed:
                rewriter.data[number] = b""
                rewriter.relocs[number] = bytearray()
                rewriter.set_name(number, ".drectve")
                rewriter.set_flags(number, NOP_FLAGS)
                for i, sym in enumerate(obj.symbols):
                    if sym and sym.section == number and i != index:
                        struct.pack_into("<IhH", rewriter.symtab, i * 18 + 8, 0, 0, 0x20)
                        rewriter.symtab[i * 18 + 16] = coff.CLASS_EXTERNAL
                if index is not None and rewriter.symtab[index * 18 + 17]:
                    rewriter.set_aux_length(index, 0)
                    struct.pack_into("<H", rewriter.symtab, (index + 1) * 18 + 4, 0)
                continue
            if (path, number) not in pads:
                continue
            data = pads[path, number]
            rewriter.data[number] = data
            rewriter.set_flags(number, (rewriter.flags(number) & ~ALIGN_MASK) | ALIGN_1)
            if index is not None and rewriter.symtab[index * 18 + 17]:
                rewriter.set_aux_length(index, len(data))
            if (path, number) in renames:
                key, _ = key_symbol(obj, number)
                rewriter.rename_symbol(key, renames[path, number])
                rewriter.symtab[key * 18 + 16] = coff.CLASS_EXTERNAL
            for alias in aliases.get((path, number), ()):
                rewriter.add_symbol(alias, 0, number)
        out = os.path.join(PLACED, os.path.basename(path))
        rewriter.write(out)
        placed.append(out)
    names = [n[1:] if n.startswith("_") else n for n in order]
    with open(os.path.join(LAYOUT, "order.txt"), "w") as f:
        f.write("\n".join(names) + "\n")
    # The functions keep their slots even when nothing calls them.
    keep = os.path.join(PLACED, "000_keep.obj")
    directives = "".join(f" /INCLUDE:{n}" for n in order).encode()
    coff.write_object(keep, [(".drectve", NOP_FLAGS, directives, [])], {}, [], {})
    report = {"functions": len(order), "end": hex(cursor),
              "moved": [(n, hex(a), hex(c)) for n, a, c in moved],
              "aliases": {f"{p}:{n}": names for (p, n), names in aliases.items()},
              "unplaced": [(p, n, s) for p, n, s in unknown]}
    with open(os.path.join(LAYOUT, "code.json"), "w") as f:
        json.dump(report, f, indent=1)
    print(f"placed {len(order)} functions up to {cursor:#x}, {len(moved)} moved, "
          f"{sum(map(len, aliases.values()))} aliases, {len(unknown)} code sections unplaced")
    return [keep, *placed]


def bind_data(objects, data_start, data_size, initial=None, code_range=None, skip=0):
    """Writes build/obj_placed/000_data.obj, the original's data section with
    the globals the objects need from it; returns its path. The section
    leaves out the first `skip` bytes, which the linker gives to the
    runtime's initializer tables (.CRT$X*): they sort before .data."""
    defined, needed, functions = set(), set(), {}
    for path in objects:
        obj = coff.Object(path)
        for sym in obj.externals():
            if sym.section > 0 or sym.section == coff.SYM_ABSOLUTE:
                defined.add(sym.name)
                if sym.section > 0 and obj.sections[sym.section - 1].flags & coff.CODE and sym.value == 0:
                    functions.setdefault(sym.name, None)
            elif sym.section == 0:
                needed.add(sym.name)  # undefined, or a common symbol
    libraries = set()
    for name in build.EXE_CONFIG["libs"]:
        path = lib_path(name)
        if path:
            libraries |= archive_symbols(path)
    needed -= defined
    needed -= libraries
    rows = read_rows()
    bound = {}
    for address, _, names in rows:
        if data_start <= address < data_start + data_size:
            for name in names:
                if name in needed:
                    if address < data_start + skip:
                        raise ValueError(f"{name} at {address:#x} is under the runtime's tables")
                    bound[name] = address - data_start - skip
    contents = bytearray(data_size - skip)
    relocs, undefined = [], set()
    if initial is not None:
        initial = initial[skip:]
        contents[:len(initial)] = initial
        starts = {}
        for address, _, names in rows:
            if code_range and code_range[0] <= address < code_range[1]:
                name = next((n for n in names if n in functions), None)
                if name:
                    starts.setdefault(address, name)
        at = 0
        while at + 4 <= len(initial):
            value = struct.unpack_from("<I", contents, at)[0]
            if value in starts:
                struct.pack_into("<I", contents, at, 0)
                relocs.append((at, starts[value], coff.DIR32))
                undefined.add(starts[value])
                at += 4
            else:
                at += 1
    defined_syms = {name: (1, offset) for name, offset in bound.items()}
    defined_syms["_layout_data_start"] = (1, 0)
    path = os.path.join(PLACED, "000_data.obj")
    coff.write_object(path, [(".data", DATA_FLAGS, bytes(contents), relocs)],
                      defined_syms, sorted(undefined - set(bound)), {})
    missing = sorted(n for n in needed if n not in bound)
    with open(os.path.join(LAYOUT, "data.json"), "w") as f:
        json.dump({"bound": len(bound), "function_pointers": len(relocs), "unbound": missing}, f, indent=1)
    print(f"bound {len(bound)} globals, {len(relocs)} function pointers")
    return path


def filler(name, flags, size):
    path = os.path.join(PLACED, f"zzz_{name.strip('.')}_fill.obj")
    fill = bytes([CODE_FILL]) * size if flags & coff.CODE else bytes(size)
    symbol = f"_layout_{name.strip('.')}_fill"
    coff.write_object(path, [(name, flags, fill, [])], {symbol: (1, 0)}, [], {})
    return path, symbol


@contextlib.contextmanager
def exe_options(**changes):
    """Temporarily changes build.EXE_CONFIG (and build.EXE, build.EXE_MAP)."""
    saved = dict(build.EXE_CONFIG), build.EXE, build.EXE_MAP
    exe, exe_map = changes.pop("exe", None), changes.pop("exe_map", None)
    build.EXE_CONFIG.update(changes)
    if exe:
        build.EXE, build.EXE_MAP = exe, exe_map
    try:
        yield
    finally:
        build.EXE_CONFIG.clear()
        build.EXE_CONFIG.update(saved[0])
        build.EXE, build.EXE_MAP = saved[1], saved[2]


def sections(path):
    """{name: (va, vsize)} of a PE image."""
    pe = compare_exe.PE(path)
    return {name: (va, vsize) for name, (va, vsize, _, _) in pe.sections.items()}


def link(objects, *, initial_data="original", ldflags=()):
    """Links build/<name>.exe from the exe's objects in the original's layout."""
    os.makedirs(LAYOUT, exist_ok=True)
    original = compare_exe.PE(project.ORIGINAL)
    text_va, text_size = original.sections[".text"][:2]
    data_va, data_size, data_raw, data_rawsize = original.sections[".data"]
    game_end = project.config["game"].get("game_end") or text_va + text_size
    placed = place_code(objects, text_va, game_end + 1)
    initial = None
    if initial_data == "original":
        initial = original.data[data_raw:data_raw + min(data_rawsize, data_size)]
    flags = [f for f in build.EXE_CONFIG["ldflags"]]
    # Identical functions keep their own slots.
    flags += ["/ORDER:@" + build.win(os.path.join(LAYOUT, "order.txt")), "/OPT:NOICF", *ldflags]
    fills, skip = {}, 0
    for attempt in range(4):
        data = bind_data(placed, data_va, data_size, initial, (text_va, game_end + 1), skip)
        extra = [filler(name, flags_, size)[0] for name, (flags_, size) in fills.items()]
        with exe_options(link_order="source", ldflags=flags):
            build.link_exe([data, *placed, *extra], customize=False)
        ours = sections(build.EXE)
        changed = False
        for name, flags_ in ((".text", coff.TEXT), (".rdata", coff.RDATA)):
            names = list(original.sections)
            following = names[names.index(name) + 1]
            if name not in ours or following not in ours:
                continue
            gap = original.sections[following][0] - ours[following][0]
            if gap > 0:
                size = fills.get(name, (flags_, 0))[1] + gap
                fills[name] = (flags_, size)
                changed = True
                print(f"padding {name} by {gap:#x}")
                break
        start = compare_exe.read_map(build.EXE_MAP).get("_layout_data_start", (None,))[0]
        if not changed and start is not None and ours[".data"][0] == data_va and start != data_va + skip:
            skip = start - data_va
            changed = True
            print(f"leaving {skip:#x} bytes to the runtime's tables")
        if not changed:
            break
    report(ours, original, data_va + skip)


def report(ours, original, data_va):
    exe_map = compare_exe.read_map(build.EXE_MAP)
    rows = read_rows()
    placed = moved = 0
    for address, _, names in rows:
        hit = next((exe_map[n][0] for n in names if n in exe_map), None)
        if hit is None:
            continue
        if hit == address:
            placed += 1
        else:
            moved += 1
    for name, (va, vsize, _, _) in original.sections.items():
        mine = ours.get(name)
        state = "missing" if not mine else ("same address" if mine[0] == va else f"at {mine[0]:#x}")
        print(f"  {name:8} original {va:#x}+{vsize:#x}, ours {state}" + (f"+{mine[1]:#x}" if mine else ""))
    start = exe_map.get("_layout_data_start", (None,))[0]
    print(f"{placed} symbols at their original addresses, {moved} elsewhere; "
          f"the original's data at {start:#x}" if start is not None else "")
    if start is not None and start != data_va:
        print(f"warning: the bound globals are not at their original addresses ({start:#x}, not {data_va:#x})")
