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

2. Runtime. With link(runtime=[...]), a first link shows which members
   of the runtime libraries the game needs; they are then linked as
   objects in the original's order (orig_runtime.py), and functions the
   original's linker folded are folded again.

3. Data. bind_game_data() finds where the game objects' own data and
   zero-initialized sections (strings, statics) were in the original,
   from what matching code points at, symbols.csv or their contents, and
   removes them. It does the same for their constants (.rdata), which
   bind_rdata() puts in 000_rdata.obj, before data-only library members
   (dxguid) and the runtime's constants. bind_data() then writes 000_data.obj: the original's
   data section, with every symbols.csv global the objects need, those
   sections' symbols, and every word that is a recovered function's
   address as a relocation to it. With initial_data="original" it holds
   the original's initialized bytes, a stand-in for initializers the
   sources do not recover yet. With a runtime, the game's part of the
   data section is split around the runtime's: 000_data.obj has the
   initialized part as .data and the zero-initialized part as .bss, and
   zzy_data_tail.obj, linked after the runtime, the tail (where the
   original's linker put common symbols), with the runtime's commons.

4. Layout. The link is repeated, with filler after .text and .rdata and
   room for the runtime's tables, until the bound globals sit at their
   original addresses.

5. Imports. The linker orders each DLL's imports its own way, so a link
   with base relocations finds every pointer to an import slot, and
   order_imports() puts the slots and their names in the original's
   order.

Intermediate files and reports go to build/layout/.
"""
from __future__ import annotations

import bisect
import collections
import contextlib
import csv
import dataclasses
import json
import os
import re
import shutil
import struct

import build
import coff
import compare_exe
import orig_runtime
import project

LAYOUT = "build/layout"
PLACED = "build/obj_placed"
COMDAT = 0x1000  # IMAGE_SCN_LNK_COMDAT
ALIGN_MASK = 0x00F00000
ALIGN_1 = 0x00100000
DATA_FLAGS = 0x40 | 0x40000000 | 0x80000000 | 0x00300000  # initialized, read, write, align 4
CODE_FILL = 0x90
BSS_FLAGS = 0x80 | 0x40000000 | 0x80000000 | 0x00300000  # uninitialized, read, write, align 4
NOP_FLAGS = 0x00100A00  # an empty, removed .drectve-like section
RDATA_FLAGS = 0x40 | 0x40000000 | 0x00500000  # initialized, read, align 16


def read_named_rows():
    """[(address, size, [names])] for the symbols.csv rows whose symbol
    column is empty (runtime functions the game does not define), with the
    name column as written and with a leading underscore."""
    with open(os.path.join(project.ROOT, "config/symbols.csv")) as f:
        return [(int(r["address"], 16), int(r["size"] or 0), [r["name"], "_" + r["name"]])
                for r in csv.DictReader(f) if not r["symbol"].strip() and r["name"]]


LAST_BOUND = {}  # name: address, of bind_data's last call
PLACED_AT = {}  # (object, section): the address place_code gave a function
EXTRA_ROWS = []  # (address, size, [symbols]) the project adds for the link only
ORIGINAL_DATA = None  # [(start, end, reason)] the original may still supply, from link()
LAST_SUPPLIED = []  # addresses of the nonzero bytes bind_data's last call took from the original


def read_rows():
    """[(address, size, [symbols])] from config/symbols.csv, with EXTRA_ROWS."""
    with open(os.path.join(project.ROOT, "config/symbols.csv")) as f:
        rows = [(int(r["address"], 16), int(r["size"] or 0), r["symbol"].split())
                for r in csv.DictReader(f)]
    return sorted(rows + [(a, s, list(n)) for a, s, n in EXTRA_ROWS], key=lambda r: r[0])


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


def mask_of(sec):
    """The offsets a section's relocations cover."""
    return {off + i for off, _, _ in sec.relocs for i in range(4)}


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

    def add_undefined(self, name):
        """Appends an undefined external symbol; returns its index."""
        self.add_symbol(name, 0, 0)
        return self.nsym - 1

    def retarget(self, old, new):
        """Points every relocation to symbol `old` at symbol `new`."""
        for number in range(1, self.nsec + 1):
            records = self.section_relocs(number)
            hit = False
            for r in range(len(records) // 10):
                if struct.unpack_from("<I", records, r * 10 + 4)[0] == old:
                    struct.pack_into("<I", records, r * 10 + 4, new)
                    hit = True
            if hit:
                self.relocs[number] = records

    def remove(self, obj, number, rename=None):
        """Empties section `number` and makes the symbols defined in it
        undefined externals, so another object's definitions serve them;
        rename gives some of them ({index: name}) new names."""
        index = section_symbol(obj, number)
        self.data[number] = b""
        self.relocs[number] = bytearray()
        self.set_name(number, ".drectve")
        self.set_flags(number, NOP_FLAGS)
        for i, sym in enumerate(obj.symbols):
            if sym and sym.section == number and i != index:
                struct.pack_into("<IhH", self.symtab, i * 18 + 8, 0, 0, 0x20)
                self.symtab[i * 18 + 16] = coff.CLASS_EXTERNAL
                if rename and i in rename:
                    self.rename_symbol(i, rename[i])
        if index is not None and self.symtab[index * 18 + 17]:
            self.set_aux_length(index, 0)
            struct.pack_into("<H", self.symtab, (index + 1) * 18 + 4, 0)

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


def place_code(objects, code_start, code_end, fold=None, adopt=None):
    """Rewrites the objects into build/obj_placed with their functions padded
    to their original addresses; returns the new paths and the names of the
    functions removed by `fold`, {name: bytes}: functions the original's
    linker folded into one outside [code_start, code_end) with those bytes."""
    fold, adopt = fold or {}, adopt or {}
    folded = []
    PLACED_AT.clear()
    symbols, primary = {}, {}
    for address, _, names in read_rows():
        for name in names:
            symbols.setdefault(name, address)
        primary.setdefault(address, names)
    stems = source_paths()
    pieces = collections.defaultdict(list)  # address: [Piece]
    removed = set()
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
                expected = fold.get(key)
                if (expected is not None and sym.storage == 2 and len(sec.data) >= len(expected)
                        and all(a == b or i in mask_of(sec) for i, (a, b) in enumerate(zip(sec.data, expected)))
                        and not any(sec.data[len(expected):].strip(bytes([CODE_FILL])))):
                    removed.add((path, number))
                    folded.append(sym.name)
                    continue
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
    chosen, aliases = {}, collections.defaultdict(list)
    for address in addresses:
        group = pieces[address]
        rank = {n: i for i, n in enumerate(primary.get(address, []))}
        best = min(group, key=lambda p: (rank.get(p.key, len(rank)), -len(p.data)))
        chosen[address] = [p for p in group if p.key == best.key]
        aliases[best.path, best.section] += adopt.get(address, [])
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
            PLACED_AT[piece.path, piece.section] = start
            if piece.static:
                renames[piece.path, piece.section] = piece.name
        order.append(group[0].name)
        cursor = end
    if code_start not in pieces:
        moved.insert(0, ("(start)", code_start, min(addresses) if addresses else code_start))
    # The linker drops a function nothing refers to, /INCLUDE or not (the
    # original's, compiled without /Gy, kept theirs): refer to each from
    # the filler after a function before it, with an addend that keeps
    # the filler's bytes.
    referenced = set()
    for path in objects:
        obj = coff.Object(path)
        for sec in obj.sections:
            if sec.name.startswith(".debug") or sec.flags & 0xA00:  # never linked
                continue
            referenced.update(obj.symbols[i].name for _, i, _ in sec.relocs)
    keeps, room, hosts = collections.defaultdict(list), {}, []
    for address in addresses:
        group = chosen[address]
        best = group[0]
        if not best.static and best.name not in referenced and not adopt.get(address):
            host = next((h for h in reversed(hosts) if room[h] + 4 <= len(pads[h])), None)
            if host is None:
                print(f"warning: no filler before {best.name} to keep it by")
            else:
                fill, = struct.unpack_from("<I", pads[host], room[host])
                at = PLACED_AT[best.path, best.section]
                keeps[host].append((room[host], best.name, (fill - at) & 0xFFFFFFFF))
                room[host] += 4
            continue
        for piece in group:
            room[piece.path, piece.section] = len(piece.data)
        hosts.append((best.path, best.section))

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
        empty = orig_runtime.empty_data(obj)
        for number in range(1, len(obj.sections) + 1):
            index = section_symbol(obj, number)
            if (path, number) in removed:
                rewriter.remove(obj, number)
                continue
            if number in empty:
                rewriter.remove(obj, number)
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
            if keeps.get((path, number)):
                data = bytearray(data)
                records = rewriter.section_relocs(number)
                for offset, target, addend in keeps[path, number]:
                    struct.pack_into("<I", data, offset, addend)
                    index = next((i for i, y in enumerate(obj.symbols) if y and y.name == target), None)
                    if index is None:
                        index = rewriter.add_undefined(target)
                    records += struct.pack("<IIH", offset, index, coff.DIR32)
                rewriter.data[number] = bytes(data)
                rewriter.relocs[number] = records
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
    return [keep, *placed], folded


def bind_data(objects, data_start, data_size, initial=None, code_range=None, skip=0,
              bindings=None, data_relocs=(), split=None, compiled=()):
    """Writes build/obj_placed/000_data.obj, the original's data section with
    the globals the objects need from it; returns [its path]. The section
    leaves out the first `skip` bytes, which the linker gives to the
    runtime's initializer tables (.CRT$X*): they sort before .data.

    bindings ({name: address}) and data_relocs ([(address, target, type,
    addend)]) come from bind_game_data. With split ({"data_end": address,
    "bss": (start, end), "tail": (start, end)}), the runtime's own data and
    zero-initialized data sit between: 000_data.obj then has the
    initialized game data up to data_end as .data and the bss range as
    .bss, and a second object (returned second, to link after the
    runtime) has the tail as .bss. compiled ([(address, bytes)], from
    bind_game_data) is the compiled initialized data, which goes over
    `initial`; data.json lists what `initial` still supplies."""
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
    bound = {}  # name: address
    for address, _, names in rows:
        if data_start <= address < data_start + data_size:
            for name in names:
                if name in needed:
                    bound[name] = address
    bound.update(bindings or {})
    for name, address in bound.items():
        if address < data_start + skip:
            raise ValueError(f"{name} at {address:#x} is under the runtime's tables")
    contents = bytearray(data_size)
    relocs = []
    own = bytearray(data_size)  # 1 where compiled data covers the section
    for address, data in compiled:
        contents[address - data_start:address - data_start + len(data)] = data
        own[address - data_start:address - data_start + len(data)] = b"\1" * len(data)
    for address, _, _, _ in data_relocs:
        own[address - data_start:address - data_start + 4] = b"\1" * 4
    supplied = []
    used = min(len(initial or b""), (split["data_end"] - data_start) if split else data_size)
    if initial is not None:
        for at in range(skip, used):
            if not own[at]:
                contents[at] = initial[at]
                if initial[at]:
                    supplied.append(at)
        starts = {}
        for address, _, names in rows:
            if code_range and code_range[0] <= address < code_range[1]:
                name = next((n for n in names if n in functions), None)
                if name:
                    starts.setdefault(address, name)
        at = skip
        while at + 4 <= used:
            value = struct.unpack_from("<I", contents, at)[0]
            if value in starts and not any(own[at:at + 4]):
                relocs.append((data_start + at, starts[value], coff.DIR32, 0))
                at += 4
            else:
                at += 1
    relocs += list(data_relocs)
    paths = []
    if split is None:
        paths.append(write_data(os.path.join(PLACED, "000_data.obj"), ".data", DATA_FLAGS,
                                data_start + skip, data_start + data_size, data_start,
                                contents[skip:], bound, relocs, "_layout_data_start"))
    else:
        data_end, (bss_start, bss_end), (tail_start, tail_end) = split["data_end"], split["bss"], split["tail"]
        sections = [(".data", DATA_FLAGS, data_start + skip, data_end), (".bss", BSS_FLAGS, bss_start, bss_end)]
        defined_syms, section_relocs, undefined = {"_layout_data_start": (1, 0), "_layout_bss_start": (2, 0)}, [], set()
        bodies = []
        for number, (name, flags, start, end) in enumerate(sections, 1):
            body = bytearray(contents[start - data_start:end - data_start]) if flags == DATA_FLAGS else bytes(end - start)
            here = []
            for address, target, kind, addend in relocs:
                if start <= address < end:
                    if flags != DATA_FLAGS:
                        raise ValueError(f"a pointer at {address:#x} is in zero-initialized data")
                    struct.pack_into("<I", body, address - start, addend)
                    here.append((address - start, target, kind))
            bodies.append((name, flags, bytes(body), here))
            for sym, address in bound.items():
                if start <= address < end:
                    defined_syms[sym] = (number, address - start)
        placed_names = {n for n, a in bound.items() if any(s <= a < e for _, _, s, e in sections)
                        or tail_start <= a < tail_end}
        for _, _, _, here in bodies:
            undefined |= {t for _, t, _ in here if t not in defined_syms}
        stray = sorted(n for n in bound if n not in placed_names)
        if stray:
            print(f"warning: {len(stray)} globals are in the runtime's data: {', '.join(stray[:5])}")
        path = os.path.join(PLACED, "000_data.obj")
        coff.write_object(path, bodies, defined_syms, sorted(undefined), {})
        paths.append(path)
        if any(contents[tail_start - data_start:tail_end - data_start]):
            raise ValueError("the tail of the original's data is not zero")
        tail = {n: a for n, a in bound.items() if tail_start <= a < tail_end}
        paths.append(write_data(os.path.join(PLACED, "zzy_data_tail.obj"), ".bss", BSS_FLAGS,
                                tail_start, tail_end, data_start, bytes(tail_end - tail_start),
                                tail, [], "_layout_tail_start"))
    missing = sorted(n for n in needed if n not in bound and not n.startswith("_layout_"))
    names = {}
    for address, _, row_names in rows:
        names.setdefault(address, row_names[0] if row_names else "?")
    starts_sorted = sorted(a for a in names if data_start <= a < data_start + data_size)
    runs = {}
    for at in supplied:
        index = bisect.bisect_right(starts_sorted, data_start + at) - 1
        owner = f"{starts_sorted[index]:#x} {names[starts_sorted[index]]}" if index >= 0 else "?"
        runs[owner] = runs.get(owner, 0) + 1
    spans = []
    for at in supplied:
        if spans and at - spans[-1][1] <= 4:
            spans[-1][1] = at + 1
        else:
            spans.append([at, at + 1])
    with open(os.path.join(LAYOUT, "data.json"), "w") as f:
        json.dump({"bound": len(bound), "pointers": len(relocs), "unbound": missing,
                   "compiled_bytes": sum(own), "from_original": len(supplied),
                   "from_original_by_symbol": runs,
                   "from_original_spans": [f"{data_start + s:#x}+{e - s:#x}" for s, e in spans]},
                  f, indent=1)
    print(f"bound {len(bound)} globals, {len(relocs)} pointers, {sum(own):#x} bytes compiled, "
          f"{len(supplied):#x} nonzero bytes from the original")
    LAST_SUPPLIED[:] = [data_start + at for at in supplied]
    LAST_BOUND.clear()
    LAST_BOUND.update(bound)
    return paths


def check_original_data(supplied):
    """Fails when the original supplies nonzero game data (addresses)
    outside the ranges link()'s original_data allows; without
    original_data, warns."""
    if ORIGINAL_DATA is None:
        if supplied:
            print(f"warning: {len(supplied)} nonzero bytes of game data come from the original")
        return
    stray, used = [], set()
    for address in supplied:
        hit = next((i for i, (lo, hi, _) in enumerate(ORIGINAL_DATA) if lo <= address < hi), None)
        if hit is None:
            if stray and address - stray[-1][1] <= 4:
                stray[-1][1] = address + 1
            else:
                stray.append([address, address + 1])
        else:
            used.add(hit)
    for i, (lo, hi, why) in enumerate(ORIGINAL_DATA):
        if i not in used:
            print(f"warning: nothing comes from the original at {lo:#x}-{hi:#x} ({why}) any more")
    if stray:
        where = ", ".join(f"{lo:#x}-{hi:#x}" for lo, hi in stray[:8])
        raise ValueError(f"the original supplies game data no initializer recovers, at {where}"
                         f"{' ...' if len(stray) > 8 else ''}: define it, or allow it in original_data")


STATIC_SUFFIX = re.compile(r"\$S\d+$")
DATA_SECTIONS = (".data", ".bss")


def game_references(original):
    """What the relocations of the functions place_code put at their
    original addresses, and that match the original there, point at
    (orig_runtime.references)."""
    entries, objs = [], {}
    for (path, number), address in PLACED_AT.items():
        obj = objs.setdefault(path, coff.Object(path))
        sec = obj.sections[number - 1]
        data = orig_runtime.trimmed(sec)
        if orig_runtime.masked_equal(data, mask_of(sec), original.read(address, len(data))):
            entries.append((path, obj, number, address))
    return orig_runtime.references(entries, original.read)


def bind_game_data(placed, sources, original, refs, data_range, kinds=DATA_SECTIONS, section=".data",
                   report="game-data.json"):
    """Removes the game objects' data sections (.data, .bss) whose original
    address is known, so 000_data serves them there. An address comes from
    what matching code points at (refs, from game_references), a
    symbols.csv row for one of the section's symbols (a static by its name
    without the compiler's $S suffix), or, for initialized data, the only
    place the original has its contents. Zero-initialized statics the
    original laid out in another order are bound one by one, when no
    relocation needs their section's own symbol. Every copy of a COMDAT
    goes where one copy does. Returns ({name: address}, [(address, target,
    type, addend)] for the relocations of the removed initialized data,
    [(address, bytes)] of its contents). kinds and section select the
    sections (.rdata for the constants) and the original's section whose
    contents locate them; data_range bounds where they can go."""
    bases, names, symbols = refs
    rows = {}
    for address, _, row_names in read_rows():
        for name in row_names:
            rows.setdefault(name, address)
    va, _, raw, rawsize = original.sections[section]
    image = original.data[raw:raw + rawsize]
    lo, hi = max(data_range[0] - va, 0), min(data_range[1] - va, rawsize)
    unbound, plans, comdats, objs, deferred, loose_contents = [], {}, {}, {}, [], {}
    for path in placed:
        source = sources.get(os.path.basename(path))
        if source is None:
            continue
        obj = objs[path] = coff.Object(path)
        stem = os.path.splitext(os.path.basename(path))[0]
        sec_refs = collections.Counter(i for sec in obj.sections for _, i, _ in sec.relocs)
        plan = plans[path] = {}

        def where(index, sym):
            found = set()
            if (source, index) in symbols:
                found.add(symbols[source, index])
            for name in (sym.name, STATIC_SUFFIX.sub("", sym.name)):
                if name in names and sym.storage == coff.CLASS_EXTERNAL:
                    found.add(names[name])
                elif name in rows:
                    found.add(rows[name])
            return found

        for number, sec in enumerate(obj.sections, 1):
            if sec.name not in kinds or sec.flags & coff.CODE or not len(sec.data):
                continue
            own = section_symbol(obj, number)
            members = [(i, y) for i, y in enumerate(obj.symbols) if y and y.section == number and i != own]
            found = set()
            if (source, number) in bases:
                found.add(bases[source, number])
            each = {}
            for index, sym in members:
                at = where(index, sym)
                each[index] = at
                found |= {a - sym.value for a in at}
            initialized = not sec.flags & 0x80
            if not found and initialized and any(sec.data):
                hits = orig_runtime.find_masked(sec.data, mask_of(sec), image, lo, hi)
                hits = [h for h in hits if (va + h) % alignment(sec.flags) == 0]
                if sec.data[-1:] == b"\0":
                    # A string does not start inside another one.
                    hits = [h for h in hits if h == 0 or image[h - 1] == 0] or hits
                placed_bases = [b for b in plan.values() if isinstance(b, int)]
                if len(hits) > 1 and placed_bases:
                    near = sorted(placed_bases)[len(placed_bases) // 2]
                    hits = [min(hits, key=lambda h: abs(va + h - near))]
                if len(hits) == 1:
                    found.add(va + hits[0])
            label = f"{stem}:{number}:{sec.name}:{len(sec.data)}"
            # Constants the original's compiler emitted in another order
            # (or not at all) can still go one by one.
            loose = initialized and not sec.relocs and not sec_refs[own] and members
            if len(found) == 1:
                base = found.pop()
                if not data_range[0] <= base <= data_range[1] - len(sec.data):
                    unbound.append(f"{label} at {base:#x}")
                    continue
                here = original.read(base, len(sec.data)) if base < va + rawsize else b""
                here = here.ljust(len(sec.data), b"\0")
                if initialized and not orig_runtime.masked_equal(sec.data, mask_of(sec), here):
                    if loose:
                        deferred.append((path, number, each, label))
                    else:
                        unbound.append(f"{label} differs at {base:#x}")
                    continue
                if not initialized and any(here):
                    unbound.append(f"{label} over data at {base:#x}")
                    continue
                plan[number] = base
                if obj.sections[number - 1].flags & COMDAT:
                    for _, sym in members:
                        if sym.storage == coff.CLASS_EXTERNAL and sym.value == 0:
                            comdats[sym.name] = base
            elif (not initialized and not sec_refs[own]
                  and all(len(at) == 1 for at in each.values()) and each):
                plan[number] = {i: next(iter(at)) for i, at in each.items()}
            elif loose:
                deferred.append((path, number, each, label))
            else:
                unbound.append(label + (" (conflict)" if found else ""))
    # One by one: each constant where matching code points at it, or else
    # where the original has its bytes, preferring bytes nothing else
    # claims (read-only constants can share bytes with equal ones).
    claimed = set()
    for path, plan in plans.items():
        for number, base in plan.items():
            if isinstance(base, int) and not objs[path].sections[number - 1].flags & 0x80:
                claimed.update(range(base, base + len(objs[path].sections[number - 1].data)))
    pieces = {}
    for path, number, each, label in deferred:
        sec = objs[path].sections[number - 1]
        own = section_symbol(objs[path], number)
        offsets = sorted({y.value for i, y in enumerate(objs[path].symbols)
                          if y and y.section == number and i != own} | {len(sec.data)})
        spans = {}
        for index, sym in enumerate(objs[path].symbols):
            if sym and sym.section == number and index != own:
                spans[index] = sec.data[sym.value:offsets[offsets.index(sym.value) + 1]]
        if any(not data for data in spans.values()):
            unbound.append(label + " (empty constant)")
            continue
        pieces[path, number] = (each, spans, label)
    for (path, number), (each, spans, label) in pieces.items():
        at = {}
        for index, data in spans.items():
            known = [a for a in each.get(index, ()) if original.read(a, len(data)) == data
                     and data_range[0] <= a <= data_range[1] - len(data)]
            if not known and data.rstrip(b"\0"):
                # The span may end in the padding before an aligned
                # constant, where the original has something else.
                short = data[:max(len(data.rstrip(b"\0")), (len(data) - 1) // 4 * 4 or 1)]
                known = [a for a in each.get(index, ()) if original.read(a, len(short)) == short
                         and data_range[0] <= a <= data_range[1] - len(data)]
                if len(known) == 1:
                    spans[index] = short
            if len(known) == 1:
                at[index] = known[0]
        for index, data in spans.items():
            if index in at:
                continue
            align = 8 if len(data) >= 8 else 4
            hits = [va + h for h in orig_runtime.find_masked(data, set(), image, lo, hi)
                    if (va + h) % align == 0]
            free = [h for h in hits if not claimed & set(range(h, h + len(data)))]
            options = free or hits
            if not options:
                break
            near = list(at.values()) or [data_range[0]]
            at[index] = min(options, key=lambda h: min(abs(h - n) for n in near))
        if len(at) != len(spans):
            unbound.append(label + " (not in the original)")
            continue
        for index, address in at.items():
            claimed.update(range(address, address + len(spans[index])))
        plans[path][number] = at
        loose_contents[path, number] = {index: spans[index] for index in at}
    for path, plan in plans.items():
        obj = objs[path]
        for number, sec in enumerate(obj.sections, 1):
            if number in plan or sec.name not in kinds or not sec.flags & COMDAT:
                continue
            for sym in obj.symbols:
                if sym and sym.section == number and sym.name in comdats:
                    plan[number] = comdats[sym.name]
                    stem = os.path.splitext(os.path.basename(path))[0]
                    label = f"{stem}:{number}:{sec.name}:{len(sec.data)}"
                    if label in unbound:
                        unbound.remove(label)
    bindings, relocs, contents, bound = {}, [], [], 0
    for path, plan in plans.items():
        if not plan:
            continue
        obj = objs[path]
        stem = os.path.splitext(os.path.basename(path))[0]
        rewriter = Rewriter(path)
        new_names = {}
        for number, base in plan.items():
            own = section_symbol(obj, number)
            if own is not None and isinstance(base, int):
                name = f"_layout_{stem}_s{number}"
                rewriter.retarget(own, rewriter.add_undefined(name))
                bindings[name] = base
            rename = {}
            for index, sym in enumerate(obj.symbols):
                if not sym or sym.section != number or index == own:
                    continue
                name = sym.name
                if sym.storage != coff.CLASS_EXTERNAL:
                    name = rename[index] = f"_layout_{stem}_{index}"
                address = base + sym.value if isinstance(base, int) else base[index]
                if bindings.setdefault(name, address) != address:
                    if not obj.sections[number - 1].flags & COMDAT:
                        raise ValueError(f"{name} is bound at {bindings[name]:#x} and {address:#x}")
                    # The original has this constant twice (its compiler
                    # did not fold them): this object's copy is its own.
                    name = rename[index] = f"_layout_{stem}_{index}"
                    bindings[name] = address
                new_names[index] = name
            rewriter.remove(obj, number, rename)
        for number, base in plan.items():
            for index, data in loose_contents.get((path, number), {}).items():
                contents.append((base[index], data))
            if not isinstance(base, int):
                continue
            if not obj.sections[number - 1].flags & 0x80:
                contents.append((base, bytes(obj.sections[number - 1].data)))
            for off, index, kind in obj.sections[number - 1].relocs:
                sym = obj.symbols[index]
                if sym.section > 0 and sym.section in plan and index == section_symbol(obj, sym.section):
                    target, addend = f"_layout_{stem}_s{sym.section}", 0
                elif index in new_names or sym.storage == coff.CLASS_EXTERNAL:
                    target, addend = new_names.get(index, sym.name), 0
                elif sym.section > 0 and obj.sections[sym.section - 1].flags & coff.CODE:
                    # A label in a function, as in a __try's scope table:
                    # the function's symbol and the label's offset.
                    _, key = key_symbol(obj, sym.section)
                    if key is None or key.storage != coff.CLASS_EXTERNAL:
                        raise ValueError(f"{path}: data at {base + off:#x} points into a function "
                                         f"with no public symbol, at {sym.name}")
                    target, addend = key.name, sym.value - key.value
                else:
                    raise ValueError(f"{path}: data at {base + off:#x} points at a static {sym.name}")
                addend += struct.unpack_from("<I", obj.sections[number - 1].data, off)[0]
                relocs.append((base + off, target, kind, addend))
        rewriter.write(path)
        bound += len(plan)
    # Every copy of a COMDAT bound at one place brings the same relocations.
    unique = {}
    for reloc in relocs:
        if unique.setdefault(reloc[0], reloc) != reloc:
            raise ValueError(f"two relocations at {reloc[0]:#x}: {unique[reloc[0]]} and {reloc}")
    relocs = list(unique.values())
    with open(os.path.join(LAYOUT, report), "w") as f:
        json.dump({"bound": bound, "unbound": unbound}, f, indent=1)
    print(f"bound {bound} of the game's {'/'.join(kinds)} sections, {len(unbound)} not")
    return bindings, relocs, contents


def write_data(path, name, flags, start, end, data_start, contents, symbols, relocs, marker):
    """Writes an object with one section covering [start, end) of the
    original's data section; symbols and relocs are by address."""
    defined = {n: (1, a - start) for n, a in symbols.items() if start <= a < end}
    defined[marker] = (1, 0)
    section_relocs, undefined = [], set()
    contents = bytearray(contents)
    for address, target, kind, addend in relocs:
        if start <= address < end:
            struct.pack_into("<I", contents, address - start, addend)
            section_relocs.append((address - start, target, kind))
            if target not in defined:
                undefined.add(target)
    coff.write_object(path, [(name, flags, bytes(contents), section_relocs)], defined,
                      sorted(undefined), {})
    return path


def filler(name, flags, size):
    path = os.path.join(PLACED, f"zzz_{name.strip('.')}_fill.obj")
    if flags & coff.CODE:
        name += "$z"  # after the runtime's code groups
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


def link_runtime(placed, objects, original, code_range, runtime, flags):
    """Links once to see which runtime members the game needs, then lays
    them out as the original's (orig_runtime). Returns the placed objects
    (again, without the functions folded into the runtime), the members
    and the libraries for the final link."""
    text_va, text_size = original.sections[".text"][:2]
    data_va, data_size = original.sections[".data"][:2]
    preliminary = os.path.join(LAYOUT, "preliminary.exe")
    with exe_options(link_order="source", ldflags=flags, exe=preliminary,
                     exe_map=os.path.join(LAYOUT, "preliminary.map")):
        data = bind_data(placed, data_va, data_size)
        build.link_exe([*data, *placed], customize=False)
        map_path = build.EXE_MAP
    paths = []
    for name in runtime:
        path = lib_path(name)
        if path is None:
            raise ValueError(f"the runtime library {name} is not on the library path")
        paths += orig_runtime.extract(map_path, name, path)
        paths += loaded_members(name, path, paths, objects)
    text = original.read(text_va, text_size)
    runtime_range = (code_range[1], text_va + text_size)
    known = {}
    for address, _, names in read_rows() + read_named_rows():
        if runtime_range[0] <= address < runtime_range[1]:
            for name in names:
                known.setdefault(name, address)
    live = compare_exe.read_map(map_path)
    code_at, folds = orig_runtime.match_code(paths, text, text_va, *runtime_range, known, live)
    objs = {path: coff.Object(path) for path in paths}
    entries = [(p, objs[p], n, a) for (p, n), a in code_at.items()]
    # Where the members' data sits: from what the matching code points at,
    # then from data contents, then from what that data points at.
    bases, names, _ = orig_runtime.references(entries, original.read)
    data_lo, data_hi = original.sections[".rdata"][0], data_va + data_size
    for path, obj in objs.items():
        for number, sec in enumerate(obj.sections, 1):
            if (path, number) in bases or sec.flags & (coff.CODE | 0x80) or not sec.data:
                continue
            if sec.name.split("$")[0] not in (".data", ".rdata"):
                continue
            name = original.section_of(data_lo) if sec.name.startswith(".rdata") else ".data"
            va, _, raw, rawsize = original.sections[name]
            image = original.data[raw:raw + rawsize]
            hits = orig_runtime.find_masked(sec.data, mask_of(sec), image, 0, len(image))
            if len(hits) == 1:
                bases[path, number] = va + hits[0]
    data_entries = [(p, objs[p], n, a) for (p, n), a in bases.items()
                    if data_lo <= a < data_hi and objs[p].sections[n - 1].data
                    and not objs[p].sections[n - 1].flags & 0x80]
    more_bases, more_names, _ = orig_runtime.references(data_entries, original.read)
    for key, value in more_bases.items():
        bases.setdefault(key, value)
    for key, value in more_names.items():
        names.setdefault(key, value)
    for path, obj in objs.items():
        for sym in obj.externals():
            if sym.section > 0 and (path, sym.section) not in bases and sym.name in names:
                bases[path, sym.section] = names[sym.name] - sym.value
    # Data made only of pointers (like strftime's __lc_time_c) is found
    # by the addresses of what it points at, once those are known.
    for _ in range(3):
        found = 0
        for path, obj in objs.items():
            for number, sec in enumerate(obj.sections, 1):
                if ((path, number) in bases or sec.flags & (coff.CODE | 0x80) or not sec.data
                        or not sec.relocs or sec.name.split("$")[0] not in (".data", ".rdata")):
                    continue
                data, mask, known = bytearray(sec.data), set(), 0
                for off, index, kind in sec.relocs:
                    sym = obj.symbols[index]
                    target = None
                    if sym.section > 0 and (path, sym.section) in bases:
                        target = bases[path, sym.section] + sym.value
                    elif sym.section == 0 and sym.name in names:
                        target = names[sym.name]
                    if target is None or kind != coff.DIR32:
                        mask.update(range(off, off + 4))
                        continue
                    addend, = struct.unpack_from("<I", sec.data, off)
                    struct.pack_into("<I", data, off, (target + addend) & 0xFFFFFFFF)
                    known += 1
                if known * 2 > len(sec.relocs):
                    name = original.section_of(data_lo) if sec.name.startswith(".rdata") else ".data"
                    va, _, raw, rawsize = original.sections[name]
                    image = original.data[raw:raw + rawsize]
                    hits = orig_runtime.find_masked(bytes(data), mask, image, 0, len(image))
                    if len(hits) == 1:
                        bases[path, number] = va + hits[0]
                        found += 1
        if not found:
            break
    data_at, bss_at = {}, {}
    for (path, number), address in bases.items():
        name = objs[path].sections[number - 1].name
        table = data_at if name == ".data" else bss_at if name == ".bss" else None
        if table is not None:
            table[path] = min(table.get(path, address), address)
    members = orig_runtime.order(paths, code_at, data_at, bss_at)
    # A member's empty, aligned data section aligns the next member's data
    # only where the original has room for it.
    data_end = {}
    for (path, number), address in bases.items():
        sec = objs[path].sections[number - 1]
        if sec.name == ".data":
            data_end[path] = max(data_end.get(path, 0), address + len(sec.data))
    unaligned = set()
    for i, path in enumerate(members):
        if path not in objs or not orig_runtime.empty_data(objs[path]):
            continue
        before = next((data_end[p] for p in reversed(members[:i]) if p in data_end), None)
        after = next((data_at[p] for p in members[i + 1:] if p in data_at), None)
        if before is not None and after is not None and (before + 15) & ~15 > after:
            unaligned.add(path)
    # A game function the original's linker folded into a runtime function,
    # and a runtime function it folded into a game function.
    starts = {}
    for (path, number), address in code_at.items():
        starts[path, number] = (address, len(orig_runtime.trimmed(objs[path].sections[number - 1])))
    fold, inside = {}, {}
    for address, size, row_names in read_rows():
        if not runtime_range[0] <= address < runtime_range[1] or not size:
            continue
        for key, (start, length) in starts.items():
            if start <= address < start + length:
                for name in row_names:
                    fold[name] = original.read(address, size)
                    inside[name] = (key, address - start)
    adopt, dropped = collections.defaultdict(list), {}
    for path, obj in objs.items():
        for number in orig_runtime.code_sections(obj):
            if (path, number) in code_at:
                continue
            _, sym = key_symbol(obj, number)
            if sym is None or sym.storage != coff.CLASS_EXTERNAL:
                continue
            address = names.get(sym.name, bases.get((path, number)))
            if address is None or not code_range[0] <= address < code_range[1]:
                continue
            data = orig_runtime.trimmed(obj.sections[number - 1])
            if orig_runtime.masked_equal(data, mask_of(obj.sections[number - 1]),
                                         original.read(address, len(data))):
                adopt[address].append(sym.name)
                dropped[path, number] = {}
    placed, folded = place_code(objects, code_range[0], code_range[1], fold, adopt)
    aliases = collections.defaultdict(list)
    for name in folded:
        key, offset = inside[name]
        aliases[key].append((name, offset))
    # Runtime functions folded into identical runtime functions.
    for (path, number), owner in folds.items():
        obj = objs[path]
        stem = os.path.splitext(os.path.basename(path))[0].replace("~", "_")
        rename = {}
        for index, sym in enumerate(obj.symbols):
            if not sym or sym.section != number or index == section_symbol(obj, number):
                continue
            name = sym.name
            if sym.storage != coff.CLASS_EXTERNAL:
                name = rename[index] = f"_layout_{stem}_{index}_{sym.name.lstrip('_')}"
            aliases[owner].append((name, sym.value))
        dropped[path, number] = rename
    orig_runtime.write(members, Rewriter, aliases, dropped, unaligned)
    libs = list(build.EXE_CONFIG["libs"])
    last = max(i for i, n in enumerate(libs) if n.lower() in {r.lower() for r in runtime})
    for i in range(last + 1, len(libs)):
        path = lib_path(libs[i])
        if path:
            out = os.path.join(orig_runtime.RUNTIME, "tail", os.path.basename(path))
            libs[i] = build.win(orig_runtime.tail_library(path, out))
    with open(os.path.join(LAYOUT, "runtime.json"), "w") as f:
        json.dump({"members": members,
                   "code": {f"{p}:{n}": hex(a) for (p, n), a in sorted(code_at.items(), key=lambda kv: kv[1])},
                   "unmatched": sorted(p for p in paths if not any(q == p for q, _ in code_at)),
                   "data": {f"{p}:{n}": hex(a) for (p, n), a in sorted(bases.items(), key=lambda kv: kv[1])},
                   "folded": folded, "folded_into_game": {a: n for a, n in adopt.items()},
                   "folded_runtime": {f"{p}:{n}": f"{o[0]}:{o[1]}" for (p, n), o in folds.items()}},
                  f, indent=1)
    commons = set()
    for obj in objs.values():
        for sym in obj.externals():
            if sym.section == 0 and sym.value:
                commons.add(sym.name)
    for obj in objs.values():
        commons -= {sym.name for sym in obj.externals() if sym.section > 0}
    info = {"bases": bases, "objs": objs,
            "commons": {n: a for n, a in names.items() if n in commons and data_va <= a < data_hi}}
    print(f"runtime: {len(members)} members, {len(code_at)} code sections matched, "
          f"{len(bases)} data sections found, {len(folded)} game functions folded into it, "
          f"{sum(map(len, adopt.values()))} of its functions folded into the game's, "
          f"{len(folds)} into its own")
    return placed, members, libs, info


def loaded_members(lib_name, lib_path_, have, objects):
    """Extracts the members of the library the link loads that its map
    does not show: members whose code /OPT:REF drops, but whose data
    stays (like setlocal's). Returns their paths."""
    defined, undefined = set(), set()
    for path in [*objects, *have]:
        for sym in coff.Object(path).externals():
            (defined if sym.section > 0 or sym.value else undefined).add(sym.name)
    available = {}
    for name, data in orig_runtime.members(lib_path_):
        if data[:2] != b"\x4c\x01":
            continue
        scratch = os.path.join(LAYOUT, "member.obj")
        with open(scratch, "wb") as f:
            f.write(data)
        externals = coff.Object(scratch).externals()
        defs = {y.name for y in externals if y.section > 0 or y.value}
        available.setdefault(name, (data, defs, {y.name for y in externals if y.section == 0 and not y.value}))
    stem = os.path.splitext(os.path.basename(lib_name))[0].lower()
    taken = {os.path.basename(p).split("~", 1)[-1] for p in have if os.path.basename(p).startswith(stem + "~")}
    added = []
    while True:
        missing = undefined - defined
        name = next((n for n, (_, defs, _) in available.items() if n not in taken and defs & missing), None)
        if name is None:
            break
        data, defs, refs = available[name]
        taken.add(name)
        defined |= defs
        undefined |= refs
        out = os.path.join(orig_runtime.RUNTIME, f"{stem}~{name}")
        with open(out, "wb") as f:
            f.write(data)
        added.append(out)
    if added:
        print(f"{lib_name}: {len(added)} members the map does not show")
    return added


def defer_loose_bss(placed, members, info):
    """Moves the zero-initialized sections no original address is known
    for (the game's unbound statics, runtime members the original lays
    out elsewhere or lacks) to the end of .bss: in the link's order they
    would push the runtime's and the tail's globals along."""
    count = 0
    for path in [*placed, *members]:
        if not path.endswith(".obj") or not os.path.exists(path):
            continue
        obj = coff.Object(path)
        runtime = path in info["objs"]
        numbers = [number for number, sec in enumerate(obj.sections, 1)
                   if sec.name == ".bss" and len(sec.data) and not sec.flags & (COMDAT | 0x800)
                   and not (runtime and (path, number) in info["bases"])
                   and os.path.basename(path)[:4] not in ("000_", "zzy_", "zzx_")]
        if not numbers:
            continue
        rewriter = Rewriter(path)
        for number in numbers:
            rewriter.set_name(number, ".bss$zz")
        rewriter.write(path)
        if runtime:
            info["objs"][path] = coff.Object(path)
        count += len(numbers)
    if count:
        print(f"moved {count} zero-initialized sections of unknown address to the end")


def alignment(flags):
    shift = (flags & ALIGN_MASK) >> 20
    return 1 << (shift - 1) if shift else 16


def runtime_gaps(members, info, split, original):
    """Inserts filler objects between runtime members where the original
    leaves more room between their data (or zero-initialized data) than
    alignment explains: there the original has something the link does not.
    The filler holds the original's bytes, a stand-in for a runtime member
    this project does not extract."""
    cursors = {".data": split["data_end"], ".bss": split["bss"][1]}
    out, count = [], 0
    for path in members:
        obj = info["objs"][path]
        for number, sec in enumerate(obj.sections, 1):
            if sec.name not in cursors or not len(sec.data):
                continue
            align = alignment(sec.flags)
            cursor = cursors[sec.name]
            at = cursor + (-cursor % align)
            base = info["bases"].get((path, number))
            if base is None and sec.flags & COMDAT:
                continue  # unreferenced, /OPT:REF drops it
            # The linker can align a section further than its flags ask
            # (to 16): only a larger gap is something else.
            if base is not None and base > cursor + (-cursor % 16):
                flags = (DATA_FLAGS if sec.name == ".data" else BSS_FLAGS) & ~ALIGN_MASK | ALIGN_1
                filler_path = os.path.join(PLACED, f"zzx_gap{count}.obj")
                filler = original.read(cursor, base - cursor) if sec.name == ".data" else bytes(base - cursor)
                coff.write_object(filler_path, [(sec.name, flags, filler, [])],
                                  {f"_layout_gap{count}": (1, 0)}, [], {})
                out.append(filler_path)
                print(f"gap of {base - cursor:#x} before {path} section {number} at {base:#x}")
                count += 1
                at = base
            elif base is not None and base < at:
                print(f"warning: {path} section {number} overlaps the runtime's data before it")
            elif base is not None:
                at = base
            cursors[sec.name] = at + len(sec.data)
        out.append(path)
    if count:
        print(f"{count} gaps in the runtime's data filled")
    return out


def runtime_split(info, data_va, data_size):
    """Where the runtime's data and zero-initialized data start and end in
    the original's data section (bind_data's split), from the addresses
    link_runtime found for its sections. The starts of the game's
    zero-initialized part and of the tail are guesses the link corrects."""
    data, bss = [], []
    for (path, number), address in info["bases"].items():
        sec = info["objs"][path].sections[number - 1]
        if not data_va <= address < data_va + data_size or sec.flags & coff.CODE:
            continue
        if sec.name == ".data":
            data.append((address, address + len(sec.data)))
        elif sec.name == ".bss":
            bss.append((address, address + len(sec.data)))
    if not data or not bss:
        raise ValueError("the runtime's data was not found in the original")
    data_end = max(e for _, e in data)
    return {"data_end": min(s for s, _ in data),
            "bss": (data_end + (-data_end % 4), min(s for s, _ in bss)),
            "tail": (max(e for _, e in bss), data_va + data_size)}


def group_start(map_path, section, group):
    """The offset in PE section number `section` where a link map's
    contribution `group` (like .rdata) starts."""
    pattern = re.compile(rf"^\s*{section:04x}:([0-9a-f]{{8}})\s+[0-9a-f]{{8}}H\s+{re.escape(group)}\s")
    with open(map_path, encoding="latin-1") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                return int(m.group(1), 16)
    return None


def drop_bound_comdats(paths, bound):
    """Removes the objects' COMDAT data sections whose symbol 000_rdata.obj
    defines: the original's linker kept the game's copy (like a 1.0 the
    runtime's testfdiv shares)."""
    for path in paths:
        obj = coff.Object(path)
        drop = [number for number, sec in enumerate(obj.sections, 1)
                if sec.flags & COMDAT and not sec.flags & coff.CODE
                and (key := key_symbol(obj, number)[1]) is not None and key.name in bound]
        if drop:
            rewriter = Rewriter(path)
            for number in drop:
                rewriter.remove(obj, number)
            rewriter.write(path)


def data_members(map_path, libraries, original, refs, lo, hi):
    """The members of data-only libraries (like dxguid.lib) the link uses
    whose symbols the original has in [lo, hi), as objects in the order
    of their addresses there: the original's linker pulled them in before
    the runtime's. Returns [(address, path)]."""
    _, names, _ = refs
    rows = {}
    for address, _, row_names in read_rows():
        for name in row_names:
            rows.setdefault(name, address)
    found = []
    for name in libraries:
        path = lib_path(name)
        if path is None:
            raise ValueError(f"the data library {name} is not on the library path")
        for member in orig_runtime.extract(map_path, name, path):
            obj = coff.Object(member)
            if any(sec.flags & coff.CODE for sec in obj.sections):
                continue
            # The member's start, from each symbol the original names.
            at = {a - y.value for y in obj.externals() if y.section > 0
                  and (a := rows.get(y.name, names.get(y.name))) is not None}
            if len(at) == 1 and lo <= min(at) < hi:
                found.append((min(at), member))
    return sorted(found)


def bind_rdata(path, start, end, original, bindings, relocs, contents, fallback):
    """Writes an object with one .rdata section covering [start, end) of the
    original's .rdata: the compiled constants bound there (contents, at
    their addresses), and where nothing compiled covers it the original's
    bytes if `fallback`, else zeros. Returns its path and the number of
    bytes the original supplied."""
    body = bytearray(original.read(start, end - start)) if fallback else bytearray(end - start)
    covered = bytearray(end - start)
    for address, data in contents:
        if start <= address and address + len(data) <= end:
            body[address - start:address - start + len(data)] = data
            covered[address - start:address - start + len(data)] = b"\1" * len(data)
    gaps = [i for i, c in enumerate(covered) if not c and body[i]]
    write_data(path, ".rdata", RDATA_FLAGS, start, end, start, bytes(body),
               {n: a for n, a in bindings.items() if start <= a < end}, relocs, "_layout_rdata_start")
    runs, run = [], None
    for i in gaps:
        if run and run[1] == i:
            run[1] = i + 1
        else:
            run = [i, i + 1]
            runs.append(run)
    with open(os.path.join(LAYOUT, "rdata.json"), "w") as f:
        json.dump({"range": [hex(start), hex(end)], "from_original": len(gaps),
                   "runs": [(hex(start + a), b - a) for a, b in runs]}, f, indent=1)
    print(f"bound {len(bindings)} constants in {start:#x}-{end:#x}, "
          f"{len(gaps)} nonzero bytes {'from the original' if fallback else 'left zero'}")
    return path


def base_relocations(path):
    """The addresses of a PE image's HIGHLOW base relocations."""
    pe = compare_exe.PE(path)
    rva, size = pe.directory(5)
    sites, at = [], pe.offset(pe.base + rva)
    end = at + size
    while at < end:
        page, block = struct.unpack_from("<II", pe.data, at)
        if not block:
            break
        for i in range((block - 8) // 2):
            entry, = struct.unpack_from("<H", pe.data, at + 8 + 2 * i)
            if entry >> 12 == 3:
                sites.append(pe.base + page + (entry & 0xFFF))
        at += block
    return sites


def import_tables(pe):
    """{dll: (descriptor offset, [(name, IAT address, ILT address, hint/name address)])}."""
    rva, _ = pe.directory(1)
    out, at = {}, pe.offset(pe.base + rva)
    while True:
        ilt, _, _, name, iat = struct.unpack_from("<IIIII", pe.data, at)
        if not name:
            return out
        entries, n = [], 0
        while True:
            value, = struct.unpack_from("<I", pe.data, pe.offset(pe.base + (ilt or iat) + 4 * n))
            if not value:
                break
            func = f"#{value & 0xFFFF}" if value & 0x80000000 else pe.cstr(pe.base + value + 2)
            entries.append((func, pe.base + iat + 4 * n, pe.base + ilt + 4 * n if ilt else None,
                            None if value & 0x80000000 else pe.base + value))
            n += 1
        out[pe.cstr(pe.base + name).upper()] = (at, entries)
        at += 20


def order_imports(exe_path, map_path, relocs_path, original):
    """Rewrites a linked image's import tables in the original's order:
    each DLL's IAT and lookup table slots, and the hint/name entries where
    the original has them, moving every pointer to a slot (from the base
    relocations of relocs_path, the same link without /FIXED) and the
    map's __imp_ symbols along. A DLL whose functions differ from the
    original's is left alone. Returns the number of slots moved."""
    pe = compare_exe.PE(exe_path)
    data = bytearray(pe.data)
    theirs, ours = import_tables(original), import_tables(pe)
    slots, moved = {}, 0  # old IAT address: new
    names_old, names_new = set(), set()
    entry_moves = []  # (old hint/name address, new, size)
    ordinal_moves = []  # (new IAT address, new lookup address, ordinal)
    for dll, (_, entries) in ours.items():
        if dll not in theirs:
            continue
        target = theirs[dll][1]
        if sorted(e[0] for e in entries) != sorted(e[0] for e in target) or entries[0][1] != target[0][1]:
            print(f"warning: {dll}'s imports differ from the original's; left in the link's order")
            continue
        where = {e[0]: e for e in target}
        for func, iat, ilt, hint in entries:
            new = where[func]
            slots[iat] = new[1]
            if iat != new[1]:
                moved += 1
            if hint is None:
                # An import by ordinal: the slot holds the ordinal itself.
                new_ilt = entries[0][2] + new[1] - target[0][1] if ilt is not None else None
                ordinal_moves.append((new[1], new_ilt, 0x80000000 | int(func[1:])))
            else:
                size = len(func) + 3 + (len(func) + 3) % 2
                names_old.update(range(hint, hint + size))
                names_new.update(range(new[3], new[3] + size))
                new_ilt = entries[0][2] + new[1] - target[0][1] if ilt is not None else None
                entry_moves.append((iat, ilt, new[1], new_ilt, hint, new[3], size))
    # The hint/name entries move to the original's places only if they
    # then tile the same bytes.
    keep_names = names_old != names_new
    if keep_names:
        print("warning: the hint/name entries do not fit the original's layout; left in place")
    old_bytes = bytes(data)
    for iat, ilt, new_iat, new_ilt, hint, new_hint, size in entry_moves:
        name_at = hint if keep_names else new_hint
        if not keep_names:
            data[pe.offset(new_hint):pe.offset(new_hint) + size] = old_bytes[pe.offset(hint):pe.offset(hint) + size]
        for old, new in ((iat, new_iat), (ilt, new_ilt)):
            if new is not None:
                struct.pack_into("<I", data, pe.offset(new), name_at - pe.base)
    for new_iat, new_ilt, value in ordinal_moves:
        for at in (new_iat, new_ilt):
            if at is not None:
                struct.pack_into("<I", data, pe.offset(at), value)
    relocated = compare_exe.PE(relocs_path)
    count = 0
    for site in base_relocations(relocs_path):
        value = relocated.read(site, 4)
        if value != pe.read(site, 4):
            raise ValueError(f"the link without /FIXED differs at {site:#x}")
        target, = struct.unpack("<I", value)
        if target in slots and slots[target] != target:
            struct.pack_into("<I", data, pe.offset(site), slots[target])
            count += 1
    with open(exe_path, "wb") as f:
        f.write(data)
    with open(map_path, encoding="latin-1") as f:
        lines = f.read().splitlines()
    line_re = re.compile(r"^(\s*[0-9a-f]{4}:)([0-9a-f]{8})(\s+)(__imp_\S+)(\s+)([0-9a-f]{8})(.*)$")
    for i, line in enumerate(lines):
        m = line_re.match(line)
        if m and int(m.group(6), 16) in slots:
            address = slots[int(m.group(6), 16)]
            offset = int(m.group(2), 16) + address - int(m.group(6), 16)
            lines[i] = f"{m.group(1)}{offset:08x}{m.group(3)}{m.group(4)}{m.group(5)}{address:08x}{m.group(7)}"
    with open(map_path, "w", encoding="latin-1") as f:
        f.write("\n".join(lines) + "\n")
    print(f"moved {moved} import slots to the original's order, {count} pointers to them")
    return moved


def link(objects, *, initial_data="original", ldflags=(), extra_rows=(), runtime=(), data_libraries=(),
         original_data=None):
    """Links build/<name>.exe from the exe's objects in the original's layout.
    extra_rows are (address, size, [symbols]) rows for functions symbols.csv
    does not list, such as a source file's static initializers. runtime
    names the libraries (like libc.lib) whose members are linked in the
    original's order (orig_runtime). data_libraries name data-only
    libraries (like dxguid.lib) whose members the original has between
    the game's constants and the runtime's: they are linked as objects
    there, and the game's constants (.rdata) are bound at their original
    addresses before them. original_data, [(start, end, reason)], lists
    the only ranges where the original may still supply nonzero game
    data; anything else it supplies fails the link."""
    global ORIGINAL_DATA
    EXTRA_ROWS[:] = extra_rows
    ORIGINAL_DATA = original_data
    os.makedirs(LAYOUT, exist_ok=True)
    original = compare_exe.PE(project.ORIGINAL)
    text_va, text_size = original.sections[".text"][:2]
    data_va, data_size, data_raw, data_rawsize = original.sections[".data"]
    game_end = project.config["game"].get("game_end") or text_va + text_size
    placed, _ = place_code(objects, text_va, game_end + 1)
    initial = None
    if initial_data == "original":
        initial = original.data[data_raw:data_raw + min(data_rawsize, data_size)]
    flags = [f for f in build.EXE_CONFIG["ldflags"]]
    # Identical functions keep their own slots.
    flags += ["/ORDER:@" + build.win(os.path.join(LAYOUT, "order.txt")), "/OPT:NOICF", *ldflags]
    members, libs, info = [], list(build.EXE_CONFIG["libs"]), None
    if runtime:
        placed, members, libs, info = link_runtime(placed, objects, original, (text_va, game_end + 1),
                                                   runtime, flags)
    bindings, data_relocs, split, constants, guids, compiled = {}, [], None, [], [], []
    if info is not None:
        sources = {os.path.basename(p): p for p in objects}
        refs = game_references(original)
        rdata_va, rdata_size = original.sections[".rdata"][:2]
        number = list(sections(os.path.join(LAYOUT, "preliminary.exe"))).index(".rdata") + 1
        start = group_start(os.path.join(LAYOUT, "preliminary.map"), number, ".rdata")
        if start is not None:
            start += rdata_va
            # A runtime COMDAT (like testfdiv's 1.0) may sit at the game's
            # copy, which the original's linker kept in its place.
            ends = [a for (p, n), a in info["bases"].items()
                    if info["objs"][p].sections[n - 1].name.startswith(".rdata")
                    and not info["objs"][p].sections[n - 1].flags & COMDAT
                    and start <= a < rdata_va + rdata_size]
            end = min(ends, default=rdata_va + rdata_size)
            guids = data_members(os.path.join(LAYOUT, "preliminary.map"), data_libraries, original,
                                 refs, start, end)
            end = min([end] + [a for a, _ in guids])
            r_bindings, r_relocs, r_contents = bind_game_data(
                placed, sources, original, refs, (start, end), (".rdata",), ".rdata", "game-rdata.json")
            constants = [bind_rdata(os.path.join(PLACED, "000_rdata.obj"), start, end, original,
                                    r_bindings, r_relocs, r_contents, initial_data == "original")]
            drop_bound_comdats(members, r_bindings)
        bindings, data_relocs, compiled = bind_game_data(placed, sources, original, refs,
                                                         (data_va, data_va + data_size))
        for name, address in info["commons"].items():
            bindings.setdefault(name, address)
        split = runtime_split(info, data_va, data_size)
        defer_loose_bss(placed, members, info)
        members = runtime_gaps(members, info, split, original)
    fills, skip = {}, 0
    for attempt in range(6):
        data = bind_data(placed, data_va, data_size, initial, (text_va, game_end + 1), skip,
                         bindings, data_relocs, split, compiled)
        # Data fillers follow the game's own data, code fillers the runtime's.
        early = [filler(n, f, z)[0] for n, (f, z) in fills.items() if not f & coff.CODE]
        late = [filler(n, f, z)[0] for n, (f, z) in fills.items() if f & coff.CODE]
        with exe_options(link_order="source", ldflags=flags, libs=libs):
            inputs = [data[0], *constants, *placed, *[p for _, p in guids], *early, *members, *data[1:], *late]
            build.link_exe(inputs, customize=False)
        ours = sections(build.EXE)
        exe_map = compare_exe.read_map(build.EXE_MAP)
        shutil.copy(build.EXE_MAP, os.path.join(LAYOUT, f"attempt{attempt}.map"))
        changed = False
        for name, flags_ in ((".text", coff.TEXT), (".rdata", coff.RDATA)):
            names_ = list(original.sections)
            following = names_[names_.index(name) + 1]
            if name not in ours or following not in ours:
                continue
            gap = original.sections[following][0] - ours[following][0]
            if name == ".rdata" and gap == 0:
                # The game's constants are short of the original's: make
                # up the size, so the file's layout follows.
                gap = original.sections[name][1] - ours[name][1]
            if gap > 0:
                size = fills.get(name, (flags_, 0))[1] + gap
                fills[name] = (flags_, size)
                changed = True
                print(f"padding {name} by {gap:#x}")
                break
        start = exe_map.get("_layout_data_start", (None,))[0]
        if not changed and start is not None and ours[".data"][0] == data_va and start != data_va + skip:
            skip = start - data_va
            changed = True
            print(f"leaving {skip:#x} bytes to the runtime's tables")
        if not changed and split is not None:
            bindings_all = LAST_BOUND
            for marker, key in (("_layout_bss_start", "bss"), ("_layout_tail_start", "tail")):
                at = exe_map.get(marker, (None,))[0]
                if at is None or at == split[key][0]:
                    continue
                lost = sorted(n for n, a in bindings_all.items() if split[key][0] <= a < at)
                if lost:
                    print(f"warning: the {key} part starts at {at:#x}, not {split[key][0]:#x}, "
                          f"past {', '.join(lost[:4])}")
                    continue
                print(f"moving the {key} part from {split[key][0]:#x} to {at:#x}")
                split[key] = (at, split[key][1])
                changed = True
        if not changed:
            break
    check_original_data(LAST_SUPPLIED)
    # The linker orders each DLL's imports its own way: link again with
    # base relocations (an exe's default is /FIXED) to find every pointer
    # to them, and reorder.
    relocs_exe = os.path.join(LAYOUT, "relocs.exe")
    with exe_options(link_order="source", ldflags=[f for f in flags if f.upper() != "/FIXED"] + ["/FIXED:NO"], libs=libs,
                     exe=relocs_exe, exe_map=os.path.join(LAYOUT, "relocs.map")):
        build.link_exe(inputs, customize=False)
    order_imports(build.EXE, build.EXE_MAP, relocs_exe, original)
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
