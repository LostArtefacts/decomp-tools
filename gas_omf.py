"""Converts a 32-bit ELF relocatable object from GNU as into an OMF
object module like MASM's, for build_watcom.py's "gas" assembler.

    gas_omf.py FILE.o FILE.obj

Each allocated ELF section but notes (.note.gnu.property) becomes a public use32 segment by its kind:
code _TEXT (class CODE), writable data _DATA (DATA), zero-initialized
_BSS (BSS) and read-only data CONST (DATA), at most one ELF section of
each kind, with the empty FLAT group MASM writes under `assume ...
FLAT`, which is every fixup's frame. Global
symbols defined in a section become PUBDEFs; undefined ones EXTDEFs.

Relocations (REL only, as GNU as writes for i386) become FIXUPPs whose
target is the symbol's segment with the symbol's offset as the
displacement, or the external with displacement 0. The addend GNU as
leaves in the bytes stays there: OMF linkers add the stored bytes to
the resolved target, as link_le.py and patch_le.py do. R_386_32 is a
segment-relative 32-bit offset. R_386_PC32 is self-relative: ELF
computes S + A - P with A in the bytes (normally -4, the field's
size), OMF S + stored - (P + 4), so the stored value becomes A + 4. A
PC32 to a symbol in its own section is resolved here, as MASM resolves
a call within its segment, and leaves no fixup.
"""
import struct
import sys
from dataclasses import dataclass

from omf import Writer

SHT_SYMTAB, SHT_RELA, SHT_NOTE, SHT_NOBITS, SHT_REL = 2, 4, 7, 8, 9
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
SHN_UNDEF, SHN_LORESERVE = 0, 0xFF00
STB_GLOBAL, STB_WEAK = 1, 2
R_386_32, R_386_PC32 = 1, 2
# ELF section alignment to OMF SEGDEF alignment
ALIGN = {0: 1, 1: 1, 2: 2, 4: 5, 16: 3, 256: 4}
KINDS = {"code": ("_TEXT", "CODE"), "data": ("_DATA", "DATA"),
         "bss": ("_BSS", "BSS"), "const": ("CONST", "DATA")}


@dataclass
class Section:
    name: str
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int

    def kind(self) -> str:
        if self.flags & SHF_EXECINSTR:
            return "code"
        if self.type == SHT_NOBITS:
            return "bss"
        return "data" if self.flags & SHF_WRITE else "const"


@dataclass
class Symbol:
    name: str
    value: int
    bind: int
    shndx: int


class Elf:
    """The sections, symbols and REL relocations of an ELF32 i386
    relocatable object."""

    def __init__(self, d: bytes) -> None:
        if d[:4] != b"\x7fELF" or d[4] != 1 or d[5] != 1:
            raise ValueError("not a little-endian ELF32 file")
        typ, machine = struct.unpack_from("<HH", d, 16)
        if typ != 1 or machine != 3:
            raise ValueError("not an i386 relocatable object")
        shoff, = struct.unpack_from("<I", d, 32)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 46)
        raw = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]
        names = raw[shstrndx][4]
        self.data = d
        self.sections = [Section(cstr(d, names + r[0]), *r[1:3], *r[4:]) for r in raw]
        self.symbols: list[Symbol] = []
        for s in self.sections:
            if s.type == SHT_SYMTAB:
                strings = self.sections[s.link].offset
                for at in range(s.offset, s.offset + s.size, 16):
                    name, value, _, info, _, shndx = struct.unpack_from("<IIIBBH", d, at)
                    self.symbols.append(Symbol(cstr(d, strings + name), value, info >> 4, shndx))
        if sum(s.type == SHT_SYMTAB for s in self.sections) > 1:
            raise ValueError("more than one symbol table")

    def contents(self, i: int) -> bytes:
        s = self.sections[i]
        return bytes(s.size) if s.type == SHT_NOBITS else self.data[s.offset:s.offset + s.size]

    def relocations(self, i: int) -> list[tuple[int, int, int]]:
        """(offset, type, symbol index) of each relocation of section `i`."""
        out = []
        for s in self.sections:
            if s.type == SHT_RELA and s.info == i:
                raise ValueError(f"RELA relocations for {self.sections[i].name}")
            if s.type == SHT_REL and s.info == i:
                for at in range(s.offset, s.offset + s.size, 8):
                    off, info = struct.unpack_from("<II", self.data, at)
                    out.append((off, info & 0xFF, info >> 8))
        return sorted(out)


def cstr(d: bytes, at: int) -> str:
    return d[at:d.index(b"\0", at)].decode()


def convert(elf: bytes, name: str) -> bytes:
    """The OMF object module for the ELF object `elf`, named `name` (its
    THEADR, the source file as MASM records it)."""
    e = Elf(elf)
    used = {sym.shndx for sym in e.symbols if sym.shndx and sym.bind in (STB_GLOBAL, STB_WEAK)}
    used |= {e.symbols[r[2]].shndx for i in range(len(e.sections)) for r in e.relocations(i)}
    segs: dict[int, int] = {}  # ELF section index to OMF segment index
    kinds: dict[str, str] = {}
    for i, s in enumerate(e.sections):
        if not s.flags & SHF_ALLOC or s.type == SHT_NOTE or (not s.size and i not in used):
            continue
        k = s.kind()
        if k in kinds:
            raise ValueError(f"{s.name} and {kinds[k]} would both be {KINDS[k][0]}")
        if s.align not in ALIGN:
            raise ValueError(f"{s.name}: no OMF alignment for {s.align}")
        kinds[k] = s.name
        segs[i] = len(segs) + 1
    for sym in e.symbols:
        if sym.bind in (STB_GLOBAL, STB_WEAK) and sym.shndx >= SHN_LORESERVE:
            raise ValueError(f"{sym.name}: absolute or common symbols are not supported")
        if sym.shndx and sym.shndx < SHN_LORESERVE and sym.shndx not in segs:
            if sym.bind in (STB_GLOBAL, STB_WEAK):
                raise ValueError(f"{sym.name} is in {e.sections[sym.shndx].name}, not in a segment")
    externs = [sym.name for sym in e.symbols if sym.bind in (STB_GLOBAL, STB_WEAK) and sym.shndx == SHN_UNDEF]

    o = Writer(name)
    flat = 1
    for n in ["FLAT"] + [x for i in segs for x in KINDS[e.sections[i].kind()]]:
        o.lname(n)
    o.rec(0x96, b"".join(o.str(n) for n in o.lnames[1:]))
    for i in segs:
        s = e.sections[i]
        seg, cls = KINDS[s.kind()]
        attr = ALIGN[s.align] << 5 | 2 << 2 | 1
        o.rec(0x99, bytes([attr]) + struct.pack("<I", s.size) + o.idx(o.lname(seg))
              + o.idx(o.lname(cls)) + o.idx(1))
    o.rec(0x9A, o.idx(o.lname("FLAT")))
    if externs:
        o.rec(0x8C, b"".join(o.str(n) + b"\0" for n in externs))
    o.rec(0x88, b"\0\xA2\1")
    for i, seg in segs.items():
        pubs = [sym for sym in e.symbols if sym.shndx == i and sym.bind in (STB_GLOBAL, STB_WEAK)]
        if pubs:
            o.rec(0x91, b"\0" + o.idx(seg) + b"".join(o.str(p.name) + struct.pack("<I", p.value) + b"\0"
                                                    for p in pubs))
    for i, seg in segs.items():
        s = e.sections[i]
        mem = bytearray(e.contents(i))
        fixups: list[tuple[int, bool, bytes, int]] = []  # offset, self-relative, target, disp
        for off, typ, si in e.relocations(i):
            sym = e.symbols[si]
            if typ not in (R_386_32, R_386_PC32):
                raise ValueError(f"{s.name}+{off:#x}: relocation type {typ} is not supported")
            if s.type == SHT_NOBITS:
                raise ValueError(f"{s.name}+{off:#x}: relocation in zero-initialized data")
            addend, = struct.unpack_from("<i", mem, off)
            if typ == R_386_PC32 and sym.shndx == i:
                struct.pack_into("<i", mem, off, sym.value + addend - off)
                continue
            if typ == R_386_PC32:
                struct.pack_into("<i", mem, off, addend + 4)
            if sym.shndx == SHN_UNDEF:
                target, disp = bytes([0x12]) + o.idx(flat) + o.idx(externs.index(sym.name) + 1), 0
            else:
                target, disp = bytes([0x10]) + o.idx(flat) + o.idx(segs[sym.shndx]), sym.value
            fixups.append((off, typ == R_386_PC32, target, disp))
        if s.type == SHT_NOBITS:
            continue
        at = 0
        while at < len(mem):
            end = min(at + 1024, len(mem))
            for off, *_ in fixups:
                if off < end < off + 4:
                    end = off
            o.rec(0xA1, o.idx(seg) + struct.pack("<I", at) + mem[at:end])
            body = b""
            for off, rel, target, disp in fixups:
                if at <= off < end:
                    where = off - at
                    body += bytes([0x80 | (not rel) << 6 | 9 << 2 | where >> 8, where & 0xFF])
                    body += target + struct.pack("<i", disp)
            if body:
                o.rec(0x9D, body)
            at = end
    o.rec(0x8A, b"\0")
    return o.bytes()


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__.split("\n\n")[1])
    with open(sys.argv[1], "rb") as f:
        elf = f.read()
    with open(sys.argv[2], "wb") as f:
        f.write(convert(elf, sys.argv[1]))


if __name__ == "__main__":
    main()
