"""Opt-in instruction ranking. compare.results alone determines acceptance."""
from __future__ import annotations
import difflib
from bisect import bisect_right
import os
import re
import struct
from dataclasses import dataclass
from functools import total_ordering
from typing import Protocol
from typing import Any
from types import NotImplementedType
import capstone as cs
from capstone import x86_const as x
import coff
import compare

Token = tuple[Any, ...]

@dataclass(frozen=True)
class Reference:
    offset: int
    kind: str
    value: Token

@dataclass(frozen=True)
class Ranking:
    broken: int
    instructions: int
    encoding: int
    actual_same: bool

    @property
    def key(self) -> tuple[int, int, int]:
        return self.broken, self.instructions, self.encoding

class Fitness:
    def __init__(self, symbols: dict[str, tuple[int, int]], image: Any, readonly: list[tuple[int, int]]) -> None:
        self.symbols = symbols
        self.image = image
        self.readonly = readonly
        self.known = {address for address, _ in symbols.values()}
        protected: list[tuple[int, int]] = []
        for start, size in sorted(set(symbols.values())):
            end = start + max(1, size)
            if protected and start <= protected[-1][1]:
                protected[-1] = (protected[-1][0], max(end, protected[-1][1]))
            else:
                protected.append((start, end))
        self.known_ranges = protected
        self.known_starts = [start for start, _ in protected]

    @classmethod
    def project(cls, symbols: dict[str, tuple[int, int]]) -> Fitness:
        image = coff.Image(os.path.join(compare.ROOT, compare.EXE))
        raw = image.data
        pe = struct.unpack_from('<I', raw, 0x3c)[0]
        count = struct.unpack_from('<H', raw, pe + 6)[0]
        optional = struct.unpack_from('<H', raw, pe + 20)[0]
        ranges: list[tuple[int, int]] = []
        for i in range(count):
            h = pe + 24 + optional + 40 * i
            size, va = struct.unpack_from('<II', raw, h + 8)
            flags = struct.unpack_from('<I', raw, h + 36)[0]
            if not flags & (0x80000000 | coff.CODE):
                ranges.append((image.base + va, image.base + va + size))
        return cls(symbols, image, ranges)

    def reference_value(self, address: int, size: int, immediate: bool) -> Token:
        known_index = bisect_right(self.known_starts, address) - 1
        if address in self.known or known_index >= 0 and address < self.known_ranges[known_index][1]:
            return ('address', address)
        if not any(a <= address and address + max(1, size) <= b for a, b in self.readonly):
            return ('address', address)
        if immediate:
            try:
                data = self.image.read(address, 256).split(b'\0', 1)
                if len(data) == 2 and all(c in (9,10,13) or 32 <= c < 127 for c in data[0]):
                    return ('string', data[0] + b'\0')
            except ValueError:
                pass
            return ('address', address)
        if size not in (1, 2, 4, 8):
            return ('address', address)
        try:
            data = self.image.read(address, size)
            if len(data) == size:
                return ('scalar', data)
        except ValueError:
            pass
        return ('address', address)

    def relocations(self, path: str, name: str) -> list[Reference]:
        obj = coff.Object(path)
        rawname = name.rsplit(':', 1)[-1]
        sym = next(s for s in obj.symbols if s and s.name == rawname and s.section > 0)
        section = obj.sections[sym.section - 1]
        end = min([s.value for s in obj.symbols if s and s.section == sym.section and s.value > sym.value and s.storage not in (compare.LABEL, compare.BLOCK, compare.FUNCTION)] or [len(section.data)])
        refs: list[Reference] = []
        for off, index, typ in section.relocs:
            if not sym.value <= off < end:
                continue
            target = obj.symbols[index]
            if target.name in self.symbols or target.section == sym.section and sym.value <= target.value < end:
                continue  # compiled_functions already resolves these accurately
            addend = int.from_bytes(section.data[off:off+4], 'little')
            token: Token = ('opaque', target.name, addend, typ)
            if typ == coff.DIR32 and target.section > 0:
                data_sec = obj.sections[target.section-1]
                found = compare.target_data(obj, target, addend)
                if found and not any(found[1]) and not data_sec.flags & 0x80000000:
                    data = found[0]
                    if target.name.startswith('$SG'):
                        token = ('string', data)
                    elif target.name.startswith('__real@') or len(data) in (1,2,4,8):
                        token = ('scalar', data)
            refs.append(Reference(off-sym.value, 'relocation', token))
        return refs

    def tokens(self, code: bytes, address: int, refs: list[Reference] | None = None) -> list[Token]:
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        decoder.detail = True
        instructions = list(decoder.disasm(code, address))
        targets: set[int] = {address}
        for ins in instructions:
            if ins.group(cs.CS_GRP_JUMP) and ins.operands and ins.operands[0].type == x.X86_OP_IMM:
                destination = ins.operands[0].imm
                if address <= destination <= address + len(code):
                    targets.add(destination)
                if ins.mnemonic != 'jmp':
                    targets.add(ins.address + ins.size)
        blocks = {target: i for i, target in enumerate(sorted(targets))}
        out: list[Token] = []
        for ins in instructions:
            relevant = [r for r in refs or [] if ins.address-address <= r.offset < ins.address-address+ins.size]
            operands: list[Token] = []
            for op in ins.operands:
                if op.type == x.X86_OP_REG:
                    operands.append(('reg', op.size, ins.reg_name(op.reg)))
                elif op.type == x.X86_OP_IMM:
                    if ins.group(cs.CS_GRP_JUMP) and op.imm in blocks:
                        value: Token = ('block', blocks[op.imm])
                    elif relevant and ins.imm_size and any(r.offset == ins.address-address+ins.imm_offset for r in relevant):
                        value = next(r.value for r in relevant if r.offset == ins.address-address+ins.imm_offset)
                    elif ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP):
                        value = ('address', op.imm)
                    else:
                        value = self.reference_value(op.imm, op.size, True)
                    operands.append(('imm', op.size, value))
                elif op.type == x.X86_OP_MEM:
                    m = op.mem
                    reference = next((r.value for r in relevant if r.offset == ins.address-address+ins.disp_offset), None)
                    value = reference if reference is not None else self.reference_value(m.disp & 0xffffffff, op.size, False) if not m.base and not m.index else ('displacement', m.disp)
                    operands.append(('mem', op.size, ins.reg_name(m.segment), ins.reg_name(m.base), ins.reg_name(m.index), m.scale, value))
                else:
                    operands.append(('operand', op.type, op.size))
            out.append((ins.mnemonic, tuple(operands)))
        consumed = sum(ins.size for ins in instructions)
        if consumed < len(code):
            out.append(('undecoded', code[consumed:]))
        return out

    def rank(self, path: str, result: Any, broken: int = 0) -> Ranking:
        name, same, code, mask, original, diffs = result
        address = self.symbols[name][0]
        ours = self.tokens(code, address, self.relocations(path, name))
        theirs = self.tokens(original, address)
        sm = difflib.SequenceMatcher(None, ours, theirs, autojunk=False)
        instruction_distance = len(ours) + len(theirs) - 2*sum(block.size for block in sm.get_matching_blocks())
        # Ignore unresolved address bytes only in secondary metric; never synthesize bytes.
        encoding = sum(not m and a != b for a,b,m in zip(code, original, mask)) + abs(len(code)-len(original))
        return Ranking(broken, instruction_distance + len(diffs), encoding, same)


@total_ordering
@dataclass(frozen=True, eq=False)
class NonMatch:
    """An ordered, truthy distance that can never compare equal to integer zero."""

    key: tuple[int, int, int]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NonMatch) and self.key == other.key

    def __lt__(self, other: object) -> bool | NotImplementedType:
        if isinstance(other, NonMatch):
            return self.key < other.key
        if isinstance(other, int) and other == 0:
            return False
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.key)

    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.key)


class RawScorer(Protocol):
    symbols: dict[str, tuple[int, int]]
    symbol_names: list[str]
    matched: set[str] | None
    why: str

    def variant(self, body: str) -> tuple[str, str, str]: ...
    def compile(self, variant: tuple[str, str, str]) -> str | None: ...
    def results(self, obj: str) -> list[Any]: ...


class RelocationScorer:
    """Opt-in adapter for permute.Scorer; no changes to comparison acceptance.

    Positional /Zd hot-line focus is disabled. The wrapped scorer's original
    disassembly display still masks relocations positionally and is diagnostic
    only; it is never used for this ranking.
    """

    def __init__(self, raw: RawScorer) -> None:
        self.raw = raw
        self.fitness = Fitness.project(raw.symbols)
        self.baseline_masks: dict[str, int] | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)

    def hot_lines(self, variant: tuple[str, str, str]) -> set[int]:
        return set()

    def score(self, variant: str | tuple[str, str, str]) -> NonMatch | int | None:
        if isinstance(variant, str):
            variant = self.raw.variant(variant)
        obj = self.raw.compile(variant)
        if obj is None:
            return None
        try:
            every = self.raw.results(obj)
            target = [row for row in every if row[0] in self.raw.symbol_names]
            if not target:
                self.raw.why = 'compiled object defines none of the target symbols'
                return None
            matched = {row[0] for row in every if row[1] and row[0] not in self.raw.symbol_names}
            if self.raw.matched is None:
                self.raw.matched = matched
            if self.baseline_masks is None:
                self.baseline_masks = {row[0]: sum(bool(byte) for byte in row[3]) for row in every}
            broken = len(self.raw.matched - matched)
            broken += sum(sum(bool(byte) for byte in row[3]) > self.baseline_masks.get(row[0], 0) for row in every)
            broken += sum(bool(row[5]) for row in every)
            exact = all(any(row[0] == name and row[1] for row in target) for name in self.raw.symbol_names)
            if exact and not broken:
                return 0
            ranks = [self.fitness.rank(obj, row) for row in target]
            return NonMatch((broken, sum(rank.instructions for rank in ranks), sum(rank.encoding for rank in ranks)))
        finally:
            os.remove(obj)
