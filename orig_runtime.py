"""Relinks the runtime library's members in the original's order.

The linker lays out an archive's members in the order it happens to pull
them in, which depends on the order it meets undefined symbols. To give
the runtime (a project's exe.runtime libraries, libc.lib by default) the
original's layout, orig_layout links the members a first link selected
as explicit objects instead, sorted by where their code (or, for data-only
members, their data) sits in the original:

- members() reads an archive; extract() writes the members a link map
  names to build/obj_runtime/.
- match_code() finds each member code section in the original's code by
  its bytes, relocation operands masked, and keeps each member in one run.
- order() sorts the members by those addresses.
- write() renames the members' code sections to `.text$x`, so they follow
  the import thunks the libraries before the runtime contribute to .text,
  and adds aliases: a game function the original's linker folded into a
  runtime function becomes a symbol on that function.
- tail_library() renames the code sections of a library after the runtime
  (kernel32.lib's thunks) to `.text$y`, so they stay after the runtime.
"""
from __future__ import annotations

import collections
import os
import re
import struct

import coff

RUNTIME = "build/obj_runtime"
CODE_GROUP = ".text$x"
TAIL_GROUP = ".text$y"


def headers(archive):
    """(header offset, size) of each member of a COFF archive."""
    pos = 8
    while pos + 60 <= len(archive):
        if archive[pos + 58:pos + 60] != b"`\n" and archive[pos + 57:pos + 59] == b"`\n":
            pos -= 1  # an odd member the archiver did not pad
        size = int(archive[pos + 48:pos + 58])
        yield pos, size
        pos += 60 + size + (size & 1)


def members(path):
    """[(name, contents)] of a COFF archive's object members, names
    lowercased and without folders."""
    with open(path, "rb") as f:
        raw = f.read()
    longnames, files = b"", []
    for pos, length in headers(raw):
        head = raw[pos:pos + 60]
        name = head[:16].decode("latin-1").strip()
        data = raw[pos + 60:pos + 60 + length]
        if name == "//":
            longnames = data
        elif name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            full = longnames[off:].split(b"\0")[0].split(b"/\n")[0].decode("latin-1")
            files.append((full.replace("\\", "/").rsplit("/", 1)[-1].lower(), data))
        elif name not in ("/", "//"):
            files.append((name.rstrip("/").lower(), data))
    return files


def map_members(map_path, lib):
    """The members of `lib` (a file name like libc.lib) a link map lists, in
    the map's order."""
    stem = os.path.splitext(os.path.basename(lib))[0].lower()
    found = []
    pattern = re.compile(r"\s(\S+):(\S+)\s*$")
    with open(map_path, encoding="latin-1") as f:
        for line in f:
            m = pattern.search(line)
            if m and m.group(1).lower() == stem:
                name = m.group(2).lower()
                if name not in found:
                    found.append(name)
    return found


def extract(map_path, lib_name, lib_path):
    """Writes the members of the library the map uses to build/obj_runtime;
    returns their paths."""
    wanted = map_members(map_path, lib_name)
    os.makedirs(RUNTIME, exist_ok=True)
    contents = {}
    for name, data in members(lib_path):
        if name in wanted and data[:2] == b"\x4c\x01":
            if name in contents and contents[name] != data:
                raise ValueError(f"{lib_name} has two members named {name}")
            contents[name] = data
    paths = []
    stem = os.path.splitext(os.path.basename(lib_name))[0].lower()
    for name in wanted:
        if name not in contents:
            continue
        # The map names the library: compare_exe reads `libc~ftol.obj` as libc's.
        path = os.path.join(RUNTIME, f"{stem}~{name}")
        with open(path, "wb") as f:
            f.write(contents[name])
        paths.append(path)
    return paths


def mask_of(sec):
    return {off + i for off, _, _ in sec.relocs for i in range(4)}


def masked_equal(data, mask, image):
    return len(image) >= len(data) and all(
        a == b or i in mask for i, (a, b) in enumerate(zip(data, image)))


def find_masked(data, mask, image, lo, hi):
    """Offsets in image[lo:hi] where `data` sits, masked bytes ignored."""
    best, start = (0, 0), 0
    for k in range(len(data) + 1):
        if k == len(data) or k in mask:
            if k - start > best[1] - best[0]:
                best = (start, k)
            start = k + 1
    a, b = best[0], min(best[1], best[0] + 16)
    if b - a < 2:
        return []
    hits, at = [], lo
    while True:
        found = image.find(data[a:b], at, hi)
        if found < 0:
            return hits
        base = found - a
        if base >= lo and base + len(data) <= hi and all(
                image[base + i] == data[i] or i in mask for i in range(len(data))):
            hits.append(base)
        at = found + 1


def code_sections(obj):
    return [n for n, sec in enumerate(obj.sections, 1) if sec.flags & coff.CODE and sec.data]


def trimmed(sec):
    """A code section without the alignment NOPs the compiler ends it with."""
    data = sec.data
    floor = max([off + 4 for off, _, _ in sec.relocs] + [0])
    while len(data) > max(floor, 1) and data[-1] in (0x90, 0xCC):
        data = data[:-1]
    return data


def references(entries, read):
    """What the relocations of sections at known original addresses point
    at in the original: entries are (path, obj, section, address), `read`
    reads the original. Returns {(path, section): base} for the sections
    their symbols are defined in, {name: address} for externals and
    {(path, symbol index): address} for defined symbols. Conflicting
    answers are dropped."""
    bases, names, symbols, bad = {}, {}, {}, set()

    def note(table, key, value):
        if key in table and table[key] != value:
            bad.add(key)
        table.setdefault(key, value)

    for path, obj, number, address in entries:
        sec = obj.sections[number - 1]
        image = read(address, len(sec.data))
        if len(image) < len(sec.data):
            continue
        for off, index, kind in sec.relocs:
            if kind not in (coff.DIR32, coff.REL32) or off + 4 > len(sec.data):
                continue
            value, = struct.unpack_from("<I", image, off)
            addend, = struct.unpack_from("<I", sec.data, off)
            if kind == coff.DIR32:
                target = (value - addend) & 0xFFFFFFFF
            else:
                target = (value + address + off + 4 - addend) & 0xFFFFFFFF
            sym = obj.symbols[index]
            if sym.section > 0:
                note(bases, (path, sym.section), (target - sym.value) & 0xFFFFFFFF)
                note(symbols, (path, index), target)
            elif sym.section == 0 and sym.storage == coff.CLASS_EXTERNAL:
                note(names, sym.name, target)
    for key in bad:
        bases.pop(key, None)
        names.pop(key, None)
        symbols.pop(key, None)
    return bases, names, symbols


def targets(obj, number):
    return [(off, obj.symbols[i].name, kind) for off, i, kind in obj.sections[number - 1].relocs]


def match_code(paths, text, text_va, lo, hi, known=None, live=None):
    """{(path, section): address} of the members' code in the original's
    code range [lo, hi). known gives original addresses by symbol name: a
    section keyed by one of them goes there, and a call to one rules out
    places where the original calls something else. A member's sections
    are one run in the original, so a section that still matches several
    places takes the one nearest to its member's unambiguous sections,
    outside every other member's run."""
    known = known or {}
    candidates, objs = {}, {}
    for path in paths:
        obj = objs[path] = coff.Object(path)
        for number in code_sections(obj):
            sec = obj.sections[number - 1]
            external = [y.name for y in obj.symbols if y and y.section == number and y.value == 0
                        and y.storage == coff.CLASS_EXTERNAL]
            if live is not None and external and not any(n in live for n in external):
                continue  # the link discards it
            data = trimmed(sec)
            hits = [text_va + h for h in find_masked(data, mask_of(sec), text, lo - text_va, hi - text_va)]
            keys = [y.name for y in obj.symbols if y and y.section == number and y.value == 0
                    and y.storage == coff.CLASS_EXTERNAL]
            fixed = [known[k] for k in keys if k in known]
            calls = [(off, obj.symbols[i].name) for off, i, kind in sec.relocs
                     if kind == coff.REL32 and obj.symbols[i].name in known]

            def agrees(at):
                for off, name in calls:
                    value, = struct.unpack_from("<i", text, at - text_va + off)
                    if at + off + 4 + value != known[name]:
                        return False
                return True

            # symbols.csv can be wrong: a filter that leaves nothing is ignored.
            hits = [h for h in hits if h in fixed] or hits
            hits = [h for h in hits if agrees(h)] or hits
            if hits:
                candidates[path, number] = (hits, len(data), bool(fixed))
    # The original's linker folded identical functions (ICF): several
    # sections can match one place. The one symbols.csv names there, or
    # else the one from the member with most other code nearby, owns it;
    # the others fold into it.
    claims = collections.defaultdict(list)
    for key, (hits, _, _) in candidates.items():
        if len(hits) == 1:
            claims[hits[0]].append(key)
    chosen, folds = {}, {}
    unique = {k[0]: [h[0] for kk, (h, _, _) in candidates.items() if kk[0] == k[0] and len(h) == 1]
              for k in candidates}
    for address, keys in claims.items():
        def rank(key):
            near = sum(1 for a in unique[key[0]] if abs(a - address) < 0x1000)
            return (not candidates[key][2], -near, key[1])
        owner = min(keys, key=rank)
        chosen[owner] = address
        for key in keys:
            if key != owner and targets(objs[key[0]], key[1]) == targets(objs[owner[0]], owner[1]):
                folds[key] = owner
    claimed = sorted((a, a + candidates[k][1]) for k, a in chosen.items())
    starts = {a: k for k, a in chosen.items()}

    def free(a, size):
        return all(a + size <= s or a >= e for s, e in claimed)

    for key, (hits, size, _) in sorted(candidates.items(), key=lambda kv: len(kv[1][0])):
        if key in chosen or key in folds:
            continue
        own = [a for k, a in chosen.items() if k[0] == key[0]]
        options = [a for a in hits if free(a, size)]
        if not options:
            same = [a for a in hits if a in starts and candidates[starts[a]][1] == size
                    and targets(objs[key[0]], key[1]) == targets(objs[starts[a][0]], starts[a][1])]
            if same:
                folds[key] = starts[same[0]]
            continue
        if own:
            pick = min(options, key=lambda a: min(abs(a - o) for o in own))
        else:
            pick = options[0]
        chosen[key] = pick
        starts[pick] = key
        claimed.append((pick, pick + size))
        claimed.sort()
    return chosen, folds


def order(paths, code_at, data_at, bss_at=None):
    """The members in the original's order: by their code's address, with
    each data-only member before the first member whose initialized (or
    else zero-initialized) data follows its own."""
    bss_at = bss_at or {}
    code = {p: min(a for (q, _), a in code_at.items() if q == p)
            for p in paths if any(q == p for q, _ in code_at)}
    ordered = sorted(code, key=code.get)
    rest = [p for p in paths if p not in code]
    for path in sorted(rest, key=lambda p: (data_at.get(p, 1 << 40), bss_at.get(p, 1 << 40))):
        index = len(ordered)
        for table in (data_at, bss_at):
            at = table.get(path)
            if at is not None:
                index = next((i for i, q in enumerate(ordered) if table.get(q, -1) > at), len(ordered))
                break
        ordered.insert(index, path)
    return ordered


def write(paths, rewriter_class, aliases, dropped=()):
    """Rewrites the members in place: code sections become `.text$x`,
    aliases {(path, section): [(name, offset)]} are added and the `dropped`
    {(path, section): {symbol index: new name}} are removed (their functions
    are defined elsewhere, under the new names)."""
    for path in paths:
        obj = coff.Object(path)
        rewriter = rewriter_class(path)
        for number in code_sections(obj):
            if (path, number) in dropped:
                rewriter.remove(obj, number, dropped[path, number])
                continue
            rewriter.set_name(number, CODE_GROUP)
            for index, sym in enumerate(obj.symbols):
                if sym and sym.section == number and sym.storage == 3 and sym.name == ".text":
                    rewriter.symtab[index * 18:index * 18 + 8] = CODE_GROUP.encode().ljust(8, b"\0")
            for name, offset in aliases.get((path, number), ()):
                rewriter.add_symbol(name, offset, number)
        rewriter.write(path)


def tail_library(lib_path, out):
    """Writes a copy of a library whose members' code sections are
    `.text$y`; returns its path."""
    archive = bytearray(open(lib_path, "rb").read())
    for pos, size in list(headers(archive)):
        start = pos + 60
        if archive[start:start + 2] == b"\x4c\x01":
            count, = struct.unpack_from("<H", archive, start + 2)
            optional, = struct.unpack_from("<H", archive, start + 16)
            for index in range(count):
                at = start + 20 + optional + index * 40
                flags, = struct.unpack_from("<I", archive, at + 36)
                if flags & coff.CODE and archive[at:at + 8] == b".text\0\0\0":
                    archive[at:at + 8] = TAIL_GROUP.encode().ljust(8, b"\0")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(archive)
    return out
