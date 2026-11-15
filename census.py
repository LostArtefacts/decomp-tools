"""Inventory current mismatches and rank their observed instruction shapes.

    python3 tools/census.py [--output build/census]

Read the existing normal build objects after running the project comparison.
This does not compile candidates. Shape categories describe observations;
they do not establish an optimizer cause. Requires Capstone for x86 decoding.
"""

from __future__ import annotations
import argparse
import collections
import csv
import hashlib
import subprocess
import difflib
import json
import os
from pathlib import Path
import re
from typing import Any
import build
import coff
import compare
import capstone

CS: capstone.Cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
CS.skipdata = True
REGISTER: re.Pattern[str] = re.compile(r"\b(?:e?[abcd]x|[abcd][lh]|e?[sd]i|e?[bs]p)\b")
STACK: re.Pattern[str] = re.compile(r"\b(?:esp|ebp)\s*[+-]\s*(?:0x[0-9a-f]+|\d+)")


def distance(a: list[str], b: list[str]) -> int:
    matcher: difflib.SequenceMatcher[str] = difflib.SequenceMatcher(
        None, a, b, autojunk=False
    )
    return (
        len(a) + len(b) - 2 * sum(block.size for block in matcher.get_matching_blocks())
    )


def reg_shape(ins: Any) -> str:
    text: str = ins.mnemonic + " " + ins.op_str
    text = STACK.sub("STACK", text)
    return REGISTER.sub("REG", text)


def main() -> None:
    os.chdir(build.ROOT)
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("build/census"))
    args: argparse.Namespace = parser.parse_args()
    output: Path = args.output
    output.mkdir(parents=True, exist_ok=True)
    sources: dict[str, str] = {}
    object_hashes: dict[str, str] = {}
    for src, path in build.sources():
        object_hashes[path] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        obj: coff.Object = coff.Object(path)
        for symbol in obj.externals():
            if symbol.section > 0:
                sources.setdefault(symbol.name, src)
    symbols: dict[str, tuple[int, int]] = compare.read_symbols()
    rows: list[dict[str, Any]] = []
    green: int = 0
    for name, same, code, mask, orig, data in compare.results(symbols):
        if same:
            green += 1
            continue
        addr, size = symbols[name]
        shown: bytes = bytes(
            orig[i] if value and i < len(orig) else code[i]
            for i, value in enumerate(mask[: len(code)])
        )
        a: list[Any] = list(CS.disasm(shown, addr))
        b: list[Any] = list(CS.disasm(orig, addr))
        astr: list[str] = [ins.mnemonic + " " + ins.op_str for ins in a]
        bstr: list[str] = [ins.mnemonic + " " + ins.op_str for ins in b]
        am: list[str] = [ins.mnemonic for ins in a]
        bm: list[str] = [ins.mnemonic for ins in b]
        ash: list[str] = [reg_shape(ins) for ins in a]
        bsh: list[str] = [reg_shape(ins) for ins in b]
        score: int = distance(
            compare.disasm(shown, addr), compare.disasm(orig, addr)
        ) + len(data)
        if shown == orig:
            category = "referenced-data-only"
        elif collections.Counter(astr) == collections.Counter(bstr):
            category = "instruction-order-only"
        elif ash == bsh:
            category = "register-stack-operands-only"
        elif am == bm:
            category = "same-mnemonic-sequence"
        elif collections.Counter(am) == collections.Counter(bm):
            category = "same-mnemonic-multiset"
        elif len(code) == size:
            category = "same-size-instruction-change"
        elif abs(len(code) - size) <= 16:
            category = "small-size-structural-change"
        else:
            category = "larger-structural-change"
        decoded_a: int = sum(ins.size for ins in a if ins.mnemonic != ".byte")
        decoded_b: int = sum(ins.size for ins in b if ins.mnemonic != ".byte")
        coverage_complete: bool = decoded_a == len(shown) and decoded_b == len(orig)
        if not coverage_complete and category in {
            "instruction-order-only",
            "register-stack-operands-only",
            "same-mnemonic-sequence",
            "same-mnemonic-multiset",
        }:
            category = "mixed-code-or-undecodable-data"
        matcher: difflib.SequenceMatcher[str] = difflib.SequenceMatcher(
            None, astr, bstr, autojunk=False
        )
        first: dict[str, Any] | None = None
        for tag, i, j, k, retail_end in matcher.get_opcodes():
            if tag != "equal":
                first = {
                    "operation": tag,
                    "ours_offset": a[i].address - addr if i < len(a) else len(code),
                    "retail_offset": b[k].address - addr if k < len(b) else len(orig),
                    "ours": astr[i : min(j, i + 5)],
                    "retail": bstr[k : min(retail_end, k + 5)],
                }
                break
        row: dict[str, Any] = {
            "name": name,
            "source": sources.get(name, "unknown/static"),
            "address": hex(addr),
            "retail_size": size,
            "compiled_size": len(code),
            "size_delta": len(code) - size,
            "canonical_score": score,
            "instruction_count": len(b),
            "instruction_distance_capstone": distance(astr, bstr),
            "distance_fraction": round(
                distance(astr, bstr) / max(1, len(a) + len(b)), 5
            ),
            "category": category,
            "decoded_bytes_ours": decoded_a,
            "decoded_bytes_retail": decoded_b,
            "full_instruction_coverage": coverage_complete,
            "linear_decode_data_bytes": sum(
                ins.size for ins in a + b if ins.mnemonic == ".byte"
            ),
            "has_x87": any(ins.mnemonic.startswith("f") for ins in a + b),
            "mask_bytes": sum(bool(v) for v in mask),
            "referenced_data_differences": len(data),
            "first_difference": first,
        }
        rows.append(row)
    rows.sort(
        key=lambda r: (
            r["canonical_score"] / max(r["retail_size"], 1),
            -r["retail_size"],
        )
    )
    by_category: dict[str, Any] = {}
    for category in sorted({r["category"] for r in rows}):
        group: list[dict[str, Any]] = [r for r in rows if r["category"] == category]
        by_category[category] = {
            "count": len(group),
            "bytes": sum(r["retail_size"] for r in group),
            "names": [r["name"] for r in group],
        }
    tu: dict[str, Any] = {}
    for src in sorted({r["source"] for r in rows}):
        group = [r for r in rows if r["source"] == src]
        tu[src] = {
            "count": len(group),
            "bytes": sum(r["retail_size"] for r in group),
            "names": [r["name"] for r in group],
        }
    report: dict[str, Any] = {
        "baseline": {
            "green": green,
            "red": len(rows),
            "red_bytes": sum(r["retail_size"] for r in rows),
        },
        "method": "Linear disassembly includes embedded jump-table/data bytes; .byte denotes undecodable data and structural categories are broad observations only. All current normal COFF functions via compare.results; known relocations resolved, unknown mask bytes replaced with retail only for disassembly. Categories are observed instruction shapes, NOT proven compiler causes. Canonical score uses local objdump per permuter; register-shape classifier merges integer registers and stack-slot offsets only. Actual masks/data mismatches retained separately.",
        "categories": by_category,
        "translation_units": tu,
        "functions": rows,
    }
    revision: str = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=build.ROOT, text=True
    ).strip()
    source_hashes: dict[str, str] = {
        src: hashlib.sha256(Path(src).read_bytes()).hexdigest()
        for src in sorted(set(sources.values()))
    }
    report["provenance"] = {
        "object_sha256": object_hashes,
        "revision": revision,
        "source_sha256": source_hashes,
        "original_sha256": hashlib.sha256(Path(compare.EXE).read_bytes()).hexdigest(),
        "cflags": build.CFLAGS,
        "input": "Existing normal COFF objects; run project comparison first.",
    }
    (output / "census.json").write_text(json.dumps(report, indent=2) + "\n")
    columns: list[str] = [
        "name",
        "source",
        "address",
        "retail_size",
        "compiled_size",
        "size_delta",
        "canonical_score",
        "category",
        "full_instruction_coverage",
        "has_x87",
        "mask_bytes",
        "referenced_data_differences",
    ]
    with (output / "census.csv").open("w", newline="") as stream:
        writer: csv.DictWriter[str] = csv.DictWriter(
            stream, fieldnames=columns, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)
    lines: list[str] = [
        json.dumps(report["baseline"]),
        "\nOBSERVED SHAPES (not proven causes)",
    ]
    lines += [
        f'{name}: {v["count"]} functions / {v["bytes"]} bytes'
        for name, v in by_category.items()
    ]
    lines += ["\nLARGE CLOSE FUNCTIONS (>=900 bytes, ranked score/bytes)"]
    lines += [
        f'{r["name"]}: {r["retail_size"]} bytes, score {r["canonical_score"]}, delta {r["size_delta"]}, {r["category"]}, {r["source"]}'
        for r in rows
        if r["retail_size"] >= 900
    ][:35]
    lines += ["\nTU CLUSTERS (by differing bytes available)"]
    lines += [
        f'{name}: {v["count"]} red / {v["bytes"]} bytes'
        for name, v in sorted(tu.items(), key=lambda item: -item[1]["bytes"])
    ]
    (output / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
