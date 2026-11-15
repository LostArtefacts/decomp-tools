from __future__ import annotations

from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import coff
import compare


class FunctionBoundaryTests(unittest.TestCase):
    def make_object(
        self,
        path: Path,
        code: bytes,
        defined: dict[str, tuple[int, int]],
        storage: dict[str, int],
        relocs: list[tuple[int, str, int]] | None = None,
        undefined: list[str] | None = None,
    ) -> None:
        coff.write_object(
            path,
            [(".text", coff.TEXT, code, relocs or [])],
            defined,
            undefined or [],
            {},
        )
        parsed: coff.Object = coff.Object(path)
        raw: bytearray = bytearray(path.read_bytes())
        symbol_offset: int = struct.unpack_from("<I", raw, 8)[0]
        for index, symbol in enumerate(parsed.symbols):
            if symbol is not None and symbol.name in storage:
                raw[symbol_offset + 18 * index + 16] = storage[symbol.name]
        path.write_bytes(raw)

    def extract(
        self, path: Path, symbols: dict[str, tuple[int, int]]
    ) -> dict[str, tuple[bytes, bytes]]:
        with patch.object(compare.build, "sources", return_value=[("src/test.c", str(path))]):
            return {
                name: (code, mask)
                for name, code, mask, _ in compare.compiled_functions(symbols)
            }

    def test_debug_records_do_not_truncate_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path: Path = Path(directory) / "debug.obj"
            code: bytes = b"\x55\x8b\xec\x33\xc0\x40\x5d\xc3"
            self.make_object(
                path,
                code,
                {"_first": (1, 0), ".bf": (1, 0), ".lf": (1, 2),
                 ".ef": (1, 7), ".bb": (1, 3), ".eb": (1, 6)},
                {".bf": 101, ".lf": 101, ".ef": 101, ".bb": 100, ".eb": 100},
            )
            self.assertEqual(
                self.extract(path, {"_first": (0x401000, len(code))}),
                {"_first": (code, bytes(len(code)))},
            )

    def test_static_jump_table_and_next_function_remain_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path: Path = Path(directory) / "switch.obj"
            first: bytes = b"\x55\x8b\xec\xc3"
            self.make_object(
                path,
                first + b"\0" * 4 + b"\xc3",
                {"_first": (1, 0), "$Lcase": (1, 2), "$Ltable": (1, 4),
                 "_second": (1, 8)},
                {"$Lcase": 6, "$Ltable": 3},
            )
            self.assertEqual(
                self.extract(path, {"_first": (0x401000, 4), "_second": (0x402000, 1)}),
                {"_first": (first, bytes(4)), "_second": (b"\xc3", bytes(1))},
            )

    def test_relocations_after_debug_line_record_are_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path: Path = Path(directory) / "call.obj"
            self.make_object(
                path,
                b"\x90\xe8\0\0\0\0\xc3",
                {"_first": (1, 0), ".lf": (1, 1)},
                {".lf": 101},
                [(2, "_callee", coff.REL32)],
                ["_callee"],
            )
            expected: bytes = b"\x90\xe8" + struct.pack("<i", 0x402000 - 0x401006) + b"\xc3"
            self.assertEqual(
                self.extract(path, {"_first": (0x401000, 7), "_callee": (0x402000, 1)}),
                {"_first": (expected, bytes(7))},
            )


if __name__ == "__main__":
    unittest.main()
