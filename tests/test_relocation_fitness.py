from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
import sys
import io
from contextlib import redirect_stderr
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import relocation_fitness as fitness
import permute
import coff
import compare

class Image:
    def read(self, address: int, size: int) -> bytes:
        return {0x5000: b'\x00\x00\x80\x3f', 0x5004: b'\x00\x00\x00\x40'}[address][:size]

class FitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rank = fitness.Fitness({'_f': (0x1000, 7), '_a':(0x6000,4), '_b':(0x6004,4)}, Image(), [(0x5000,0x5010)])

    def object(self, path: Path, value: bytes, code: bytes = b'\x90\xd8\x0d\0\0\0\0\xc3', name: str = '__real@4@3fff8000000000000000') -> None:
        coff.write_object(str(path), [('.text',coff.TEXT,code,[(3,name,coff.DIR32)]),('.rdata',coff.RDATA,value,[])], {'_f':(1,0),name:(2,0)}, [], {})

    def test_shifted_literal_uses_coff_content(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.obj'
            self.object(path,b'\0\0\x80\x3f')
            code=b'\x90\xd8\x0d\0\0\0\0\xc3'
            original=b'\xd8\x0d\x00\x50\0\0\xc3'
            refs=self.rank.relocations(str(path),'_f')
            ours=self.rank.tokens(code,0x1000,refs)
            theirs=self.rank.tokens(original,0x1000)
            self.assertEqual(ours[1],theirs[0])
            self.assertEqual(refs[0].value,('scalar',b'\0\0\x80\x3f'))
            self.assertEqual(code[3:7],b'\0'*4)
            self.object(path,b'\0\0\0\x40')
            self.assertNotEqual(self.rank.tokens(code,0x1000,self.rank.relocations(str(path),'_f'))[1],theirs[0])

    def test_known_mutable_globals_are_distinct(self) -> None:
        self.assertNotEqual(self.rank.tokens(bytes.fromhex('a100600000'),0x1000), self.rank.tokens(bytes.fromhex('a104600000'),0x1000))

    def test_known_readonly_global_addends_keep_address_identity(self) -> None:
        ranker=fitness.Fitness({'_array':(0x5000,8)},Image(),[(0x5000,0x5010)])
        with patch.object(Image,'read',return_value=b'\0'*4):
            first=ranker.tokens(bytes.fromhex('a100500000'),0x1000)
            second=ranker.tokens(bytes.fromhex('a104500000'),0x1000)
        self.assertNotEqual(first,second)
        self.assertIn("('address', 20484)",repr(second))

    def test_branch_target_survives_instruction_insertion(self) -> None:
        a=self.rank.tokens(bytes.fromhex('740190c3'),0x1000)
        b=self.rank.tokens(bytes.fromhex('74029090c3'),0x1000)
        self.assertEqual(a[0],b[0])

    def test_equal_tokens_do_not_claim_actual_match(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.obj'
            coff.write_object(str(path), [('.text',coff.TEXT,bytes.fromhex('8b00c3'),[])], {'_f':(1,0)}, [], {})
            result=('_f',False,bytes.fromhex('8b00c3'),b'\0'*3,bytes.fromhex('8b0420c3'),[])
            ranking=self.rank.rank(str(path),result)
            self.assertEqual(ranking.instructions,0)
            self.assertGreater(ranking.encoding,0)
            self.assertFalse(ranking.actual_same)

    def test_double_string_and_opaque_table(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.obj'
            for name,data,expected in [('__real@8@3fff8000000000000000',b'\0'*7+b'\x40',('scalar',b'\0'*7+b'\x40')),('$SG12',b'hello\0\xcc\xcc',('string',b'hello\0')),('_table',bytes(range(16)),('opaque','_table',0,coff.DIR32))]:
                self.object(path,data,name=name)
                self.assertEqual(self.rank.relocations(str(path),'_f')[0].value,expected)

    def test_exact_raw_candidate_uses_authoritative_result(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.obj'
            coff.write_object(str(path), [('.text',coff.TEXT,b'\xc3',[])], {'_f':(1,0)}, [], {})
            image=Image()
            with patch.object(compare.build,'sources',return_value=[('src/test.c',str(path))]), patch.object(compare.coff,'Image',return_value=image), patch.object(Image,'read',return_value=b'\xc3'):
                result=next(compare.results({'_f':(0x1000,1)}))
            ranking=self.rank.rank(str(path),result)
            self.assertEqual(ranking.key,(0,0,0))
            self.assertTrue(ranking.actual_same)

    def test_operand_register_and_opcode_are_significant(self) -> None:
        original=self.rank.tokens(bytes.fromhex('8b00c3'),0x1000)
        self.assertNotEqual(original,self.rank.tokens(bytes.fromhex('8b08c3'),0x1000))
        self.assertNotEqual(original,self.rank.tokens(bytes.fromhex('0300c3'),0x1000))

    def test_concurrent_decoding_has_no_shared_capstone_handle(self) -> None:
        code=bytes.fromhex('740190c3')
        expected=self.rank.tokens(code,0x1000)
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual=list(pool.map(lambda _: self.rank.tokens(code,0x1000),range(80)))
        self.assertTrue(all(tokens==expected for tokens in actual))


class AdapterTests(unittest.TestCase):
    def test_nonmatch_zero_distance_is_truthy_and_ordered_above_match(self) -> None:
        zero=fitness.NonMatch((0,0,0))
        self.assertTrue(zero)
        self.assertNotEqual(zero,0)
        self.assertGreater(zero,0)
        self.assertLess(0,zero)
        self.assertLess(zero,fitness.NonMatch((0,0,1)))
        self.assertLess(fitness.NonMatch((0,9999,9999)),fitness.NonMatch((1,0,0)))
        self.assertEqual(sorted([fitness.NonMatch((1,0,0)),zero,0]),[0,zero,fitness.NonMatch((1,0,0))])

    def test_authoritative_exact_and_retention_gates(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'fixture.obj'
            raw=Mock()
            raw.symbols={'_f':(0x1000,1)};raw.symbol_names=['_f'];raw.matched=None
            def compile_variant(variant: Any) -> str:
                coff.write_object(str(path),[('.text',coff.TEXT,b'\xc3',[])],{'_f':(1,0)},[],{})
                return str(path)
            raw.compile.side_effect=compile_variant
            exact=('_f',True,b'\xc3',b'\0',b'\xc3',[])
            green=('_oldgreen',True,b'\xc3',b'\0',b'\xc3',[])
            raw.results.return_value=[exact,green]
            ranker=fitness.Fitness(raw.symbols,Image(),[])
            with patch.object(fitness.Fitness,'project',return_value=ranker):
                adapter=fitness.RelocationScorer(raw)
            self.assertEqual(adapter.score(('','','')),0)
            raw.results.return_value=[('_f',False,b'\xc3',b'\0',b'\xc3',[]),green]
            self.assertEqual(adapter.score(('','','')),fitness.NonMatch((0,0,0)))
            raw.results.return_value=[exact,('_oldgreen',False,b'\xc3',b'\0',b'\xc3',[])]
            self.assertNotEqual(adapter.score(('','','')),0)
            raw.results.return_value=[('_f',True,b'\xc3',b'\1',b'\xc3',[]),green]
            self.assertNotEqual(adapter.score(('','','')),0)
            raw.results.return_value=[('_f',True,b'\xc3',b'\0',b'\xc3',[('bad-data',)]),green]
            self.assertNotEqual(adapter.score(('','','')),0)
            raw.symbol_names=['_f','_missing']
            raw.results.return_value=[exact,green]
            self.assertNotEqual(adapter.score(('','','')),0)

    def test_unsupported_modes_fail_before_build(self) -> None:
        for options,le in [(['--pad'],False),(['--plan'],False),([],True)]:
            with self.subTest(options=options,le=le), patch.object(sys,'argv',['permute.py','_f','--fitness','relocations',*options]), patch.object(permute,'LE',le), patch.object(permute.build,'compile_all',side_effect=AssertionError('must not build')), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    permute.main()
                self.assertEqual(error.exception.code,2)

if __name__=='__main__': unittest.main()
