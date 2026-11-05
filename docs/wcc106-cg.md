# Watcom C 10.6's code generator (WCC386.EXE), as far as it decides a red function

What `tools/wccoracle.py` hooks, and what the hooks have shown so far.
Open Watcom's cg source (bld/cg) is a good map: the functions below all
exist there with the same structure, but check details against the
binary, not the source.

## How wcc386 runs

`BINNT/WCC386.EXE` is a 9K PE stub ("WATCOM C/C++32 Run-Time system").
It opens `BINW/WCC386.EXE` (found next to itself), whose MZ header has
a "CF" block at 0x50: image at file offset 0x2800, 0x88192 bytes in the
file of which 0x822b4 are code and data (the rest are relocations),
0x98000 bytes of memory, entry 0x33ada. The LX header at 0xe38 in that
file is only a small DOS side loader; ignore it.

The stub LocalAllocs the image and jumps to it with `call esi` at
0x41001d. Under Wine the image lands at 0x8f0020 every time (all 12124
relocations add exactly that), so the addresses below are run-time
addresses. wccgdb.py reads esi at 0x41001d and shifts everything if
the base ever differs. `wccoracle.py SRC --dump IMAGE` writes the
relocated image; `objdump -D -b binary -m i386 -M intel
--adjust-vma=0x8f0020 IMAGE` disassembles it. There are no symbols;
the functions were found from SortList's callers and their comparators.

Debugging works like c2oracle: `winedbg --gdb --no-start --port N
BINNT\WCC386.EXE flags file.c`, then gdb `target remote :N`. A whole
file with 40 functions traces in 5 to 15 seconds.

## Globals

- 0x975930 Names[N_TEMP], the temp list (newest first: AllocTemp
  prepends, so it starts in descending id order).
- 0x975920 LastTemp (AssignOtherLocals sorts only up to it).
- 0x975940 ConfList.
- 0x975954 CurrProc. Every proc_def is allocated at the same address,
  so it does not tell functions apart; NewProc's store at 0x932065
  does (one hit per function, in source order).

## Structures (offsets as 10.6 has them)

name (temp): +0 next_name, +4 class (byte: 0 const, 1 memory, 2 temp,
3 register, 4 indexed), +8 size, +0xc conflict, +0x10 offset, +0x14 front
end symbol (small handle for user variables, 0 for compiler temps),
+0x18 usage (word: 0x80 NEEDS_MEMORY, 0x40 HAS_MEMORY), +0x1c alias,
+0x20 location (the frame offset once allocated), +0x24 id, +0x2a
temp_flags (word: 0x100 CONST_TEMP, 0x200 USED_AS_FD, 0x20 a stack
parameter, 0x80 seen on hoisted loop invariants).

conflict_node: +0 next_conflict, +4 next_for_name, +8 name, +0xc
start_block, +0x10 tree, +0x14 savings (compared unsigned), +0x54 state.

hw_reg_set is one dword: bytes and words in the low bits, the 32-bit
registers on top. eax 0x1000003, edx 0x200000c, ebx 0x4000030, ecx
0x80000c0, esi 0x10000100, edi 0x20000200 (al 1, ah 2, dl 4, dh 8, bl
0x10, bh 0x20, cl 0x40, ch 0x80, si 0x100, di 0x200). 0x400 also comes
back from GiveBestReg; probably bp, not confirmed.

## Functions

| address  | Open Watcom name | notes |
|----------|------------------|-------|
| 0x9603ce | SortList (cgsrtlst.c) | counts the list, calls DoSortList |
| 0x96028d | DoSortList | array + ShellSort; merge sort only if CGAlloc fails |
| 0x960350 | ShellSort | same as OW: `adjust = !adjust; gap = gap/2 + adjust`, swaps while `before(a[i+gap], a[i])`; unstable |
| 0x952bc5 | AllocBefore (dataflo.c, RoughSortTemps) | same as OW: non-const before const, conflict before none, savings `>`, else id `>` |
| 0x952ce3 | RoughSortTemps (the SortList call) | walks the blocks first, then SortList(Names[N_TEMP], 0, AllocBefore) |
| 0x94eb69 | TempAllocBefore (x86temps.c) | USED_AS_FD first unconditionally (no `CurrProc->targ.sp_align` test), then size `<`, then same id and offset `>` |
| 0x94eacf | AssignOtherLocals (temps.c) | sort at 0x94eaf5, AllocNewLocal loop 0x94ebdc..0x94ec20 |
| 0x94ee1a | AllocNewLocal | first allocated gets the highest frame offset |
| 0x94a080 | (no OW match found) | SortList(Names[N_TEMP]) by id descending, comparator 0x94a076 |
| 0x951a28 | ConfBefore (regalloc.c) | savings `>` |
| 0x951a34 | SortConflicts | |
| 0x951900 | AssignConflicts | sorts at 0x95196f, then per conflict: savings 0 -> 0x9517d8 (InMemory), else 0x951820 |
| 0x951820 | GiveRegister | BuildRegTree 0x94ea59, GiveBestReg at 0x951858, BitOff 0x950f84 + FreeAConflict 0x94ae2f on success |
| 0x9514a8 | GiveBestReg(conf, tree, except, needs_one) | returns the hw_reg_set given (0 = none); calls NeighboursUse 0x951a84, recurses for hi/lo, 0x951374 and 0x951024 per candidate (TooGreedy / CountRegMoves, not yet told apart) |
| 0x932065 | NewProc | stores the new proc_def into CurrProc |

## What decides the stack slot order

Stack temps get their slots in Names[N_TEMP] order in AssignOtherLocals.
TempAllocBefore never returns true for two plain temps of the same
size, so that sort keeps the order, and the order is the one
RoughSortTemps left. RoughSortTemps sorts the whole temp list (100+
entries in a big function) with the unstable ShellSort, and temps with
equal rough savings come out in an order that depends only on their
positions in the list and the list length. Positions start as
descending creation order. SortConflicts later sorts the conflicts by
their real savings, but that does not move the temps.

`tools/wccoracle/shellsim.py` replays the sort on a traced list (it
reproduces the traced result exactly) and searches for what gives a
wanted order: a different creation order of the tied temps (`--perm`),
or extra or missing temps at any position (`--extra K`, `--drop`).

## Case notes

### fmvscrn Func4fbf4 (proc 13 of build/fmvscrn_best.c)

The five tied temps are the hoisted loop invariants of the Func502d0
call, `&field108`, `&field100`, `&fieldbc`, `&fieldb8` (created right to
left as t40, t39, t38, t37, so t37 = &b8), and the spilled parameter
`data` (t4). All have rough savings 21. In a list of 130 temps they
start at positions 101..104 and 126 and come out in the order t37 t40
t39 t4 t38, which with AllocNewLocal gives [esp] &bc, +4 data, +8 &100,
+0xc &108, +0x10 &b8. The original needs the order &100 &b8 &bc data
&108 out of the sort.

Replaying the sort: with the current creation order no insertion or
removal of up to 20 low-savings temps anywhere produces it (only two
very high savings temps inserted between t40 and t39 do). Creating the
four in the order &100, &108, &bc, &b8 (oldest first) gives it with
the rest of the list unchanged. The preheader stores come in the same
order in the original and the draft (&b8, &bc, &100, &108), so the
hoisting order matches; what has to change is which temp each address
was given when it was first created, or the rough savings of some of
them.

### rplgraph Func50d04 (proc 4 of build/rplgraph_best.c)

`--what regs` lists every GiveRegister in ConfList order with the
register it got. Many temps tie at savings 341 and 321 and alternate
between ebx and ecx; the original's esi/edi for the loop temps has to
come from GiveBestReg's per-register scoring (0x951374 / 0x951024),
which the tracer does not show yet.

## Next steps

- Hook 0x951374 and 0x951024 inside GiveBestReg to print the score
  of each candidate register (the rplgraph question).
- Find where rough savings (the RoughSortTemps input) are computed,
  to know what source change moves a temp out of a tie.
- Name functions in the output (CurrProc's label to the front end
  symbol) instead of numbering them.
