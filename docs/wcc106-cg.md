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
registers on top. eax 0x1000003, ebx 0x200000c, ecx 0x4000030, edx
0x80000c0, esi 0x10000100, edi 0x20000200, ebp 0x400 (al 1, ah 2, bl 4,
bh 8, cl 0x10, ch 0x20, dl 0x40, dh 0x80, si 0x100, di 0x200). This was
checked against compiled code (a function whose loop counter lands in
ebx). 0x800 (probably esp) is always in the except set.

instruction: +4 next (a block's list ends at the OP_BLOCK head, opcode
0x4b), +0x22 opcode (byte), +0x30 result, +0x38 type_class, +0x3f
num_operands, +0x44 operands[0],
+0x48 operands[1]. conflict_node +0x20 is with.regs, the registers its
neighbours use (NeighboursUse fills it in GiveBestReg), and +0x38 /
+0x3c are ins_range.first / last.

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
| 0x951f40 | RegAlloc (the loop part) | calls AssignConflicts at 0x951f9b until it returns 1; later passes only see new temps (the loads ExpandOps adds for operands left in memory) |
| 0x9514a8 | GiveBestReg(conf, tree, except, needs_one) | returns the hw_reg_set given (0 = none); calls NeighboursUse 0x951a84, recurses for hi/lo when tree->regs is NULL, then loops over tree->regs (below) |
| 0x951374 | TooGreedy(conf, reg, tree->temp) | called at 0x9515a7; a true result skips the candidate |
| 0x951024 | CountRegMoves(conf, reg, conf->tree, 3) | called at 0x9515c0; the candidate's score |
| 0x95c83b | (Pentium split pass init) | called once per function from 0x93c3ed; zeroes the round-robin cursors 0x9767bc (bytes), 0x9767b8 (words), 0x9767c0 (dwords) |
| 0x95c5a7 | (Pentium split of one instruction) | 0x95c4de picks the register, 0x93183a builds the `mov reg,[mem]` (and a `mov [mem],reg` after it when the memory operand is also the result) |
| 0x95c4de | (round-robin register pick) | the register lists are 0x96f694 for dwords (eax edx ebx ecx esi edi ebp esp), 0x96f4bc for words, 0x96f464 for bytes |
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

Later drafts. Case 1's `fieldb4 += field15c` (instead of
`fieldb4 = &fieldb4[field15c]`) is an `add [b4],esi` the split pass
turns into exactly the original's load/add/store, and case 1 then
matches up to the stack offsets, but one noconf temp just before the
call temps goes away (131 temps, the five at 103..106 and 127) and the
sort gives &b8 &bc &100 &108 data. No single extra temp fixes that
list; two noconf temps do, one created among the case 2 / case 3 ids
(positions 60..86) and one between the loads of field154 / fieldb4
and the CSE of `fieldb4 + field15c` at the top of case 1 (position
113 or 114); so does dropping one of the CSE'd `video->video` /
`sound->sound` loads (t102, t108, t109) plus one noconf temp created
between t17 and t18, early in the loop body (position 117). Dead locals and the usual
neutral rewrites (`!x` / `x == 0`, operand order of compares, `!= 0`
on calls) change neither the code nor the temp list.

The registers of case 3 then are one place behind the original's in
the split round-robin (the `buffer2` update: original esi, draft ecx;
`field124 -= buffer`: esi / ecx), while case 1, which the pass visits
last, matches: the original makes one attempt more before the
`buffer2` split and one fewer between it and case 1. The original's
`buffer2` update is the split `add [edx+48h],eax` (`+=`); with `+=`
the draft gets the same instruction, but the attempt gets ecx and is
undone, and `sound->sound` is in eax instead of edx, so its
`mov edx,[esp+18h]` cannot be scheduled above the Func4f55c call.

What adds a noconf temp. Almost every neutral rewrite leaves the temp
list alone (the front end folds them before cg sees them): `x++` /
`++x` / `x += 1` / `x = x + 1` on a `movie->` field, casts between int
and dword or pointer and dword, `!x` / `x == 0`, `!(a >= b && c < d)`,
`(void)` on a call, comma statements, `default: break;`, `++x == y` as
the condition. What does change it is a different instruction stream
before CSE: `p->a = &p->a[n]` or `p->a = p->a + n` instead of
`p->a += n` creates the extra load and add as temps, and when CSE and
the RMW folding turn it back into the same `add [mem],reg` they stay
in the list as noconf (the `buffer2` update: `&buffer2[...]` has two
more noconf temps than `+=`, same instruction). A `?:` result is a
temp of its own (sav 60); an `if`/`else` instead removes it. The
const temps at the head of the list (flags 0x101/0x103, register
"memory", no code) are one per distinct constant stored or compared
in the loop, in each size it is used: 0, 1 and 2 in dword and byte
(`state`), 3, -1 (also every `x - 1` index), 0x114 (word), and one
more with savings 1 not identified; returns do not make one.

The noconf temps also move the registers: the temp list order out of
RoughSortTemps feeds the GiveRegister ties, so a noconf temp with no
code of its own changes code elsewhere. With `buffer2 +=`,
`fieldb4 += field15c` (129 temps) one noconf temp anywhere
in case 2 (list positions 62..84) gives exactly the original's stack
slot order. `movie->fieldc4 = movie->fieldc4 + (...)` in case 2 adds
one there (same as `&fieldc4[...]`): build/fmvscrn_best.c now has
this, slots exact, 52 lines differ (was 61), the rest being eax/edx
swaps in the case 2 compare and the start of case 3, the case 3
`buffer2` / `buffer_size` splits, the `field10c` imul order and the
[R+0x14] load order. On the same 129-temp base, writing the second
`buffer_size -=` as `buffer_size = buffer_size - ...` (one noconf near
position 52) instead fixes all of case 3 (`mov edx,[esp+18h]` above
the call, the `buffer2` split into esi, the `field10c` code): only
two swapped instruction pairs are left, but the slot order is wrong
(&b8 &100 data &108 &bc), and shellsim finds no single insertion that
fixes it there (moving one noconf temp from positions 49..53 to
62..84 would). The two effects do not add up: both rewrites together
are far worse (49 masked lines). `buffer1 = &buffer1[buffer]` on top
of the fieldc4 draft fixes the call region and `buffer2` split too (43
lines differ) but makes the `buffer1` update non-RMW, which the
original's `add [eax+44h],edx` rules out.

The masked line counts above hide register differences. Comparing
with the registers kept (only esp offsets and jump targets stripped),
the `buffer_size =` draft still has 23 lines wrong (the fieldc4 draft
37): the case 2 `data +=` load swaps eax/edx, the case 2 compare's
imul, and the case 3 else branch (`buffer_size` load/sub/store in
ebx, original edi; field10c in ecx, original esi; the idiv divisor
and the `current` load; `lea`/`imul` of `field10c - 1`), plus the
[R+0x14] order. Its `buffer_size` update is the original's form
(load, sub, store), which the fieldc4 draft gets as an RMW `sub`.

Since the five noconf temps at 49..53 are interchangeable in the
sort, moving one of them into case 2 gives the fieldc4 draft's
signature again: the case 3 fix and the slot order cannot both come
from noconf positions alone. On the `buffer_size =` draft shellsim
finds two other ways: any temp with a conflict (savings above 21, any
flags) created at list position 73 or 74, or dropping one of the
const temps (positions 0..11) and adding a temp at 57 or 61..64.
Positions 73/74 lie between the case 2 compare (`p2` below drops a
temp at 78) and the `fieldc4` update (64/65), that is the
`field110 >= field38` test and `field110++`. Tried there with no
effect on the list: `field110 += 1`, `else { field110++; }`,
`++fieldfc == field34`, `(dword)(fieldc4 + ...video)`,
`&(...)->video[fieldc4]`. A `?:` on `field104 == field120` lands at 80;
`x ? 1 : 0` conditions add two const temps instead.
`video + (dword)fieldc4` in the compare drops one at 78. Moving the
else branch's `buffer2 +=` above the call moves a temp from 52 to 50.
`data = data + ...[1]` adds one at 80 (131 temps; dropping any of
49..53 then gives the right slots, but the registers are far off).

## How GiveBestReg picks a register

The candidates are tree->regs in table order: eax, edx, ebx, ecx, esi,
edi, ebp, then 0x800. Each one is skipped if it overlaps with.regs or
the except set, or if TooGreedy says so; otherwise CountRegMoves scores
it (roughly, the moves into or out of that register that the
conflict's instructions would save; not looked at in detail). A
candidate replaces the best so far if its score is greater (signed), or
if it is equal and it is already in GivenRegisters (0x975900, every
register handed out in this function so far) while the best so far is
not. So with all scores 0 the first free register in table order wins,
unless a later one has been used before and the earlier one has not.
`--what regs,cands` prints all of this per conflict.

## The Pentium split pass and its round-robin

With -5r, after register allocation, a pass splits instructions with
a memory operand into a load into a free register and the
register-only operation (`sub edx,[esp+1c]` becomes `mov ecx,[esp+1c]`
and `sub edx,ecx`); the scoreboarder later reuses the loaded register
for other reads of the same memory (so a later `mov ecx,[esp+1c]`
disappears, or becomes `mov ecx,esi`). These loads are not temps and
never go through GiveRegister.

The register comes from a round-robin per operand size: starting after
the register picked last (after eax at the start of each function), the
first one that is not live at the instruction, not used by it and not
its result. Every attempt advances the cursor, also the ones whose
split is undone later and leaves nothing in the final code. So one
extra or missing split attempt anywhere earlier in the function shifts
the register of every later split by one place in eax, edx, ebx, ecx,
esi, edi, ebp. When no register is free the pick returns none and the
cursor stays where it was.

`--what splits` lists the attempts in order, once the function's
instructions are final (at 0x9557e8, before the code is emitted): the
register each got, the instruction as it was before the split
(`opNN result <- operands`, temps as tID, registers by name, `#n`
constants, `[index+base+constant]`), and below it the new moves that
are still in the final instruction lists, as they ended up (a load the
scoreboarder turned into `mov reg <- reg` shows that way), or "undone".
Opcodes are printed as numbers: 0x26 is mov (MakeMove at 0x93183a
builds it); the others look like Open Watcom's order shifted by one
(add 1, sub 3, mul 5, div 7, the compares from 0x30), unchecked.

### rplgraph Func50d04 (proc 4 of build/rplgraph_best.c)

`--what regs` lists every GiveRegister in ConfList order with the
register it got. The loop's short temps (loads of memory variables,
savings 341 and 321) mostly have no neighbours but ebp and take the
first register CountRegMoves scores highest. The registers that differ
from the original are not from GiveRegister at all: the loop head's
`mov ecx,[esp+1c]` / `mov esi,[esp+24]`, the loop end's
`mov ebx,[esp+8]` and the split branch's method and pixel_bytes loads
are split-pass loads (`--what splits`). Ours picks ebx for the loop
end compare and ecx, esi at the loop head; the original's ecx, then
esi, edi are each one place later in the round-robin, so the original
made one more split attempt between the `test` of clipped_height
before the loop and the loop end compare (in block order, where the
loop end comes right after the pretest), or had ebx live there.

The split pass is Open Watcom's LdStAlloc (cg/intel/c/x86ldstr.c):
Enregister picks the first memory or temp operand of any instruction
but calls, LA, CONVERT, ROUND and SELECT, and for a mov only a
constant stored to memory or a temp; FindRegister is the round-robin
(one rover each for byte, word and dword, so only dword attempts move
this cursor). LdStCompress folds a split back later when the register
buys nothing, which is what "undone" is. A traceless extra attempt
therefore needs a non-mov instruction with a memory operand, or a
constant store to memory, that LdStCompress or a later pass removes.

The loop shape comes from TwistLoop (cg/c/loopopts.c), not the front
end: the front end emits `init; top: if (!cond) goto out; body; cont:
inc; goto top`, and the twist copies the condition into the pre-header
(MakeCondition) when the condition block holds only the compare. With
`row = 0` constant propagation turns the copy into `test h,h`; with
`row = g ^ g` (or `g - g`, `position - position`) the copy stays
`cmp row,h`, while the xor with memory is the extra attempt that makes
every later pick match.

In visit order the blocks around the loop are: the old pre-header
(ends with the `test`), the mode 3 block (`mov ebx,[page_bytes]`,
`imul ebx,eax`, `shr`, `mov esi,[source]`, call), the merged cont and
condition block (`add row,1`, `cmp row,[esp+8]`), then the new
pre-header with the hoisted `stride >> 1`, `clipped_width >> 1` and
`clipped_width >> 2`. None of these has an attempt the original's
final code could hide, so the original's extra attempt more likely
came from another block visited in this stretch (a different block
order) than from an extra instruction in these.

Tried without a match (all keep the base's 29 lines or get worse):
operand order, casts, `/ 4` and a local for the mode 3 argument;
`if`/`else` instead of the early return; `continue` at the end of the
then branch; `clipped_height > row`, `++row`, `row += 1`; `row++` at
the end of the body or `first = 0` in the increment; `height` reused
for clipped_height (104 lines); guards before the loop (`if (h > 0)`,
`if (h <= 0) return;`, `== 0`, `!= 0`, with `row = 0` before or
after): all keep the duplicate pretest because the zero for row is
placed between the two tests (1184, 9 lines); `do`/`while` with a
`g ^ g` init inside `if (h > 0)` (1174, 32 lines); `row++` copied into
both branches makes TwistLoop's sibling duplicate the condition into
the then branch (1189).

## Next steps

- Find where rough savings (the RoughSortTemps input) are computed,
  to know what source change moves a temp out of a tie.
- Name functions in the output (CurrProc's label to the front end
  symbol) instead of numbering them.
