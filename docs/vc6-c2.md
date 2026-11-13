# VC6's back end (c2.dll), as far as it decides a red function

Visual C++ 6.0 SP3, cl 12.00.8168: c2.dll loads at its image base
0x10700000 (nothing else claims it under wine), so the addresses below
hold in every run. `c2oracle.py` puts breakpoints on them; this file is
the model behind its output. Nothing here is copied compiler code: these
are the rules, with the address where each one lives so the next person
can check them.

c2.dll is VC5's C2.EXE (docs/vc5-c2.md) rebuilt with small changes. The
structures (expression nodes, live range records, the register table,
the sort keys) carry over; the addresses do not, and a few constants
changed (the loop multiplier, the register table stride, the operand
hash). To find the VC6 twin of a VC5 routine, match its instructions
fuzzily (same call pattern, same constants) around the expected place.

## How cl runs the back end

VC6's cl.exe loads c2.dll in process and calls its export
`_InvokeCompilerPass@12` (argc, argv, ...), `_AbortCompilerPass@4` on a
fatal error; there is no c2.exe to rerun on kept files. `cl /B2 DLL`
swaps the DLL. c2oracle/c2stub.c is a stand-in that loads the real
c2.dll (env C2REAL) and, with C2O_BREAK set, executes `int 3` before
forwarding the call. c2oracle.py runs cl.exe under
`winedbg --gdb --no-start --port N`; the gdb script continues past the
initial stops until c2.dll is mapped (the int 3), then plants its
breakpoints. Build the stand-in with `cl /nologo /O2 /LD c2stub.c`
(c2oracle.py does it into build/c2oracle/ the first time). A run takes
about 3 s for a small file and 10 s for control.c; --raw on a big
function takes minutes.

## Globals

| what | VC6 c2.dll | VC5 C2.EXE |
|---|---|---|
| function being compiled (front end symbol: +0x18 decorated name, +0x28 ID) | [0x107ac378] | 0x495f1c |
| register preference table `1 2 3 7 8 4 6 0` = eax ecx edx esi edi ebx ebp | 0x107adff4 (const copy 0x107a09f0) | 0x491100 |
| round robin pointer into it | 0x1079d710 | 0x491120 |
| per-register table; a range's register pointer (+0x10) is 0x107ac730 + 0x54 * reg | 0x107ac730 | 0x494750, 0x50 stride |
| global allocator work list head | [0x1079d864] | 0x4910d4 |

Registers are numbered as in VC5: 1 eax, 2 ecx, 3 edx, 4 ebx, 5 esp,
6 ebp, 7 esi, 8 edi.

## The global allocator

Driver: round start 0x107207e6, loop 0x10720888 (VC5 0x416f7c /
0x4171e4). Work list insertion sort 0x10715922, color one range
0x107159af (edx = range), commit 0x10716715 / 0x107169c9, split flag
tested at 0x1072090a (eax nonzero: split), register known at 0x10720930
(esi = range). A range whose weighted references are <= 0 is skipped
(0x10720874, esi = range) and lives in memory.

Live range record (0x44 bytes, as VC5): +0 back end symbol (byte +4 == 3
compiler temp, slot at +0x1c; otherwise [[sym+8]] is the front end
symbol), +0xc priority, +0x10 register pointer, +0x18 weight sum in the
current block, +0x24 references, +0x3c weighted references, +0x40
position.

### Rule G1: who gets a register, and which

Every variable, parameter and compiler temp (CSE values, loaded fields,
induction pointers) the optimiser kept as a candidate is a live range.
Ranges are colored one at a time from a list sorted by priority
descending, then position descending (0x10715922). Each takes the FIRST
register of eax ecx edx esi edi ebx ebp it does not conflict with
(0x107159af). A range live across a call conflicts with eax/ecx/edx, so
call-crossing ranges get esi, edi, ebx, ebp in priority order. A range
used as a byte skips esi/edi/ebp (`unsigned char c` -> ebx). When a
range cannot be colored it is split, the pieces go back on the list,
all priorities are recomputed and a new round starts (`-- round` in the
output).

Priority (0x10714414 per block, 0x10714c06 / 0x10714c2e referenced,
0x10714c53 live through):

    for each block B: m(B) = 1 << loop_depth(B)    (1, 2, 4, 8; VC5 was 1, 4, 8, 16)
                      N(B) = distinct ranges referenced in B
    range referenced in B:          priority += m(B) * N(B) * w   (w = 2 per reference)
    range live through B, unused:   priority -= m(B) * N(B)

Ties: higher position first. The position is the instruction count of a
backward walk where the range starts, so within a block the range
defined EARLIER in the IL wins a tie. Declaration order does not matter.

Checked cases (oracle and listing agree):

    a = h(1); b = h(2); c = h(3); d = h(4); h(a); h(b); h(c); h(d); ...
      -> a esi, b edi, c ebx, d ebp       (equal priority, definition order)
    the same with the definitions in order d, c, b, a -> d esi, c edi, b ebx, a ebp
    a, b, c, d used 1, 2, 3, 4 times -> d esi, c edi, b ebx, a ebp
    b = h(1); a = h(2); if (p) h(b); if (q) g1 = h(a + p + q + r);
      -> a esi (25: used in the busy block, N = 4), b edi (20), though b came first
    a used before and after a 3-deep loop, b inside it:
      a pays m * N in each loop block it lives through (-6), b 36 -> b esi, a edi

To give X a better register than Y: raise X's priority (reference it in
a block with more live ranges, or in a loop) or lower Y's (keep Y live
through more blocks unused); at equal priority, define X first.
`c2oracle.py SRC NAME --global` prints the numbers, `--raw` every block's
contribution, so check the gap before editing.

## Rule L1: scratch registers for what the global allocator left

Picker 0x10734e4b (ecx = tuple, edx = its use), commit 0x10735143
(ecx = register); the return address into the commit tells the path:
0x10734f18 round robin, 0x10734fc7 preferred, 0x1073513b first free,
0x10735061 evicted. The pointer is reset to eax once per function
(0x1073362d, the local allocator's start). The rules are VC5's (see
"Local register choice" in vc5-c2.md): preferred register if the value
is a copy of a register value or an address off a plain base register;
else round robin over eax/ecx/edx, carried across statements and blocks
in code generation order; else the first free of eax ecx edx esi edi
ebx ebp. An esi/edi load the global list does not explain comes from
that last path: eax/ecx/edx were all busy. `f(bp[0], bp[1], bp[2])`
twice: ecx, edx, ecx, edx, ... (eax holds bp).

## Rule S1: commutative operand order and compares

After the sort (0x10709451: ebx parent, eax the sorted operand list)
operands are ordered by key = rank << 24 | count << 16 | hash16, highest
first, as in VC5. The side with the higher Sethi-Ullman rank is
evaluated first: in `item->y + GCB[3] <= l->y + bounds[2]`, l->y loads
first because `bounds[2]` (a load through a register pointer) makes that
side rank 2. VC6 also canonicalises compares: `b >= a` for `a <= b`
gives identical code. Unlike VC5 the leaf hash is NOT fold16(front end
ID), and declaration order did not change anything in the cases tried. A
temp holding a call result takes the rank of its defining tree (9 for a
call), and single-use locals are forwarded before the sort, so naming a
call result does not change the order; the register a result lands in
is the local picker's choice, made after the sort.

## Opcodes seen in VC6 sort output

op16d add, op16f index scale (`i * 2`), op171 shl, op172 and, op173 or,
op15f sign-extending load, op15a push argument, op184 call.

## The list scheduler (reversed 2026-11-13)

VC6 schedules once per function, after register allocation, on machine
instructions (VC5 also had a pre-pass on x87 blocks). The structure is
VC5's schedmd.c. Driver 0x10739fad (edx = pass flag, stored at
[0x1079f270]; 0 in our builds). Per region the driver calls 0x1073a818
(build the DAG), 0x1073b689 (priorities) and 0x1073bf95 (schedule); the
region is done at 0x1073a0aa. 0x1073c17b picks the instructions for one
cycle and returns how many at 0x1073c05e; the chosen DAG nodes are at
0x1079f248.

- A DAG node: +0xc successor edges (+0 next, +0xc node, +0x10 kind
  bits, +0x14 latency), +0x10/+0x14 ready list links, +0x1c the
  instruction (a tuple: +4 opcode, operands from +0x18, the result at
  +0x1c), +0x20 predecessors left, +0x22 successor count, +0x28/+0x2c
  priority, +0x30 earliest cycle, +0x34 height, +0x36 position in the IL
  block, +0x39/+0x3a flags.
- Machine operands: class 1 register leaf (+0x18 points into the
  register table 0x107ac730, 0x54 per register), class 2 a variable in
  memory (+0x14 symbol), class 5/6 memory reference (+0x24 offset,
  +0x28 base, +0x1c the alias tag), class 7 constant.
- Tuple opcodes seen: 1 mov, 8 ret, 0xd push (argument), 0xe call,
  0xf jcc, 0x10 jmp, 0x12 lea, 0x2d add, 0xb9 pop, 0xba push
  (prologue), 0xc1 imul. Edge kinds as far as seen: 1 true, 2 anti,
  4 output (registers), 0x20 memory.

### Rule P1: priority

    height(n)   = 1 + max over successors s of (height(s) + latency(n -> s))   (0x1073b6bf)
    priority(n) = height(n) * 0x2000 + 0x10000 if n reads memory (flag +0x3a bit 0)

(0x1073b78b: the terms are shifted by the table at [0x10799204], which
holds -1 13 -5 -1 -2 16 16 for /G5, so the other terms vanish; one more
0x10000 comes from flag +0x3a bit 1 when the tuple's +0xa & 0xf000 is
0x4000, not seen yet.) Bit 0 was set on every load traced and on no
push, lea or store. A load
therefore outranks everything of similar height, and loads rise as far
as their dependencies allow.

### Rule P2: picking (0x1073c17b)

The ready list (insertion 0x1073c0b2) is sorted by priority descending,
then IL position ascending. Each cycle the picker walks it from the head
and takes up to two instructions (U and V pipe, [0x10799250] = 2),
restarting from the head after each pick. It skips an instruction when
the pairing hook [0x10799214] returns < 0 for it (not pairable in this
slot), when 0x1073c4ad or the register check 0x1073c505 object, or when
its earliest cycle (+0x30, the predecessors' cycles plus latency) is
later than the current cycle. A load's result has latency 1, so its
consumer cannot go in the same cycle and the next ready instruction
fills the V slot. `--sched --raw` prints every decision.

Consequence for source edits: two independent instructions of equal
priority come out in IL order, so the IL order (statement order, the
tuple generator's operand order, the order the allocator inserted
reloads) decides. An instruction moves up past others only if its
height is greater, it is a load, or the instructions before it are not
ready (waiting on a load's latency).

### Rule P3: memory dependences and alias tags (0x1073ada2, 0x107025f1)

Besides register dependences, the DAG gets an edge from a store to
every later load or store that may touch the same memory (kind 0x20) and from those to the call (0x40/0x80).
For a store to an address-taken local L and a load through a pointer,
the test is 0x107025f1 -> 0x1070390f -> 0x10703a4e(L, tag): the load's
alias tag (memory operand +0x1c) names a points-to set (table
[0x1079d6b0], tags >= [0x1079d670] go through [0x1079d6bc]); they
conflict if L ([fe+5] & 2: address taken) is in it. Checked in micro
tests:

    item a parameter:                    room_number store -> no edge to item->x loads
    item = &items[n], items a pointer:    edge (items may point to any escaped local)
    item = &aitems[n], aitems an array:   no edge

So `room_number = item->room_number; GetFloor(item->pos.x_pos, ...,
&room_number)` keeps the field loads behind the store when item comes
from the global `items` pointer, and lets them rise above it (and above
the `lea` of &room_number) when item is a parameter (Splash,
LavaBurn, CreatureUnderwater, ... all match that way). ScalesControl
and ControlTwoBlockPlatform are red because retail's loads rose there
although item = &items[item_number]: with the edge removed the
scheduler reproduces retail's order exactly (room load, z load, lea,
store, y load, push), so retail's z load had a tag without room_number.
What source gives an items-derived pointer such a tag is open: hoisting
the store, a comma expression, and declaring another address-taken
local did not.

ControlBirdBlade is the converse: retail kept `mov dword [esi+0x34],0`
(`*(sint32 *)&item->item_flags[0] = 0`) behind the frame_number store,
ours pairs it with the load before (the stores have different tags, so
no edge). Five spellings of the cast store changed nothing.

## Rule R1: where split ranges get their loads and stores

When the allocator splits a range (the "(split)" line of --global), the
pieces go back on the list and, at the next round start (0x107207f5
calls 0x10723b3e for the split range), the code that moves the value
between memory and register at the piece boundaries is inserted
(0x10723c73 -> 0x10724868 makes the tuples). So the reloads at a block
end are created in the order their ranges were split. In TestTriggers
the reloads before the jump to the join come out `edx <- trigger`,
`edi <- flags` (both priority 0x14000, so the scheduler keeps that IL
order); trigger was split in a later round than flags, so the later
split's reload sits first: insertion is at a fixed point, newest first
(inferred from this one case, not yet checked in a micro test).
Retail has edi first, which needs flags split after trigger, i.e. flags
lower in priority than trigger (-326) in trigger's round.
