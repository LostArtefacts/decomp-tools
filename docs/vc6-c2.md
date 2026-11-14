# VC6's back end (c2.dll), as far as it decides a red function

Visual C++ 6.0 SP3, cl 12.00.8168: c2.dll loads at its image base
0x10700000 (nothing else claims it under wine), so the addresses below
hold in every run. They are 8168's; tr04's original was compiled by a
later c2.dll, build 12.00.8447, whose code addresses differ (see "Build
12.00.8447" for the table and what changed). `c2oracle.py` puts breakpoints on them; this file is
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

## Build 12.00.8447

tr04's original carries Rich `@comp.id` build 8447, and c2.dll writes
that from its own build (8168: `or edi,0x1fe8` at 0x10758d44; 8447:
`or edi,0x20ff` at 0x10768c20), so the original was compiled by a
c2.dll 12.00.8447, a later VC6 SP3 back end (timestamp 1999-03-23, its
own Rich header says it was built by 8447 too). Both DLLs are 737329
bytes; every section has the same size and address except .text, which
grew by 0x1b8 (.rdata's strings moved within it).
c2oracle.py reads the build from the version resource
(`VS_FIXEDFILEINFO`, dwFileVersionLS >> 16) and c2gdb.py picks the
address set for it. `C2ORACLE_DLL=c2_8168.dll c2oracle.py ...` traces
the other DLL from the bin directory, for comparing the two.

The linker laid the functions out in another order, but every global,
the register table, the structures and the .databe/.bssbe layout are
where 8168 has them, so only code addresses move. Every 8168 address in
this file has an 8447 twin whose surrounding instructions are identical
but for relocated addresses (matched by unique 6-instruction n-grams
extended to whole runs, then a diff of the gaps):

| 8168 | 8447 | used for |
|---|---|---|
| 0x107025f1 | 0x10702e99 | P3 memory dependence test |
| 0x1070390f | 0x1070341f | P3 |
| 0x10703a4e | 0x1070355e | P3 points-to lookup |
| 0x10709383 | 0x1070d0c8 | S2 key copy |
| 0x107093d0 | 0x1070d115 | S2 key copy end |
| 0x10709451 | 0x1070d196 | S1 after the sort |
| 0x107094b4 | 0x1070d1f9 | S1 count |
| 0x10709518 | 0x1070d25d | S2 operand hash |
| 0x10709584 | 0x1070d2c9 |  |
| 0x107095be | 0x1070d303 |  |
| 0x107095cc | 0x1070d311 |  |
| 0x107095e7 | 0x1070d32c |  |
| 0x107095f9 | 0x1070d33e |  |
| 0x1070961e | 0x1070d363 |  |
| 0x10709620 | 0x1070d365 |  |
| 0x1070964e | 0x1070d393 |  |
| 0x10709687 | 0x1070d3cc |  |
| 0x1070968a | 0x1070d3cf |  |
| 0x10711a0f | 0x1072127e | C1 literal restore |
| 0x10714414 | 0x1072255a | G1 per block |
| 0x10714c06 | 0x10722d4c | G1 referenced |
| 0x10714c2e | 0x10722d74 | G1 referenced |
| 0x10714c53 | 0x10722d99 | G1 live through |
| 0x10715922 | 0x1072371a | G1 work list sort |
| 0x107159af | 0x107237a7 | G1 color one range |
| 0x10716715 | 0x107245c3 | G1 commit |
| 0x107169c9 | 0x10724877 | G1 commit |
| 0x1071732f | 0x1072cac2 | C1 setup |
| 0x1071a8a6 | 0x1072abbf | C1 tuple walker |
| 0x1071aadd | 0x1072adf6 | C1 literal check |
| 0x1071b22d | 0x1072b546 | C1 repeated-value test |
| 0x1071c2c0 | 0x1072c600 | C1 eligibility |
| 0x1071c38e | 0x1072c6ce | C1 intern |
| 0x1071c446 | 0x1072c786 | C1 reuse bit |
| 0x1071c523 | 0x1072c863 | C1 new symbol |
| 0x107207e6 | 0x1072d5c5 | G1 round start |
| 0x107207f5 | 0x1072d5d4 | R1 split range call |
| 0x10720874 | 0x1072d653 | G1 skipped range |
| 0x10720888 | 0x1072d667 | G1 loop |
| 0x1072090a | 0x1072d6e9 | G1 split flag |
| 0x10720930 | 0x1072d70f | G1 register known |
| 0x10723b3e | 0x1073e8f6 | R1 piece boundaries |
| 0x10723c73 | 0x1073ea2b | R1 |
| 0x10724868 | 0x1073f5d8 | R1 makes the tuples |
| 0x1073362d | 0x10731a59 | L1 rotation reset |
| 0x10734e4b | 0x10733273 | L1 picker |
| 0x10734f18 | 0x10733340 | L1 round robin |
| 0x10734fc7 | 0x107333ef | L1 preferred |
| 0x10735061 | 0x10733489 | L1 evicted |
| 0x1073513b | 0x10733563 | L1 first free |
| 0x10735143 | 0x1073356b | L1 commit |
| 0x10739fad | 0x1073ad9b | scheduler driver |
| 0x1073a0aa | 0x1073ae98 | region done |
| 0x1073a818 | 0x1073b3a2 | build the DAG |
| 0x1073ada2 | 0x10738546 | P3 memory edges |
| 0x1073b689 | 0x10738c53 | P1 priorities |
| 0x1073b6bf | 0x10738c89 | P1 height |
| 0x1073b78b | 0x10738d55 | P1 shifts |
| 0x1073bf95 | 0x1073955f | schedule |
| 0x1073c05e | 0x10739628 | cycle count returned |
| 0x1073c0b2 | 0x1073967c | P2 ready list insertion |
| 0x1073c17b | 0x10739745 | P2 cycle picker |
| 0x1073c4ad | 0x10739a77 | P2 check |
| 0x1073c505 | 0x10739acf | P2 register check |
| 0x10792e3b | 0x10792ff6 | S2 defining tree |

What differs in the code. The asserts (`mov edx, line` /
`mov ecx, "E:\8447\vc98\p2\src\..."`) say which sources moved:
P2\color.c -23 lines before line 840, P2\fg.c +30 before 5660,
P2\globlopt.c +3 between 3346 and 3972, P2\emit.c +2 between 782 and
829, P2\x86\schedmd.c -8 before 1836; the other 43 files with asserts
keep their line numbers. The coloring routine, the priority computation, the local
picker, the operand hash and the scheduler's DAG, priority and picker
routines are instruction-for-instruction the same in both builds apart
from those line constants, so G1, C1, L1, S1, S2, P1, P2, P3 and R1 hold
unchanged under 8447. The local allocator's start (0x107335c3, 8447
0x107319ef) and nine other loops over static tables now end on
`jb`/`ja` instead of `jl`/`jg` (presumably an unsigned type in c2's own
source; no effect on what c2 decides). The per-node expression simplifier (8168
0x10707d5c, 8447 0x1070ba8d, ecx = the node) gained a type-class test
(`[node+0xa] & 0xf000 == 0x1000`, 8447 0x1070be72) on one of its paths.

Checked: oracle traces of InitialiseBat (all options) and TestTriggers
(--global --regs --sched --sort, 2111 lines) are identical under both
builds but for heap addresses. Recompiling tr04 with 8447 changed only
DoUwEffect, through rule B1.

### Rule B1 (8447 only): a masked sum drops its addend's mask

Both builds rewrite `(x >> n) << m`, n > m, as `(x >> (n - m)) & mask`.
When that is an addend of a sum masked again, 8447 widens the inner
mask by every bit the outer mask clears and the other addend is known
to have clear (so no carry can come out of them); a mask that becomes
-1 is dropped (the simplifier's trace shows `and(..., -1)`). 8168 keeps
the inner mask as it is:

```c
int f(unsigned char *p, int o) { return ((o & ~3) + ((*p >> 6) << 2)) & ~3; }
/* 8168: shr eax,4; and al,0xfc; add eax,edx; and al,0xfc
   8447: shr eax,4; add eax,edx; and al,0xfc */
```

With `& ~1` outside, 8447's inner mask is 0xfd (bit 0 freed, bit 1
still needed); with `(o & ~7)` as the other addend it is dropped too;
with a plain `o` (low bits unknown), a `^` instead of the `+`, or no
outer mask, both builds compile the same.

A bitfield `+=` is exactly that shape. `p->y += p->yvel >> 6`, with
`sint32 y : 30` at bit 2, is `old ^ ((t ^ old) & ~3)` with
t = (old & ~3) + (yvel >> 4 & ~3) in 8168, which simplifies to
`t ^ (old & 3)`. In 8447 t = (old & ~3) + (yvel >> 4), whose low bits
are not zero, so the merge stays `t ^ ((yvel >> 4 ^ old) & 3)`: one
`and` fewer, one `xor` more, and the trees, the temps after them and
their live ranges differ from the first loop on (DoUwEffect: temp
indices shift by 2 to 5, two extra ranges get eax and ecx, p->x is no
longer kept in ebp). `-=`, `|=`, a plain addend (`p->y += p->yvel`) and
`(unsigned)i >> 6` (which becomes `lea [base+x*4]`) compile the same in
both builds; `>> 6` of an unsigned char, signed char, unsigned short or
int as a `+=` addend all change. Retail DoUwEffect has the 8447 form.

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

### Rule C1: repeated literals become candidates, not necessarily registers

The setup at 0x1071732f calls the machine-tuple walker 0x1071a8a6.
At 0x1071aadd it checks a literal operand's tuple with 0x1071c2c0, then
interns eligible operands through 0x1071c38e. A new value gets a back end
symbol of kind 13 (0x1071c523), with its defining expression at +0x28.
Finding that value again sets symbol byte +5 bit 0x10 (0x1071c446).
Later, 0x1071b22d checks this bit: an operand without it is restored to a
literal through 0x10711a0f; a repeated value follows the candidate path.

Checked with `/O2 /G5` and an opaque `Consume(int)` call between two
independent expressions:

```c
int f(int x, int y)
{
    int a = x & 728;
    Consume(a);
    return y & 729;
}
```

Here 728 was interned once, then removed, and had no global-allocation
range. Changing only 729 to 728 gave one new-value event, one reuse
event, two retained operands, and a `constant{728}` range in the global
trace. That range was still skipped (weighted references -1, priority
0). Thus finding a literal in the source, retaining it in the tuple
stream, counting it in a particular block, and assigning it a register
are separate decisions. Do not infer the timing of if-conversion just
from an absent constant in `--global`.

### Rule G2: a variable assigned in two steps is two ranges

Each definition of a variable starts its own live range (web), so
`c = x >> 5; c = 255 - c;` gives c two ranges where
`c = 255 - (x >> 5)` gives one, and the intermediate value, a local
scratch before, now goes through G1. The second range starts at its
first instruction (`mov reg,255`) while the first is still live, so the
two conflict and cannot share a register. Both count as ranges in the
block, which also raises every range's N there.

Checked in ProcessMeshData's prelit loop (`sint16 c`, RGBONLY(c, c, c)
into prelight[j]): the one-step form gave c eax (224), its sign
extension eax, j ecx, and the shifted load a scratch edx. The two-step
form gave the shifted value eax (256, colored first by position), c
ecx, the sign extension eax and j edx, which is retail. The scratch
picks after the loop moved with it (rule L1).

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

A source local can change this sequence even when its own generated
instructions are unchanged. In SkeletonControl, the conditional turn
limit originally used an implicit copy of a mood value held in ecx.
The copy preferred ecx, but ecx was still live, so the local picker took
eax through round robin and advanced the pointer to ecx. Giving the
conditional result a named `sint16 turn_limit` made it a global range
(priority 96, assigned eax). The same `mov eax,ecx` then bypassed the
local picker. The next scratch allocation, an address in case 16, took
eax instead of ecx, and the later allocations rotated accordingly.
Paired `--regs --raw` traces agreed through the preceding 90 allocation
events and identified this missing event directly. Thus identical bytes
at an edited expression do not prove unchanged allocator state.

### Rule L2: a shared tail is generated once, then duplicated

A statement after an if/else, such as `Unlock(vb);` after both arms,
can come out duplicated at the end of each arm, each copy jumping to the
join. Its code is generated once, after the last arm in code generation
order, and copied afterwards: both copies carry the same scratch
registers, and the round robin pointer entering them is where the last
arm left it. Writing the call in each arm instead makes two blocks
generated in turn: the first copy follows the first arm, and the second
arm then starts from where that copy left the pointer.

Checked in ProcessMeshData (`if (nNorms > 0) {normals} else {prelit}`
then Unlock): with the call in each arm, the first copy's vtable load
took ecx and the prelit arm's first scratch edx; with one shared call,
the prelit arm's first scratch took eax and both copies took the
register after the prelit loop's last pick. Retail has the shared form.

## Rule S1: commutative operand order and compares

After the sort (0x10709451: ebx parent, eax the sorted operand list)
operands are ordered by key = rank << 24 | count << 16 | hash16, highest
first, as in VC5. VC6's count includes the operator itself: it is one
plus the sum of its operands' counts (0x107094b4); constants count as
zero. The side with the higher Sethi-Ullman rank is
evaluated first: in `item->y + GCB[3] <= l->y + bounds[2]`, l->y loads
first because `bounds[2]` (a load through a register pointer) makes that
side rank 2. VC6 also canonicalises compares: `b >= a` for `a <= b`
gives identical code. A temp holding a call result takes the rank of its
defining tree (9 for a call), and single-use locals are forwarded before
the sort, so naming a call result does not change the order; the register
a result lands in is the local picker's choice, made after the sort.

### Rule S2: VC6's operand hash (reversed 2026-11-13)

The hash routine is 0x10709518. `fold16(v)` means the xor of the high
and low 16 bits; all results below are truncated to 16 bits.

| expression | hash16 | code |
|---|---|---|
| ordinary class 1/2 symbol, without a defining tree | `rol16(fold16(symbol[+0x1c]), 5)` | 0x107095e7 .. 0x1070961e |
| class 3 symbol | `fold16(symbol[+0x1c])` | 0x107095f9 .. 0x1070968a |
| class 1/2 compiler temp, symbol byte +4 == 3 | `symbol[+0x1c] << 6` | 0x10709620 |
| memory reference, class 5/6 | `fold16(offset) + opcode - 0x145 + (hash(base) << 8)` | 0x10709584 .. 0x107095be |
| operator | `opcode - 0x145 + sum(hash(child[i]) << (i & 7))` | 0x1070964e .. 0x10709687 |

A class 1/2 compiler temp with a defining tree uses that tree instead
(0x107095cc -> 0x10792e3b). VC6 memory nodes store their offset at +0x24
and base at +0x28, four bytes later than VC5. This matters when decoding
the oracle: reading VC5's offsets makes a real `mesh->x` look like `[0]`.
The preceding tree walk can also copy a defining tree's whole key into
a memory operand whose base is a CSE temp (0x10709383 .. 0x107093d0),
instead of giving that operand the ordinary memory-leaf key. This is
why the `mesh + 8` CSE below carries its address tree's rank and count.

The ordinary symbol's +0x1c is a back end index, not the front end ID at
front-end-symbol +0x28. An index can change when an earlier first use
creates another symbol, even if copy propagation later removes its
instructions. Changing declaration order alone did not change it in the
cases checked.

Checked in SkeletonControl: `pos.x` had index 0x18c and key
`00.01.3180`. The mesh pointer had index 0x190 and hash 0x3200, so its
zero-offset load had key `00.01.0007`: shifting the base hash by eight
discarded its high byte. The xor consequently loaded `pos.x` first,
where retail loads `mesh->x` first. Introducing a real `sint16 num_meshes`
copy and defining it and the loop counter before the mesh pointer's
first definition moved the pointer index to 0x192. The predicted hash
became 0x3240, and the load's key became `00.01.4007`, ahead of `pos.x`.
The oracle confirmed those exact keys, and a stock build changed only
the two wanted loads. The copy itself was optimized away. `mesh->z`
already had rank 1 from its nonzero-offset address, so it stayed first
without relying on the hash.

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
Hoisting the store, a comma expression, and declaring another
address-taken local did not give it such a tag. Declaring room_number
in the block that uses it, below the `item = &items[...]` assignment,
did (both match that way now). In micro tests the tag behaves as if it
recorded the address-taken locals in scope where the pointer is
assigned (--sched --raw prints it as `[tag.set:base+off]`):

    item = &items[n] at function level, room_number declared there too:
        item->x, ->y, ->z loads tag 10.4; the store has 0x20 edges to them
    item = &items[n] at function level, room_number in an inner block:
        loads tag 10.3; no edge, the loads rise above the store
    both inside the inner block:
        loads tag 10.4 again; the edges are back

A load can still stay behind the store for a register reason: when the
stored value's register is the load's destination, the anti dependence
(kind 2) orders them whatever the tag.

ControlBirdBlade is the converse: retail kept `mov dword [esi+0x34],0`
(`*(sint32 *)&item->item_flags[0] = 0`) behind the frame_number store,
ours paired it with the load before (the stores have different tags, so
no edge). Five spellings of the cast store changed nothing; a volatile
store to frame_number (`*(volatile sint16 *)&item->frame_number = ...`)
keeps the order and matches.

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
