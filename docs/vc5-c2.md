# VC5's back end (C2.EXE), as far as it decides a red function

Visual C++ 5.0 SP3, cl 11.00.7022: C2.EXE is 660240 bytes, image base
0x400000, no relocations, so the addresses below hold in every run.
`c2oracle.py` puts breakpoints on them; this file is the model behind its
output. Nothing here is copied compiler code: these are the rules, with
the address where each one lives so the next person can check them.

## How cl runs the back end

cl.exe runs c1.dll/c1xx.dll in process, then spawns c2.exe with no
command line: the flags travel in the environment variable
`MSC_CMD_FLAGS` (`-il <tempdir>\aNNNNN -f file -Fofile.obj -G5 ...`).
The intermediate files are `aNNNNNex` (code), `gl` (global symbols), `sy`
(local symbols, names and front end IDs in the clear) and `in`, and cl
deletes them afterwards. `cl /B2 stand-in.exe` swaps the back end;
c2oracle/c2keep.c is a stand-in that copies the files and the flags, then
runs the real c2. Rerunning c2.exe on the copies with the same
MSC_CMD_FLAGS (and another -Fo) gives the same object, so the back end
can be debugged on its own: `winedbg --gdb --no-start --port N c2.exe`,
then gdb `target remote :N`. The proxy takes ONE connection, so wait for
it to print "target remote" instead of probing the port.

## Globals

- 0x495f1c: the function being compiled (a front end symbol: +0x18 its
  decorated name, `_f` or `?f@@...`, +0x28 its front end ID).
- 0x491100: the register preference table, eight dwords
  `1 2 3 7 8 4 6 0`. c2 numbers the registers 1 eax, 2 ecx, 3 edx,
  4 ebx, 5 esp, 6 ebp, 7 esi, 8 edi, so the order is eax ecx edx esi
  edi ebx ebp.
- 0x491120: the round robin pointer into that table (see below).
- 0x491180 + 4*reg: nonzero while the register holds a value.
- 0x491140 + 4*reg: the register's mask, tested against a value's
  interference set by 0x40181e.
- 0x48fb60: round robin on/off (on in our builds).

## Expression trees

A node: +0 next operand (operand lists are singly linked), +4 opcode
(word), +8 class (byte), +0xc sort key, +0x14 symbol for leaves,
+0x18 first operand for operators. Opcodes seen: 0x141 add, 0x143 mul,
0x135 and, 0x14b shr (the hash mixes the opcode in, so these matter).

Classes, as the hash routine 0x4053bf switches on them (table 0x405528):

| class | what | hash16 |
|---|---|---|
| 1-3 | a value in a symbol: +0x14 back end symbol | front end symbol: fold16(ID); compiler temp (symbol byte +4 == 3): its slot number, symbol +0x1c |
| 4 | address of a symbol (+0x14 front end symbol) | fold16(ID) |
| 5-6 | memory reference: +0x20 offset, +0x24 base node | fold16(offset) ^ opcode ^ hash(base) |
| 7 | integer constant, 64 bits at +0x18 | fold16 of the value |
| 8 | constant in memory (+0x14 -> value) | fold16(value) |
| 9-10 | | 0 |
| 11-20 | operators, operands from +0x18 | opcode ^ XOR of the operands' hash16 |

fold16(x) = (x & 0xffff) ^ (x >> 16). A class 1 or 2 node whose
symbol has a defining tree (symbol +0x14, a temp the optimiser made for
an expression) hashes as that tree (0x405473 -> 0x465ed9), not by its
slot. A back end symbol's front end
symbol is `[[sym+8]]`; it holds the name at +0x18 and the ID at +0x28.

## Commutative operand sort (0x40516b, 0x405301, 0x40922a, 0x408d58)

0x40516b walks a tree bottom up, gives every node a key (0x405301) and,
for an operator whose operands may be reordered, sorts its operand list
(0x4052ec calls the list sort 0x40922a with the comparator 0x408d58).

key = rank << 24 | count << 16 | hash16, compared unsigned, highest
first, so rank decides, then count, then the hash:

- rank: leaves 0. An operator takes the rank of its first operand, then
  for each further operand: if that one's rank is higher, its rank + 1;
  if equal, + 1. Class 13 adds 7 more, class 17 adds 5.
- count: leaves 1, constants (classes 7, 8) 0; an operator the sum of
  its operands' counts. So a constant always sorts after a variable of the
  same rank, and a bigger subtree before a smaller one.
- hash16: the table above.

What this means for source: within a `+` chain of products (matrix rows),
each product's rank and count are the same, so the hash orders them, and
the hash comes from front end IDs (declaration order, header contents:
every declaration before the function moves the IDs) and, for values the
optimiser has put in compiler temps (CSE, loop IVs, the `(sint16)` loads
of vertex fields), from the temp's slot number, which is the order the
optimiser created the temps in. Parentheses and source operand order do
not matter. `c2oracle.py FILE NAME --sort` prints each sorted list with
the keys; to swap two operands, change the input to the one that decides
(an ID: move a declaration; a temp slot: change which load is seen
first).

## Local register choice (0x435c37, commits through 0x435f38)

The picker for a value that needs a scratch register, in this order:

1. Preferred register (value record +0x2c, a node whose +0x1c is the
   register): taken if free and not in the value's interference set.
   It is set when the value is copied straight into a register-bound node
   (use opcode 1 into a class 1 node, any register but esp), or when the
   use (opcode 0x12) addresses memory through a plain base, which prefers
   the base's register. This path does NOT move the round robin.
2. Round robin (only if 0x48fb60): from the pointer 0x491120, the first
   of eax, ecx, edx (table entries below 4) that is free and does not
   interfere, wrapping once; the pointer then moves to the entry after the
   chosen one (back to eax after edx). The pointer is reset to eax once per
   function, at 0x42a90e, NOT per block or statement, so it carries across
   calls, branches and statements in code generation order.
3. First free in the whole table: eax ecx edx esi edi ebx ebp.
4. Otherwise 0x45d93e evicts a register (0x45a827 handles a spill).

So a run of `f(p->byte)` calls loads their arguments into al, cl, dl,
al, ... and where the run starts depends on how many round robin picks
came before it in the function (in a test, every `D("x", s->int_field)`
call before the run moved its start by one register). When ours starts one
register late, the target had one round robin pick fewer earlier (or a
pick that went through path 1 instead). `c2oracle.py FILE NAME --regs`
prints every pick with its path, so comparing the two sequences shows
where they part.

Where the picker is called from, and the exact path 1 conditions:

- The local pass walks each block's instructions (0x42a90e resets the
  pointer, then per instruction 0x42a99f releases the registers of values
  that die there and 0x42aa3c gives the instruction's results registers).
  0x42aa3c skips a result that is not a compiler temp (symbol byte +4 !=
  3) or that already sits in a register (0x435c01 looks the value up in
  0x491180); everything else goes through the picker, its only caller
  being 0x42aa95. So there is no other way for a scratch temp to get a
  register: when the target's sequence is shifted, one of its picks went
  through path 1 or a pick happened that ours lacks.
- Path 1, use opcode 1 (a copy): its first operand (+0x18) must be class
  1 and that symbol's register ([[op+0x18]+8]+0x1c) in 1..8 but not 5
  (esp). Copying a field load into a temp has a class 5 operand, so it
  never prefers anything.
- Path 1, use opcode 0x12 (an address computation, `add eax,0xc` for
  `&p->field`): its first operand must be a class 5 memory reference with
  a base (+0x24), no index (+0x1c == 0) and either +0x28 == 0 or (+0x10 &
  0xf) == 0 with +0x20 == 0; it prefers the base node's register.
- The value record (+0x18 of the result node) +0x1c is the value's index
  into the interference bit sets, the same number as its temp slot; +0x2c
  was empty on entry for every pick traced so far, so the preference
  comes from the two rules above, not from an earlier pass.
  `c2oracle.py --regs --raw` prints the record, its preference on entry
  and the index under each pick.

Which values live in callee-saved registers (esi/edi/ebx/ebp for whole
ranges) is decided by the global allocator below, not this picker.

## The global allocator (P2\color.c, reversed 2026-11-05)

C2.EXE names its sources in assert stubs: `P2\color.c` (0x49dfb4, stubs
at 0x4676b2.., 0x469159.., returning into 0x40ed04, 0x41a9bb, 0x41b1cc,
0x41c35c) is the global allocator, `P2\regasg.c` (0x49ddcc, 0x46f321,
0x4784e8) the local one, `P2\stack.c` (0x49e12c, 0x470315 -> 0x43f9a1)
the frame layout. It is a priority-based colorer in the Chow-Hennessy
style, not a Chaitin simplify/select: every live range gets a priority,
the ranges are colored one at a time, highest first, and a range that
doesn't fit is split or left in memory.

Driver 0x416e6a (once per function): the regions ("tiles", levels in
the array at 0x494244) are handled innermost first. For each round:

1. 0x40ee1d (body 0x40ee.. - 0x40f77a) walks the blocks and computes the
   priorities (below).
2. 0x438f32 builds the work list 0x4910d4 with 0x41b6fa, an insertion
   sort: descending by priority (+0xc); equal priorities descending by
   the position (+0x40); a range equal in both goes before the ones
   already in the list.
3. The loop at 0x4171e4 takes the head of the list: 0x41a985 colors it
   (returns the ranges it had to split, if any), 0x41b785 and 0x41ba2b
   commit the register (+0x10). A split puts the pieces back in the list
   and the driver goes back to step 1 (0x416f7c), so a function can show
   several rounds with changed priorities.
4. Then 0x41beb8 runs top down over the levels, and 0x42aadd finishes.

The live range record (0x44 bytes): +0 the back end symbol (a variable,
a parameter, or a compiler temp), +4 flags (0x1000000 set on a range
that was split), +0xc priority, +0x10 the register, as a pointer
0x494758 + 0x50 * reg into the per register table 0x494750 (whose +0xd
byte has flag 0x10 and +0x3c a cost; 0x42b204 sets that cost to
0x1000000 for eax/ecx/edx and 0 for esi/edi/ebx/ebp), +0x18 the sum of
the reference weights in the current block, +0x1c the range's index in
the bit sets, +0x24 the number of references, +0x3c the weighted
references (sum of multiplier * weight), +0x40 the position.

The candidate set: every live range of a variable, parameter or temp
the optimiser kept as a register candidate. Not every range reaches
0x41a985: the driver takes a range with weighted references (+0x3c) at
or below zero down another path (0x417213), and in the nested loop test
a variable with a positive priority in the first round was never
colored and lived in memory, so the cut-off is not just the sign of
the priority. Ranges that don't appear in `--global` live in memory.

The priority (0x40f5bb .. 0x40f75d, per block, after the block's
references were counted at 0x40f237 / 0x40f468):

- m(B) = 1 << (loop depth + 1), depth -1 outside loops: 1 outside any
  loop, 4 in a loop, 8 in a loop inside it, 16 one deeper (0x40f6cf).
- N(B) = the number of distinct ranges referenced in block B (0x40f5c9:
  the popcount of the block's set, plus the ranges in its lists).
- w(ref) from 0x40fada: 2 for most references; 0 seen for the write of
  a read-modify-write in a loop (`a += g(b)`: the read gave 2, the write
  0). Not checked further.
- For every range live in B: if it is referenced there, priority +=
  m(B) * N(B) * (sum of its w in B); if it is only live through B,
  priority -= m(B) * N(B).

So a variable used in a busy block (many other ranges referenced next
to it) gets more for the same use, and a variable that is live across
a loop where it is not used pays for every block of that loop, scaled
by how busy the block is. In a test, `a` used once in an outer loop and
live across an inner loop of three ranges lost 24 there and went to the
stack.

The position (+0x40, the tie-break) is written at 0x416ad3 by the walk
0x416a8d: blocks in their list order, the instructions of each block
from last to first, one count per instruction (0x416c2f); each time a
range starts (its +0x34 is 0) it takes the current count, so the final
value comes from the last block that defines it. With equal priority
the range with the higher position is colored first, which within one
block is the one whose definition comes EARLIER in the source. In a
test, `a += g(b); b += g(c) + a; c ^= g(d);` in a loop gave a, b, c the
same priority 102 and positions 23, 17, 13: esi, edi, ebx in that order.

The register: the first in the preference table eax ecx edx esi edi
ebx ebp that the range does not conflict with; a range live across a
call conflicts with eax/ecx/edx, so the callee-saved ones go out in the
order esi, edi, ebx, ebp to the ranges in priority order.

What it means for source: which value gets esi is the highest
priority range that lives across a call or a clobber; to move a value
up, give it more references in busy blocks, or take away the blocks it
is live through unused (shorter live range, a loop that doesn't carry
it). Statement order of independent loads doesn't matter (the
optimiser reorders them; all 24 orders of draw_scaled_spriteC's four
`inptr[k]` loads compile the same). `c2oracle.py SRC NAME --global`
prints each range in coloring order with its priority, position,
references and register; `--raw` adds every block's multiplier and each
range's contribution.

Not reversed yet: the frame (stack.c, around 0x43f9a1): which spilled
ranges share a slot, and when a dead parameter's home is reused (the
target's draw_scaled_spriteC keeps x2 and later the loop counter in
inptr's slot and has one more slot than ours).

## x87 scheduling (pre-pass reversed 2026-11-05, agent 13)

The scheduler is P2\x86\schedmd.c, a list scheduler, driver 0x40d9be.
The pass driver calls it twice per function: 0x4535dc with edx = 1 (the
pre-pass, before the global allocator 0x416e6a and the local one
0x42a8aa) and 0x45373b with edx = 0 (the post-pass, on machine
instructions, where 0x456d68 patches the stack with fxch). 0x49321c
holds the pass. Per block (0x40da53): 0x431ec0 builds the DAG, 0x430b4c
sets the priorities, 0x4315f1 schedules.

- A DAG node: +0x10/+0x14 ready list links, +0x1c the tuple (an
  expression node: +4 opcode, operands from +0x18), +0x20 predecessors
  left, +0x2c priority, +0x30 earliest cycle, +0x36 the tuple's position
  in the IL block.
- Ready list 0x493134, insertion 0x43170c: priority descending, then IL
  position ascending. The cycle picker 0x43179a walks it from the head
  and takes up to two (U/V pairing via the hook 0x493074, 0x431b0c, and
  the register check 0x431b6a when round robin is on); the taken nodes
  are in 0x4930b0, their count in eax at 0x4316ca.
- Priority: the path length to the block end, in units of 0x1000 (the
  loads of a cross product 0x36000, the subtractions 0x32000, the
  multiplies 0x20000, the final subtract 0x18000 in the test below).

So the pre-pass never reorders two loads of equal height: of the four
factor loads of a cross product, which comes first is the IL order, and
that is the order the tuple generator walked the tree after the LATER
commutative sort (the one c2 runs again after CSE, printed further down
by `--sort` for the same statement). The first-pass lists can agree while
the later ones do not, which is why earlier tests saw "same sorted
lists, different load orders".

In the later pass the factors `(double)(a->xs - b->xs)` are temps whose
key is their definition's: and(op138(op142(load, load))), hash16 =
C ^ hash(load a) ^ hash(load b), C a constant (0x14f in hwinsert.cpp).
A load hashes as fold16(offset) ^ 0x122 ^ hash(base):

- If the base is the parameter itself (mx/p0.c), the IDs decide:
  fold16(ID(v3)) ^ fold16(ID(v2)) ^ the offsets against the other
  factor's. Declarations before the function change it (p0 vs p8).
- If the fields' addresses are CSE temps (hwinsert.cpp's
  InsertGT3_ZBuffered, every field used in both branches), the base
  hashes as the address temp's slot, so the key is C ^ slot(&a->f) ^
  slot(&b->f) and IDs do not enter at all (hence flat pad sweeps).
  Those temps are made per vertex in source order, 31 slots apart, and
  within a vertex in the clipped branch's copy order (v1: ooz 632, xs
  635, ys 638; v2 at +31, v3 at +62),
  so ours puts v1y before v3x and v1x before v3y. The target's order
  (v3x v1y v3y v1x) follows if v3's group came before v1's, or if all
  of them moved by +38..+60 or -30..-57 slots (computed from the keys;
  not checked in gdb). Slot numbers come from c2's temp pool history
  (see Commutative operand sort): a source change before the cross
  product that allocates one or two more 32-entry chunks, or frees
  slots that are then reused, is what would move them.

In a micro test (a13/m/gen.py), a statement BEFORE the cross product
that reads the six fields in a vertex order of 1 3 2 or 2 3 1 gives the
target's order; 1 2 3, 2 1 3, 3 1 2 and 3 2 1 give ours. Reads after it
change nothing.

Integer code (SkidooControl) had no pre-pass picks in its blocks, so its
order is the tuple generator's alone (see SkidooControl at the end of
"IDs moved for one function only").

`c2oracle.py SRC NAME --x87` prints each pre-pass block's tuples in IL
order, with the scheduled position and the priority of each.

Older notes: of two consumers of a shared value the first placed gets
`fld st(0)`; the post-pass hoists long fdivs and patches with fxch. The
listing's mnemonic table is 0x49a69c, indexed by the machine
instruction's byte +0x30 (fadd..fdivr 0x3a-0x3f, faddp..fdivrp
0x40-0x45, fxch 0x54, fld 0x55, fst 0x57, fstp 0x58, fchs 0x6c);
0x425525 and the compares around 0x433d3f, 0x433eac, 0x434648 and
0x46f16c test for an fxch.

## Symbol IDs that are easy to miss

Measured with `c2oracle.py --sort` (it prints `name#ID`):

- An `if (c) {} else return;` costs one ID more than `if (!c) return;`
  (with an empty statement in place of `{}` too), so the else's label is
  a symbol. Taking an `else` away after a branch that ends in `return`
  saves one.
- A repeated prototype costs two IDs, with or without parameter names;
  deleting a repeat saves two.
- A prototype's named parameters count, so moving a prototype moves
  them with it.

## Branch layout

After a call whose result is tested for a return, `if (!n) return;`
compiles to `je <shared epilogue>; jmp <join>` when the code that follows
is an else branch, while `if (n) {} else return;` gives `jne <join>`
followed by a copy of the epilogue. InsertGT3_ZBuffered needs the second.

## Case notes

- InsertGT4_ZBuffered and InsertGT3_ZBuffered (hwinsert.cpp): the clip
  `&`/`|` chains are sorted by the parameters' IDs (memory references
  hash as offset ^ opcode ^ ID). GT4 needs its parameter IDs one higher
  than the old layout or another odd shift (1, 3, 9, 11, 13, ...); GT3
  needs 12 or 13 (mod 8 = 4 or 5). Both are done by moving real
  declarations (a9d2ba3, d482039). What is left is the cross product's
  load order (6 and 12 bytes), see x87 scheduling.
- S_DrawSprite and draw_scaled_spriteC (scalespr.cpp) are not x87:
  S_DrawSprite differs in integer matrix term order, register choice and
  block order (the `else if (x | y | z)` branch is inverted in the
  target; swapping the branches fixes the jump but not the rest);
  draw_scaled_spriteC has a frame four bytes bigger in the target (one
  more stack slot) and different registers. Neither reacts to 0-63
  extra declarations.

- Func4524e0 (setup.cpp): the GUID lea's take eax by preference (path 1);
  then `settings->RenderMode` takes eax by round robin, so
  PerspectiveCorrect gets cl. The target has the same `mov eax,[esi+0x10];
  push eax` but PerspectiveCorrect in al, so its RenderMode load came
  through path 1 (or one more round robin pick happened in the same
  stretch). A `(DWORD)` cast does not change it. Also flat (identical
  code): an unsigned RenderMode field, LONG return types on the four
  registry helpers, a `guidString` local for the GUID calls (any subset),
  removing the joystick block or its else, a second RenderMode call, and
  compiling without /GX. Under the conditions above, a plain field load
  can't take path 1, so the shift has to come from a pick ours lacks
  earlier (two of them, mod 3) or from a PerspectiveCorrect use shape
  we haven't found. It's worth only 42 bytes of the exe.
- calc_roomvert (3d_gen.cpp): `--sort` shows each matrix row sorted twice.
  The first sort (rank 03, before the loop optimiser) is not what gets
  emitted; the second (rank 02, where the `(sint16)` vertex loads are
  compiler temps) is. With o0 = objptr[0] (a symbol) and y, z the temps
  for objptr[1], objptr[2], m_k the temps for the mptr loads, each product
  hashes to 0x76 ^ h(vertex) ^ h(matrix) (0x76 = 0x143 mul ^ 0x135 and;
  the two memory-reference opcodes cancel). The target needs, with the
  slot numbers of that build: row 0 y > z > x (where x = 0x76 ^ fold16(ID
  objptr) ^ fold16(ID mptr)), row 1 y > z, row 2 z > y. Source term
  order (all 216 orders of the three rows) and local declaration order
  (permute.py --decls, 1500 orders) produce identical code. Adding any
  function before it moves both the IDs and the slots (one empty function
  swapped the y/z slots), and how many temps that function uses doesn't
  matter (the pool is recycled LIFO).
- EnumDisplayModesCallback (winvid.cpp, 834 bytes of the exe): not c2 but
  the front end's inliner. The target inlines InsertDisplayModeInListSorted
  twice with an uneven pattern: hw list: Head inlined but its node
  constructor called, Tail inlined with the constructor inlined; sw list:
  Head called, Tail inlined with the constructor called; CompareVideoModes
  called in both. Calls in the target: GetRenderBitDepth new ctor CVM new
  Head CVM new new ctor new. That looks like a per-function inline budget
  running out: making Head and CompareVideoModes `inline` (ours has them
  out of line) gives "new new new new Tail new", so a budget exists. All
  16 combinations of inline on Head, Tail, CompareVideoModes and the
  constructor miss it, and so do the definition's position and
  inline_depth 2..8 at the top of the file. With inline_depth(2) from the
  callback on, swRendererSupported moves to bl as in the target
  (otherwise it is spilled to the stack). Next: vary the sizes of the
  inlined bodies, since the budget is probably counted in front end nodes.
  When `#pragma inline_depth` takes effect: what counts is the depth in
  effect where the callees are defined (Head, Tail and the constructor
  come after the callback in the file). A pragma just before the
  callback and a reset right after it change nothing, and replacing the
  file's first pragma changes nothing either. `inline_depth(2)` from the
  node constructor on, with Head made `inline`, cuts the callback's
  differing bytes from about 826 to 589, but Head is then never emitted
  out of line (0x4470c0 is lost), and the exe link fails ("No room for
  allocation" for a `$T` constant of setup.obj in config/layout/data.py),
  so it's not landed.

## Headers scored by exe bytes

The earlier header searches kept a variant only when it made a function
match. Scored by the bytes of the exe instead, one or two real header
lines at the top of a file took 3362 bytes off in one round:

- larafire.c: `<stdio.h>` before game.h (LaraGun 535 -> 3: the bitfield
  store `lara.flare_control_left = ...` is an XOR of a temp and `lara`,
  and `lara`'s ID had to rise above the temp's slot, 0x12a).
- control.c: `<windows.h>` + `<stdio.h>` (ObjectOnLOS, 694 -> 0; dinput.h
  alone leaves 12).
- hair.c: `<windows.h>` (HairControl: the csv size also had to take in its
  jump table, 2533 -> 2556).
- skidoo.c: `<ddraw.h>` + `<malloc.h>` (SkidManControl 320 -> 0; ddraw.h
  alone breaks SkidmanPush and SkidooDynamics, malloc.h puts them back).
- output.cpp: `<dinput.h>` first (S_GetObjectBounds 267 -> 111, and
  S_InsertBackPolygon is no longer shifted).
- text.c: `<string.h>` (GetTextScaleV, 52).
- 3d_gen.cpp: `<io.h> <conio.h> <direct.h> <sys/stat.h>` after string.h
  (+384 IDs), then the InsertSprite/InsertTransQuad pointers and the
  ins_objectGT3/GT4 prototypes moved from the bottom `extern "C" {}`
  block to just before calc_vertice_light (+22, each line with its own
  `extern "C"`): calc_roomvert 542 -> 0, calc_object_vertices 367 -> 31,
  calc_vertice_light 211 -> 55.

Why big shifts: the sort compares fold16(ID) of symbols with the slot
numbers of compiler temps, so a function often needs its IDs moved by
hundreds, and the band is narrow: in 3d_gen.cpp the top of the file
had to move by exactly 384 mod 512 (365..410 all break a transform).
Small pad scans (0..64) never see this.

Method that found these, in this order:

1. Header sweep per file: each system header alone at the top, then
   `<windows.h>` + one, then the best + one, scoring the sum of
   differing bytes over every function the object defines (a variant
   that improves one function but breaks a neighbour shows up as a net
   number). Real headers only; a header the file already gets through
   another one still moves IDs when it comes first.
2. If nothing fits, pad-scan the top of the file in big steps (multiples
   of 128 up to 4096), then narrow down to the exact band.
3. Measure what each header costs: the front end ID of a symbol is the
   4 bytes (little endian) just before `\0name\0` in the `sy` file that
   c2oracle's stand-in keeps; compile the file with a header added and
   compare the ID of one of the function's parameters. Costs are not
   additive when headers share includes, so check the sum the same way.
   In 3d_gen.cpp (after the existing standard.h list): io 217, wchar
   248, mbstring 197, typeinfo 182, iostream 851, fstream 1060, dplay
   428, conio 62, sys/stat 53, direct 52, search 46, tchar 45, malloc
   41, mbctype 35, new/eh 18, locale 16, setjmp/dos 15, signal 10,
   sys/types 7, stddef 2, errno/limits/fcntl/share 1, ctype/float/excpt
   0; objbase/ole2/winsock -369 (before windows.h they change what it
   pulls in).
4. Then pad-scan locally for what is left and supply it by moving real
   declarations from below the last function that cares.

Flat under all of this: S_CalculateLight (pads 1..300 before it),
S_GetObjectBounds (pads 1..1000 before it), SkidooControl (1..1024),
texture.cpp, scalespr.cpp, draw.c (GetRoomBounds), winvid.cpp (headers,
include moves).

## winvid.cpp: inlining

- The atexit helper at 0x444a80 (DisplayAdapterList's destructor, 194
  bytes) has the whole chain inlined in the target: node delete,
  DISPLAY_ADAPTER, both DISPLAY_MODE_LISTs with DisplayModeListDelete,
  the STRING_FLAGGED members. Ours calls DisplayModeListDelete
  (0x447060). `#pragma inline_depth(5)` or `(8)` before the list's
  destructor or before the DisplayAdapterList definition changes
  nothing; before DisplayModeListDelete's definition it costs
  WinVidStart 430 bytes.
- `inline_depth(2)` before the node constructor with Head made inline
  (826 -> 589 bytes in the object) is not usable: the callback then
  comes out 37 bytes longer than its 945-byte slot, so the exe layout
  overflows ("The linked code exceeded its recovered layout"). The data
  side of that failure ("No room for allocation" for setup.obj's
  `$T` constant) now falls back to the other initialised section
  (config/layout/data.py), so a variant like it can be measured once its
  code fits.

## The inliner (C2.EXE, P2\inline.c)

Inline expansion is done by the back end: C2.EXE carries the source
path `E:\utc\src\\P2\inline.c` (0x49e144), used by two cold assert
stubs at 0x4721f6 and 0x4722c4 that jump back into 0x44b6c7..0x44b9e0.
Those are the splicing helpers (0x44ab79 .. 0x44bdcb). The decisions
are made in 0x42491e (once per function) and 0x4249cb (once per level,
recursive); `c2oracle.py SRC NAME --inline` prints them.

### The budget model (reversed 2026-11-05)

- Every function carries a size, a word at front end symbol +0x64,
  read from the `gl` file at 0x420ae1. The front end (c1xx) computes it;
  c2 never changes it. The unit is roughly IL nodes: `dwCount++;` is 7,
  `next = nextNode;` 8, `if (x == 7) x = 3;` 20, a two assignment
  constructor 38. Line breaks, `this->`, casts, initialiser lists and
  `a, b` comma forms cost the same; a ternary store is 7 less than the
  if/else, a named temporary for the return value 5 more.
- The caller's budget (0x42492f): max(1000, 2 * its own size), capped
  at 35000. So almost every function starts with 1000.
- 0x4251e8 collects the candidate call sites of the function, in
  source order: calls of inline functions (declared `inline`, defined in
  the class, or compiler generated), not calls of ordinary functions.
  Each record holds the inline_depth limit of the call site.
- 0x4249cb walks the sites in order. For each one, with B the budget
  left at this level and n the number of sites left (this one
  included):
  1. refused if the arguments don't fit the parameters, if
     depth > the site's limit (depth is 1 for the caller's own calls),
     if size > 40 and size > B, or if the running total (0x490e70, the
     caller's size plus every inlined size) is over 35000 (0x424eef ..
     0x424f53; C4710 for an `inline` callee);
  2. otherwise B -= size, but only if size > 40 (0x424f6b): a callee
     of size 40 or less is free and is always inlined while the depth
     allows;
  3. the callee's own sites are expanded first, recursively, with the
     budget B // n (0x424bf5: the budget is shared between the sites
     still to come), and what they spend comes off B too (0x424c29);
  4. then the body is spliced in (0x44ab79 .. 0x44ba88). Two late
     checks after the payment can still refuse it (0x46b024, 0x46b06a).
- The limit of a call site is the `#pragma inline_depth` in effect
  where the call is written: in the caller, or in the inline body that
  contains it. Calls inside compiler generated functions (implicit
  constructors and destructors, `?_G` scalar deleting destructors) take
  the pragma in effect where they were first generated. Without any
  pragma the limit is 8.

Consequences for matching:

- Of two sites at the same level, a later one can be inlined after an
  earlier one was refused only if it is smaller (or free). A free
  callee (size <= 40) is never refused for budget.
- The budget shrinks fast with the number of sites that follow: the
  first of five sites passes a fifth of what is left to its own calls.
  Extra inline calls after a site (even free ones that leave no code)
  make that site's nested expansions poorer. Tested in
  WinVidGetDisplayAdapters with no pragmas: 0..6 calls of a free inline
  helper after the delete loop give, for its nested
  DisplayModeListDelete x2 and ~STRING_FLAGGED x2, `++++`, `++++`,
  `-+++`, `-+--`, `--+-`, `----`: four extra sites give exactly the
  target's `--+-`.

### What the target needs (winvid.cpp)

Target decisions, read from the exe (+ inlined, - called):

- EnumDisplayModesCallback: hw Sorted+ (Head+ (ctor-), ctor+, Tail+
  (ctor+)); sw Sorted+ (Head-, ctor+, Tail+ (ctor-)). CompareVideoModes
  is an ordinary function (it is placed before the callers, so it is
  not an inline copy), so it is not a site.
- WinVidStart: in the hw list copy, Tail+ with its ctor-; sw Tail-.
- WinVidGetDisplayAdapters: ?_G+ ~NODE+ ~ADAPTER+, ~ML+ (DMLD-) x2,
  ~INFO+ (driverName ~SF+, driverDescription ~SF-).
- EnumDisplayAdaptersCallback: the node constructor and ?0ADAPTER
  inlined, ?0INFO and both ?0ML called. The target also stores
  node->next/previous BEFORE the body's constructors run, so the
  adapter node has a constructor with an initialiser list
  `(prevNode, nextNode) : next(nextNode), previous(prevNode)`; making
  that change alone costs 66 bytes, because of the budget below.
- $E2 (0x444a80): everything inlined, down to DisplayModeListDelete
  and both ~STRING_FLAGGED at depth 6.

What that means with the model above, with no pragma anywhere (limit
8 everywhere):

- $E2 makes the target's decisions (everything inlined).
- The display mode node constructor must be bigger than 40 (ours is
  38): a free callee can't be refused, but the target calls it in
  places where it is inlined elsewhere at the same depth (Head's and
  sw Tail's in EnumDisplayModesCallback, hw Tail's in WinVidStart,
  which gets a budget of 8 there). Checked: with no pragma and a
  constructor of 46 (a third store, which itself costs code, so not
  usable), WinVidStart still matches.
- EnumDisplayModesCallback, with Head before the loop and Tail after
  it (our order) and Head the same size as Tail, can't be reached at
  any sizes: sw Head refused and the later sw Tail inlined needs
  Head > Tail + ctor. Brute force over the sizes: with the loop and
  Tail BEFORE Head in the sorted insert (`if (head) {loop; Tail} else
  Head`), Head == Tail == 101 works for ctor 56..69 with the sorted
  insert at about 200..260; with our order it needs Head about 180 for
  Tail 101.
- WinVidGetDisplayAdapters needs exactly four more inline call sites
  after the delete loop (or the equivalent division elsewhere): the
  budget of ~INFO's level must be 44..87, and with one site there it is
  831.
- EnumDisplayAdaptersCallback refuses ?0ML (size 41) at depth 3, so the
  budget at ?0ADAPTER's sites must be under 41; with one site at the top
  it is 856. That needs at least six more inline sites after the
  `new` (or deeper nesting).

So with the flattened call graph the target can't be reached without
pragmas: the original used more small inline functions (accessors, list
helpers) than our source had, and a bigger node constructor.

### Solved: the list template (2026-11-05)

The original's lists are one template with every method defined in the
class (the design of Core's SPECIFIC/template.h, which is also inside
Core's INCLUDE.H), shared by winvid.cpp, winin.cpp and ds.cpp: tr02's
src/specific/template.h. With it, all four targets above and $E2 come out
with no pragma at all (winvid, winin and ds now have none). What made the
difference, in the model's terms:

- Wrappers add levels, not cost. `Insert` calls `AddHead(item)` which is
  `NewHead() = item`: AddHead (30) is free, but it is a level of its own,
  and it shares the budget among Insert's three sites (AddHead, the node
  constructor, AddTail).
- The node constructor constructs the payload. `NODE(prev, next) :
  next(..), previous(..)` in `struct NODE { NODE *next, *previous; T body; }`
  is 38 for a T without a constructor, 49 once DISPLAY_MODE has its empty
  `DISPLAY_MODE() {}` (Core's ScreenMode has one, plus a four-argument
  constructor and `Set`), 65 for DISPLAY_ADAPTER (whose implicit
  constructor is 119). Over 40, so it is no longer free: that is the
  "constructor of size >= 41" EnumDisplayModesCallback and WinVidStart
  needed. Sizes seen: NewHead/NewTail 101, Insert 184, RemoveAll 84/95,
  Set 53, the four-argument ctor 56, LIST() 41, ~LIST 29, the generic
  adapter's implicit ctor 76 and dtor 51, STRING_FLAGGED() 53, ~ 44,
  `operator LPTSTR` 23, SetGuid 74, GetHead 23, GetNext 37, `operator[]` 23.
- The extra sites in the callers are the template's accessors and the
  adapter's helpers: EnumDisplayAdaptersCallback calls NewTail, SetGuid
  and twice `operator LPTSTR` (strcpy into a STRING_FLAGGED), so NewTail
  gets (1000 - 101) // 4; WinVidGetDisplayAdapters calls RemoveAll, then
  GetHead, GetNext and `operator[]` in a `for (node = l.GetHead(); node;
  node = l.GetNext(node))` loop.
- That loop is also where the odd `if (!node) break;` at the end of the
  old loops came from: GetNext's own null test, inlined.
- Out-of-line copies keep their addresses but get template names in
  symbols.csv (`?NewHead@?$LIST@UDISPLAY_MODE@@@@QAEAAUDISPLAY_MODE@@XZ`,
  `??0NODE@?$LIST@UDISPLAY_MODE@@@@QAE@PAU01@0@Z`, ...); CompareVideoModes
  is `DISPLAY_MODE::operator<` (Core's Insert compares with `<`).
- Moving STRING_FLAGGED and the list above CalculateCompatibleColor (the
  include goes at the top) shifts its parameters' IDs and flips its OR
  chain (it matches at +2 and +6..10 more symbols, period 16). The rest
  of the template's API (GetTail, GetPrev, IsEmpty and STRING_FLAGGED's
  `(LPTSTR)` constructor, all in Core's design) brings it back.
- Not inliner, but found on the way: EnumDisplayAdaptersCallback's
  callee-saved pushes sit at the top in the target and were shrink-wrapped
  in ours until the function used Core's early returns (`if
  (!DDrawCreate(..)) return TRUE;` and `if (DX_TRY(..)) { DDrawRelease();
  return TRUE; }`) with each memset next to its dwSize store; and the
  sorted insert tests `if (!prev) head = .. else prev->next = ..`.

Older observations, from before the model (their explanations are
superseded by it):

- The order of the inline definitions in the file does not matter
  (all 96 orders of the node constructor, Head, Tail and the sorted
  insert, before and after the callback, compile the same).
- `#pragma inline_depth` counts where the callee is DEFINED: with Head
  made `inline` and `#pragma inline_depth(1)` or `(2)` just before
  Head's definition (back to 3 before Tail's), every expansion of Head
  keeps its node constructor as a call, while Tail's expansions inline
  it. That is exactly the target's hw half of EnumDisplayModesCallback
  (the first ~150 instructions match; 799 -> 453 differing bytes in the
  object). Not landed: the sw half still inlines Head and Tail's
  constructor, so the function is 1029 bytes for a 945-byte slot.
- There is a per-caller budget, consumed in source order, and it does
  not count plain statements: 16 extra `dwCount++` in Head, Tail or the
  sorted insert, or duplicating whole blocks of the caller itself,
  change nothing. It counts branches in the inlined bodies: with each
  extra `if (x == 7) x = 3;` in the sorted insert, 6 make the sw Tail a
  call, 12 the whole sw sorted insert; 7 to 10 in Head make the sw Head
  a call while the hw Head still inlines (the target's pattern for
  Head). The sw Tail's constructor as a call (also the target's) never
  appeared in a 6x14x4 grid of such bloats, so the window for it is
  narrower than one branch. So the target's inlined bodies are worth
  more branches than ours, or the budget unit is not the branch.
- The same uneven pattern is in WinVidGetDisplayAdapters: the target
  inlines driverName's ~STRING_FLAGGED and calls driverDescription's
  (FlaggedStringDelete); ours calls both.
- The atexit helper at 0x444a80 ($E2, DisplayAdapterList's destructor;
  the target inlines everything, ours calls DisplayModeListDelete and
  ~DISPLAY_ADAPTER_INFO) does not move with DisplayModeListDelete
  defined right after its class, ~DISPLAY_MODE_LIST defined out of the
  class after it, an explicit empty ~DISPLAY_ADAPTER_INFO, the
  STRING_FLAGGED destructor in the class, or inline_depth 6/8 at the top,
  before ~DISPLAY_ADAPTER_LIST or before the DisplayAdapterList
  definition (any combination of up to three).
- th08's "parameter types matter" lesson: swRendererSupported as BOOL or
  int costs 30 bytes, BYTE is the same as bool; the sorted insert taking
  `const DISPLAY_MODE &` is the same.

## Shifts that worked (2026-11-05)

- 3dinsert.cpp: `<math.h>` + `<direct.h>` before 3dglodef.h (+392 IDs):
  visible_zclip 92 -> 38 in the exe. Its pad map: only shifts that are
  multiples of 8 work, then with period 128 from 256 on (256+8 = 264,
  392, 520 best); below 256 nothing does. What is left is x87 order
  (flat for 0..39 more declarations in front of it).
- 3d_gen.cpp: calc_object_vertices needed +12/13 or +26..31 (or +44/45,
  +108/109) while calc_vertice_light after it must not move. Moving the
  InsertSprite pointer and the ins_objectGT3 prototype from between the
  two functions to just before calc_object_vertices shifts only the
  first one: 31 -> 2 bytes, the other unchanged. calc_vertice_light is
  flat for 1..199 declarations in front of it.

## Source shapes that the allocator is not behind (2026-11-05, agent 9)

Four of the top reds turned out not to be register allocation at all;
look for these before reading `--global`:

- Immediate size gives away a field's signedness. `r->bound_active -= 2`
  on a uint16 field is `66 81 /0 fffe` (imm16, the constant is 65534);
  on a sint16 field it is `66 83 /0 fe` (imm8, -2). A 66 81 / 66 83
  difference on a 16-bit add or sub means the field is signed: room.h's
  bound_active is sint16 (GetRoomBounds 371 -> 50 exe bytes; the rest is
  shift and the door-plane sum).
- `n << 1` and `n * 2` are different expressions to the optimiser's CSE
  even though both come out as `lea r,[n+n]`. When the target computes
  the same `lea` twice into two stack slots (AddTexturePage16:
  `memcpy(dst, src, width << 1); src += width * 2;`), one of them is
  a shift. This is also where that function's "one more slot" came
  from (frame 0x80 vs 0x7c); 394 -> 34 exe bytes. `+`, casts to DWORD,
  sizeof and a uint16 pointer step are all merged with `* 2`.
- Early returns stay in source order: the target tests
  `if (!n || off screen) return 0;` before `if (n < 8 || clipped)
  return -1;` in S_GetObjectBounds, and nothing in the back end swaps
  two such ifs. Moving `n++` after the divide that follows it moves the
  loads the scheduler puts around the idiv (111 -> 35).

Flat this round (so not the cause): GetRoomBounds' door-plane sum under
all 6 term orders x 4 inner orders, the 24 local declaration orders,
index vs pointer forms, dropping the casts and inverting the test
(the sort keys tie in the first sort and are decided by temp slots
in the second); LoadTexturePage's `jge; mov al,1; test al,al; je`
(unique in the exe) under 9 DX_TRY bodies, Core's `Log 0&&` statement
and 9 condition shapes; AddTexturePage16's 110 single declaration moves
and counter directions; SkidooControl's frame sync under 3 sum shapes
(inverting the if costs 18); draw_scaled_spriteC's inner and outer loop
forms (for down, for up, while: the optimiser makes the same loops).

The frame (P2\stack.c, the function at 0x43f93b, its assert returns to
0x43f9a1) is not reversed. What the targets show: a stack home is
shared by ranges whose memory lives don't overlap, and a parameter's
home is reused once the parameter sits in a register. draw_scaled_spriteC,
slots from esp+0x10 after the pushes: target ubase, vadd, source, dqptr,
uadd, skip, i (second loop), pix (second loop), with x2, then width,
then the first loop's i in inptr's home; ours width, vadd, dqptr+i,
source, uadd, x2+skip, pix, with ubase in inptr's home. The target's
extra slot is the second loop's i: there dqptr is reloaded from its
slot inside the loop (not colored), so i cannot share it; ours keeps
dqptr in eax in that loop. So the slot difference follows from the
coloring, and it is the coloring that has to change.

## Loop and flag shapes (2026-11-05, agent 10)

Plain-diff triage of every red; these shapes landed:

- `lea r,[eax]` where ours has `mov r,eax` is a countdown loop written
  with the decrement in the test: `for (j = width; j--;)` (AddTexturePage16's
  inner loop, as InsertClippedPoly_Textured before it). `for (j = n; j; j--)`,
  `j != 0` and up-counting forms give `mov`.
- A separate counter where the target copies the count (`mov edx,edi`) and
  then reuses the count's register: `for (dest = PhdVBuf, i = numvert; i--;
  dest++)` in calc_vertice_light. A loop on a negative count with no entry
  test after the `if (numvert < 0)` is `for (; numvert < 0; numvert++)`, not
  `numvert = -numvert; for (; numvert > 0; numvert--)` (c2 drops the
  repeated test itself). Returns that the target shares (`mov eax,esi`
  before each epilogue) are one `return objptr;` at the end.
- An increment that sits in the loop body vs in the for's third clause
  moves the `add` (calc_vertice_light: `dest++, objptr += 3` in the clause
  puts the dest step first, as the target has it).
- `jge skip; mov al,1; test al,al; je skip` (no setcc) is a bool variable
  set to a constant and then tested, not an inline returning bool:
  `if (reset || !surface) reset = true; else if (FAILED(x)) reset = true;
  if (reset) ...` in LoadTexturePage (92 -> 7). Every DX_TRY body (if/else,
  ternary, `rc` variable) gives `setl` or a fully threaded `jge`.
- Pointer stepping vs indexing in an inner loop moves where the pointer
  copy is scheduled: AdjustTextureUVs `*uv -= adjust; ... uv++;` (5 -> 2).
- A goto into a shared tail (`goto flare_in_hand;`) changes the local
  register rotation of the code after the label: LaraGun matched once the
  armless case repeated the two calls instead (c2 merges the tails anyway).
- permute.py --decls also fixes x87 operand order when `--sort` shows the
  two operands as symbols (calc_object_vertices `f_mid_sort + zv`: the
  float locals' IDs decide; 672 tries). After adding a local, rerun it on
  the file's later functions (phd_RotateLight flipped and came back with
  one declaration move).

- ins_poly_trans8's 8-way clip AND/OR order follows the IDs of the
  vn1..vn8 locals: `permute.py --decls --limit 8000` (about 40 min) found
  `int npoints; VERTEX_INFO *v; PHD_VBUF *vn1, *vn5, *vn3, *vn2, *vn7,
  *vn4, *vn8, *vn6;` (113 -> 48 exe bytes). The full 8! is not searched.

Triage of the rest (not landed):

- InsertGT3_ZBuffered, InsertGT4_ZBuffered, InsertGT3_Sorted: the
  cross-product factor loads (x87 scheduler, see above). GT3_Sorted's clip
  AND/OR order is the sort of `v->clip` (keys fold16(ID) ^ 0x159, the
  params' IDs): one more symbol before the function fixes it (21 -> 12),
  but every real declaration moved there breaks InsertGT4_Sorted and the
  InsertObject*_Sorted functions. Prototype parameter names are not
  symbols.
- Func4524e0: the target keeps RenderMode's load in eax as a preferred
  pick (the rotation stays at eax, so PerspectiveCorrect gets al); ours
  picks it round robin. Flat under casts, field types and a repeated
  tail.
- SkidooControl: the second store survives in the target because the
  first branch's value is in di (the skidoo anim index, picked first free
  after the lara anim index took edx), so the two tails differ. In ours
  the skidoo index is picked first (edx) and both branches store dx, which
  c2 merges. Every sum shape of the frame expression is canonicalised
  (9 orders, parens, negations, casts); `+=` splits cost 20.
- visible_zclip: one to three symbols before it (moving FltNearZ etc. up)
  or two fewer all cost 24..34; term orders are canonicalised.
- AddTexturePage16 (32 left), calc_vertice_light (9 left: the count copy
  comes after the multiply in ours), AdjustTextureUVs (2: `lea ebp,[eax]`
  from a global count; every countdown form tried gives mov or a +1 lea),
  LoadTexturePage (7: the flag stays in bl across the call in ours, al in
  the target).

## Flat under header sweeps and top pads 32..4096 (step 32)

texture.cpp (AddTexturePage16, LoadTexturePage), draw.c (GetRoomBounds),
output.cpp (S_CalculateLight, S_GetObjectBounds), skidoo.c
(SkidooControl), winvid.cpp and hwinsert.cpp: these reds are not
ID-driven. scalespr.cpp moves only 32 bytes (top pads 256..511 mod 512:
S_DrawSprite 434 -> 431, draw_scaled_spriteC 424 -> 395) and its
remaining differences are global register allocation (which values get
esi/edi/ebx/ebp, and the target's extra stack slot).

## Big three (2026-11-05, agent 11)

Exe file 1744 -> 576 differing bytes. None of these needed the
allocator model changed; each was a source shape (and one ID shift)
that the earlier sweeps had not tried.

- S_CalculateLight (326 -> 66): `1 << (dynamic[i].falloff << 1)` in the
  range test, `dynamic[i].falloff * 2 - intensity` in the shade. The
  target computes `lea ecx,[edx+edx]` from the falloff it already has
  and then reloads the field for the shade's `add ecx,ecx`; with `* 2`
  in both, c2 CSEs them (spilling the product) and the coloring of the
  whole dynamic loop moves. The same `<< 1` vs `* 2` rule as
  AddTexturePage16.
- S_CalculateLight, slot sharing: a parameter's home (room_number,
  [esp+0x48]) goes to a spilled range that starts after the parameter's
  last use. `brightest = 0;` before `r = &room[room_number];` starts
  brightest while room_number is live, so brightest gets its own slot
  and the loop counters and adder take room_number's home, as in the
  target (74 -> 66). Left: the target's frame is 8 bytes bigger (angles
  shares r's slot, dz's spill gets its own; ours shares dz with angles)
  and r sits in edx (ours ecx). Flat under all 172 sampled orders of
  the declaration lines and angles[3]/[4] (the frame is not
  declaration-ordered).
- S_DrawSprite (490 -> 0): Core's shape, the zero-offset case first
  (`else if (!(x | y | z))`, which makes it the fall-through) and
  `zp = zv / PhdPersp;` right after the branches, before the sprite
  loads; then the products' order (z, x, y in every matrix row) needs
  the IDs of the header globals shifted by 5 mod 16 (pads 5, 21, 53, 69
  match; 13, 37, 45 leave 14). Pads after 3dglodef.h (moving only the
  function's own IDs, x by +10 etc.) change nothing, although a key of
  `fold16(ID(x)) ^ hash([phd_mxptr+off])` would predict they do: the
  key of a product of a parameter and a matrix element read through a
  temp is not just that XOR (not reversed). Landed with
  `#include "../specific/time.h"` between global.h and 3dglodef.h
  (frontend.h and sound.h there also match). The earlier pad sweep used
  steps of 32 and missed the window: scan pads in steps of 1 over a
  period, and again after each structural fix.
- draw_scaled_spriteC (467 -> 49): Core's shape, `x2 -= x1; y2 -= y1;`
  reusing the corners as width and height (no width/height/i locals),
  the outer loop `for (; y2 > 0; y2--)`, the inner `for (j = x2; ...)`,
  and skip computed after pixptr (467 -> 210: frame, the eax width and
  the edx/ecx picks of the set-up code). Then `u = ubase;` BEFORE
  `line = source + ...` in each row (202 -> 41 object bytes): which
  of two independent statements comes first does matter when it moves
  where a live range starts (u's range then covers the line computation
  and the coloring of the row header changes), unlike the order of
  independent loads. Left: u and pixptr swap esi/edx. The model gives
  u 168 and 160 (one range per loop) and pixptr 148, so u is colored
  first and takes edx; the target needs pixptr above both. Flat: 8
  pixptr expression forms, `if ((pix = ...))`, `(v >> 16) << 8`, dqptr
  as a uint8 pointer, `pixptr++` in the for clause, `v += vadd` first,
  `j; j--` / `j--;` forms, the u init in the for clause (worse).

## IDs moved for one function only (2026-11-05, agent 12)

A pad of one symbol before InsertGT3_Sorted fixed its clip AND/OR
order (21 -> 12) but broke InsertGT4_Sorted and the InsertObject*_Sorted
functions after it. The shift can be confined to the function: add one
symbol before it and take one away inside it, after its parameters
(their IDs are what the sort key reads), so everything after it keeps
its old IDs. Both halves are `else` labels:

- `if (z >= phd_zfar) return; else if (z < phd_znear) ...` in
  InsertLine_ZBuffered, the function before (+1, its code unchanged).
- InsertGT3_Sorted's `if (...) { ...; return; } else { ... }` written
  without the `else` and the body unindented (-1 after the parameters).

9126202: InsertGT3_Sorted 21 -> 12, nothing else moves; exe file
576 -> 567. Use this whenever a pad sweep in front of a function shows
it improving while a later function breaks.

Step-1 pads, 1..64 at the top of the file and 1..64 in front of each
red function, scored over the whole object (a12/runpads.sh): flat for
every other red (output.cpp, draw.c, 3dinsert.cpp, setup.cpp,
texture.cpp, scalespr.cpp, hwinsert.cpp's ZBuffered pair, winvid.cpp,
3d_gen.cpp, file.cpp); skidoo.c top pads 33..160 too (SkidooControl only
goes 101 -> 124 from pad 118 on, the first statement's operand order).
These reds are not ID-driven.

SkidooControl: the target evaluates the frame sum's lara_item side
first (lara_item into ecx, its anim index into edx, the skidoo index
from ax then gets edi, anims last in eax); ours loads anims first (ecx)
and the skidoo index takes edx, so both branches store dx and c2 merges
the stores. Flat: Core's `fb + (frame - fb)` and 8 other sum shapes,
casts, the anim_number assignment inside the index, pads before the
function 1..64, and declaring anims before lara_item (anim.h ahead of
game.h), so the order of the two shared leaves is not their ID order.
Writing the index out again (no CSE of ax) does give lara_item first and
two stores, but recomputes the index (+18).

draw_scaled_spriteC, the u/pixptr priorities from `--global --raw`:
pixptr loses 32 in each row header (m 4, N 8, live through) and 32 in
each inner load block (m 8, N 4), where u gains 64 in each. Moving the
row tail into the for clause, the inner increments into its clause,
dropping `line` (much worse) and swapping the increments are all flat
or worse. What would move it: two fewer ranges referenced in the row
header (u -16, pixptr +16 over both loops).

SkidooControl, traced further (agent 13). The listing (c2 -Fa) has the
same order as the object, and -G3 gives the same code, so the order is
the tuple generator's, then the global allocator: `--global` shows
lara_item (position 300) and anims (297) both at priority 16, so
lara_item is colored first and takes eax, anims ecx. In the target
lara_item is in ecx because its load comes BEFORE the movsx that ends
the anim_number temp in ax (the two conflict), and anims after it (no
conflict: eax). Our tuples load anims, then the skidoo index, then
lara_item, then the lara index; the target's local picks (lara index
edx, skidoo index then edi as first free) say it built the lara index
before the skidoo index. In the later commutative sort the SUB's
operands are A = [anims + skidoo_index*32 + 16] (key 01.02.5762) and
B = [anims + [lara_item+20]*32 + 16] (01.02.0099): equal rank and
count, and our generator walks A first. Not found yet: the rule that
picks which operand of a non-commutative op (op142) is generated first;
the place to look is the tuple generator that consumes these sorted
trees (P2\x86\code.c or lower.c). 'ex' (index written out) makes A's
index contain lara_item, which is why it flips.

