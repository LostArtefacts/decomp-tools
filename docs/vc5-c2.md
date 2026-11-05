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
ranges) is decided by the global allocator, not this picker; it walks
the same table from 0x491104 (lines using 0x491100/0x491104 around
0x43xxxx, 0x45xxxx, 0x46xxxx, 0x47xxxx); not reversed yet.

## x87 scheduling

Not reversed yet. From test compiles: a pre-pass (only /O2 or /Ot)
orders FPU ops by the longest latency path to the block end (fdiv >>
fmul/fadd/fchs), ties keep source order; of two consumers of a shared
value the first placed gets `fld st(0)`; a Pentium post-pass hoists long
fdivs and patches with fxch.

Where to start reading C2.EXE:

- 0x49a69c: the listing's mnemonic table (pointers to names), indexed by
  c2's internal instruction opcode, which an instruction keeps in its
  byte +0x30: fadd..fdivr 0x3a-0x3f, faddp..fdivrp 0x40-0x45, fxch 0x54,
  fld 0x55, fst 0x57, fstp 0x58, fchs 0x6c.
- 0x456d68 builds an fxch (stores 0x54 at +0x30), in the post-pass that
  fixes the stack after it moves instructions; 0x425525 and the compares
  around 0x433d3f, 0x433eac, 0x434648 and 0x46f16c test for one.

What decides the order of two equal chains (the four `(a->xs - b->xs)`
style factors of a 2D cross product, as in the hwinsert routines):

- /Os emits the commutative sort's operand order as it is. Under /O2 the
  scheduler reorders the factors of each product, and the result is not
  a function of the sort keys: in a test file, 0 and 8 extra
  declarations before the function give the same sorted lists but
  different load orders.
- In that test the order changes with the number of declarations before
  the function, in runs of about six (0-1, 2-7, 8-13, 14-19, ...), and
  not with the length of any name. The three orders seen were B A C D,
  A B D C and A B C D (A, B the factors of the first product).
- In hwinsert.cpp neither InsertGT3_ZBuffered nor InsertGT4_ZBuffered
  changes its order for 0-95 extra declarations, so the input that
  decides is not only the IDs. Every cast and negation form of the factors
  tried (`-(b - a)`, `(-b + a)`, `(double)` on the factor or not, the
  products swapped, `-(c*d) + a*b`) compiles to the same code; `(double)`
  on the separate operands changes the whole function's operand keys.

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

So with the present call graph the target can't be reached without
pragmas: the original used more small inline functions (accessors, list
helpers) than our source has, and a bigger node constructor. Dropping
all five pragmas from winvid.cpp costs 506 bytes (WinVidStart 298,
WinVidGetDisplayAdapters 145, EnumDisplayAdaptersCallback 63) and wins
$E2; the third pragma (`inline_depth(3)` after WinVidGetDisplayAdapters)
changes nothing on its own.

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

## Flat under header sweeps and top pads 32..4096 (step 32)

texture.cpp (AddTexturePage16, LoadTexturePage), draw.c (GetRoomBounds),
output.cpp (S_CalculateLight, S_GetObjectBounds), skidoo.c
(SkidooControl), winvid.cpp and hwinsert.cpp: these reds are not
ID-driven. scalespr.cpp moves only 32 bytes (top pads 256..511 mod 512:
S_DrawSprite 434 -> 431, draw_scaled_spriteC 424 -> 395) and its
remaining differences are global register allocation (which values get
esi/edi/ebx/ebp, and the target's extra stack slot).
