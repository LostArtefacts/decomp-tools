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
