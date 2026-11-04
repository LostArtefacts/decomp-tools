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

fold16(x) = (x & 0xffff) ^ (x >> 16). A back end symbol's front end
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

## Case notes

- Func4524e0 (setup.cpp): the GUID lea's take eax by preference (path 1);
  then `settings->RenderMode` takes eax by round robin, so
  PerspectiveCorrect gets cl. The target has the same `mov eax,[esi+0x10];
  push eax` but PerspectiveCorrect in al, so its RenderMode load came
  through path 1 (or one more round robin pick happened in the same
  stretch). A `(DWORD)` cast does not change it.
