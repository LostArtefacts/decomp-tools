"""gdb side of c2oracle.py: breakpoints in C2.EXE (VC5 SP3, 11.00.7022)
or c2.dll (VC6 SP3, 12.00.8168, or the later 12.00.8447).

Loaded with `gdb -x`; reads its settings from the environment
(C2O_PORT, C2O_FUNC, C2O_WHAT, C2O_RAW, C2O_C2 = vc5 or vc6, C2O_BUILD =
c2.dll's build, 8168 or 8447). Every line
meant for the user starts with "| " (or "== " for a function header).
The addresses and structure offsets are documented in ../docs/vc5-c2.md
and ../docs/vc6-c2.md; each back end's are in ADDR below.
"""
import os

import gdb

FUNC = os.environ["C2O_FUNC"]
WHAT = set(os.environ.get("C2O_WHAT", "sort").split(","))
RAW = bool(os.environ.get("C2O_RAW"))
C2 = os.environ.get("C2O_C2", "vc5")
BUILD = os.environ.get("C2O_BUILD", "8168")

# Where each back end decides things. c2.dll is VC5's C2.EXE rebuilt with
# small changes: the structures carry over, the addresses and some of the
# registers do not. None: not located in that back end.
ADDR = {
    "vc5": dict(
        cur_func=0x495F1C,  # the function being compiled (a front end symbol)
        sort=0x4052F9,
        picker=0x435C37, assign=0x435F38, rot_reset=0x42A90E,
        rotation=0x491120, prefs=0x491100,
        paths={0x435CF9: "round robin", 0x435DB5: "preferred", 0x435E74: "first free", 0x435E22: "evicted"},
        regtab=0x494758, regstride=0x50,
        color=0x41A985, split=0x4171C8, assigned=0x4171E2, skipped=None, round=None,
        commit=None, scored=None, picked=None,
        block=0x40F6DE, use=(0x40F70F, 0x40F745), thru=0x40F72C, weight_reg="edx",
        inline=True, x87=True, sched=None,
        sched_pass=0x49321C, sched_nodes=0x4930B0, sched_took=0x4316CA, sched_region=0x40DA6A,
    ),
    "vc6": dict(
        cur_func=0x107AC378,
        sort=0x10709451,
        picker=0x10734E4B, assign=0x10735143, rot_reset=0x10733637,
        rotation=0x1079D710, prefs=0x107ADFF4,
        paths={0x10734F18: "round robin", 0x10734FC7: "preferred", 0x1073513B: "first free", 0x10735061: "evicted"},
        regtab=0x107AC730, regstride=0x54,
        color=0x107159AF, split=0x1072090A, assigned=0x10720930, skipped=0x10720874, round=0x107207E6,
        commit=0x10716715, scored=0x10716771, picked=0x1071689A,
        block=0x10714414, use=(0x10714C06, 0x10714C2E), thru=0x10714C53, weight_reg="esi",
        inline=False, x87=False, sched=True,
        sched_pass=0x1079F270, sched_nodes=0x1079F248, sched_took=0x1073C05E, sched_region=0x1073A0AA,
        sched_shifts=0x10799204,
        pick_pipe=0x1073C1E8, pick_hook=0x1073C1FB, pick_regs=0x1073C223, pick_late=0x1073C245, pick_take=0x1073C255,
    ),
}
# 12.00.8447 (a later VC6 SP3 c2.dll, the one tr04's original was built
# with) links its functions in another order but keeps every global and
# structure where 8168 has them, so only the code addresses move. Each
# was matched by its surrounding instructions (identical in both builds
# but for relocated addresses), see docs/vc6-c2.md.
ADDR["vc6-8447"] = dict(
    ADDR["vc6"],
    sort=0x1070D196,
    picker=0x10733273, assign=0x1073356B, rot_reset=0x10731A63,
    paths={0x10733340: "round robin", 0x107333EF: "preferred", 0x10733563: "first free", 0x10733489: "evicted"},
    color=0x107237A7, split=0x1072D6E9, assigned=0x1072D70F, skipped=0x1072D653, round=0x1072D5C5,
    commit=0x107245C3, scored=0x1072461F, picked=0x10724748,
    block=0x1072255A, use=(0x10722D4C, 0x10722D74), thru=0x10722D99,
    sched_took=0x10739628, sched_region=0x1073AE98,
    pick_pipe=0x107397B2, pick_hook=0x107397C5, pick_regs=0x107397ED, pick_late=0x1073980F, pick_take=0x1073981F,
)
if C2 == "vc6" and BUILD != "8168":
    C2 += "-" + BUILD
ADDR = ADDR[C2]
C2 = C2[:3]
CUR_FUNC = ADDR["cur_func"]

OPS = {
    0x11F: "const", 0x120: "sym", 0x135: "and", 0x136: "or", 0x137: "xor",
    0x141: "add", 0x143: "mul", 0x14B: "shr", 0x14A: "shl", 0x14C: "sar",
} if C2 == "vc5" else {
    0x16D: "add", 0x171: "shl", 0x172: "and", 0x173: "or", 0x15A: "arg", 0x184: "call",
}

inf = None


def rd(addr, size=4):
    return int.from_bytes(bytes(inf.read_memory(addr, size)), "little")


def cstr(addr, limit=80):
    if not addr:
        return ""
    data = bytes(inf.read_memory(addr, limit))
    return data.split(b"\0", 1)[0].decode("latin-1")


def reg(name):
    return int(gdb.selected_frame().read_register(name)) & 0xFFFFFFFF


def func_name():
    fn = rd(CUR_FUNC)
    return cstr(rd(fn + 0x18)) if fn else ""


def plain(mangled):
    if mangled.startswith("?"):
        return mangled[1:].split("@", 1)[0]
    return mangled.lstrip("_").split("@", 1)[0]


def in_func():
    return FUNC == "*" or plain(func_name()) == FUNC


def out(text=""):
    print("| " + text, flush=True)


# Tree nodes: +0 next operand, +4 opcode, +8 type, +0xc sort key,
# +0x14 back end symbol (leaves), +0x18 first operand (interior).
def children(node):
    c = rd(node + 0x18)
    seen = 0
    while c and seen < 64:
        yield c
        c = rd(c)
        seen += 1


def opname(op):
    return OPS.get(op, "op%x" % op)


def symbol(sym, depth=0):
    """Back end symbol -> 'name#id' or 'temp@slot' (byte +4 == 3: a temp);
    a temp the optimiser made for an expression shows it in braces."""
    if (rd(sym + 4) & 0xFF) == 3:
        text = "temp@%d" % rd(sym + 0x1C)
        if C2 == "vc6" and depth == 0 and rd(sym + 0x14):
            text += "{" + describe(rd(sym + 0x14), 2) + "}"
        return text
    fe = rd(rd(sym + 8))
    return "%s#%x" % (cstr(rd(fe + 0x18)) or "?", rd(fe + 0x28))


def fold16(v):
    return (v & 0xFFFF) ^ (v >> 16)


# Node classes (byte +8), as the hash 0x4053bf switches on them:
#  1-3 register/symbol leaf (+0x14 symbol), 4 address of a symbol
#  (+0x14 front end symbol), 5-6 memory reference (VC5: +0x20 offset,
#  +0x24 base node; VC6: +0x24 offset, +0x28 base node),
#  7 integer constant (+0x18/+0x1c), 8 constant in memory
#  (+0x14 -> value), 9-10 no hash, 11-20 operators (+0x18 operands).
def describe(node: int, depth: int = 0) -> str:
    op = rd(node + 4) & 0xFFFF
    cls = rd(node + 8) & 0xFF
    if cls in (1, 2, 3):
        sym = rd(node + 0x14)
        text = symbol(sym, depth) if sym else "reg(op %x)" % op
    elif cls == 4:
        fe = rd(node + 0x14)
        text = "&%s#%x" % (cstr(rd(fe + 0x18)) or "?", rd(fe + 0x28))
    elif cls in (5, 6):
        base = rd(node + (0x28 if C2 == "vc6" else 0x24))
        off = rd(node + (0x24 if C2 == "vc6" else 0x20))
        inner = describe(base, depth + 1) if base and depth < 3 else ""
        text = "[%s%s%s]" % (inner, "+" if inner else "", ("%d" % (off - (1 << 32) if off >> 31 else off)))
    elif cls == 7:
        v = rd(node + 0x18)
        text = "%d" % (v - (1 << 32) if v >> 31 else v)
    elif cls == 8:
        text = "constmem(%08x)" % rd(rd(node + 0x14))
    elif cls >= 11:
        kids = list(children(node))
        if depth >= 3 or not kids:
            text = opname(op) + ("(...)" if kids else "")
        else:
            text = opname(op) + "(" + ", ".join(describe(k, depth + 1) for k in kids) + ")"
    else:
        text = "class%d(op %x)" % (cls, op)
    if RAW and depth == 0:
        text += "  [%08x op=%x cls=%d %s]" % (node, op, cls, " ".join("%08x" % rd(node + 4 * i) for i in range(4, 10)))
    return text


def key(node):
    k = rd(node + 0xC)
    return "%02x.%02x.%04x" % (k >> 24, (k >> 16) & 0xFF, k & 0xFFFF)


class Stop(gdb.Breakpoint):
    def __init__(self, addr, fn):
        super().__init__("*0x%x" % addr, internal=True)
        self.fn = fn

    def stop(self):
        try:
            if in_func():
                self.fn()
        except gdb.error as e:
            print("!! %s" % e)
        return False


# Commutative operand sort: 0x4052ec sorts ebx's operand list with the
# comparator 0x408d58 (descending key); at 0x4052f9 eax is the sorted list.
def after_sort():
    parent = reg("ebx")
    first = reg("eax")
    kids = []
    c = first
    while c and len(kids) < 64:
        kids.append(c)
        c = rd(c)
    if len(kids) < 2:
        return
    out("sort %s  (key %s)" % (opname(rd(parent + 4) & 0xFFFF), key(parent)))
    for k in kids:
        out("    %s  %s" % (key(k), describe(k)))
        if RAW:
            tree(k, 3)


def tree(node: int, indent: int, depth: int = 0) -> None:
    """--raw: every node under NODE with its key, through temps' defining trees."""
    if depth > 6:
        return
    cls = rd(node + 8) & 0xFF
    kids = []
    if cls >= 11:
        kids = list(children(node))
    elif cls in (5, 6) and rd(node + (0x28 if C2 == "vc6" else 0x24)):
        kids = [rd(node + (0x28 if C2 == "vc6" else 0x24))]
    elif cls in (1, 2) and rd(node + 0x14) and rd(rd(node + 0x14) + 0x14):
        kids = [rd(rd(node + 0x14) + 0x14)]
    for k in kids:
        out("%s%s  op %x cls %d  %s" % (" " * (2 * indent), key(k), rd(k + 4) & 0xFFFF, rd(k + 8) & 0xFF, describe(k, 3)))
        tree(k, indent + 1, depth + 1)


REGS = {1: "eax", 2: "ecx", 3: "edx", 4: "ebx", 5: "esp", 6: "ebp", 7: "esi", 8: "edi"}
ROTATION = ADDR["rotation"]  # -> next entry of the preference table
PREFS = ADDR["prefs"]  # 1 2 3 7 8 4 6 0: eax ecx edx esi edi ebx ebp
pick = {}


# Local register picker 0x435c37 (ecx = tuple, edx = its use): remember the
# rotation pointer, then 0x435f38 (ecx = register) commits the choice.
def picker():
    pick["node"] = reg("ecx")
    pick["use"] = reg("edx")
    pick["rot"] = (rd(ROTATION) - PREFS) // 4
    if RAW:
        node = pick["node"]
        rec = rd(node + 0x18)
        pref = rd(rec + 0x2C)
        sym = rd(node + 0x14)
        out("    value %s rec %08x pref %s interf %08x" % (symbol(sym) if sym else "?", rec,
            REGS.get(rd(pref + 0x1C), "-") if pref else "-", rd(rec + 0x1C)))


# Where the commit was called from: how the register was found. Round
# robin: next free of eax ecx edx from the rotation pointer; preferred:
# the value's own preferred register (+0x2c); first free: in eax ecx edx
# esi edi ebx ebp; evicted: a register was freed for it.
PATHS = ADDR["paths"]


def assign():
    r = reg("ecx")
    ret = rd(reg("esp"))
    if ret not in PATHS:
        out("reg %-3s <- %s   (caller %x)" % (REGS.get(r, r), describe(reg("edx")), ret))
        return
    node = pick.pop("node", None)
    rot = REGS.get(rd(PREFS + 4 * pick.get("rot", 0)), "?")
    out("reg %-3s <- %s   (%s; round robin was at %s)" % (REGS.get(r, r), describe(pick.get("use", 0)) if node else "?",
                                                         PATHS[ret], rot))


# Inliner (0x42491e per function, 0x4249cb per level, see docs/vc5-c2.md).
# In 0x4249cb's frame: [esp+0x48] budget left, [esp+0x30] depth,
# [esp+0x2c] call sites left at this level, [esp+0x14] the site record
# (+4 call tuple, +8 depth limit byte); ebx the callee (front end symbol:
# +0x18 name, +0x64 size word, +0x6a flags). 0x490e70: running size.
TOTAL = 0x490E70


def sx16(v):
    return v - 0x10000 if v & 0x8000 else v


def callee():
    ebx = reg("ebx")
    return "%s (size %d)" % (plain(cstr(rd(ebx + 0x18))), sx16(rd(ebx + 0x64, 2)))


def fr(off):
    v = rd(reg("esp") + off)
    return v - (1 << 32) if v >> 31 else v


def ind():
    return "  " * max(0, fr(0x30) - 1)


def inl_start():
    fn = rd(reg("esi"))
    out("caller %s: size %d, budget %d" % (plain(func_name()), sx16(rd(fn + 0x64, 2)), reg("eax")))


def inl_site():
    site = rd(reg("esp") + 0x14)
    out("%ssite %s: depth %d/%d, budget %d, sites left %d, total %d" % (
        ind(), callee(), fr(0x30), rd(site + 8) & 0xFF, fr(0x48), fr(0x2C), rd(TOTAL)))


def inl_refuse(why):
    return lambda: out("%s  -> refused (%s)" % (ind(), why))


def inl_take():
    size = sx16(reg("eax") & 0xFFFF)
    out("%s  -> inlined, costs %d" % (ind(), size if size > 40 else 0))


def inl_child():
    # 0x424bf5: about to expand the callee's own sites with budget/sites left
    out("%s  -> its own sites get %d // %d = %d" % (ind(), fr(0x48), fr(0x2C), fr(0x48) // max(1, fr(0x2C))))


def inl_used():
    used = reg("eax")
    used = used - (1 << 32) if used >> 31 else used
    out("%s  -> they used %d, budget now %d" % (ind(), used, fr(0x48) - used))


# The global allocator (P2\color.c): priority-based coloring of live
# ranges. A live range record: +0 back end symbol, +4 flags, +0xc
# priority, +0x10 register (&regtab[r] + 8, regtab = 0x494750, 0x50 per
# register), +0x24 references, +0x3c weighted references, +0x40 the walk
# position that breaks priority ties. See docs/vc5-c2.md.
GREGS = {1: "eax", 2: "ecx", 3: "edx", 4: "ebx", 5: "esp", 6: "ebp", 7: "esi", 8: "edi"}


def range_name(rng):
    try:
        sym = rd(rng)
        if sym and C2 == "vc6" and rd(sym + 4, 1) == 13:
            # VC6: a repeated literal made a register candidate (rule C1)
            return "literal{%s}" % describe(rd(sym + 0x28), 1)
        return symbol(sym) if sym else "?"
    except gdb.error:
        return "range@%x" % rng


def range_reg(rng):
    p = rd(rng + 0x10)
    if not p:
        return "memory"
    return GREGS.get((p - ADDR["regtab"]) // ADDR["regstride"], "?%x" % p)


def glob_block():
    # a block's references were counted, about to fold them into the
    # priorities. VC5: the multiplier is 1 << (loop depth + 1), in edi;
    # VC6: 1 << loop depth, in eax, the block in ebp.
    if C2 == "vc6":
        out("  block %x: multiplier %d" % (reg("ebp"), reg("eax")))
        return
    blk = rd(reg("esp") + 0x20)
    out("  block %x: depth %d, multiplier %d" % (blk, sx16(rd(blk + 0x86, 2)), reg("edi")))


def glob_use():
    rng = reg("eax")
    out("    %s referenced: %d + %d * %d" % (range_name(rng), sx32(rd(rng + 0xC)), reg(ADDR["weight_reg"]), rd(rng + 0x18)))


def glob_thru():
    rng = reg("eax")
    out("    %s live through: %d - %d" % (range_name(rng), sx32(rd(rng + 0xC)), reg(ADDR["weight_reg"])))


COLORED = []


def glob_color():
    rng = reg("edx")
    glob_color.cur = rng
    if rng not in COLORED:
        COLORED.append(rng)
    out("%-24s priority %6d  position %4d  refs %3d  weighted %5d" % (
        range_name(rng), sx32(rd(rng + 0xC)), rd(rng + 0x40), rd(rng + 0x24), sx32(rd(rng + 0x3C))))


def glob_split():
    if reg("eax"):
        # VC6: 0x107159af could not color the whole range; it is split and
        # its pieces go back on the list (their spill and reload code is
        # inserted when the next round starts)
        out("    (split)" if C2 == "vc6" else "    (split: the ranges it conflicts with get pieces)")


def glob_assigned():
    out("    -> %s" % range_reg(reg("esi")))


def glob_skip():
    # VC6 0x10720874: a range with weighted references <= 0 stays in memory
    rng = reg("esi")
    out("%-24s skipped (weighted %d, priority %d)" % (range_name(rng), sx32(rd(rng + 0x3C)), sx32(rd(rng + 0xC))))


# VC6's register choice (the commit routine, 0x107245c3 in 8447,
# 0x10716715 in 8168; ecx = the range, edx = its register class, [esp+4]
# = the IDs of its interfering ranges not yet colored). It zeroes
# score[0..8] at 0x1079d868, then for each neighbour n with weighted
# references W = n+0x3c > 0 adds n's affinity weight for each register r
# still in n's available set (n+0x20), and 100 * W when that set is just
# {r}; then subtracts the range's own affinities (+0x34: next, register
# descriptor (+0x1c number), weight). The pick walks the class's register
# list (0x107a0a14[class]: eax ecx edx esi edi ebx ebp for class 0) and
# takes an available register only on a strictly lower score, so ties go
# to the earlier one. See docs/vc6-c2.md, rule G1.
SCORE = 0x1079D868
RANGE_IDS = 0x1079D88C  # range ID & 0x3ff -> chain of ranges through +0x2c
CLASSES = 0x107A0A14
COMMIT = {}


def bitset(setp):
    """Members of a c2 bit set: [setp] -> chain of {base, next, mask}."""
    res = []
    node = rd(setp) if setp else 0
    while node and len(res) < 4096:
        base, mask = rd(node), rd(node + 8)
        res.extend(base + b for b in range(32) if mask >> b & 1)
        node = rd(node + 4)
    return res


def range_by_id(i):
    rng = rd(RANGE_IDS + 4 * (i & 0x3FF))
    while rng and rd(rng + 0x1C) != i:
        rng = rd(rng + 0x2C)
    return rng


def affinities(rng):
    """A range's register affinities: (register number, weight)."""
    res = []
    p = rd(rng + 0x34)
    while p and len(res) < 16:
        res.append((rd(rd(p + 4) + 0x1C), sx32(rd(p + 8))))
        p = rd(p)
    return res


def class_regs(cls):
    regs, p = [], rd(CLASSES + 4 * cls)
    while rd(p) and len(regs) < 8:
        regs.append(rd(p))
        p += 4
    return regs


def commit_entry():
    rng = reg("ecx")
    expect = [0] * 9
    lines = []
    for i in bitset(rd(reg("esp") + 4)):
        n = range_by_id(i)
        if not n:
            lines.append("      neighbour id %d: not found" % i)
            continue
        w = sx32(rd(n + 0x3C))
        avail = bitset(rd(n + 0x20))
        parts = []
        if w > 0:
            for r, wt in affinities(n):
                if r in avail:
                    expect[r] += wt
                    parts.append("wants %s %+d" % (GREGS.get(r, r), wt))
            if len(avail) == 1:
                expect[avail[0]] += 100 * w
                parts.append("only %s: +100*%d" % (GREGS.get(avail[0], avail[0]), w))
        if parts or RAW:
            lines.append("      neighbour %s (weighted %d, available %s): %s" % (
                range_name(n), w, " ".join(GREGS.get(r, str(r)) for r in avail) or "none",
                ", ".join(parts) or "nothing"))
    own = affinities(rng)
    for r, wt in own:
        expect[r] -= wt
    COMMIT.clear()
    COMMIT.update(rng=rng, cls=reg("edx"), expect=expect, lines=lines, own=own)


def commit_scored():
    rng = reg("ebx")
    if COMMIT.get("rng") != rng:
        return
    if rng != getattr(glob_color, "cur", None):
        out("  commit %s" % range_name(rng))
    for line in COMMIT["lines"]:
        out(line)
    if COMMIT["own"]:
        out("      own affinity: %s" % ", ".join("%s -%d" % (GREGS.get(r, r), wt) for r, wt in COMMIT["own"]))
    avail = set(bitset(rd(rng + 0x20)))
    score = [sx32(rd(SCORE + 4 * r)) for r in range(9)]
    order = [r for r in class_regs(COMMIT["cls"]) if r in avail]
    best = None
    for r in order:
        if best is None or score[r] < score[best]:
            best = r
    COMMIT.update(order=order, best=best, score=score)
    shown = order if not RAW else range(1, 9)
    out("    score %s" % ", ".join("%s %d" % (GREGS.get(r, r), score[r]) for r in shown) +
        ("" if order else " (nothing available)"))
    bad = [GREGS.get(r, r) for r in range(1, 9) if score[r] != COMMIT["expect"][r]]
    if bad:
        out("    !! score model differs on %s: expected %s" % (" ".join(bad), ", ".join(
            "%s %d" % (GREGS.get(r, r), COMMIT["expect"][r]) for r in range(1, 9))))


def commit_picked():
    if "order" not in COMMIT:
        return
    r = reg("edi")
    order, score = COMMIT["order"], COMMIT["score"]
    text = "    picked %s" % GREGS.get(r, "none")
    if order and r != order[0]:
        text += "  ** not first free: %s scores %d, %s %d" % (
            GREGS.get(order[0]), score[order[0]], GREGS.get(r, r), score[r])
    if r != (COMMIT["best"] or 0):
        text += "  !! the score model picks %s" % GREGS.get(COMMIT["best"], "none")
    out(text)
    COMMIT.clear()


def glob_final():
    # at the local allocator's start: what every colored range ended with
    if COLORED:
        out("-- final: " + ", ".join("%s=%s" % (range_name(r), range_reg(r)) for r in COLORED))
        COLORED.clear()


def sx32(v):
    return v - (1 << 32) if v >> 31 else v


# The list scheduler (P2\x86\schedmd.c, driver 0x40d9be). 0x49321c is 1
# in the pre-pass (before register allocation), 0 in the post-pass. A DAG
# node: +0x10/+0x14 ready list links, +0x1c the tuple, +0x2c priority,
# +0x30 earliest cycle, +0x36 the tuple's position in the IL block.
# A tuple is an expression node: +4 opcode, operands from +0x18.
SCHED = {}


def sched_tuple(t):
    try:
        return "op%x(%s)" % (rd(t + 4) & 0xFFFF, ", ".join(describe(k, 1) for k in children(t)))
    except gdb.MemoryError:
        return "op%x(?)" % (rd(t + 4) & 0xFFFF)


def operand(node, depth=0):
    """VC6, after register allocation: a machine operand (register leaf,
    variable, [base+offset], constant)."""
    try:
        op = rd(node + 4) & 0xFFFF
        cls = rd(node + 8) & 0xFF
        if cls == 1:
            r = rd(node + 0x18)
            if ADDR["regtab"] <= r < ADDR["regtab"] + 9 * ADDR["regstride"]:
                return GREGS.get((r - ADDR["regtab"]) // ADDR["regstride"], "?")
            return symbol(rd(node + 0x14), 1) if rd(node + 0x14) else "reg?"
        if cls == 2:
            text = symbol(rd(node + 0x14), 1) if rd(node + 0x14) else "mem?"
            if RAW:
                text += "{%x.%x}" % (rd(node + 0x10) & 0xFFFF, rd(node + 0x1C))
            return text
        if cls in (5, 6):
            base = rd(node + 0x28)
            off = sx32(rd(node + 0x24))
            inner = operand(base, depth + 1) if base and depth < 2 else ""
            if RAW:
                inner = "%x.%x:" % (rd(node + 0x10) & 0xFFFF, rd(node + 0x1C)) + inner
            return "[%s%s]" % (inner, ("%+d" % off) if inner else "%d" % off) if off or not inner else "[%s]" % inner
        if cls == 7:
            return "%d" % sx32(rd(node + 0x18))
        return "op%x" % op
    except gdb.error:
        return "?"


# VC6 machine tuple opcodes seen in scheduled blocks
MNEMONICS6 = {0x1: "mov", 0x8: "ret", 0xD: "push", 0xE: "call", 0xF: "jcc", 0x10: "jmp", 0x12: "lea",
              0x2D: "add", 0xB9: "pop", 0xBA: "push", 0xC1: "imul"}


def sched_tuple6(t):
    ops = [operand(c) for c in children(t)]
    dest = rd(t + 0x1C)
    op = rd(t + 4) & 0xFFFF
    return "%s %s%s" % (MNEMONICS6.get(op, "op%x" % op), (operand(dest) + " <- ") if dest else "", ", ".join(ops))


def sched_took():
    if C2 == "vc5" and rd(ADDR["sched_pass"]) != 1:
        return
    for j in range(max(0, min(reg("eax"), 4))):
        n = rd(ADDR["sched_nodes"] + 4 * j)
        SCHED[rd(n + 0x36, 2)] = (len(SCHED) + 1, rd(n + 0x2C), (sched_tuple6 if C2 == "vc6" else sched_tuple)(rd(n + 0x1C)), n)


# VC6 cycle picker 0x1073c17b (8168 addresses here; ecx = cycle): walks the ready list from
# the head and takes a node unless the pairing hook [0x10799214] returns
# < 0 for it (0x1073c1e8), 0x1073c4ad objects (0x1073c1fb), the register
# check 0x1073c505 objects (0x1073c223, only when [0x107ac0b0] is set) or
# its earliest cycle +0x30 is later than the cycle plus the busy time of
# its unit (0x1073c245). Under --raw, each decision is printed.
TRACE = []


def pick_why(why):
    def f():
        n = reg("esi")
        TRACE.append("cycle %d: %d %s" % (rd(reg("esp") + 0x18), rd(n + 0x36, 2), why()))
    return f


def pick_pipe():
    v = reg("eax") & 0xFFFF
    return "pairing class %d%s" % (sx16(v), " -> rejected" if v & 0x8000 else "")


def sched_region():
    if RAW and C2 == "vc6" and SCHED:
        w = rd(ADDR["sched_shifts"])
        out("-- priority shifts: %s" % " ".join("%d" % sx16(rd(w + 2 * i, 2)) for i in range(7)))
    if TRACE:
        out("-- picker: cycle: IL position, decision")
        for line in TRACE:
            out("  " + line)
        TRACE.clear()
    if not SCHED:
        return
    out("-- %s block, in IL order: IL position, scheduled position, priority, tuple" % (
        "pre-pass" if C2 == "vc5" else "scheduled"))
    for s in sorted(SCHED):
        k, prio, text, n = SCHED[s]
        if RAW and C2 == "vc6":
            # DAG node +0xc: successor edges (+0 next, +0xc node, +0x14 latency)
            succ, e = [], rd(n + 0xC)
            while e and len(succ) < 64:
                succ.append("%d/%d%s" % (rd(rd(e + 0xC) + 0x36, 2), rd(e + 0x14, 2), "" if rd(e + 0x10) == 1 else ":%x" % rd(e + 0x10)))
                e = rd(e)
            text += "   [t %x] h %d s %d f %02x %02x -> %s" % (rd(n + 0x1C), rd(n + 0x34, 2), rd(n + 0x22, 2), rd(n + 0x39, 1), rd(n + 0x3A, 1),
                                                     " ".join(succ))
        out("  %3d -> %3d  %8x  %s" % (s, k, prio, text if len(text) < 160 or RAW else text[:157] + "..."))
    SCHED.clear()



# Range records have a numeric ID at +0x1c, distinct from the backend
# symbol slot at symbol+0x1c. Freed records retain that ID when reused.
def range_info(rng: int) -> str:
    sym = rd(rng)
    if not sym:
        origin = "empty"
    elif rd(sym + 4, 1) == 13:
        node = rd(sym + 0x28)
        origin = "literal{%s}" % describe(node, 1)
        if rd(node + 8, 1) == 3:
            source = rd(node + 0x14)
            origin += " offset=%d" % sx32(rd(source + 0x24))
    else:
        origin = symbol(sym)
    return "%s lr=%d be=%x range=%x sym=%x" % (
        origin, rd(rng + 0x1c), rd(sym + 0x1c) if sym else 0, rng, sym)


def ranges_reset() -> None:
    out("range pool reset: free=%x next-ID=%d" % (rd(0x107ae038), rd(0x1079d74c)))


def ranges_allocated() -> None:
    rng = reg("esi")
    out("range allocated: %s caller=%x free-head=%x next-ID=%d" % (
        range_info(rng), rd(reg("esp") + 8), rd(0x107ae038), rd(0x1079d74c)))



def ranges_pruned() -> None:
    sym = reg("esi")
    aux = rd(sym + 0x30)
    rng = rd(aux + 0xc)
    uses = sx32(rd(aux + 0x14))
    out("literal prune: bucket=%d counter=%d keep=%s %s" % (
        (reg("ebx") - 0x1079d750) // 4, uses, uses >= 1, range_info(rng)))


def ranges_freed() -> None:
    caller = rd(reg("esp"))
    bucket = " bucket=%d" % ((reg("ebx") - 0x1079d750) // 4) if caller == 0x1072ce7c else ""
    out("range freed:%s %s caller=%x old-head=%x" % (
        bucket, range_info(reg("ecx")), caller, rd(0x107ae038)))


def ranges_split_order() -> None:
    node = reg("ebx")
    entries: list[str] = []
    while node and len(entries) < 1024:
        entries.append(range_info(node))
        node = rd(node + 0x14)
    out("-- split materialization order: " + " ; ".join(entries))


def main() -> None:
    global inf
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("target remote :%s" % os.environ["C2O_PORT"])
    inf = gdb.selected_inferior()
    if C2 == "vc6":
        # cl.exe runs c2.dll in process: the stand-in stops on an int 3
        # once it has loaded it (image base 0x10700000, no relocation)
        for _ in range(20):
            try:
                rd(0x10701000)
                break
            except gdb.error:
                gdb.execute("continue")
    if "sort" in WHAT:
        Stop(ADDR["sort"], after_sort)
    if "regs" in WHAT:
        Stop(ADDR["picker"], picker)
        Stop(ADDR["assign"], assign)
        Stop(ADDR["rot_reset"], lambda: out("-- rotation reset to eax"))
    if "inline" in WHAT and ADDR["inline"]:
        Stop(0x424946, inl_start)
        Stop(0x424EEF, inl_site)
        Stop(0x424A67, inl_refuse("arguments, depth, size or total"))
        Stop(0x46AFB8, inl_refuse("special callee"))
        Stop(0x46B06A, inl_refuse("not expandable"))
        Stop(0x46B024, inl_refuse("not expandable, warned"))
        Stop(0x424F79, inl_take)
        Stop(0x424BF5, inl_child)
        Stop(0x424C10, inl_used)
    if ("x87" in WHAT and ADDR["x87"]) or ("sched" in WHAT and ADDR["sched"]):
        Stop(ADDR["sched_took"], sched_took)
        Stop(ADDR["sched_region"], sched_region)
        if RAW and C2 == "vc6":
            Stop(ADDR["pick_pipe"], pick_why(pick_pipe))
            Stop(ADDR["pick_hook"], pick_why(lambda: "0x1073c4ad (8168) says %d" % reg("eax")))
            Stop(ADDR["pick_regs"], pick_why(lambda: "register check says %d" % reg("eax")))
            Stop(ADDR["pick_late"], pick_why(lambda: "earliest %d, cycle + busy %d" % (reg("eax"), reg("edx"))))
            Stop(ADDR["pick_take"], pick_why(lambda: "TAKEN"))
    if "global" in WHAT:
        if ADDR["round"]:
            Stop(ADDR["round"], lambda: out("-- round (pieces of the split range get their loads and stores)"))
        Stop(ADDR["color"], glob_color)
        Stop(ADDR["split"], glob_split)
        Stop(ADDR["assigned"], glob_assigned)
        if ADDR["commit"]:
            Stop(ADDR["commit"], commit_entry)
            Stop(ADDR["scored"], commit_scored)
            Stop(ADDR["picked"], commit_picked)
        if ADDR["skipped"]:
            Stop(ADDR["skipped"], glob_skip)
        Stop(ADDR["rot_reset"], glob_final)
        if RAW:
            Stop(ADDR["block"], glob_block)
            for a in ADDR["use"]:
                Stop(a, glob_use)
            Stop(ADDR["thru"], glob_thru)
    if "ranges" in WHAT and C2 == "vc6" and BUILD == "8447":
        Stop(0x1072cb16, ranges_reset)
        Stop(0x1072124e, ranges_allocated)
        Stop(0x107213c6, ranges_freed)
        Stop(0x1072ce61, ranges_pruned)
        Stop(0x1073e958, ranges_split_order)
    print("== %s" % FUNC)
    gdb.execute("continue")


main()
