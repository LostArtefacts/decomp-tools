"""gdb side of c2oracle.py: breakpoints in C2.EXE (VC5 SP3, 11.00.7022).

Loaded with `gdb -x`; reads its settings from the environment
(C2O_PORT, C2O_FUNC, C2O_WHAT, C2O_RAW). Every line meant for the user
starts with "| " (or "== " for a function header). The addresses and
structure offsets are documented in ../docs/vc5-c2.md.
"""
import os

import gdb

FUNC = os.environ["C2O_FUNC"]
WHAT = set(os.environ.get("C2O_WHAT", "sort").split(","))
RAW = bool(os.environ.get("C2O_RAW"))

CUR_FUNC = 0x495F1C  # the function being compiled (a front end symbol)

OPS = {
    0x11F: "const", 0x120: "sym", 0x135: "and", 0x136: "or", 0x137: "xor",
    0x141: "add", 0x143: "mul", 0x14B: "shr", 0x14A: "shl", 0x14C: "sar",
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
    print("| " + text)


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


def symbol(sym):
    """Back end symbol -> 'name#id' or 'temp@slot' (byte +4 == 3: a temp)."""
    if (rd(sym + 4) & 0xFF) == 3:
        return "temp@%d" % rd(sym + 0x1C)
    fe = rd(rd(sym + 8))
    return "%s#%x" % (cstr(rd(fe + 0x18)) or "?", rd(fe + 0x28))


def fold16(v):
    return (v & 0xFFFF) ^ (v >> 16)


# Node classes (byte +8), as the hash 0x4053bf switches on them:
#  1-3 register/symbol leaf (+0x14 symbol), 4 address of a symbol
#  (+0x14 front end symbol), 5-6 memory reference (+0x20 offset, +0x24
#  base node), 7 integer constant (+0x18/+0x1c), 8 constant in memory
#  (+0x14 -> value), 9-10 no hash, 11-20 operators (+0x18 operands).
def describe(node, depth=0):
    op = rd(node + 4) & 0xFFFF
    cls = rd(node + 8) & 0xFF
    if cls in (1, 2, 3):
        sym = rd(node + 0x14)
        text = symbol(sym) if sym else "reg(op %x)" % op
    elif cls == 4:
        fe = rd(node + 0x14)
        text = "&%s#%x" % (cstr(rd(fe + 0x18)) or "?", rd(fe + 0x28))
    elif cls in (5, 6):
        base = rd(node + 0x24)
        off = rd(node + 0x20)
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


def tree(node, indent, depth=0):
    """--raw: every node under NODE with its key, through temps' defining trees."""
    if depth > 6:
        return
    cls = rd(node + 8) & 0xFF
    kids = []
    if cls >= 11:
        kids = list(children(node))
    elif cls in (5, 6) and rd(node + 0x24):
        kids = [rd(node + 0x24)]
    elif cls in (1, 2) and rd(node + 0x14) and rd(rd(node + 0x14) + 0x14):
        kids = [rd(rd(node + 0x14) + 0x14)]
    for k in kids:
        out("%s%s  op %x cls %d  %s" % (" " * (2 * indent), key(k), rd(k + 4) & 0xFFFF, rd(k + 8) & 0xFF, describe(k, 3)))
        tree(k, indent + 1, depth + 1)


REGS = {1: "eax", 2: "ecx", 3: "edx", 4: "ebx", 5: "esp", 6: "ebp", 7: "esi", 8: "edi"}
ROTATION = 0x491120  # -> next entry of the preference table 0x491100
PREFS = 0x491100  # 1 2 3 7 8 4 6 0: eax ecx edx esi edi ebx ebp
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


# Where 0x435f38 was called from: how the register was found.
PATHS = {
    0x435CF9: "round robin",  # next free of eax ecx edx from the rotation pointer
    0x435DB5: "preferred",  # the value's own preferred register (+0x2c)
    0x435E74: "first free",  # first free in eax ecx edx esi edi ebx ebp
    0x435E22: "evicted",  # 0x45d93e freed one
}


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


def main():
    global inf
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("target remote :%s" % os.environ["C2O_PORT"])
    inf = gdb.selected_inferior()
    if "sort" in WHAT:
        Stop(0x4052F9, after_sort)
    if "regs" in WHAT:
        Stop(0x435C37, picker)
        Stop(0x435F38, assign)
        Stop(0x42A90E, lambda: out("-- rotation reset to eax"))
    if "inline" in WHAT:
        Stop(0x424946, inl_start)
        Stop(0x424EEF, inl_site)
        Stop(0x424A67, inl_refuse("arguments, depth, size or total"))
        Stop(0x46AFB8, inl_refuse("special callee"))
        Stop(0x46B06A, inl_refuse("not expandable"))
        Stop(0x46B024, inl_refuse("not expandable, warned"))
        Stop(0x424F79, inl_take)
        Stop(0x424BF5, inl_child)
        Stop(0x424C10, inl_used)
    print("== %s" % FUNC)
    gdb.execute("continue")


main()
