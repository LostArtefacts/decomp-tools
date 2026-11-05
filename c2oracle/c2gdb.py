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
    return plain(func_name()) == FUNC


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
    print("== %s" % FUNC)
    gdb.execute("continue")


main()
