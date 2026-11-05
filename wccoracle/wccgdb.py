"""gdb side of wccoracle.py: breakpoints in Watcom 10.6's code generator.

Loaded with `gdb -x`; settings come from the environment (WCO_PORT,
WCO_PROC, WCO_WHAT, WCO_DUMP). Lines meant for the user start with "| " or "== ".
Addresses are run-time addresses for the image the BINNT stub loads at
0x8f0020 (see ../docs/wcc106-cg.md); if the stub ever picks another
base, every address is shifted by the difference.
"""
import os

import gdb

PROC = os.environ.get("WCO_PROC", "")
WHAT = set(os.environ.get("WCO_WHAT", "temps,conf,regs,slots").split(","))

BASE = 0x8F0020
STUB_CALL = 0x41001D       # call esi into the loaded image (esi = BASE + 0x33ada)
ENTRY_RVA = 0x33ADA
IMAGE_SIZE = 0x822B4       # code and data, file offset 0x2800 of BINW/WCC386.EXE

SORTLIST = 0x9603CE        # SortList( list, next_offset, before )
CMP = {
    0x952BC5: ("RoughSortTemps", "temp"),   # dataflo.c AllocBefore
    0x94EB69: ("AssignOtherLocals", "temp"),  # x86temps.c TempAllocBefore
    0x951A28: ("SortConflicts", "conf"),    # regalloc.c ConfBefore
    0x94A076: ("SortTempsById", "temp"),    # id descending, 0x94a080
}
LOCALS_DONE = 0x94EC22     # AssignOtherLocals after the AllocNewLocal loop
GIVE_CALL = 0x951858       # GiveRegister: call GiveBestReg(conf, tree, except, needs_one)
GIVE_RET = 0x95185D
SORT_RETURNS = (0x952CE8, 0x94EAFA, 0x951974, 0x951A47, 0x94A093)
CURR_PROC = 0x975954
NEW_PROC = 0x932065        # NewProc: mov [CurrProc],edx (a new proc_def)
NAMES_TEMP = 0x975930

CLASS = {0: "const", 1: "mem", 2: "temp", 3: "reg", 4: "idx"}

inf = None
delta = 0
state = {"n": 0, "pending": None}


def A(x):
    return x + delta


def rd(addr, size=4):
    return int.from_bytes(bytes(inf.read_memory(addr, size)), "little")


def reg(name):
    return int(gdb.selected_frame().read_register(name)) & 0xFFFFFFFF


def out(text=""):
    if PROC == "" or str(state["n"]) == PROC:
        print("| " + text, flush=True)


def on_newproc():
    state["n"] += 1
    if PROC == "" or str(state["n"]) == PROC:
        print("== proc %d" % state["n"], flush=True)


def temp(n):
    """One name: class, id, size, flags, the conflict's savings, location."""
    cls = rd(n + 4, 1)
    size = rd(n + 8)
    if cls != 2:
        return "%s@%x size %d" % (CLASS.get(cls, cls), n, size)
    conf = rd(n + 0xC)
    sav = ("sav %d" % rd(conf + 0x14)) if conf else "noconf"
    loc = rd(n + 0x20)
    loc = "" if loc == 0x7FFFFFFF or loc == 0xFFFFFFFF else " loc %d" % (loc - (1 << 32) if loc & 0x80000000 else loc)
    return "t%d size %d sym %#x off %d flags %#x use %#x %s%s" % (
        rd(n + 0x24), size, rd(n + 0x14), rd(n + 0x10), rd(n + 0x2A, 2), rd(n + 0x18, 2), sav, loc)


def conf(c):
    return "conf@%x sav %d state %#x %s" % (c, rd(c + 0x14), rd(c + 0x54, 2), temp(rd(c + 8)))


def walk(head, off):
    n, seen = head, 0
    while n and seen < 2000:
        yield n
        n = rd(n + off)
        seen += 1


class Hook(gdb.Breakpoint):
    def __init__(self, addr, fn):
        super().__init__("*%#x" % addr, internal=True)
        self.fn = fn

    def stop(self):
        try:
            self.fn()
        except gdb.error as e:
            print("!! %s" % e, flush=True)
        return False


def on_sort():
    before = reg("ebx")
    if before - delta not in CMP:
        return
    name, kind = CMP[before - delta]
    if kind == "temp" and "temps" not in WHAT or kind == "conf" and "conf" not in WHAT:
        return
    head, off = reg("eax"), reg("edx")
    show = temp if kind == "temp" else conf
    out("%s: before" % name)
    for i, n in enumerate(walk(head, off)):
        out("  %2d %s" % (i, show(n)))
    state["pending"] = (name, off, show)


def after_sort():
    if not state["pending"]:
        return
    name, off, show = state["pending"]
    state["pending"] = None
    out("%s: after" % name)
    for i, n in enumerate(walk(reg("eax"), off)):
        out("  %2d %s" % (i, show(n)))


def on_locals():
    out("stack slots (AllocNewLocal order = list order):")
    for n in walk(rd(A(NAMES_TEMP)), 0):
        if rd(n + 4, 1) == 2 and rd(n + 0x18, 2) & 0x80 and rd(n + 0x2A, 2) & 0x20 == 0:
            out("  " + temp(n))


def on_give():
    c = reg("eax")
    out("give %s" % conf(c))


REGS = {0x1000003: "eax", 0x200000C: "edx", 0x4000030: "ebx", 0x80000C0: "ecx",
        0x10000100: "esi", 0x20000200: "edi", 0x3: "ax", 0xC: "dx", 0x30: "bx", 0xC0: "cx",
        0x100: "si", 0x200: "di", 0x1: "al", 0x2: "ah", 0x4: "dl", 0x8: "dh", 0x10: "bl",
        0x20: "bh", 0x40: "cl", 0x80: "ch", 0: "memory"}


def on_given():
    v = reg("eax")
    out("   -> %s" % REGS.get(v, "%#x" % v))


def main():
    global inf, delta
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("target remote :%s" % os.environ["WCO_PORT"])
    inf = gdb.selected_inferior()
    gdb.execute("break *%#x" % STUB_CALL)
    gdb.execute("continue")
    delta = reg("esi") - ENTRY_RVA - BASE
    gdb.execute("delete")
    if delta:
        print("!! image base %#x, shifting addresses" % (BASE + delta), flush=True)
    if os.environ.get("WCO_DUMP"):
        open(os.environ["WCO_DUMP"], "wb").write(bytes(inf.read_memory(BASE + delta, IMAGE_SIZE)))
        print("== image at %#x dumped" % (BASE + delta), flush=True)
        gdb.execute("kill")
        return
    Hook(A(NEW_PROC), on_newproc)
    Hook(A(SORTLIST), on_sort)
    for r in SORT_RETURNS:
        Hook(A(r), after_sort)
    if "slots" in WHAT:
        Hook(A(LOCALS_DONE), on_locals)
    if "regs" in WHAT:
        Hook(A(GIVE_CALL), on_give)
        Hook(A(GIVE_RET), on_given)

    try:
        gdb.execute("continue")
    except gdb.error:
        pass


main()
