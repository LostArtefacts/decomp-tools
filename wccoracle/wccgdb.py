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
SPLIT_RESET = 0x95C83B     # resets the round-robin cursors of the Pentium memory operand split
SPLIT_PICK = 0x95C5DD      # after the pick: eax = the chosen entry of the register list, ecx = ins
ASSIGN_CONFLICTS = 0x951900  # one register allocation pass
GIVEN_REGS = 0x975900      # GivenRegisters, every register handed out so far
CAND = 0x95157E            # GiveBestReg loop body: esi = candidate, edi = conf
GREEDY_RET = 0x9515AC      # after TooGreedy( conf, reg, tree->temp ): al
MOVES_RET = 0x9515C5       # after CountRegMoves( conf, reg, conf->tree, 3 ): eax
CAND_NEXT = 0x951602       # every candidate ends here
SORT_RETURNS = (0x952CE8, 0x94EAFA, 0x951974, 0x951A47, 0x94A093)
CURR_PROC = 0x975954
NEW_PROC = 0x932065        # NewProc: mov [CurrProc],edx (a new proc_def)
NAMES_TEMP = 0x975930

CLASS = {0: "const", 1: "mem", 2: "temp", 3: "reg", 4: "idx"}

inf = None
delta = 0
state = {"n": 0, "pending": None, "cand": None}


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


def regs(v):
    """A register set as names, 32-bit registers first."""
    if v in REGS:
        return REGS[v]
    names = []
    for bits, name in sorted(REGS.items(), key=lambda kv: -kv[0]):
        if bits and v & bits == bits:
            names.append(name)
            v &= ~bits
    if v:
        names.append("%#x" % v)
    return "+".join(names)


def ins_refs(ins):
    """The temps an instruction mentions (a scan of its operand words)."""
    if not ins:
        return "-"
    temps = {}
    for n in walk(rd(A(NAMES_TEMP)), 0):
        temps[n] = "t%d" % rd(n + 0x24)
    found = []
    for off in range(0x10, 0x50, 4):
        v = rd(ins + off)
        if v in temps:
            found.append("%s@%x" % (temps[v], off))
    return "ins@%x opc %#x [%s]" % (ins, rd(ins + 0x22, 1), " ".join(found))


def on_give():
    c = reg("eax")
    out("give %s from %#x" % (conf(c), rd(reg("esp") + 0x10) - delta))
    if "cands" in WHAT:
        out("     given so far %s" % regs(rd(A(GIVEN_REGS))))
        out("     range %s .. %s" % (ins_refs(rd(c + 0x38)), ins_refs(rd(c + 0x3C))))
        if os.environ.get("WCO_WALK"):
            i, last = rd(c + 0x38), rd(c + 0x3C)
            for _ in range(40):
                out("       . " + ins_refs(i))
                if i == last or rd(i + 0x22, 1) == 0:
                    break
                i = rd(i + 4)
        state["first"] = True


def on_split_reset():
    out("split pass (round-robin cursors reset)")


def on_split_pick():
    p, ins = reg("eax"), reg("ecx")
    out("  split %s -> %s" % (ins_refs(ins), regs(rd(p)) if p else "none free"))


def on_assign():
    out("AssignConflicts")


def on_cand():
    esp, c, r = reg("esp"), reg("edi"), reg("esi")
    if state.get("first"):
        state["first"] = False
        out("     neighbours use %s, except %s" % (regs(rd(c + 0x20)), regs(rd(esp + 0xC))))
    why = []
    if rd(c + 0x20) & r:
        why.append("conflicts")
    if rd(esp + 0xC) & r:
        why.append("excepted")
    state["cand"] = {"reg": r, "why": why, "best": rd(esp + 8), "score": None}


def on_greedy():
    if state["cand"] is not None and reg("eax") & 0xFF:
        state["cand"]["why"].append("too greedy")


def on_moves():
    if state["cand"] is not None:
        v = reg("eax")
        state["cand"]["score"] = v - (1 << 32) if v & 0x80000000 else v


def on_cand_next():
    c = state["cand"]
    state["cand"] = None
    if c is None:
        return
    best = c["best"] - (1 << 32) if c["best"] & 0x80000000 else c["best"]
    if c["score"] is None:
        text = ", ".join(c["why"])
    else:
        text = "moves %d (best so far %d)%s" % (
            c["score"], best, " <- best" if reg("ebp") == c["reg"] else "")
    out("     %-4s %s" % (regs(c["reg"]), text))


REGS = {0x1000003: "eax", 0x200000C: "ebx", 0x4000030: "ecx", 0x80000C0: "edx",
        0x10000100: "esi", 0x20000200: "edi", 0x400: "ebp", 0x3: "ax", 0xC: "bx", 0x30: "cx",
        0xC0: "dx", 0x100: "si", 0x200: "di", 0x1: "al", 0x2: "ah", 0x4: "bl", 0x8: "bh",
        0x10: "cl", 0x20: "ch", 0x40: "dl", 0x80: "dh", 0: "memory"}


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
        Hook(A(ASSIGN_CONFLICTS), on_assign)
        Hook(A(GIVE_CALL), on_give)
        Hook(A(GIVE_RET), on_given)
    if "splits" in WHAT:
        Hook(A(SPLIT_RESET), on_split_reset)
        Hook(A(SPLIT_PICK), on_split_pick)
    if "cands" in WHAT:
        Hook(A(CAND), on_cand)
        Hook(A(GREEDY_RET), on_greedy)
        Hook(A(MOVES_RET), on_moves)
        Hook(A(CAND_NEXT), on_cand_next)

    try:
        gdb.execute("continue")
    except gdb.error:
        pass


main()
