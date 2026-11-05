"""Replays Watcom 10.6's SortList (an unstable ShellSort) on a dumped list.

    shellsim.py TRACE [--sort N] [--want tA,tB,...] [--extra K]

TRACE is wccoracle.py --what temps output for one proc. The N-th
RoughSortTemps "before" list (default the first) is sorted again with
AllocBefore and checked against the traced "after" list. With --want,
the listed temps' relative order after the sort is shown, and with
--extra K every way of inserting up to K dummy temps (no conflict or savings 0,
so they sort low and only shift positions) at any position is tried
and the ones that give the wanted order are printed. --perm also tries
every permutation of the wanted temps' initial positions (what swapping
the creation order of those temps in the source does).
"""
import argparse, itertools, re


def shellsort(a, before):
    """cgsrtlst.c ShellSort, as 10.6 has it (0x960350)."""
    length = len(a)
    gap, adjust = length, 1
    while True:
        adjust = 0 if adjust else 1
        gap = gap // 2 + adjust
        while True:
            swap = False
            for i in range(length - gap):
                if before(a[i + gap], a[i]):
                    a[i], a[i + gap] = a[i + gap], a[i]
                    swap = True
            if not swap:
                break
        if gap == 1:
            break
    return a


def alloc_before(t1, t2):
    """dataflo.c AllocBefore (0x952bc5): const temps last, then savings, then id."""
    c1, c2 = t1["flags"] & 0x100, t2["flags"] & 0x100
    if c1 and not c2:
        return False
    if not c1 and c2:
        return True
    if t1["sav"] is None and t2["sav"] is not None:
        return False
    if t1["sav"] is not None:
        if t2["sav"] is None:
            return True
        return t1["sav"] > t2["sav"]
    return t1["id"] > t2["id"]


LINE = re.compile(r"^\s+\d+ t(\d+) size \d+ .*flags (0x[0-9a-f]+) .*?(noconf|sav (\d+))")


def lists(path, name="RoughSortTemps"):
    out, cur = [], None
    for line in open(path):
        if line.startswith(name + ":"):
            cur = []
            out.append((line.split(":")[1].strip(), cur))
        elif cur is not None and LINE.match(line):
            m = LINE.match(line)
            cur.append({"id": int(m.group(1)), "flags": int(m.group(2), 16),
                        "sav": int(m.group(4)) if m.group(4) else None})
        elif not line.startswith("  "):
            cur = None
    return out


def order(lst, want):
    return [t["id"] for t in lst if t["id"] in want]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--sort", type=int, default=1)
    ap.add_argument("--want", default="")
    ap.add_argument("--extra", type=int, default=0)
    ap.add_argument("--perm", action="store_true")
    ap.add_argument("--tie", type=int, default=21, help="savings of the tied group (for dummies that join it)")
    ap.add_argument("--drop", action="store_true", help="also try removing one temp")
    a = ap.parse_args()
    ls = lists(a.trace)
    before, after = ls[2 * a.sort - 2][1], ls[2 * a.sort - 1][1]
    got = shellsort(list(before), alloc_before)
    ok = [t["id"] for t in got] == [t["id"] for t in after]
    print("replay matches the trace" if ok else "replay DIFFERS from the trace", len(before), "temps")
    if not a.want:
        return
    want = [int(x.lstrip("t")) for x in a.want.split(",")]
    print("now:", order(got, set(want)))
    pos = [i for i, t in enumerate(before) if t["id"] in want]
    perms = itertools.permutations(want) if a.perm else [None]
    for p in perms:
        base = list(before)
        if p:
            byid = {t["id"]: t for t in before}
            for i, tid in zip(pos, p):
                base[i] = byid[tid]
        if a.drop:
            for i, t in enumerate(base):
                if t["id"] in want:
                    continue
                r = order(shellsort(base[:i] + base[i + 1:], alloc_before), set(want))
                if r == want:
                    print("wanted order with", "perm %s" % (p,) if p else "same order",
                          "without t%d (position %d, %s)" % (t["id"], i, t["sav"]))
        for k in range(a.extra + 1):
            for at in (range(len(base) + 1) if k else [0]):
                for sav in ((None, 0, a.tie, 1 << 30) if k else (None,)):
                    if at == 0 and k == 0 and sav is not None:
                        continue
                    dummy = [{"id": 10000 + j, "flags": 1, "sav": sav} for j in range(k)]
                    lst = base[:at] + dummy + base[at:]
                    r = order(shellsort(list(lst), alloc_before), set(want))
                    if r == want:
                        print("wanted order with", "perm %s" % (p,) if p else "same order",
                              "%d dummies (%s) before position %d" % (k, "noconf" if sav is None else "sav %d" % sav, at))


if __name__ == "__main__":
    main()
