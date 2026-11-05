"""Shows what Watcom 10.6's code generator decides for each function.

    wccoracle.py SRC [--proc N] [--what temps,conf,regs,slots] [-- FLAGS...]
    wccoracle.py SRC --dump IMAGE

SRC is compiled by BINNT/WCC386.EXE (the build's compiler, flags from
build.cflags unless FLAGS are given) under winedbg's gdb proxy, with
breakpoints in the code generator (see docs/wcc106-cg.md):

  temps   Names[N_TEMP] before and after RoughSortTemps (AllocBefore:
          const temps last, then conflict savings descending, then id
          descending) and the TempAllocBefore sort in AssignOtherLocals.
  conf    the conflict list before and after SortConflicts (savings
          descending). Both sorts are SortList's unstable ShellSort, so
          ties come out in an order that depends on list positions.
  regs    every GiveRegister call: the conflict, and what GiveBestReg
          returned (0 = no register, the conflict goes to memory).
  slots   the temps that got stack memory, in AllocNewLocal order, with
          the location each got.

Functions are numbered in the order the code generator sees them
("== proc N"); --proc limits the output to one. A temp is printed as
tID with its size, front end symbol handle, flags, usage, the savings of
its conflict and its location once it has one.

--dump writes the relocated code generator image (as loaded, at
0x8f0020) to IMAGE and stops; `objdump -D -b binary -m i386
--adjust-vma=0x8f0020 IMAGE` then shows the addresses this tool uses.

Needs gdb and winedbg on the PATH. WCO_DEBUG=1 shows gdb's own output.
"""
import argparse, os, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_watcom  # noqa: E402
import project  # noqa: E402

GDB_SCRIPT = os.path.join(HERE, "wccoracle", "wccgdb.py")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("src")
    ap.add_argument("--proc", default="")
    ap.add_argument("--what", default="temps,conf,regs,slots")
    ap.add_argument("--dump", default="")
    ap.add_argument("flags", nargs="*")
    a = ap.parse_args()
    w = project.watcom()
    flags = a.flags or build_watcom.cflags(a.src)
    work = os.path.join(project.ROOT, "build", "wccoracle")
    os.makedirs(work, exist_ok=True)
    port = free_port()
    env = dict(build_watcom.env(w), WCO_PORT=str(port), WCO_PROC=a.proc, WCO_WHAT=a.what,
               WCO_DUMP=os.path.abspath(a.dump) if a.dump else "")
    log = os.path.join(work, "winedbg.log")
    exe = build_watcom.winpath(os.path.join(w, "BINNT", "WCC386.EXE"))
    obj = build_watcom.winpath(os.path.join(work, "out.obj"))
    proxy = subprocess.Popen(["winedbg", "--gdb", "--no-start", "--port", str(port), exe, *flags,
                              "-fo=" + obj, build_watcom.winpath(a.src)],
                             env=env, cwd=work, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(300):
            if "target remote" in open(log, errors="replace").read():
                break
            time.sleep(0.05)
        r = subprocess.run(["gdb", "-nx", "-batch", "-ex", "source " + GDB_SCRIPT],
                           env=env, capture_output=True, text=True, errors="replace")
    finally:
        try:
            proxy.wait(10)
        except subprocess.TimeoutExpired:
            proxy.kill()
    if os.environ.get("WCO_DEBUG"):
        print(r.stdout, r.stderr)
    lines = [l for l in r.stdout.splitlines() if l.startswith(("| ", "== ", "!! "))]
    if not lines:
        sys.exit("no output from wcc386:\n%s%s" % (r.stdout[-2000:], r.stderr[-2000:]))
    for line in lines:
        print(line[2:] if line.startswith("| ") else line)


if __name__ == "__main__":
    main()
