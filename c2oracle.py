r"""Shows the decisions MSVC's back end (VC5's C2.EXE, VC6's c2.dll) makes for one function.

    c2oracle.py SRC NAME [--sort] [--regs] [--global] [--inline] [--x87] [--sched] [--raw]

SRC is a file in src/ and NAME a function it defines (or any other .c
file, compiled with the project's cflags). The file is compiled as
build.py compiles it (its flags, the CRLF copy in build/src), with cl's
/B2 pointing at a small stand-in for the back end. Which back end is
the project's: [build] bin holding c2.dll means VC6, else VC5.

VC5: the stand-in, c2oracle/c2keep.c, keeps the intermediate files, and
the real C2.EXE then runs on them under gdb, through winedbg's gdb proxy.
VC6: cl.exe loads c2.dll in process, so cl itself runs under the proxy;
the stand-in, c2oracle/c2stub.c, a DLL, loads the real c2.dll and stops
on an int 3 so gdb can plant its breakpoints there. Either way they sit
at the places where the back end decides the things a red function
usually gets wrong, and it prints them for NAME:

  --sort  the commutative operand sort: for each `+ * & | ^` node, its
          operands in the order c2 puts them, with the sort key of each
          (rank, count, hash16) and what it is: a symbol with its front
          end ID, a compiler temp with its slot, a constant, a memory
          reference, or a subtree. The operand with the highest key goes
          first; to swap two operands, change what feeds their hashes
          (see docs/vc5-c2.md).
  --regs  the local register picker: each value that gets a scratch
          register, the register, and how it was found (preferred,
          round robin over eax/ecx/edx with where the pointer stood,
          first free, evicted). "-- rotation reset" marks the function
          start. Values the global allocator keeps in esi/edi/ebx/ebp
          are not shown yet.
  --global  the global allocator (P2\color.c): each live range in the
          order it is colored, with its priority, tie-break position,
          reference count, weighted references, and the register it
          got (or a note that it was split). With --raw, also every
          block with its loop multiplier and each range's priority
          change there (referenced: + multiplier * ranges * weights;
          live through: - multiplier * ranges).
  --x87   VC5: the scheduler's pre-pass (it runs on blocks with x87 code,
          before register allocation): for each block, its tuples in
          IL order with the position the scheduler gave each one and
          its priority. Equal priorities keep IL order, so when two
          loads come out in the wrong order, the IL already had them
          that way: look at the commutative sort of the pass that
          made the IL (`--sort`, the later lists for the same tree).
  --sched VC6: the list scheduler (one pass, after register
          allocation, on every block): for each block, its machine
          instructions in IL order (`mov edx <- [esi+72], esi`: the
          result, then the operands) with the position the scheduler
          gave each and its priority (hex). Equal priorities keep IL
          order; a load gets 0x10000 on top of its height, so loads
          rise. With --raw also each instruction's height, successors
          (IL position/latency:kind, kind 0x20 = a store before a load
          that may alias it), the alias tag of each memory operand,
          and the cycle picker's decision on every ready instruction
          (slow on a big file: minutes).
  --inline  the inliner: the caller's size and budget, then each inline
          candidate call site in the order c2 visits it, with the
          callee's size, the depth against the site's inline_depth
          limit, the budget left and how many sites are left at that
          level; whether it is inlined (and what it costs: 0 up to size
          40) or refused, and the budget its own call sites get. Only
          with this option; NAME may be `*` for every function. VC5 only.

With no option it shows --sort, --regs and --x87 (VC5) or --sched (VC6). Output lines name symbols as
`name#ID` (front end ID, hex) and compiler temps as `temp@SLOT`; memory
references as `[base+offset]`; opN is a c2 opcode. A run takes about
15 seconds; set C2O_DEBUG=1 to see gdb's own output. --raw adds the node addresses and
raw words, and under each pick the value record, its preferred register on
entry and its interference index; under --sort it also prints every node
below each sorted operand with its key, following a temp into the
expression it holds. The rules behind all of this, with the back end's addresses, are
in docs/vc5-c2.md and docs/vc6-c2.md. Under VC6 --global also prints
"-- round" when the allocator starts over after a split, the ranges it
leaves in memory, and a final line with every range's register.

Needs gdb and winedbg (wine's) on the PATH. The stand-in is compiled
with the project's cl the first time, into build/c2oracle/ (VC6:
`cl /nologo /O2 /LD c2stub.c`).
"""
import argparse, os, shutil, socket, subprocess, sys, time

import build, project

ROOT = project.ROOT
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(ROOT, "build", "c2oracle")
KEEP_SRC = os.path.join(HERE, "c2oracle", "c2keep.c")
STUB_SRC = os.path.join(HERE, "c2oracle", "c2stub.c")
GDB_SCRIPT = os.path.join(HERE, "c2oracle", "c2gdb.py")


def bin_file(name):
    """A file in the compiler's bin directory, on this machine."""
    path = build.host(build.BUILD["bin"] + "\\" + name)
    if not build.NATIVE and path[1:3] == ":\\":
        path = os.path.join(build.ENV["WINEPREFIX"], "drive_" + path[0].lower(), *path[3:].split("\\"))
    return path


VC6 = os.path.exists(bin_file("c2.dll"))


def winpath(path):
    """A Linux path as wine's Z: drive sees it."""
    return path if build.NATIVE else "Z:" + os.path.abspath(path).replace("/", "\\")


def stand_in():
    """VC5: c2keep.exe; VC6: c2stub.dll. Built when missing or older than its source."""
    src = STUB_SRC if VC6 else KEEP_SRC
    exe = os.path.join(WORK, "c2stub.dll" if VC6 else "c2keep.exe")
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(src):
        os.makedirs(WORK, exist_ok=True)
        env = dict(build.ENV, INCLUDE=build.host(build.BUILD["include"][-1]),
                   LIB=build.host(build.BUILD["lib"][-1]))
        r = subprocess.run((["wine"] if not build.NATIVE else []) +
                           [build.host(build.BUILD["bin"] + "\\cl.exe"), "/nologo", "/O2", *(["/LD"] if VC6 else []),
                            "/Fe" + winpath(exe), "/Fo" + winpath(exe[:-4] + ".obj"), winpath(src)],
                           env=env, cwd=WORK, capture_output=True, text=True)
        if r.returncode:
            sys.exit("%s did not build:\n%s%s" % (os.path.basename(src), r.stdout, r.stderr))
    return exe


def in_src(src):
    return os.path.abspath(src).startswith(os.path.join(ROOT, "src") + os.sep)


def compile_args(src):
    """cl's flags and source for SRC: build.py's for a file in src/, else the project's cflags."""
    if not in_src(src):
        return [*build.CFLAGS, winpath(src)]
    return [*build.file_flags(src), "/I" + build.win(build.CONVERTED), build.win(convert(src))]


def convert(src):
    """Writes the CRLF copies of src/ to build/src, as build.py does."""
    import glob
    for path in glob.glob(os.path.join(ROOT, "src/**/*.*"), recursive=True):
        copy = os.path.join(ROOT, build.CONVERTED, os.path.relpath(path, os.path.join(ROOT, "src")))
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if build.CRLF:
            text = text.replace("\n", "\r\n")
        data = build.encode(text)
        if not os.path.exists(copy) or open(copy, "rb").read() != data:
            os.makedirs(os.path.dirname(copy), exist_ok=True)
            with open(copy, "wb") as f:
                f.write(data)
    return os.path.join(build.CONVERTED, os.path.relpath(os.path.abspath(src), os.path.join(ROOT, "src")))


def front_end(src, keep):
    """Runs cl on SRC with the stand-in; returns c2's flags, pointing at the kept copies."""
    if os.path.isdir(keep):
        shutil.rmtree(keep)
    os.makedirs(keep)
    obj = os.path.join(keep, "cl.obj")
    env = dict(build.ENV, C2KEEP=winpath(keep), C2REAL=build.host(build.BUILD["bin"] + "\\c2.exe"))
    cmd = (["wine"] if not build.NATIVE else []) + [
        build.host(build.BUILD["bin"] + "\\cl.exe"), "/nologo", "/c",
        "/B2" + winpath(stand_in()), "/Fo" + winpath(obj), *compile_args(src)]
    r = subprocess.run(cmd, env=env, cwd=ROOT, capture_output=True, text=True, errors="replace")
    if r.returncode or not os.path.exists(os.path.join(keep, "flags.txt")):
        sys.exit("cl failed:\n" + r.stdout + r.stderr)
    flags = open(os.path.join(keep, "flags.txt")).read().split()
    il = flags[flags.index("-il") + 1]
    flags[flags.index("-il") + 1] = winpath(keep) + "\\" + il.rsplit("\\", 1)[-1]
    flags = [("-Fo" + winpath(os.path.join(keep, "c2.obj"))) if f.startswith("-Fo") else f for f in flags]
    return " ".join(flags)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def back_end(flags, name, what, raw, keep, src=None):
    """Runs the back end under gdb. VC5: C2.EXE on the kept files (flags);
    VC6: cl.exe on SRC with the stand-in DLL, which stops once c2.dll is in."""
    port = free_port()
    log = os.path.join(keep, "winedbg.log")
    env = dict(build.ENV, MSC_CMD_FLAGS=flags or "", C2O_FUNC=name, C2O_WHAT=",".join(what),
               C2O_RAW="1" if raw else "", C2O_PORT=str(port), C2O_C2="vc6" if VC6 else "vc5")
    if VC6:
        env.pop("MSC_CMD_FLAGS")
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        env.update(C2REAL=build.host(build.BUILD["bin"] + "\\c2.dll"), C2O_BREAK="1")
        cmd = [build.host(build.BUILD["bin"] + "\\cl.exe"), "/nologo", "/c", "/B2" + winpath(stand_in()),
               "/Fo" + winpath(os.path.join(keep, "c2.obj")), *compile_args(src)]
        cwd = ROOT
    else:
        cmd = [build.host(build.BUILD["bin"] + "\\c2.exe")]
        cwd = keep
    proxy = subprocess.Popen(["winedbg", "--gdb", "--no-start", "--port", str(port), *cmd],
                             env=env, cwd=cwd, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    try:
        # The proxy accepts one connection, so wait for it to say it listens.
        for _ in range(300):
            if "target remote" in open(log, errors="replace").read():
                break
            time.sleep(0.05)
        r = subprocess.run(["gdb", "-nx", "-batch", "-ex", "source " + GDB_SCRIPT],
                           env=env, capture_output=True, text=True, errors="replace")
    finally:
        try:
            proxy.wait(20 if VC6 else 10)
        except subprocess.TimeoutExpired:
            proxy.kill()
    if os.environ.get("C2O_DEBUG"):
        print(r.stdout, r.stderr)
    out = [l for l in r.stdout.splitlines() if l.startswith(("| ", "== ", "!! "))]
    if not out:
        sys.exit("no output from the back end for %s:\n%s%s" % (name, r.stdout[-2000:], r.stderr[-2000:]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("src")
    ap.add_argument("name")
    ap.add_argument("--sort", action="store_true")
    ap.add_argument("--regs", action="store_true")
    ap.add_argument("--x87", action="store_true")
    ap.add_argument("--sched", action="store_true")
    ap.add_argument("--inline", action="store_true")
    ap.add_argument("--global", dest="glob", action="store_true")
    ap.add_argument("--raw", action="store_true")
    a = ap.parse_args()
    what = [w for w in ("sort", "regs", "x87", "sched", "inline") if getattr(a, w)]
    what = (what + ["global"] if a.glob else what) or ["sort", "regs", "sched" if VC6 else "x87"]
    keep = os.path.join(WORK, "keep")
    if VC6:
        if os.path.isdir(keep):
            shutil.rmtree(keep)
        os.makedirs(keep)
        flags = None
    else:
        flags = front_end(a.src, keep)
    for line in back_end(flags, a.name, what, a.raw, keep, a.src):
        print(line[2:] if line.startswith("| ") else line)


if __name__ == "__main__":
    main()
