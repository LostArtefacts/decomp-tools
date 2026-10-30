"""Compiles src/*.c with Watcom C 10.6 and assembles src/*.asm with MASM
6.11, both under Wine, into build/obj/.

    build.py [FILE.c|FILE.asm...]

The flags are build.cflags and build.asflags in project.toml. WATCOM
is the compiler directory, with BINNT, H and LIB386; it defaults to the
first in build.watcom that has one. MASM is the directory holding ML.EXE
6.11; it defaults to the first in build.masm that has one. An object is
rebuilt when its source or any header or include file in src/ is newer.
"""
import glob, os, subprocess, sys

import project
from project import ROOT, masm, watcom

CFLAGS = project.config["build"]["cflags"]
AFLAGS = project.config["build"]["asflags"]


def winpath(path):
    return "Z:" + os.path.abspath(path).replace("/", "\\")


def env(w):
    e = dict(os.environ)
    e.setdefault("WINEPREFIX", os.path.join(ROOT, ".wine"))
    e.setdefault("WINEDEBUG", "-all")
    e["WATCOM"] = winpath(w)
    e["INCLUDE"] = winpath(os.path.join(ROOT, "src")) + ";" + winpath(os.path.join(w, "H"))
    return e


def compile(w, src, obj):
    if src.endswith(".asm"):
        cmd = ["wine", os.path.join(masm(), "ML.EXE"), *AFLAGS, "/I" + winpath("src"),
               "/Fo" + winpath(obj), winpath(src)]
    else:
        cmd = ["wine", os.path.join(w, "BINNT", "WCC386.EXE"), *CFLAGS,
               "-fo=" + winpath(obj), winpath(src)]
    r = subprocess.run(cmd, env=env(w), capture_output=True, text=True)
    out = "\n".join(l for l in r.stdout.splitlines() + r.stderr.splitlines()
                    if l.strip() and not l.startswith(" Assembling:"))
    if r.returncode or not os.path.exists(obj):
        sys.exit(f"{out}\nerror: {os.path.relpath(src, ROOT)} failed to compile")
    if out:
        print(out)


def main():
    os.chdir(ROOT)
    w = watcom()
    os.makedirs("build/obj", exist_ok=True)
    srcs = sys.argv[1:] or sorted(glob.glob("src/*.c") + glob.glob("src/*.asm"))
    names = [os.path.splitext(os.path.basename(s))[0] for s in srcs]
    if len(set(names)) != len(names):
        sys.exit("error: a .c and an .asm file in src/ share a name")
    headers = max((os.path.getmtime(h) for h in glob.glob("src/*.h") + glob.glob("src/*.inc")), default=0)
    if not sys.argv[1:]:
        names = {os.path.splitext(os.path.basename(s))[0] for s in srcs}
        for obj in glob.glob("build/obj/*.obj"):
            if os.path.splitext(os.path.basename(obj))[0] not in names:
                os.remove(obj)
    built = 0
    for src in srcs:
        obj = os.path.join("build/obj", os.path.splitext(os.path.basename(src))[0] + ".obj")
        if os.path.exists(obj) and os.path.getmtime(obj) >= max(os.path.getmtime(src), headers):
            continue
        if os.path.exists(obj):
            os.remove(obj)
        compile(w, src, obj)
        built += 1
    print(f"{built} of {len(srcs)} objects rebuilt")


if __name__ == "__main__":
    main()
