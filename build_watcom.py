"""Compiles src/*.c with Watcom C 10.6 and assembles src/*.asm with MASM
6.11 or Watcom WASM, under Wine, into build/obj/.

    build.py [FILE.c|FILE.asm...]

The flags are build.cflags and build.asflags in project.toml. A file
named in build.file_cflags, by its stem (`player = ["-od", ...]` for
src/player.c), is compiled with that list instead of build.cflags: the
whole list, nothing is added to it. bss.py and permute.py compile and
preprocess with the same flags (cflags() below). WATCOM
is the compiler directory, with BINNT, H and LIB386; it defaults to the
first in build.watcom that has one. MASM is the directory holding ML.EXE
6.11; it defaults to the first in build.masm that has one. An object is
rebuilt when its source or any header or include file in src/ is newer,
or when its flags changed (build/obj/flags.json records them).
build.file_assemblers selects "wasm" or "gas" for individual assembly
modules; the default is "masm". WASM uses build.wasmflags and
BINNT/WASM.EXE from the Watcom installation. "gas" runs GNU as
(build.gas, natively, not under Wine) with build.gasflags on a source in
its own syntax (`.intel_syntax noprefix` for Intel's) and converts the
ELF object it writes to OMF with gas_omf.py.
"""
import glob, json, os, subprocess, sys, tempfile

import gas_omf
import project
from project import ROOT, masm, watcom

CFLAGS = project.config["build"]["cflags"]
FILE_CFLAGS = project.config["build"]["file_cflags"]
AFLAGS = project.config["build"]["asflags"]
FILE_ASSEMBLERS = project.config["build"]["file_assemblers"]
WASM_FLAGS = project.config["build"]["wasmflags"]
GAS = project.config["build"]["gas"]
GAS_FLAGS = project.config["build"]["gasflags"]


def winpath(path):
    return "Z:" + os.path.abspath(path).replace("/", "\\")


def cflags(src: str) -> list[str]:
    """The wcc386 flags for the source file `src`: its build.file_cflags
    entry if it has one, else build.cflags."""
    return FILE_CFLAGS.get(os.path.splitext(os.path.basename(src))[0], CFLAGS)


def assembler(src: str) -> str:
    name = FILE_ASSEMBLERS.get(os.path.splitext(os.path.basename(src))[0], "masm")
    if name not in ("masm", "wasm", "gas"):
        sys.exit(f"error: unknown assembler {name!r} for {src}")
    return name


def asflags(src: str) -> list[str]:
    return {"wasm": WASM_FLAGS, "gas": GAS_FLAGS}.get(assembler(src), AFLAGS)


def env(w):
    e = dict(os.environ)
    e.setdefault("WINEPREFIX", os.path.join(ROOT, ".wine"))
    e.setdefault("WINEDEBUG", "-all")
    e["WATCOM"] = winpath(w)
    e["INCLUDE"] = winpath(os.path.join(ROOT, "src")) + ";" + winpath(os.path.join(w, "H"))
    return e


def run(cmd, w, cwd=None):
    """Runs `cmd` under Wine with the compiler's environment: (exit code,
    output). The output goes through a file, not a pipe: a pipe stays
    open in wine's helper processes and every call would wait about
    four seconds for them. wcc386 leaves NAME.err in `cwd` on errors."""
    with tempfile.TemporaryFile("w+", errors="replace") as f:
        code = subprocess.run(cmd, env=env(w), cwd=cwd, stdin=subprocess.DEVNULL, stdout=f,
                              stderr=subprocess.STDOUT).returncode
        f.seek(0)
        return code, f.read()


def gas(src: str, obj: str) -> None:
    """Assembles `src` with GNU as into `obj`, through an ELF object
    beside it."""
    elf = os.path.splitext(obj)[0] + ".o"
    try:
        r = subprocess.run([GAS, *asflags(src), "-o", elf, src], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, errors="replace")
        out = (r.stdout + r.stderr).strip()
        if r.returncode or not os.path.exists(elf):
            sys.exit(f"{out}\nerror: {os.path.relpath(src, ROOT)} failed to assemble")
        if out:
            print(out)
        with open(elf, "rb") as f:
            data = gas_omf.convert(f.read(), winpath(src))
    except ValueError as e:
        sys.exit(f"error: {os.path.relpath(src, ROOT)}: {e}")
    finally:
        if os.path.exists(elf):
            os.remove(elf)
    with open(obj, "wb") as f:
        f.write(data)


def compile(w: str, src: str, obj: str) -> None:
    if src.endswith(".asm") and assembler(src) == "gas":
        return gas(src, obj)
    if src.endswith(".asm"):
        if assembler(src) == "wasm":
            cmd = ["wine", os.path.join(w, "BINNT", "WASM.EXE"), *asflags(src),
                   "-i=" + winpath("src"), "-fo=" + winpath(obj), winpath(src)]
        else:
            cmd = ["wine", os.path.join(masm(), "ML.EXE"), *asflags(src), "/I" + winpath("src"),
                   "/Fo" + winpath(obj), winpath(src)]
    else:
        cmd = ["wine", os.path.join(w, "BINNT", "WCC386.EXE"), *cflags(src),
               "-fo=" + winpath(obj), winpath(src)]
    code, out = run(cmd, w)
    out = "\n".join(l for l in out.splitlines() if l.strip() and not l.startswith(" Assembling:"))
    if code or not os.path.exists(obj):
        sys.exit(f"{out}\nerror: {os.path.relpath(src, ROOT)} failed to compile")
    if out:
        print(out)


def main() -> None:
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
    unknown = set(FILE_CFLAGS) - set(names)
    if unknown and not sys.argv[1:]:
        print(f"warning: build.file_cflags names no file in src/: {' '.join(sorted(unknown))}")
    unknown = set(FILE_ASSEMBLERS) - set(names)
    if unknown and not sys.argv[1:]:
        print(f"warning: build.file_assemblers names no file in src/: {' '.join(sorted(unknown))}")
    record = "build/obj/flags.json"
    try:
        recorded = json.load(open(record))
    except (OSError, ValueError):
        recorded = {}
    built = 0
    for src in srcs:
        stem = os.path.splitext(os.path.basename(src))[0]
        obj = os.path.join("build/obj", stem + ".obj")
        flags = (["assembler=" + assembler(src), *asflags(src)]
                 if src.endswith(".asm") else cflags(src))
        if os.path.exists(obj) and os.path.getmtime(obj) >= max(os.path.getmtime(src), headers) \
                and recorded.get(stem, flags) == flags:
            recorded[stem] = flags
            continue
        if os.path.exists(obj):
            os.remove(obj)
        compile(w, src, obj)
        recorded[stem] = flags
        json.dump(recorded, open(record, "w"), indent=1, sort_keys=True)
        built += 1
    json.dump(recorded, open(record, "w"), indent=1, sort_keys=True)
    print(f"{built} of {len(srcs)} objects rebuilt")


if __name__ == "__main__":
    main()
