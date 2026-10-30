"""Compiles src/ with the original compiler and links the hook DLL.

    build.py        the hook DLL, build/<name>.dll
    build.py exe    the standalone game, build/<name>.exe

<name> is game.name in project.toml, which also gives the flags and
libraries below. With build.toolchain = "watcom", build_watcom.py
builds instead.

Every function in config/symbols.csv that src/ defines is hooked: the DLL
overwrites the original function with a jump to the new one. Every other
symbol becomes an absolute symbol at its original address, so new code
calls and reads the original game.

The standalone exe links src/ without src/dll/ but with src/exe/ against
the real libraries, plus the original's resources. Its objects go to
their own directory, exe.obj_dir, compiled with exe.cflags and
exe.defines added: a macro there (TR2_EXE) guards the definitions of
the game's globals and tables in the files that own them, so the DLL
binds the original's. When exe.cflags has /GL, as the original's Rich
header can show, the exe's objects hold no machine code and are linked
with /LTCG: the plain objects in build/obj, which the DLL and compare.py
use, then give the link order.

FEAT (a comma-separated list) turns on the exe's optional features,
exe.features in project.toml: `FEAT=frame_cap build.py exe` compiles
with /DFEAT_FRAME_CAP=1 into build/obj_frame_cap. The DLL is always
built from the vanilla code, so it still matches the original.

build.hook names a Python file with the game's own steps. It may define:

    exe_flags(feats)      extra cl flags for the exe's objects (it may also
                          generate the files they need)
    headers()             more headers whose changes rebuild everything
    exe_resources(feats)  the executable whose resources the exe gets,
                          instead of the original's
"""
import collections, csv, glob, importlib.util, json, os, struct, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

import coff, project

ROOT = project.ROOT
BUILD, DLL_CONFIG, EXE_CONFIG = (project.config[k] for k in ("build", "dll", "exe"))
OBJ = "build/obj"  # the DLL's, which compare.py reads
OBJ_EXE = EXE_CONFIG["obj_dir"]  # the vanilla standalone exe's
CONVERTED = "build/src"  # src/ converted to build.encoding
ENCODING = BUILD["encoding"]
CRLF = BUILD["crlf"]
# Recorded with each object's flags, so switching either rebuilds it.
RECORDED = [BUILD["bin"]] + (["crlf"] if CRLF else [])
SOURCE_EXTS = (".c", ".cpp", ".s", ".asm")  # what gets built; headers and the rest are only converted
ASM_EXTS = (".s", ".asm")  # assembled with build.ml and build.asflags
DLL = project.DLL
EXE = project.EXE
EXE_MAP = project.EXE_MAP
ORIGINAL = project.ORIGINAL
CFLAGS = BUILD["cflags"]
# The exe's; a file's `// cflags:` line can drop them (`-/GL`). Defines
# come after a file's own flags.
EXE_CFLAGS = CFLAGS + EXE_CONFIG["cflags"]
EXE_DEFINES = ["/D" + d for d in EXE_CONFIG["defines"]]
GL = "/GL" in EXE_CFLAGS  # the exe is linked with /LTCG
FEATURES = EXE_CONFIG["features"]  # FEAT name: macro
# FEAT name: the sources only the exe with that feature builds
FEATURE_SOURCES = {f: {os.path.normpath(p) for p in paths}
                   for f, paths in EXE_CONFIG["feature_sources"].items()}
GLUE_PREFIX = "dll_"  # objects from src/dll/, the DLL's own code
DLL_ONLY, EXE_ONLY = "dll", "exe"  # subdirectories of src/ only one target builds
TIMEOUT = BUILD["timeout"]  # cl spins forever after a fatal error
# Compiles run in parallel on half the cores by default, leaving the rest
# free; JOBS overrides it.
JOBS = int(os.environ.get("JOBS") or max(1, (os.cpu_count() or 2) // 2))

ENV = dict(
    os.environ,
    WINEPREFIX=os.environ.get("WINEPREFIX", os.path.join(ROOT, ".wine")),
    WINEDEBUG=os.environ.get("WINEDEBUG", "-all"),
    INCLUDE=";".join(BUILD["include"]),
    LIB=";".join(BUILD["lib"]),
)

_hook = None


def hook(name):
    """The game's build hook function `name`, or None."""
    global _hook
    if _hook is None:
        _hook = False
        if BUILD["hook"]:
            path = os.path.join(ROOT, BUILD["hook"])
            spec = importlib.util.spec_from_file_location("build_hook", path)
            _hook = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(_hook)
    return getattr(_hook, name, None) if _hook else None


def win(path):
    return path.replace("/", "\\")


def run_tool(name, *args):
    """Runs an MSVC tool, or build.ml for "ml"; returns its exit code and
    its output, without the lines that only name the file."""
    exe = BUILD["ml"] if name == "ml" else BUILD["bin"] + "\\" + name + ".exe"
    cmd = ["wine", exe, "/nologo", *args]
    try:
        r = subprocess.run(cmd, env=ENV, timeout=TIMEOUT, capture_output=True, text=True, errors="replace")
    except subprocess.TimeoutExpired:
        return 1, f"{name} timed out (fatal error?): {' '.join(args)}"
    out = "\n".join(l for l in r.stdout.splitlines() if l.strip() and not l.endswith(SOURCE_EXTS))
    return r.returncode, out


def tool(name, *args):
    code, out = run_tool(name, *args)
    if out:
        print(out)
    if code:
        sys.exit(code)


def read_sizes():
    with open("config/symbols.csv") as f:
        return {s: int(r["size"] or 0) for r in csv.DictReader(f) for s in r["symbol"].split()}


def read_symbols():
    with open("config/symbols.csv") as f:
        return {s: int(r["address"], 16) for r in csv.DictReader(f) for s in r["symbol"].split()}


def encode(text):
    """Encodes `text` as build.encoding for cl.

    cl reads source bytes as single-byte characters, so in a double-byte
    encoding (Shift-JIS, cp932) a character whose second byte is 0x5c
    ("能", "表", "ソ") would end in an escape inside a string literal:
    that byte is doubled.
    """
    out = bytearray()
    for ch in text:
        b = ch.encode(ENCODING)
        out += b
        if len(b) == 2 and b[1] == 0x5C:
            out += b"\\"
    return bytes(out)


def features():
    """The features FEAT asks for, sorted."""
    names = sorted({f.strip() for f in os.environ.get("FEAT", "").split(",") if f.strip()})
    unknown = [f for f in names if f not in FEATURES]
    if unknown:
        sys.exit(f"unknown FEAT {', '.join(unknown)}; known: {', '.join(FEATURES) or 'none'}")
    return names


def compile_all(target=DLL, exe_flags=False, feats=()):
    """Compiles src/ from a copy in build/src/ in build.encoding.

    Sources are UTF-8, but the game's strings are in the code page it was
    written in and cl copies string bytes as they are, so each file is
    converted first.
    Objects go to build/obj or, with `exe_flags`, with the exe's flags to
    exe.obj_dir, or build/obj_<features> with features.
    An object is rebuilt when its source or any header is newer, or when
    its flags changed: each object directory's flags.json records them.
    """
    if not exe_flags:
        obj_dir, base, defines = OBJ, CFLAGS, []
    else:
        obj_dir = "_".join([OBJ, *feats]) if feats else OBJ_EXE
        base = EXE_CFLAGS
        defines = EXE_DEFINES + ["/D%s=1" % FEATURES[f] for f in feats]
        extra = hook("exe_flags")
        if extra:
            defines += extra(list(feats))
    os.makedirs(obj_dir, exist_ok=True)
    for src in glob.glob("src/**/*.*", recursive=True):
        copy = os.path.join(CONVERTED, os.path.relpath(src, "src"))
        with open(src, encoding="utf-8") as f:
            text = f.read()
        if CRLF:
            text = text.replace("\n", "\r\n")
        data = encode(text)
        if not os.path.exists(copy) or open(copy, "rb").read() != data:
            os.makedirs(os.path.dirname(copy), exist_ok=True)
            with open(copy, "wb") as f:
                f.write(data)
    more = hook("headers")
    headers = max((os.path.getmtime(h) for h in glob.glob("src/**/*.h", recursive=True)
                   + (list(more()) if more else []) if os.path.exists(h)), default=0)
    record = os.path.join(obj_dir, "flags.json")
    try:
        with open(record) as f:
            built = json.load(f)
    except (OSError, ValueError):
        built = {}
    objs, stale = [], []
    for src, obj in sources(target, obj_dir, feats):
        objs.append(obj)
        flags = file_flags(src, base) + defines
        if not (os.path.exists(obj) and os.path.getmtime(obj) > max(os.path.getmtime(src), headers)
                and built.get(obj) == flags + RECORDED):
            stale.append((src, obj, flags))

    def compile_one(job):
        src, obj, flags = job
        converted = win(os.path.join(CONVERTED, os.path.relpath(src, "src")))
        if src.lower().endswith(ASM_EXTS):
            return run_tool("ml", *BUILD["asflags"], "/Fo" + win(obj), converted)
        return run_tool("cl", "/c", *flags, "/I" + win(CONVERTED), "/Fo" + win(obj), converted)

    failed = 0
    with ThreadPoolExecutor(JOBS) as pool:
        # Results come back in source order, so the output reads as before.
        for (src, obj, flags), (code, out) in zip(stale, pool.map(compile_one, stale)):
            print("ml" if src.lower().endswith(ASM_EXTS) else "cl", src)
            if out:
                print(out)
            if code:
                built.pop(obj, None)
                failed = failed or code
            else:
                built[obj] = flags + RECORDED
    with open(record, "w") as f:
        json.dump(built, f, indent=1, sort_keys=True)
    if failed:
        sys.exit(failed)
    return objs


def sources(target=DLL, obj_dir=OBJ, feats=()):
    """Yields (source, object) for each .c, .cpp, .s and .asm in src/ that
    `target` builds with the features `feats`."""
    skip = EXE_ONLY if target == DLL else DLL_ONLY
    unused = set().union(*(paths for f, paths in FEATURE_SOURCES.items() if f not in feats))
    found = (glob.glob(os.path.join(ROOT, "src/**/*" + ext), recursive=True) for ext in SOURCE_EXTS)
    for src in sorted(sum(found, [])):
        rel = os.path.relpath(src, os.path.join(ROOT, "src"))
        if rel.split(os.sep)[0] == skip or os.path.normpath(os.path.relpath(src, ROOT)) in unused:
            continue
        yield os.path.relpath(src, ROOT), os.path.join(obj_dir, os.path.splitext(rel.replace("/", "_"))[0] + ".obj")


def file_flags(src, base=CFLAGS):
    """The flags for one file: `base`, changed by a `// cflags: ...` or
    `/* cflags: ... */` first line. `/X` adds a flag, `-/X` removes a
    default one."""
    with open(src) as f:
        first = f.readline().strip()
    if first.startswith("/* cflags:") and first.endswith("*/"):
        first = "//" + first[2:-2]
    changes = first.split(":", 1)[1].split() if first.startswith("// cflags:") else []
    flags = [f for f in base if "-" + f not in changes]
    return flags + [c for c in changes if not c.startswith("-")]


def write_hooks(objs, symbols):
    """Writes the hook table and the symbols that point into the original.

    The linker rejects calls to absolute symbols, so each original function
    that new code calls gets a thunk instead: push <address>; ret. It
    leaves every register intact, whatever the calling convention.
    """
    defined, code, undefined, called, glue = set(), set(), set(), set(), set()
    for path in objs:
        obj = coff.Object(path)
        for s in obj.externals():
            if s.section <= 0:
                undefined.add(s.name)
                if os.path.basename(path).startswith(GLUE_PREFIX):
                    glue.add(s.name)
                continue
            defined.add(s.name)
            # The DLL's own code is never a game function, even when it
            # shares a name with one (Init).
            if (obj.sections[s.section - 1].flags & coff.CODE
                    and not os.path.basename(path).startswith(GLUE_PREFIX)):
                code.add(s.name)
        for sec in obj.sections:
            called.update(obj.symbols[i].name for _, i, t in sec.relocs if t == coff.REL32)
    # Data that src/ defines, such as vtables, is never hooked. Functions
    # the linker folded into one share an address; one hook covers them.
    # A function shorter than the 5-byte jump isn't hooked either: the
    # jump would overwrite the next one, so the original's copy runs.
    sizes = read_sizes()
    hookable = {n for n in code & symbols.keys() if not 0 < sizes.get(n, 5) < 5}
    short = len(code & symbols.keys()) - len(hookable)
    hooks = sorted({symbols[n]: n for n in sorted(hookable)}.items())
    # Imports the hook installer itself uses stay real imports: it runs
    # from DllMain and should not rely on the game's import table.
    external = {n: a for n, a in symbols.items()
                if n in undefined - defined and not (n.startswith("__imp_") and n in glue)}

    table, table_relocs = bytearray(), []
    for addr, name in hooks:
        table_relocs.append((len(table) + 4, name, coff.DIR32))
        table += struct.pack("<II", addr, 0)
    table += bytes(8)
    thunks, entry = bytearray(), {"_g_Hooks": (1, 0)}
    for name, addr in external.items():
        if name in called:
            entry[name] = (2, len(thunks))
            thunks += struct.pack("<BIB", 0x68, addr, 0xC3).ljust(8, b"\xcc")
    absolute = {n: a for n, a in external.items() if n not in entry}
    # Functions with exception handling address the handler chain as
    # fs:[__except_list]; the CRT defines it as the absolute value 0.
    if "__except_list" in undefined:
        absolute["__except_list"] = 0

    path = os.path.join(OBJ, "hooks.obj")
    coff.write_object(path, [(".rdata", coff.RDATA, bytes(table), table_relocs),
                             (".text", coff.TEXT, bytes(thunks), [])],
                      entry, [n for _, n in hooks], absolute)
    print(f"{len(hooks)} hooked, {len(external)} used from the original"
          + (f", {short} too short to hook" if short else ""))
    return path


def link_order(objs, symbols, how):
    """Sorts the game's objects into the original's order, by the original
    addresses of the functions that only that object defines (an inline
    function other objects also emit doesn't count):

        median  their median address, which ignores a function the
                original's linker folded into another object's identical
                one
        first   their lowest address
        source  no sorting: source file order

    Objects that define no such function (data, globals) go last, in
    their given order."""
    if how == "source":
        return list(objs)
    if how not in ("median", "first"):
        sys.exit(f"exe.link_order is median, first or source, not {how}")
    code = {}
    for path in objs:
        obj = coff.Object(path)
        code[path] = {s.name for s in obj.externals()
                      if s.section > 0 and obj.sections[s.section - 1].flags & coff.CODE}
    count = collections.Counter(n for names in code.values() for n in names)

    def key(path):
        addrs = sorted(symbols[n] for n in code[path] if count[n] == 1 and n in symbols)
        if not addrs:
            return 1 << 32
        return addrs[len(addrs) // 2] if how == "median" else addrs[0]
    return sorted(objs, key=key)


def link_exe(objs, exe_objs=None, feats=()):
    """Links the standalone game with the libraries the original was built
    with (exe.libs, in the original's order: it decides the import table
    and where library code lands). `objs` give the link order; with /GL,
    `exe_objs` are the same files' /GL objects, which get linked."""
    import rsrc
    exe_objs = exe_objs or objs
    res = os.path.join(os.path.dirname(exe_objs[0]), f"{project.NAME}.res")
    resources = hook("exe_resources")
    image = (resources(list(feats)) if resources else None) or ORIGINAL
    rsrc.write_res(res, rsrc.resources(image))
    linked = dict(zip(objs, exe_objs))
    ordered = [linked[o] for o in link_order(objs, read_symbols(), EXE_CONFIG["link_order"])]
    tool("link", *EXE_CONFIG["ldflags"], "/MAP:" + win(EXE_MAP), "/OUT:" + win(EXE),
         *map(win, ordered), win(res), *EXE_CONFIG["libs"])
    copy_header_fields(ORIGINAL, EXE)
    print("linked", EXE)


def copy_header_fields(src, dst):
    """Gives dst the original's link timestamp, the one header field the
    linker has no option for."""
    with open(src, "rb") as f:
        orig = f.read(0x400)
    pe = struct.unpack_from("<I", orig, 0x3C)[0]
    with open(dst, "r+b") as f:
        f.seek(0x3C)
        dpe = struct.unpack("<I", f.read(4))[0]
        f.seek(dpe + 8)
        f.write(orig[pe + 8:pe + 12])


def main():
    if project.TOOLCHAIN == "watcom":
        import build_watcom
        return build_watcom.main()
    os.chdir(ROOT)
    if sys.argv[1:] == ["exe"]:
        feats = features()
        if feats:
            print("features:", ", ".join(feats))
        if GL:
            # /GL objects hold no code to order them by: the plain ones do.
            link_exe(compile_all(EXE, feats=feats), compile_all(EXE, True, feats), feats)
        else:
            link_exe(compile_all(EXE, True, feats), feats=feats)
        return
    if sys.argv[1:]:
        sys.exit(__doc__)
    objs = compile_all()
    hooks = write_hooks(objs, read_symbols())
    tool("link", *DLL_CONFIG["ldflags"], "/MAP:" + win(DLL[:-4] + ".map"), "/OUT:" + win(DLL),
         *map(win, objs), win(hooks), *DLL_CONFIG["libs"])
    print("linked", DLL)


if __name__ == "__main__":
    main()
