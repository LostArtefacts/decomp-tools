"""Reads the game's project.toml, the one place for what differs between
the games: names, paths, the code's end, compiler and linker flags,
libraries, and the backend.

    project.py get KEY        print a setting (game.name, ghidra.project...)
    project.py ghidra         print the Ghidra installation's directory
    project.py orig           verify the original's checksums, copy it to build/
    project.py game           set up build/game: game data, patched exe and DLL
                              (le: game files, CD image, hooked exe)
    project.py standalone     copy the standalone exe (and extras) into build/game
    project.py clean          remove build outputs (keeps the Ghidra project)

The file is project.toml in the game repository's root (the directory
above tools/), or the one the DECOMP_PROJECT environment variable names.
Other tools import this module and read `config`, or the shorthands
below. Paths in the file are relative to the repository's root.

game.format picks the backend: "pe" (the default) for a Windows PE
built with MSVC into a hook DLL, "le" for a DOS4GW LE built with Watcom
C and MASM into objects hooked into a copy of the LE. build.toolchain
defaults to the format's: "msvc" for pe, "watcom" for le. The Watcom,
MASM and DOSBox search lists are globs, with ~ for the home directory,
tried in order, the newest match of each first; the WATCOM, MASM and
DOSBOX environment variables override them.
"""
import copy, glob, os, shutil, subprocess, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.dirname(os.path.abspath(__file__))
PATH = os.environ.get("DECOMP_PROJECT") or os.path.join(ROOT, "project.toml")

REQUIRED = object()  # a setting without a default
TOOLCHAINS = {"pe": "msvc", "le": "watcom"}  # each format's default toolchain

# Every setting, with its default.
DEFAULTS = {
    "game": {
        "name": REQUIRED,  # short name: build/<name>.dll, build/<name>.exe
        "dir": REQUIRED,  # the original game's files
        "exe": REQUIRED,  # the original executable's name in dir
        "format": "pe",  # the backend: "pe" (Windows, MSVC) or "le" (DOS4GW, Watcom)
        "original": REQUIRED,  # where its verified copy goes, an ASCII path
        "game_end": REQUIRED,  # the game's code ends here; libraries follow
        "title": "",  # the progress chart's title; defaults to the name
        "window_title": "",  # play.py looks for a window with this title
        "locale": "",  # play.py's LANG and LC_ALL, such as ja_JP.UTF-8; empty keeps the user's
        "screen": "640x480x24",  # play.py's Xvfb screen
        "checksums": "",  # a `sha1sum -c` file, run from its own directory
        "standalone_extras": [],  # globs copied into build/game with the standalone exe
        "code": [],  # le: the code object's [start, end) in the flattened executable
        "hooked": "",  # le: where `project.py game` writes the hooked exe, in build/game
        "copy": [],  # le: files of dir copied into build/game
        "link": [],  # le: globs of dir symlinked into build/game
        "cd": "",  # le: the CD image in build/game that play.py mounts as D:
    },
    "ghidra": {
        "path": "",  # the Ghidra installation; GHIDRA overrides it
        "search": ["~/opt/ghidra_*"],  # globs searched for the newest installation without either
        "project": "",  # defaults to the original's file name without .exe
        "functions": "",  # defaults to build/functions_<project>.csv
    },
    "build": {
        "toolchain": "",  # "msvc" or "watcom"; defaults to the format's
        "bin": r"C:\msvc5\bin",
        "include": [r"C:\dx5\include", r"C:\msvc5\include"],
        "lib": [r"C:\dx5\lib", r"C:\msvc5\lib"],
        "cflags": REQUIRED,
        "encoding": "cp1252",  # what src/'s UTF-8 is converted to for cl
        "crlf": False,  # convert src/'s LF line endings to CRLF for cl
        "ml": r"C:\masm611\bin\ml.exe",  # the assembler for src/'s .s and .asm files
        "asflags": ["/c", "/coff"],
        "timeout": 60,
        "hook": "",
        "watcom": ["~/opt/watcom10.6"],  # watcom: globs searched for Watcom C 10.6
        "masm": ["~/opt/masm611"],  # watcom: globs searched for MASM 6.11's ML.EXE
        "hook_base": 0x200000,  # watcom: where patch_exe.py loads the compiled functions
    },
    "dll": {
        "ldflags": ["/DLL", "/NODEFAULTLIB", "/ENTRY:DllMain", "/BASE:0x30000000"],
        "libs": ["kernel32.lib", "user32.lib", "winmm.lib"],
    },
    "exe": {
        "obj_dir": "build/obj_exe",
        "cflags": [],
        "defines": [],
        "link_order": "median",
        "ldflags": ["/SUBSYSTEM:WINDOWS", "/FIXED"],
        "libs": ["libc.lib"],
        "features": {},
        "feature_sources": {},
    },
    "symbols": {
        "import_libs": [".wine/drive_c/msvc5/lib", ".wine/drive_c/dx5/lib"],
        "manifest": "",  # a TRX symbol manifest that manifest.py names functions and globals from
        "libs": [],  # le: Watcom libraries, in the Watcom directory, that seed_symbols.py fingerprints
    },
    "dosbox": {
        "search": ["~/opt/dosbox-staging*/dosbox"],  # le: globs searched for dosbox-staging
    },
    "hooks": {
        "progress": False,  # pre-commit redraws docs/progress.svg
        "compare": False,  # pre-commit fails unless every compiled function matches
        "one_function": False,  # one newly matching function per commit, named in the subject
        "pairs": False,  # with one_function, a commit may make two functions match: "Decompile A and B"
        "no_comments": False,  # pre-commit fails on comments, tabs or CRs in staged src/ files
    },
    "reference": {
        "source": "",  # a reference source tree, such as the developers' own, for probe.py and fn.py
        "prefer": [],  # its directories whose definitions fn.py shows first, as the closest to the target
        "skip": [],  # its directories that are stale copies, left out of lookups
        "layout": {},  # its top directories mapped to src/'s: {"GAME": "", "SPECIFIC": "specific"}
        "dsp": "",  # the Visual C++ project file in source that probe.py builds
        "dsp_config": "",  # the configuration probe.py builds, such as "TombRaid - Win32 Release"
        "defines": [],  # extra cl flags for the reference, such as ["/DCODER=0"]
        "probe": "build/probe.csv",  # where probe.py writes its results
    },
    "tools": {
        "remote": "git@github.com:LostArtefacts/decomp-tools.git",  # where `just tools-push` pushes
    },
}

def merge(defaults, values, where=""):
    """`values` over `defaults`, refusing keys `defaults` doesn't know."""
    out = copy.deepcopy(defaults)
    for key, value in values.items():
        name = where + key
        if key not in defaults:
            sys.exit(f"{PATH}: unknown setting {name}")
        if isinstance(value, dict) and isinstance(defaults.get(key), dict) and defaults[key]:
            out[key] = merge(defaults[key], value, name + ".")
        else:
            out[key] = value
    return out


def load(path=PATH):
    try:
        with open(path, "rb") as f:
            values = tomllib.load(f)
    except FileNotFoundError:
        sys.exit(f"{path} is missing: copy one from tools/examples/ and adapt it")
    config = merge(DEFAULTS, values)
    for section, settings in config.items():
        for name, value in settings.items():
            if value is REQUIRED:
                sys.exit(f"{path}: {section}.{name} is required")
    game, ghidra = config["game"], config["ghidra"]
    if game["format"] not in TOOLCHAINS:
        sys.exit(f"{path}: game.format is {game['format']!r}, not one of {', '.join(TOOLCHAINS)}")
    build = config["build"]
    build["toolchain"] = build["toolchain"] or TOOLCHAINS[game["format"]]
    if build["toolchain"] != TOOLCHAINS[game["format"]]:
        sys.exit(f"{path}: build.toolchain {build['toolchain']!r} does not build game.format "
                 f"{game['format']!r}, {TOOLCHAINS[game['format']]!r} does")
    if game["format"] == "le":
        for name in ("code", "hooked"):
            if not game[name]:
                sys.exit(f"{path}: game.{name} is required with game.format = \"le\"")
    game["title"] = game["title"] or game["name"]
    game["window_title"] = game["window_title"] or game["title"]
    stem = os.path.splitext(os.path.basename(game["original"]))[0]
    ghidra["project"] = ghidra["project"] or stem
    ghidra["functions"] = ghidra["functions"] or f"build/functions_{ghidra['project']}.csv"
    return config


config = load()
NAME = config["game"]["name"]
ORIGINAL = config["game"]["original"]  # the original exe, copied to an ASCII name
GAME_END = config["game"]["game_end"]  # the game's code ends here; libraries follow
DLL = f"build/{NAME}.dll"
FORMAT = config["game"]["format"]
# The standalone exe (le: build/<name>.exe is the original, so <name>_standalone.exe)
EXE = f"build/{NAME}_standalone.exe" if FORMAT == "le" else f"build/{NAME}.exe"
EXE_MAP = f"build/{NAME}_exe.map"  # the DLL's map is build/<name>.map
GAME = "build/game"  # a runnable copy of the game
TOOLCHAIN = config["build"]["toolchain"]
CODE = tuple(config["game"]["code"])  # le
ELF = f"build/{NAME}.elf"  # le: the flattened original
FUNCTIONS = "build/functions.csv"  # le: functions.py's function starts
HOOKED = os.path.join(GAME, config["game"]["hooked"])  # le
STANDALONE_LE = "STANDALN.EXE"  # le: the standalone exe's name in DOSBox


def get(key):
    value = config
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            sys.exit(f"no setting {key}")
        value = value[part]
    return value


def ghidra_home():
    """The Ghidra installation: GHIDRA, ghidra.path, or the newest match
    of ghidra.search."""
    path = os.environ.get("GHIDRA") or config["ghidra"]["path"]
    if path:
        return os.path.join(ROOT, os.path.expanduser(path))
    found = sorted((p for g in config["ghidra"]["search"] for p in glob.glob(os.path.expanduser(g))),
                   key=os.path.basename)
    if not found:
        sys.exit("no Ghidra: set GHIDRA or ghidra.path in project.toml")
    return found[-1]


def locate(var, patterns, holds=""):
    """What the environment variable `var` names, or else the first match
    of the globs `patterns`, the newest of each first, that holds the
    file `holds`."""
    ok = lambda p: os.path.exists(os.path.join(p, holds) if holds else p)
    if os.environ.get(var) and (not holds or ok(os.environ[var])):
        return os.environ[var]
    for pattern in patterns:
        for path in sorted(glob.glob(os.path.expanduser(pattern)), reverse=True):
            if ok(path):
                return path


def watcom():
    return locate("WATCOM", config["build"]["watcom"], os.path.join("BINNT", "WCC386.EXE")) or \
        sys.exit("error: set WATCOM or build.watcom to a Watcom C 10.6 directory")


def masm():
    return locate("MASM", config["build"]["masm"], "ML.EXE") or \
        sys.exit("error: set MASM or build.masm to a directory with MASM 6.11's ML.EXE")


def dosbox():
    return locate("DOSBOX", config["dosbox"]["search"]) or \
        sys.exit("error: set DOSBOX or dosbox.search to a dosbox-staging binary")


def orig():
    """Verifies the original's files against game.checksums and copies the
    executable to game.original."""
    sums = config["game"]["checksums"]
    if sums:
        subprocess.run(["sha1sum", "--quiet", "-c", os.path.basename(sums)],
                       cwd=os.path.join(ROOT, os.path.dirname(sums)), check=True)
    os.makedirs(os.path.dirname(ORIGINAL), exist_ok=True)
    shutil.copyfile(os.path.join(config["game"]["dir"], config["game"]["exe"]), ORIGINAL)
    if FORMAT == "le":
        import le
        objs, fixups = le.write_elf(le.LE(ORIGINAL), ELF)
        print(f"wrote {ELF}: {len(objs)} objects, {len(fixups)} fixups")


def game():
    """Copies the game's files into build/game, its exe replaced with one
    that loads the hook DLL."""
    if FORMAT == "le":
        return game_le()
    import patch_exe
    shutil.copytree(config["game"]["dir"], GAME, dirs_exist_ok=True, symlinks=True)
    os.remove(os.path.join(GAME, config["game"]["exe"]))
    patch_exe.patch(ORIGINAL, os.path.join(GAME, f"{NAME}.exe"))
    shutil.copyfile(DLL, os.path.join(GAME, os.path.basename(DLL)))


def game_le():
    """Copies game.copy and links game.link into build/game, and writes the
    original with the compiled functions hooked in to game.hooked."""
    import patch_le
    src = config["game"]["dir"]
    os.makedirs(os.path.dirname(HOOKED), exist_ok=True)
    for name in config["game"]["copy"]:
        os.makedirs(os.path.dirname(os.path.join(GAME, name)), exist_ok=True)
        shutil.copyfile(os.path.join(src, name), os.path.join(GAME, name))
    for pattern in config["game"]["link"]:
        for path in sorted(glob.glob(os.path.join(src, pattern))):
            link = os.path.join(GAME, os.path.relpath(path, src))
            if os.path.lexists(link):
                os.remove(link)
            os.symlink(os.path.abspath(path), link)
    patch_le.patch(HOOKED)


def standalone():
    """Copies the standalone exe into build/game as <name>_standalone.exe
    (le: as STANDALONE_LE next to game.hooked, a DOS 8.3 name), with
    game.standalone_extras."""
    if FORMAT == "le":
        dest = os.path.join(os.path.dirname(HOOKED), STANDALONE_LE)
    else:
        dest = os.path.join(GAME, f"{NAME}_standalone.exe")
    shutil.copyfile(EXE, dest)
    for pattern in config["game"]["standalone_extras"]:
        for path in sorted(glob.glob(pattern)):
            shutil.copy(path, GAME)


def clean():
    if FORMAT == "le":
        paths = ["build/obj", "build/link", GAME, "build/shots", EXE, *glob.glob(f"build/{NAME}.*")]
    else:
        paths = ["build/src", GAME, *glob.glob("build/obj*"), *glob.glob(f"build/{NAME}.*"),
                 *glob.glob(f"build/{NAME}_exe.*")]
    for path in paths:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.remove(path)


def main():
    os.chdir(ROOT)
    args = sys.argv[1:]
    if args[:1] == ["get"] and len(args) == 2:
        value = get(args[1])
        print(" ".join(map(str, value)) if isinstance(value, list) else value)
    elif args == ["ghidra"]:
        print(ghidra_home())
    elif len(args) == 1 and args[0] in ("orig", "game", "standalone", "clean"):
        globals()[args[0]]()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
