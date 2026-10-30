"""Reads the game's project.toml, the one place for what differs between
the games: names, paths, the code's end, compiler and linker flags,
libraries.

    project.py get KEY        print a setting (game.name, ghidra.project...)
    project.py ghidra         print the Ghidra installation's directory
    project.py orig           verify the original's checksums, copy it to build/
    project.py game           set up build/game: game data, patched exe and DLL
    project.py standalone     copy the standalone exe (and extras) into build/game
    project.py clean          remove build outputs (keeps the Ghidra project)

The file is project.toml in the game repository's root (the directory
above tools/), or the one the DECOMP_PROJECT environment variable names.
Other tools import this module and read `config`, or the shorthands
below. Paths in the file are relative to the repository's root.
"""
import copy, glob, os, shutil, subprocess, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.dirname(os.path.abspath(__file__))
PATH = os.environ.get("DECOMP_PROJECT") or os.path.join(ROOT, "project.toml")

REQUIRED = object()  # a setting without a default

# Every setting, with its default.
DEFAULTS = {
    "game": {
        "name": REQUIRED,  # short name: build/<name>.dll, build/<name>.exe
        "dir": REQUIRED,  # the original game's files
        "exe": REQUIRED,  # the original executable's name in dir
        "original": REQUIRED,  # where its verified copy goes, an ASCII path
        "game_end": REQUIRED,  # the game's code ends here; libraries follow
        "title": "",  # the progress chart's title; defaults to the name
        "window_title": "",  # play.py looks for a window with this title
        "locale": "",  # play.py's LANG and LC_ALL, such as ja_JP.UTF-8; empty keeps the user's
        "screen": "640x480x24",  # play.py's Xvfb screen
        "checksums": "",  # a `sha1sum -c` file, run from its own directory
        "standalone_extras": [],  # globs copied into build/game with the standalone exe
    },
    "ghidra": {
        "path": "",  # the Ghidra installation; GHIDRA overrides it
        "search": ["~/opt/ghidra_*"],  # globs searched for the newest installation without either
        "project": "",  # defaults to the original's file name without .exe
        "functions": "",  # defaults to build/functions_<project>.csv
    },
    "build": {
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
    },
    "hooks": {
        "progress": False,  # pre-commit redraws docs/progress.svg
        "compare": False,  # pre-commit fails unless every compiled function matches
        "one_function": False,  # one newly matching function per commit, named in the subject
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
EXE = f"build/{NAME}.exe"
EXE_MAP = f"build/{NAME}_exe.map"  # the DLL's map is build/<name>.map
GAME = "build/game"  # a runnable copy of the game


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


def orig():
    """Verifies the original's files against game.checksums and copies the
    executable to game.original."""
    sums = config["game"]["checksums"]
    if sums:
        subprocess.run(["sha1sum", "--quiet", "-c", os.path.basename(sums)],
                       cwd=os.path.join(ROOT, os.path.dirname(sums)), check=True)
    os.makedirs(os.path.dirname(ORIGINAL), exist_ok=True)
    shutil.copyfile(os.path.join(config["game"]["dir"], config["game"]["exe"]), ORIGINAL)


def game():
    """Copies the game's files into build/game, its exe replaced with one
    that loads the hook DLL."""
    import patch_exe
    shutil.copytree(config["game"]["dir"], GAME, dirs_exist_ok=True, symlinks=True)
    os.remove(os.path.join(GAME, config["game"]["exe"]))
    patch_exe.patch(ORIGINAL, os.path.join(GAME, f"{NAME}.exe"))
    shutil.copyfile(DLL, os.path.join(GAME, os.path.basename(DLL)))


def standalone():
    """Copies the standalone exe into build/game as <name>_standalone.exe,
    with game.standalone_extras."""
    shutil.copyfile(EXE, os.path.join(GAME, f"{NAME}_standalone.exe"))
    for pattern in config["game"]["standalone_extras"]:
        for path in sorted(glob.glob(pattern)):
            shutil.copy(path, GAME)


def clean():
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
