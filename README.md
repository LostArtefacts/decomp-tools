# decomp-tools

Tooling for matching decompilations of the Windows Tomb Raider games,
Tomb Raider II to Chronicles, built with MSVC 5 and 6 under Wine, on
Linux. The goal of such a project is C source that compiles, with the
original toolchain, into code byte-for-byte identical to the original
executable.

The tools compile the game's source under Wine and compare every
function with the original byte for byte. They hook the new code into
the running game through a DLL, link a standalone executable and compare
it with the original section by section. They also drive the game
headless under Xvfb, analyze the original with headless Ghidra and name
its functions from TRX's symbol manifests.

They started as a fork of [Cirno Labs' decomp-tools](https://github.com/Cirno-Labs/decomp-tools),
the Touhou games' MSVC 7 tooling. The differences: C sources as well
as C++, a configurable source encoding instead of Shift-JIS, MSVC 5/DX5
defaults, an optional Rich header, MSVC 5 and 6's float constant names,
and `manifest.py`.

This repository holds tools only. It contains no game code or data, no
decompiled source and nothing from Microsoft's toolchain or SDKs. Each
game repository brings its own source and symbols, and each user brings
their own copy of the game and the compiler.

## The games

The Steam releases, as read from their PE and Rich headers
(`peinfo.py`):

| Game | Executable | Linked | Linker | Compiler |
| --- | --- | --- | --- | --- |
| TR2 | `Tomb2.exe` | 1997-12-10 | 5.02, no Rich header | MSVC 5.0 (`TOMBRAID.DSP` is a 5.00 project) |
| TR3 | `tomb3.exe` | 1998-12-02 | 5.10 | MSVC 5.0 SP3: 492 unmarked objects, cvtres 5.00.1668 |
| TR4 | `tomb4.exe` | 1999-12-17 | 6.00.8447 | MSVC 6.0: C 12.00.8168 and 8447, MASM 6.13 |
| TR5 | `PCTomb5.exe` | 2000-11-13 | 6.00.8447 | MSVC 6.0: C 12.00.8168 and 8447, MASM 6.13 |

TRX's `docs/symbols/` has a manifest of named functions and globals
for each of them.

## Using it in a game repository

A game repository includes this repository as a git submodule at
`tools/`, describes itself in `project.toml` at its root, and
imports the shared recipes into its justfile:

```just
import 'tools/common.just'

# the game's own recipes follow
```

It expects this layout around it:

```
project.toml  the game's settings (see below)
justfile      imports tools/common.just
config/       symbols.csv: address, size, name and decorated symbol
src/          decompiled source (.c or .cpp); src/dll/ is the hook DLL's
              own code, src/exe/ the data and globals only the
              standalone exe builds
orig/         the user's game files (not tracked) and their checksums
.wine/        the Wine prefix with the toolchain (not tracked)
build/        outputs
tools/        this repository
```

`examples/tr2.toml` is tr02's configuration. To add the tools to a game
repository:

```sh
git submodule add https://github.com/LostArtefacts/decomp-tools.git tools
cp tools/examples/tr2.toml project.toml   # then adapt it
echo "import 'tools/common.just'" > justfile
just tools-init hooks
```

## Recipes

`just` lists them. `common.just` has:

| Recipe | Does |
| --- | --- |
| `build` | compile `src/` and link the hook DLL, `build/<name>.dll` |
| `compare [SYMBOL...]` | compare every compiled function with the original; disassembly diffs for SYMBOLs |
| `game` | set up `build/game/`: the game's files, an exe patched to load the DLL, the DLL |
| `run [STEP...]` | run the patched game headless (`wait:S key:K hold:K:S shot:NAME`) |
| `exe [STEP...]` | link the standalone `build/<name>.exe`; `FEAT=a,b` turns on features |
| `compare-exe [-v]` | compare the standalone exe with the original, section by section |
| `dxsdk INSTALLER` | install a DirectX SDK's headers and libraries into the prefix (`C:\dx5`) |
| `analyze` | analyze the original with headless Ghidra, create the functions `config/symbols.csv` lists that it missed, seed `config/symbols.csv` |
| `manifest [-n] [FILE]` | name `config/symbols.csv`'s rows from a TRX manifest |
| `decompile [ADDR...]` | write Ghidra's pseudocode to `build/decomp/` |
| `probe [-j N]` | compile the reference source tree and score each of its functions against the original |
| `fn NAME [-d\|-g\|-a]`, `fn --next [N]` | one function: target file, the reference's definition and what `src/` lacks; its diff; Ghidra's version; what to do next |
| `permute NAME [-j N] [-t S]` | search source variants of a function for a byte match |
| `progress` | render `docs/progress.svg` |
| `hooks` | use `tools/hooks/`: 50/72 commit messages without type prefixes or trailers, and the game's commit rules (see `[hooks]`) |
| `clean` | remove build outputs (keeps the Ghidra project) |

Compiles run on half the cores; `JOBS` overrides it. Ghidra is found
through `GHIDRA`, `ghidra.path` or the newest `~/opt/ghidra_*` or
`~/data.local/work/ghidra_*`. Without a `java` on `PATH`, a `jdk-21*`
next to it is used.

### The submodule

| Recipe | Runs |
| --- | --- |
| `tools-init` | `git submodule update --init tools`, then puts `tools/` on a `main` branch at the recorded commit |
| `tools-pull` | `git pull --ff-only` on `tools/`' `main` |
| `tools-push` | `git push` of `tools/`' `main` to `tools.remote`, `git@github.com:LostArtefacts/decomp-tools.git` |

`tools/` is a checkout of this repository, so a change to the tools is
a commit made inside `tools/` (`git -C tools commit`), pushed with
`just tools-push`. The game repository then records the new commit
with a commit of its own (`git add tools`). In the other games, run
`just tools-pull` and commit the pointer the same way.

A fresh clone of a game needs `git clone --recursive`, or
`git submodule update --init tools` after it: the justfile imports
from `tools/`, so `just` can't run before. Either leaves `tools/` on a
detached HEAD, where a commit belongs to no branch; `just tools-init`
puts it on `main` at the same commit.

## Tools

| File | Does |
| --- | --- |
| `project.py` | reads `project.toml`; the `orig`, `game`, `standalone` and `clean` steps |
| `build.py` | compiles `src/` (re-encoded, per-file flags, parallel), writes the hook table and thunks, links the DLL and the standalone exe |
| `compare.py` | compares compiled functions with the original, relocations resolved through `symbols.csv` |
| `compare_exe.py` | compares the standalone exe with the original: headers, Rich header, sections, imports, code and data by symbol |
| `order.py` | lists, per object, which of the standalone exe's functions sit at their original address and in the original's order (`--summary`: one line per object) |
| `reorder.py` | sorts a source file's function definitions into the original's address order |
| `patch_exe.py` | adds the hook DLL to a copy of the original's import table |
| `play.py` | runs the game under Xvfb, sends keys, takes screenshots |
| `seed_symbols.py` | adds Ghidra's functions and the imports to `symbols.csv` |
| `manifest.py` | names `symbols.csv`'s rows from a TRX manifest, with MSVC's C decorations |
| `dxsdk.py` | unpacks a DirectX SDK download into the prefix |
| `name.py` | names a row of `symbols.csv` |
| `rename.py` | renames functions in the working tree or throughout history |
| `render_progress.py` | draws the progress image |
| `coff.py`, `rsrc.py`, `peinfo.py` | COFF objects, resources, PE and Rich header |
| `ghidra/` | headless Ghidra: analysis, function export, decompilation |
| `probe.py` | compiles `reference.source` as its project file builds it and scores each function against the original |
| `fn.py` | everything about one function in one call, and the order to do them in |
| `permute.py` | searches rewrites of one function (declaration order, operand order, statement order, if/else) for a byte match, compiling each variant alone |
| `gate.py` | the commit rules `[hooks]` turns on, for the hooks |
| `hooks/` | `commit-msg` and `pre-commit` |

## project.toml

Paths are relative to the game repository's root. Hex numbers are
written as such (`0x459FF0`). `DECOMP_PROJECT` names another file.

### `[game]`

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | required | short name: `build/<name>.dll`, `build/<name>.exe`, `<name>.exe` in `build/game/`, the hook log's prefix |
| `dir` | required | the original game's files, such as `orig/tomb2` |
| `exe` | required | the original executable's file name in `dir` |
| `original` | required | where the verified executable is copied, an ASCII path such as `build/tomb2.exe` |
| `game_end` | required | the address the game's code ends at; library code follows |
| `checksums` | none | a `sha1sum -c` file, run from its own directory |
| `title` | `name` | the progress image's title |
| `window_title` | `title` | the window `play.py` looks for |
| `locale` | none | `play.py`'s `LANG` and `LC_ALL`; none keeps the user's |
| `screen` | `640x480x24` | `play.py`'s Xvfb screen |
| `standalone_extras` | `[]` | globs copied into `build/game/` with the standalone exe |

### `[ghidra]`

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | none | the Ghidra installation; `GHIDRA` overrides it |
| `project` | `original`'s name without `.exe` | the Ghidra project in `build/ghidra/` |
| `functions` | `build/functions_<project>.csv` | the exported function list |

### `[build]`

| Key | Default | Meaning |
| --- | --- | --- |
| `cflags` | required | the compiler flags; a source file's first line `// cflags: /Os -/Oi` or `/* cflags: ... */` adds and removes some |
| `encoding` | `cp1252` | the code page `src/`'s UTF-8 is converted to before `cl` reads it; with `cp932` a second byte of `\` is doubled |
| `crlf` | `false` | convert `src/`'s LF line endings to CRLF before `cl` reads it: VC++ 5 can allocate registers differently for the same code by line endings; switching it rebuilds everything |
| `bin` | `C:\msvc5\bin` | where `cl.exe` and `link.exe` are, in the Wine prefix |
| `include` | `C:\dx5\include`, `C:\msvc5\include` | `INCLUDE` |
| `lib` | `C:\dx5\lib`, `C:\msvc5\lib` | `LIB`, in search order |
| `ml` | `C:\masm611\bin\ML.EXE` | the assembler for `src/`'s `.s` and `.asm` files |
| `asflags` | `/c /coff` | its flags |
| `timeout` | `60` | seconds before a compile counts as hung |
| `hook` | none | a Python file with the game's own build steps, see below |

### `[dll]`

| Key | Default | Meaning |
| --- | --- | --- |
| `ldflags` | `/DLL /NODEFAULTLIB /ENTRY:DllMain /BASE:0x30000000` | the hook DLL's linker flags |
| `libs` | `kernel32.lib user32.lib winmm.lib` | its libraries |

### `[exe]`

| Key | Default | Meaning |
| --- | --- | --- |
| `obj_dir` | `build/obj_exe` | the standalone exe's objects; `build/obj` shares the DLL's |
| `cflags` | `[]` | flags added to `build.cflags`, before a file's own |
| `defines` | `[]` | macros defined after a file's own flags (`TR2_EXE=1`) |
| `link_order` | `median` | object order: by the `median` or `first` original address of the functions only that object defines, or `source` order |
| `ldflags` | `/SUBSYSTEM:WINDOWS /FIXED` | linker flags |
| `libs` | `libc.lib` | libraries, in the original's order |
| `features` | `{}` | `FEAT` names and their macros: `frame_cap = "FEAT_FRAME_CAP"` compiles `FEAT=frame_cap` into `build/obj_frame_cap` with `/DFEAT_FRAME_CAP=1` |
| `feature_sources` | `{}` | sources only the exe with a feature builds and links |

The exe's map is `build/<name>_exe.map`, the DLL's `build/<name>.map`.

### `[reference]`

A reference source tree, such as the developers' own, which `probe.py`
compiles and `fn.py` reads.

| Key | Default | Meaning |
| --- | --- | --- |
| `source` | none | the tree, relative to the repository |
| `prefer` | `[]` | its directories whose definitions `fn.py` shows first, as the closest to the target |
| `skip` | `[]` | its directories of stale copies, left out of lookups |
| `layout` | `{}` | its top directories mapped to `src/`'s, such as `{GAME = "", SPECIFIC = "specific"}` |
| `dsp` | none | the Visual C++ project file `probe.py` builds |
| `dsp_config` | none | the configuration it builds, such as `TombRaid - Win32 Release` |
| `defines` | `[]` | extra `cl` flags for the reference |
| `probe` | `build/probe.csv` | where `probe.py` writes its scores, which `fn.py` reads |

### `[symbols]`, `[hooks]`, `[tools]`

| Key | Default | Meaning |
| --- | --- | --- |
| `symbols.import_libs` | `.wine/drive_c/msvc5/lib`, `.wine/drive_c/dx5/lib` | where `seed_symbols.py` looks up decorated import names |
| `symbols.manifest` | none | the TRX manifest `manifest.py` reads by default |
| `hooks.progress` | `false` | the pre-commit hook redraws `docs/progress.svg` and adds it |
| `hooks.compare` | `false` | the pre-commit hook fails unless every compiled function matches the original byte for byte |
| `hooks.one_function` | `false` | a commit makes at most one more function match, and then its subject is `Decompile NAME (0xADDRESS)`; needs `hooks.progress` |
| `hooks.no_comments` | `false` | the pre-commit hook fails when a staged file in `src/` (outside `src/dll/`) holds a comment, a tab or a carriage return |
| `tools.remote` | `git@github.com:LostArtefacts/decomp-tools.git` | where `tools-push` pushes, over SSH |

### The commit rules

With `hooks.no_comments`, the pre-commit hook first reads each staged
C or C++ file in `src/` and refuses the commit when it holds a comment,
a tab or a carriage return, outside string literals. Code is written
out function by function, never copied from a reference's source with
its comments and formatting. `src/dll/` is exempt.

With `hooks.compare` or `hooks.one_function`, the pre-commit hook builds
`src/` and runs the comparison (`gate.py`). `src/` and `config/` then
may have no unstaged changes, so that what is built is what is
committed. The functions that matched before are the ones HEAD's
`docs/progress.svg` shows as matching. A commit that makes none match
must not start with `Decompile `, except an amend that keeps the
subject. `git commit --no-verify` skips the hooks.

### The build hook

`build.hook` is for what the settings don't cover. The file may define:

- `exe_flags(feats)`: extra compiler flags for the standalone exe's
  objects, given the features asked for; it may also generate the files
  they need
- `headers()`: more headers whose changes rebuild everything
- `exe_resources(feats)`: the executable whose resources the standalone
  exe gets, instead of the original's

## Requirements

- Python 3.11 or later (for `tomllib`), [just](https://github.com/casey/just)
  recent enough for the `[default]` attribute
- Wine (32-bit), binutils (`objdump`), 7-Zip
- For `run`: Xvfb, xdotool, ImageMagick and 32-bit Mesa OpenGL
- The original toolchain in the Wine prefix (bring your own copies)
- Ghidra, for analysis

## License

GNU General Public License, version 3 only (`GPL-3.0-only`), see
[`LICENSE`](LICENSE).
