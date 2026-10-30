# The recipes every game shares. A game's justfile imports this file
# (`import 'tools/common.just'`) and adds its own. project.toml in the
# game's root says what differs between the games.

export WINEPREFIX := justfile_directory() / ".wine"
export WINEDEBUG := env("WINEDEBUG", "-all")

# [default] makes it the default although it is imported: just only takes
# the first recipe of the root justfile otherwise.

# List recipes
[default]
default:
    @just --list

# Compile src/ and link the hook DLL, build/<name>.dll
build:
    python3 tools/build.py

# Compare compiled functions with the original; show a diff for each SYMBOL
[positional-arguments]
compare *symbols: build _orig
    python3 tools/compare.py "$@"

# Set up build/game: game data, patched exe and the hook DLL
game: build _orig
    python3 tools/project.py game

# Run the patched game headless with STEPS (wait:S key:K hold:K:S shot:NAME)
[positional-arguments]
run *steps: game
    python3 tools/play.py "$@"

# Link the standalone build/<name>.exe (no DLL; FEAT=a,b adds features); with STEPS, run it like `run`
[positional-arguments]
exe *steps: game
    python3 tools/build.py exe
    python3 tools/project.py standalone
    if [ $# -gt 0 ]; then python3 tools/play.py --standalone "$@"; fi

# Compare the standalone exe with the original, section by section (-v: more)
[positional-arguments]
compare-exe *args: _orig
    python3 tools/compare_exe.py "$@"

# Install a DirectX SDK's headers and libraries from its INSTALLER into the prefix (C:\dx5)
dxsdk installer:
    python3 tools/dxsdk.py {{ quote(installer) }}

# Analyze the original with headless Ghidra; add new functions to symbols.csv
analyze: _orig
    tools/ghidra/analyze.sh
    python3 tools/seed_symbols.py

# Name symbols.csv's functions and globals from the TRX manifest (symbols.manifest)
manifest *args: _orig
    python3 tools/manifest.py {{ args }}

# Decompile ADDRs (default: every function) with Ghidra into build/decomp/
decompile *addrs:
    tools/ghidra/decompile.sh {{ addrs }}

# Compile the reference source tree (reference.*) and score its functions against the original
probe *args: _orig
    python3 tools/probe.py {{ args }}

# One function: where it goes, the reference's definition, -d its diff, -g Ghidra's; --next N what to do next
fn *args: _orig
    python3 tools/fn.py {{ args }}

# Search source variants of NAME for a byte match (-j JOBS -t SECONDS)
permute name *args: _orig
    python3 tools/permute.py {{ name }} {{ args }}

# Render docs/progress.svg from symbols.csv and the build
progress: build _orig
    python3 tools/render_progress.py

# Use tools/hooks/ here and in tools/: 50/72 messages, no trailers; commits redraw progress.svg if hooks.progress
hooks:
    git config core.hooksPath tools/hooks
    git -C tools config core.hooksPath hooks

# Remove build outputs (keeps the Ghidra project)
clean:
    python3 tools/project.py clean

# Verify the original and copy it to build/ under an ASCII name
_orig:
    python3 tools/project.py orig

# After a clone or a pointer change, tools/ is on a detached HEAD.

# Check out tools/ at the commit the game records, on a main branch
tools-init:
    git submodule update --init tools
    git -C tools switch -q -C main "$(git rev-parse :tools)"

# Bring tools/ up to decomp-tools' main; commit the new pointer afterwards
tools-pull:
    git -C tools switch -q main
    git -C tools pull -q --ff-only
    git -C tools log -1 --oneline

# Push the commits made in tools/ to decomp-tools' main (tools.remote)
tools-push:
    git -C tools push "$(python3 tools/project.py get tools.remote)" main
