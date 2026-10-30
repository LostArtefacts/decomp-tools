#!/bin/sh
# Decompiles functions from the Ghidra project made by analyze.sh into
# build/decomp/<address>.c. With no arguments, every function.
# GHIDRA (or ghidra.path in project.toml) is the installation. With
# game.format = "le", the program is the flattened build/<game.name>.elf.
set -e
cd "$(dirname "$0")/../.."
project() { python3 tools/project.py "$@"; }
. tools/ghidra/env.sh
NAME=$(project get ghidra.project)
PROGRAM=$(basename "$(project get game.original)")
if [ "$(project get game.format)" = le ]; then
	PROGRAM=$(project get game.name).elf
	set -- -nothunks "$@"
fi
"$GHIDRA/support/analyzeHeadless" build/ghidra "$NAME" \
	-process "$PROGRAM" -noanalysis -readOnly \
	-scriptPath tools/ghidra \
	-postScript Decompile.java "$PWD/build/decomp" "$@" \
	> build/ghidra/decompile.log 2>&1
grep REPORT build/ghidra/decompile.log
