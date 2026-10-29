#!/bin/sh
# Imports the original executable (copied to build/ by `just analyze`) into
# a headless Ghidra project, creates the functions config/symbols.csv
# lists that the analysis missed, and exports the function list. The paths come
# from project.toml; GHIDRA (or ghidra.path there) is the installation,
# see env.sh.
set -e
cd "$(dirname "$0")/../.."
project() { python3 tools/project.py "$@"; }
. tools/ghidra/env.sh
NAME=$(project get ghidra.project)
ORIGINAL=$(project get game.original)
FUNCTIONS=$(project get ghidra.functions)
mkdir -p build/ghidra
"$GHIDRA/support/analyzeHeadless" build/ghidra "$NAME" \
	-import "$ORIGINAL" -overwrite \
	-scriptPath tools/ghidra \
	-postScript CreateFunctions.java "$PWD/config/symbols.csv" \
	-postScript ExportFunctions.java "$PWD/$FUNCTIONS" \
	> build/ghidra/analyze.log 2>&1
grep REPORT build/ghidra/analyze.log
