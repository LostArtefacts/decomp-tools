#!/bin/sh
# Imports the original executable (copied to build/ by `just analyze`) into
# a headless Ghidra project, creates the functions config/symbols.csv
# lists that the analysis missed, and exports the function list. The paths come
# from project.toml; GHIDRA (or ghidra.path there) is the installation,
# see env.sh.
#
# With game.format = "le", it imports the flattened executable instead
# (build/<game.name>.elf, from `just analyze`), with the functions
# functions.py finds, written to build/functions.csv, and Watcom's
# register calling convention.
set -e
cd "$(dirname "$0")/../.."
project() { python3 tools/project.py "$@"; }
. tools/ghidra/env.sh
NAME=$(project get ghidra.project)
ORIGINAL=$(project get game.original)
FUNCTIONS=$(project get ghidra.functions)
mkdir -p build/ghidra
if [ "$(project get game.format)" = le ]; then
	python3 tools/functions.py > build/functions.csv
	"$GHIDRA/support/analyzeHeadless" build/ghidra "$NAME" \
		-import "build/$(project get game.name).elf" -overwrite \
		-processor x86:LE:32:default -cspec gcc \
		-scriptPath tools/ghidra \
		-preScript Watcom.java \
		-postScript Watcom.java "$PWD/build/functions.csv" \
		-postScript ExportFunctions.java "$PWD/$FUNCTIONS" -nothunks \
		> build/ghidra/analyze.log 2>&1
else
	"$GHIDRA/support/analyzeHeadless" build/ghidra "$NAME" \
		-import "$ORIGINAL" -overwrite \
		-scriptPath tools/ghidra \
		-postScript CreateFunctions.java "$PWD/config/symbols.csv" \
		-postScript ExportFunctions.java "$PWD/$FUNCTIONS" \
		> build/ghidra/analyze.log 2>&1
fi
grep REPORT build/ghidra/analyze.log
