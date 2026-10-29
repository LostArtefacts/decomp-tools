# Sourced by the Ghidra scripts from the game repository's root: GHIDRA
# is the installation project.py finds, JAVA_HOME (without a java on
# PATH) a jdk-21* next to it.
GHIDRA=$(python3 tools/project.py ghidra)
if [ -z "$JAVA_HOME" ] && ! command -v java >/dev/null; then
	JAVA_HOME=$(ls -d "$(dirname "$GHIDRA")"/jdk-21* 2>/dev/null | tail -1)
	[ -n "$JAVA_HOME" ] && export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
fi
