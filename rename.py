"""Renames decompiled functions and globals, now or throughout history.

    rename.py OLD=NEW...                  rename in the working tree
    rename.py --history BASE OLD=NEW...   rewrite the commits after BASE

OLD and NEW are bare identifiers (ScriptMoveAngle, not Enemy::ScriptMoveAngle);
@FILE reads more pairs from FILE, one "OLD NEW" per line. A rename covers
every whole-word occurrence in the tracked text files: code (not its
string literals, which the exe holds), symbols.csv names and mangled
symbols, notes, the function names in docs/progress.svg. The image is not redrawn: a placeholder renamed
keeps the colour of an unnamed function until `just progress`.

Only functions src/*.c and src/*.cpp define and the names in
config/symbols.csv (globals, and the functions src/ does not define) are
renamed, in the tracked files outside tools/. A name src/ or config/
already uses is refused, unless OLD's symbol spells it: an import thunk
takes its import's name.
--history applies each rename from the commit that first defines the
function or lists the name, commit messages included, so the name
belongs to the commit that decompiled it; earlier commits keep the
placeholder. It runs git filter-branch over the branch, which needs a
clean working tree, and leaves the old history in refs/original/
(git update-ref -d refs/original/refs/heads/BRANCH drops it).
"""
import os, re, shutil, subprocess, sys, tempfile

import project

ROOT = project.ROOT
TOOLS = os.path.dirname(os.path.abspath(__file__))
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SVG = "docs/progress.svg"
CSV = "config/symbols.csv"


def parse_pairs(args):
    pairs = []
    for arg in args:
        if arg.startswith("@"):
            with open(arg[1:]) as f:
                pairs += [tuple(l.split()) for l in f if l.strip() and not l.startswith("#")]
        else:
            pairs.append(tuple(arg.split("=", 1)))
    for pair in pairs:
        if len(pair) != 2 or not all(IDENT.match(n) for n in pair):
            sys.exit(f"not an OLD=NEW pair of identifiers: {pair}")
    olds = [o for o, _ in pairs]
    news = [n for _, n in pairs]
    if len(set(olds)) != len(olds) or len(set(news)) != len(news):
        sys.exit("a name is renamed or used twice")
    return pairs


def word(name):
    """`name` as a whole word, or behind the underscore of a symbol (_Name)."""
    return re.compile(rb"(?<![A-Za-z0-9_])(_?)" + re.escape(name.encode()) + rb"\b")


def sub(old, new, data):
    """Renames `old` to `new` in `data`, keeping a symbol's underscore."""
    return word(old).sub(lambda m: m.group(1) + new.encode(), data)


# The comments and string literals of C and assembly. A string is data
# the exe holds ("Meshes" in a table of allocation names), so it keeps
# its text; a comment is renamed like code.
C_TOKENS = re.compile(rb'//[^\n]*|/\*.*?\*/|("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')', re.S)
ASM_TOKENS = re.compile(rb'[;#][^\n]*|("[^"\n]*"|\'[^\'\n]*\')')
TOKENS = {".c": C_TOKENS, ".cpp": C_TOKENS, ".h": C_TOKENS, ".hpp": C_TOKENS,
          ".s": ASM_TOKENS, ".asm": ASM_TOKENS, ".inc": ASM_TOKENS}


def sub_file(path, pairs, data):
    """Applies `pairs` to file `path`'s `data`, outside its string literals."""
    tokens = TOKENS.get(os.path.splitext(path)[1].lower())

    def rename(chunk):
        for old, new in pairs:
            chunk = sub(old, new, chunk)
        return chunk
    if not tokens:
        return rename(data)
    out, at = [], 0
    for m in tokens.finditer(data):
        out.append(rename(data[at:m.start()]))
        out.append(m.group() if m.group(1) else rename(m.group()))
        at = m.end()
    out.append(rename(data[at:]))
    return b"".join(out)


def definition(name):
    """A definition of function `name` at the start of a line."""
    return re.compile(rb"^[A-Za-z_].*\b" + re.escape(name.encode()) + rb"\(", re.M)


def paths(root):
    """The files under `root`: the tracked ones in a git work tree, else
    every one but .git, orig/, build/ and .wine/. tools/ is left out, as
    the tools are shared between projects."""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                         text=True, cwd=root).stdout.strip()
    if top and os.path.samefile(top, root):
        listed = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True,
                                cwd=root).stdout.decode().split("\0")
        yield from (p for p in listed if p and not p.startswith("tools/"))
        return
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel == ".":
            dirnames[:] = [d for d in dirnames if d not in (".git", "orig", "build", ".wine", "tools")]
        for name in filenames:
            yield os.path.relpath(os.path.join(dirpath, name), root)


def text_files(root):
    """The files under `root` that hold text."""
    for rel in paths(root):
        path = os.path.join(root, rel)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if b"\0" not in data:
            yield rel, data


def symbols(files):
    """The rows of symbols.csv, as (name, symbol) pairs."""
    rows = files.get(CSV, b"").decode().splitlines()[1:]
    return [(cols + [""])[2:4] for cols in (row.split(",") for row in rows) if len(cols) >= 3]


def defines(files, name):
    pattern = definition(name)
    return any(path.startswith("src/") and path.endswith((".c", ".cpp")) and pattern.search(data)
               for path, data in files.items())


def defined(files, name):
    """Whether `files` define function `name` or list it in symbols.csv.
    Under --history, a function the tip defines counts only from the
    commit that defines it, though symbols.csv lists it earlier."""
    if defines(files, name):
        return True
    return name not in FUNCTIONS and any(n == name for n, _ in symbols(files))


FUNCTIONS = set(os.environ.get("RENAME_FUNCTIONS", "").split())  # set by --history


def code_text(path, data):
    """`data` with its comments and string literals removed, for a file
    type `TOKENS` covers; empty for any other file."""
    tokens = TOKENS.get(os.path.splitext(path)[1].lower())
    if not tokens:
        return b""
    out, at = [], 0
    for m in tokens.finditer(data):
        out.append(data[at:m.start()])
        at = m.end()
    out.append(data[at:])
    return b"".join(out)


def in_use(files, old, new):
    """Whether the code (src/'s C/C++/asm, outside comments and string
    literals, or symbols.csv's name/symbol columns) uses `new` for
    something else: not the name `old`'s symbol spells (DirectSoundCreate
    for a thunk's _DirectSoundCreate@12)."""
    spelled = re.compile(r"_?" + re.escape(new) + r"(@\d+)?\Z")
    if any(n == old and spelled.match(symbol) for n, symbol in symbols(files)):
        return False
    if any(word(new).search(code_text(p, d)) for p, d in files.items() if p.startswith("src/")):
        return True
    return any(word(new).search(n.encode()) or word(new).search(symbol.encode())
              for n, symbol in symbols(files))


def rename_tree(root, pairs, strict=False):
    """Applies the renames of the functions and globals `root` defines.
    Returns the pairs applied."""
    files = dict(text_files(root))
    active = [(o, n) for o, n in pairs if defined(files, o)]
    if strict:
        for old, new in pairs:
            if (old, new) not in active:
                sys.exit(f"{old} is not defined in src/ or {CSV}")
            if in_use(files, old, new):
                sys.exit(f"{new} is already in use")
    for path, data in files.items():
        new_data = sub_file(path, active, data)
        if new_data != data:
            with open(os.path.join(root, path), "wb") as f:
                f.write(new_data)
    return active


def rename_message(pairs):
    """Renames in the commit message on stdin what the commit defines."""
    commit = os.environ["GIT_COMMIT"]
    message = sys.stdin.buffer.read()
    for old, new in pairs:
        if word(old).search(message):
            found = subprocess.run(["git", "grep", "-q", "-E", definition(old).pattern.decode(),
                                    commit, "--", "src/*.c", "src/*.cpp"])
            listed = subprocess.run(["git", "grep", "-q", "-E", rf"^[^,]*,[^,]*,{old}(,|$)",
                                     commit, "--", CSV])
            if found.returncode == 0 or (old not in FUNCTIONS and listed.returncode == 0):
                message = sub(old, new, message)
    sys.stdout.buffer.write(message)


def rename_history(base, args):
    pairs = parse_pairs(args)
    if subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                      capture_output=True, text=True, cwd=ROOT).stdout:
        sys.exit("the working tree has changes")
    # Check the renames against the tip first.
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(f"git archive HEAD | tar -x -C {tmp}", shell=True, check=True, cwd=ROOT)
        files = dict(text_files(tmp))
        functions = [o for o, _ in pairs if defines(files, o)]
        rename_tree(tmp, pairs, strict=True)
    # Commits are rewritten with this copy of the tools, not their own.
    tools = tempfile.mkdtemp()
    for name in os.listdir(TOOLS):
        if name.endswith(".py"):
            shutil.copy(os.path.join(TOOLS, name), tools)
    # And with this project.toml, which older commits may not have.
    shutil.copy(project.PATH, os.path.join(tools, "project.toml"))
    with open(os.path.join(tools, "pairs.txt"), "w") as f:
        f.writelines(f"{o} {n}\n" for o, n in pairs)
    me = f"{sys.executable} {os.path.join(tools, 'rename.py')}"
    pairs_arg = "@" + os.path.join(tools, "pairs.txt")
    env = dict(os.environ, FILTER_BRANCH_SQUELCH_WARNING="1",
               DECOMP_PROJECT=os.path.join(tools, "project.toml"),
               RENAME_FUNCTIONS=" ".join(functions))
    result = subprocess.run(["git", "filter-branch", "-f",
                             "--tree-filter", f"{me} --tree {pairs_arg}",
                             "--msg-filter", f"{me} --message {pairs_arg}",
                             f"{base}..HEAD"], cwd=ROOT, env=env)
    shutil.rmtree(tools)
    return result.returncode


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    if args[0] == "--history":
        return rename_history(args[1], args[2:])
    if args[0] == "--tree":
        rename_tree(os.getcwd(), parse_pairs(args[1:]))
        return 0
    if args[0] == "--message":
        rename_message(parse_pairs(args[1:]))
        return 0
    for old, new in rename_tree(ROOT, parse_pairs(args), strict=True):
        print(f"{old} -> {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
