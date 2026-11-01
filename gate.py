"""The commit rules the git hooks check, as project.toml's [hooks] turns
them on.

    gate.py pre-commit       hooks.compare: every compiled function matches
    gate.py commit-msg FILE  hooks.one_function: the commit's subject names
                             the one function it decompiles

hooks.no_comments fails the commit when a staged file in src/ holds a
comment, a tab or a carriage return, so nothing is ported from a
reference's source as is. src/dll/, the DLL's own code, is exempt, and so
is a first line `// cflags: ...`, which build.py reads as the file's
compiler flags.

hooks.compare builds src/ and fails the commit unless every function it
defines matches the original byte for byte (`just compare`), and unless
every function HEAD's progress image shows as matching is still
compiled. src/ and config/ must have no unstaged changes, so what is
built is what is committed.

hooks.one_function allows at most one newly matching function per
commit, or two with hooks.pairs, for two functions that only match
together; such a commit's subject is `Decompile A and B`, in address
order. The functions that matched before are the ones HEAD's
docs/progress.svg shows as matching, so it needs hooks.progress. A
commit that adds one has the subject `Decompile NAME (0xADDRESS)`, with
the function's name and address from config/symbols.csv; any other
commit has a subject that doesn't start with `Decompile `. Amending a
commit with the same subject passes.

A group of functions that only match together lands one function per
commit with DECOMP_ALLOW_DIFF=NAME[,NAME...] in the environment: the
named functions may differ in that commit (the neighbour the group
breaks until it is complete), and when they match again they don't
count as newly matching.

hooks.allow_diff lists functions that are in src/ though they don't
match, such as ones that are logically equivalent but allocate registers
differently. They may differ in every commit. A commit that adds one to
the list decompiles it, as if it newly matched: its subject is
`Decompile NAME (0xADDRESS)`, and it is that commit's one function.
A function that matched at HEAD and joins the list in a commit that
decompiles another one is a neighbour the new function broke, and
doesn't count.

pre-commit leaves the newly matching functions in the git directory for
commit-msg, which runs after it. `git commit --no-verify` skips both.
"""
import csv, os, re, subprocess, sys, tempfile

import project

ROOT = project.ROOT
HOOKS = project.config["hooks"]
SVG = "docs/progress.svg"


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=check)


def marker():
    return os.path.join(git("rev-parse", "--absolute-git-dir").stdout.strip(), "decomp-new-functions")


def rows():
    with open(os.path.join(ROOT, "config/symbols.csv")) as f:
        return {s: (int(r["address"], 16), r["name"]) for r in csv.DictReader(f) for s in r["symbol"].split()}


def allow_diff_at_head():
    """hooks.allow_diff in HEAD's project.toml."""
    import tomllib
    shown = git("show", "HEAD:project.toml", check=False)
    if shown.returncode:
        return set()
    return set(tomllib.loads(shown.stdout).get("hooks", {}).get("allow_diff", []))


def matched_at_head():
    """The addresses HEAD's progress image shows as matching, or None
    without one."""
    import render_progress
    shown = git("show", f"HEAD:{SVG}", check=False)
    if shown.returncode:
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".svg") as f:
        f.write(shown.stdout)
        f.flush()
        return {a for a, same in render_progress.built_from_svg(f.name).items() if same}


def strip_strings(text):
    return re.sub(r'"(\\.|[^"\\\n])*"|\'(\\.|[^\'\\\n])*\'', '""', text)


def commented():
    """The staged src/ files with comments, tabs or CRs, and why."""
    staged = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "--", "src").stdout.split()
    bad = []
    for name in staged:
        if name.startswith("src/dll/") or not name.endswith((".c", ".cpp", ".h", ".hpp")):
            continue
        text = git("show", f":{name}").stdout
        code = re.sub(r"\A(//\s*cflags:[^\n]*|/\*\s*cflags:[^\n]*\*/)\n", "\n", text)
        why = [w for w, hit in (("comments", any(c in strip_strings(code) for c in ("/*", "//"))),
                                ("tabs", "\t" in text), ("CRs", "\r" in text)) if hit]
        if why:
            bad.append(f"  {name}: {', '.join(why)}")
    return bad


def pre_commit():
    path = marker()
    if os.path.exists(path):
        os.remove(path)
    if HOOKS.get("no_comments"):
        bad = commented()
        if bad:
            print("pre-commit: src/ takes no comments, tabs or CRs (hooks.no_comments):")
            print("\n".join(bad))
            return 1
    if not HOOKS["compare"] and not HOOKS["one_function"]:
        return 0
    if git("diff", "--quiet", "--", "src", "config", check=False).returncode:
        print("pre-commit: src/ or config/ has unstaged changes; stage them or stash them")
        return 1
    built = subprocess.run([sys.executable, os.path.join(ROOT, "tools/build.py")], cwd=ROOT,
                           capture_output=True, text=True)
    if built.returncode:
        print(built.stdout + built.stderr)
        print("pre-commit: the build failed")
        return 1
    import compare
    symbols, names = compare.read_symbols(), rows()
    matched, differ, compiled = set(), [], set()
    for name, same, *_ in compare.results(symbols):
        compiled.add(names[name][0])
        if same:
            matched.add(names[name][0])
        else:
            differ.append(name)
    listed = set(HOOKS["allow_diff"])
    allowed = set(os.environ.get("DECOMP_ALLOW_DIFF", "").replace(",", " ").split()) | listed
    excused = [name for name in differ if names[name][1] in allowed]
    differ = [name for name in differ if names[name][1] not in allowed]
    for name in excused:
        print(f"pre-commit: {names[name][1]} differs, allowed by hooks.allow_diff or DECOMP_ALLOW_DIFF")
    if HOOKS["compare"]:
        before = matched_at_head() or set()
        by_address = {a: n for a, n in names.values()}
        gone = sorted(a for a in before - compiled if by_address.get(a) not in allowed)
        if gone:
            print("pre-commit: these functions matched at HEAD but aren't compiled any more")
            print("(inlined everywhere now, or their definition went missing):")
            for address in gone:
                print(f"  {address:#010x} {by_address.get(address, '?')}")
            return 1
    if HOOKS["compare"] and differ:
        print("pre-commit: these functions don't match the original (just compare):")
        for name in differ:
            print(f"  {names[name][0]:#010x} {names[name][1]}")
        return 1
    if HOOKS["one_function"]:
        before = matched_at_head()
        if before is not None:
            by_address = {a: n for a, n in names.values()}
            new = sorted(a for a in matched - before if by_address[a] not in allowed)
            new += sorted({a for a, n in names.values()
                           if n in listed - allow_diff_at_head() and a not in before})
            with open(path, "w") as f:
                for address in new:
                    f.write(f"{address:#x} {by_address[address]}\n")
    return 0


def commit_msg(message_file):
    path = marker()
    if not HOOKS["one_function"] or not os.path.exists(path):
        return 0
    with open(path) as f:
        new = [line.split() for line in f.read().splitlines()]
    os.remove(path)
    with open(message_file, encoding="utf-8") as f:
        subject = next((l.strip() for l in f if l.strip() and not l.startswith("#")), "")
    if len(new) == 2 and HOOKS["pairs"]:
        want = f"Decompile {new[0][1]} and {new[1][1]}"
        if subject != want:
            print(f"commit-msg: the commit decompiles a pair; its subject must be: {want}")
            return 1
        return 0
    if len(new) > 1:
        print(f"commit-msg: {len(new)} functions newly match; commit one function at a time:")
        for address, name in new:
            print(f"  {address} {name}")
        return 1
    if new:
        address, name = new[0]
        want = f"Decompile {name} ({address})"
        if subject != want:
            print(f"commit-msg: the commit decompiles {name}; its subject must be: {want}")
            return 1
    elif subject.startswith("Decompile "):
        head = git("log", "-1", "--format=%s", check=False).stdout.strip()
        if subject != head:
            print("commit-msg: no function newly matches, but the subject starts with Decompile")
            return 1
    return 0


def main():
    args = sys.argv[1:]
    os.chdir(ROOT)
    if args == ["pre-commit"]:
        return pre_commit()
    if len(args) == 2 and args[0] == "commit-msg":
        return commit_msg(args[1])
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
