"""The commit rules the git hooks check, as project.toml's [hooks] turns
them on.

    gate.py pre-commit       hooks.compare: every compiled function matches
    gate.py commit-msg FILE  hooks.one_function: the commit's subject names
                             the one function it decompiles

hooks.compare builds src/ and fails the commit unless every function it
defines matches the original byte for byte (`just compare`). src/ and
config/ must have no unstaged changes, so what is built is what is
committed.

hooks.one_function allows at most one newly matching function per
commit. The functions that matched before are the ones HEAD's
docs/progress.svg shows as matching, so it needs hooks.progress. A
commit that adds one has the subject `Decompile NAME (0xADDRESS)`, with
the function's name and address from config/symbols.csv; any other
commit has a subject that doesn't start with `Decompile `. Amending a
commit with the same subject passes.

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


def pre_commit():
    path = marker()
    if os.path.exists(path):
        os.remove(path)
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
    matched, differ = set(), []
    for name, same, *_ in compare.results(symbols):
        if same:
            matched.add(names[name][0])
        else:
            differ.append(name)
    if HOOKS["compare"] and differ:
        print("pre-commit: these functions don't match the original (just compare):")
        for name in differ:
            print(f"  {names[name][0]:#010x} {names[name][1]}")
        return 1
    if HOOKS["one_function"]:
        before = matched_at_head()
        if before is not None:
            by_address = {a: n for a, n in names.values()}
            new = sorted(matched - before)
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
