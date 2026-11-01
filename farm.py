"""Runs permute.py over many functions at once, unattended, and keeps
the matches it finds.

    farm.py [-p PARALLEL] [-j JOBS] [-t SECONDS] [-r ROUNDS] [NAME...]
    farm.py --apply [NAME...]

The functions default to project.toml's hooks.allow_diff, the ones in
src/ that don't match yet. Each round runs every function still
unmatched through a random search of -t seconds with a fresh seed,
starting from the best variant so far (build/permute/NAME.c), after
`permute.py NAME --decls` on that variant whenever it changed since the
last one, PARALLEL functions at a time with JOBS compiles each. Logs go to build/farm/NAME.log, and every lower score is
printed as it is found; a body that matches
is kept as build/farm/NAME.c. -r 0 runs rounds until every function
matches or the farm is stopped; a stopped farm keeps what it found.

src/ is never written while searching, so the farm can run on another
machine from a copy of the repository: copy build/farm/*.c back.

Searches run with permute.py --file, so they may also reorder the
file's top-level declarations; such a match is kept whole as
build/farm/NAME.file.

--apply writes each kept body over its function's definition in src/,
or the whole file when the match reordered its declarations, so apply
those one at a time.
Build and compare after it, since a body can flip other functions, then
commit each one, taking it off hooks.allow_diff in that commit.
"""
import argparse, glob, os, random, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

import project

ROOT = project.ROOT
os.chdir(ROOT)
OUT = "build/farm"
HERE = os.path.dirname(os.path.abspath(__file__))


def found(name):
    return os.path.join(OUT, f"{name}.c")


def search(name, args, seed):
    log = open(os.path.join(OUT, f"{name}.log"), "a")
    permute = [sys.executable, os.path.join(HERE, "permute.py"), name, "-j", str(args.j), "--file"]
    best = os.path.join("build/permute", f"{name}.c")
    marker = os.path.join(OUT, f"{name}.decls")
    body = open(best).read() if os.path.exists(best) else None
    steps = [["-t", str(args.t), "-s", str(seed), "--start", best]]
    if body is None or not os.path.exists(marker) or open(marker).read() != body:
        steps.insert(0, ["--decls", "--start", best])
    written = current = None
    for extra in steps:
        kind = "declaration orders" if extra[0] == "--decls" else "random search"
        log.write(f"== {' '.join(extra)}\n")
        log.flush()
        run = subprocess.Popen(permute + extra, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace")
        for line in run.stdout:
            log.write(line)
            log.flush()
            m = re.match(r".*, score (\d+) as written$", line)
            if m:
                written = int(m[1])
                current = current if current is not None else written
            m = re.match(r"starting from .*, score (\d+)$", line)
            if m:
                current = min(current, int(m[1])) if current is not None else int(m[1])
            m = re.match(r"\s+\d+ tries: score (\d+)$", line)
            if m and (current is None or int(m[1]) < current):
                print(f"{name}: {current} -> {m[1]} ({kind})", flush=True)
                current = int(m[1])
        done = subprocess.CompletedProcess(run.args, run.wait())
        if extra[0] == "--decls" and os.path.exists(best):
            open(marker, "w").write(open(best).read())
        if done.returncode == 0:
            body = open(best).read()
            open(found(name), "w", encoding="utf-8", newline="\n").write(body)
            whole = os.path.splitext(best)[0] + ".file"
            if os.path.exists(whole):
                shutil.copy(whole, os.path.join(OUT, f"{name}.file"))
            print(f"{name}: MATCH ({written} in src/)", flush=True)
            return True
    print(f"{name}: no match this round, best {current} ({written} in src/)", flush=True)
    return False


def apply(names):
    sys.path.insert(0, HERE)
    import permute
    for name in names:
        if not os.path.exists(found(name)):
            continue
        src, text, start, end = permute.find_function(name)
        body = open(found(name)).read()
        whole = os.path.join(OUT, f"{name}.file")
        if os.path.exists(whole):
            done = open(whole, encoding="utf-8").read()
            print(f"{name}: written to {src}, with its declarations reordered")
        else:
            done = text[:start] + body + text[end:]
            print(f"{name}: written to {src}")
        open(src, "w", encoding="utf-8", newline="").write(done)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*")
    ap.add_argument("-p", type=int, default=max(1, (os.cpu_count() or 2) // 4))
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("-t", type=float, default=1800)
    ap.add_argument("-r", type=int, default=1)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    names = args.names or list(project.config["hooks"]["allow_diff"])
    os.makedirs(OUT, exist_ok=True)
    if args.apply:
        apply(names)
        return 0
    subprocess.run([sys.executable, os.path.join(HERE, "build.py")], check=True, stdout=subprocess.DEVNULL)
    rounds = 0
    while True:
        todo = [n for n in names if not os.path.exists(found(n))]
        if not todo or (args.r and rounds >= args.r):
            break
        rounds += 1
        print(f"round {rounds}: {len(todo)} functions", flush=True)
        with ThreadPoolExecutor(args.p) as pool:
            list(pool.map(lambda n: search(n, args, random.randrange(1 << 30)), todo))
    kept = sorted(os.path.basename(p)[:-2] for p in glob.glob(os.path.join(OUT, "*.c")))
    print(f"{len(kept)} matches kept in {OUT}: {' '.join(kept)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
