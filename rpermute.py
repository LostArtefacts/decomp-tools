"""Runs permute.py on another machine, such as a faster Windows box that
compiles without wine, and brings its result back.

    rpermute.py NAME [permute.py's options]

project.toml's [remote] names the machine: `host` is an ssh host with
its own copy of the project (the toolchain under .wine/drive_c and the
original exe), `root` is that copy's directory and `python` its Python.
Each run sends src/, config/, project.toml and tools/ there, along with
build/permute/NAME.c and NAME.file when they exist so --start can use
them, runs `permute.py NAME ...` in the copy, and copies NAME.c and
NAME.file back to build/permute/. The output and the exit code are
permute.py's.
"""
import os, subprocess, sys

import project

ROOT = project.ROOT
os.chdir(ROOT)
REMOTE = project.config["remote"]
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR"]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if not REMOTE["host"] or not REMOTE["root"]:
        sys.exit("project.toml has no [remote] host and root")
    name, host, root = sys.argv[1], REMOTE["host"], REMOTE["root"].rstrip("/\\")
    win = root.replace("/", "\\")
    ours = [os.path.join("build/permute", f"{name}{ext}") for ext in (".c", ".file")]
    sent = ["src", "config", "project.toml", "tools"] + [p for p in ours if os.path.exists(p)]
    tar = subprocess.Popen(["tar", "-cf", "-", "--exclude=.git", "--exclude=__pycache__", *sent],
                           stdout=subprocess.PIPE)
    subprocess.run(SSH + [host, f'rmdir /s /q "{win}\\src" 2>nul & tar -xf - -C "{root}"'],
                   stdin=tar.stdout, check=True)
    tar.wait()
    args = " ".join(f'"{a}"' if " " in a else a for a in sys.argv[2:])
    done = subprocess.run(SSH + [host, f'cd /d "{win}" && {REMOTE["python"]} tools\\permute.py {name} {args}'])
    for path in ours:
        if os.path.exists(path):
            os.remove(path)
        subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                        f"{host}:{root}/{path}", path], stderr=subprocess.DEVNULL)
    return done.returncode


if __name__ == "__main__":
    sys.exit(main())
