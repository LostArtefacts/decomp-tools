"""Installs a DirectX SDK's headers and import libraries into the Wine
prefix.

    dxsdk.py INSTALLER [DIR]

INSTALLER is the SDK's download, such as the DirectX 5 SDK's
idx5sdk.exe: a self-extractor holding a cabinet that holds an
InstallShield self-extractor of the CD's files. 7-Zip unpacks each
layer until one has sdk/inc and sdk/lib. Their files are copied to
DIR\\include and DIR\\lib, by default C:\\dx5, the first directory of
build.include. The Borland libraries are left out.
"""
import os, shutil, subprocess, sys, tempfile

import project

ROOT = project.ROOT
PREFIX = os.environ.get("WINEPREFIX", os.path.join(ROOT, ".wine"))


def unpack(path, into):
    subprocess.run(["7z", "x", "-y", "-bso0", "-bsp0", "-o" + into, path], check=True)


def find_sdk(top):
    for dirpath, dirnames, _ in os.walk(top):
        lower = {d.lower(): d for d in dirnames}
        if os.path.basename(dirpath).lower() == "sdk" and "inc" in lower and "lib" in lower:
            return os.path.join(dirpath, lower["inc"]), os.path.join(dirpath, lower["lib"])
    return None


def nested(top):
    """The archives one layer down: executables and cabinets."""
    for dirpath, _, filenames in os.walk(top):
        for name in filenames:
            if name.lower().endswith((".exe", ".cab")) or name.upper() == "CABINET":
                yield os.path.join(dirpath, name)


def windows_dir(path):
    """C:\\dx5 as a path in the prefix."""
    drive, _, rest = path.partition(":")
    return os.path.join(PREFIX, f"drive_{drive.lower()}", *rest.strip("\\").split("\\"))


def main():
    args = sys.argv[1:]
    if not 1 <= len(args) <= 2:
        sys.exit(__doc__)
    include = project.config["build"]["include"][0]
    dest = windows_dir(args[1] if len(args) > 1 else include.rsplit("\\", 1)[0])
    with tempfile.TemporaryDirectory() as tmp:
        layer, todo, found = 0, [os.path.abspath(args[0])], None
        while todo and not found and layer < 4:
            out = os.path.join(tmp, str(layer))
            for path in todo:
                try:
                    unpack(path, out)
                except subprocess.CalledProcessError:
                    pass
            found = find_sdk(out)
            todo, layer = list(nested(out)), layer + 1
        if not found:
            sys.exit(f"no sdk/inc and sdk/lib in {args[0]}")
        for src, sub in zip(found, ("include", "lib")):
            target = os.path.join(dest, sub)
            os.makedirs(target, exist_ok=True)
            count = 0
            for name in sorted(os.listdir(src)):
                if os.path.isfile(os.path.join(src, name)):
                    shutil.copy(os.path.join(src, name), os.path.join(target, name))
                    count += 1
            print(f"{count} files in {os.path.relpath(target, ROOT)}")


if __name__ == "__main__":
    main()
