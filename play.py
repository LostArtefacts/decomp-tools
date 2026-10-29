"""Runs the patched game, headless under Xvfb, and drives it with keys.

    play.py [--exe NAME | --standalone] [STEP...]

Steps run in order:

    wait:SECONDS     wait
    key:KEY          tap a key (xdotool names: z, x, Escape, Up, Down, ...)
    hold:KEY:SECONDS hold a key down
    shot:NAME        save a screenshot to build/shots/NAME.png

--exe runs build/game/NAME instead of the patched <name>.exe, and
--standalone the standalone build, <name>_standalone.exe there (<name>
is game.name in project.toml). With no steps the game starts on a fresh
Xvfb display, and a screenshot is taken after 15 seconds. The hook log
from the DLL is printed. Needs Xvfb, xdotool and ImageMagick. game.locale
sets the game's locale (ja_JP.UTF-8 for a game that expects Shift-JIS
text and file names), game.screen the Xvfb screen.
"""
import os, subprocess, sys, time

import project

ROOT = project.ROOT
GAME = os.path.join(ROOT, project.GAME)
SHOTS = os.path.join(ROOT, "build/shots")
TITLE = project.config["game"]["window_title"]
LOCALE = project.config["game"]["locale"]
SCREEN = project.config["game"]["screen"]


def free_display():
    n = 99
    while os.path.exists(f"/tmp/.X{n}-lock"):
        n += 1
    return f":{n}"


def xdo(env, *args):
    return subprocess.run(["xdotool", *args], env=env, capture_output=True, text=True).stdout.strip()


def main():
    args = sys.argv[1:]
    exe = f"{project.NAME}.exe"
    if args[:1] == ["--exe"]:
        exe, args = args[1], args[2:]
    elif args[:1] == ["--standalone"]:
        exe, args = f"{project.NAME}_standalone.exe", args[1:]
    steps = args or ["wait:15", "shot:start"]
    display = free_display()
    env = dict(os.environ, DISPLAY=display,
               WINEPREFIX=os.environ.get("WINEPREFIX", os.path.join(ROOT, ".wine")),
               WINEDEBUG="-all,+debugstr")
    if LOCALE:
        env.update(LANG=LOCALE, LC_ALL=LOCALE)
    os.makedirs(SHOTS, exist_ok=True)
    xvfb = subprocess.Popen(["Xvfb", display, "-screen", "0", SCREEN, "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = os.path.join(ROOT, "build/game.log")
    try:
        time.sleep(1)
        with open(log, "w") as out:
            game = subprocess.Popen(["wine", exe], cwd=GAME, env=env, stdout=out, stderr=out)
        for step in steps:
            kind, _, arg = step.partition(":")
            if game.poll() is not None:
                print(f"the game exited before {step}")
                break
            if kind == "wait":
                time.sleep(float(arg))
            elif kind == "key":
                xdo(env, "keydown", arg)
                time.sleep(0.1)
                xdo(env, "keyup", arg)
                time.sleep(0.1)
            elif kind == "hold":
                key, _, secs = arg.partition(":")
                xdo(env, "keydown", key)
                time.sleep(float(secs))
                xdo(env, "keyup", key)
            elif kind == "shot":
                path = os.path.join(SHOTS, arg + ".png")
                subprocess.run(["import", "-window", "root", path], env=env, check=True)
                print("screenshot", os.path.relpath(path, ROOT))
            else:
                sys.exit(f"unknown step: {step}")
        if not xdo(env, "search", "--name", TITLE):
            print("no game window")
    finally:
        subprocess.run(["wineserver", "-k"], env=env, stderr=subprocess.DEVNULL)
        xvfb.terminate()
        xvfb.wait()
    for line in open(log, errors="replace"):
        if f"{project.NAME}:" in line and "hooks installed" in line or "err:" in line:
            print(line.rstrip())


if __name__ == "__main__":
    main()
