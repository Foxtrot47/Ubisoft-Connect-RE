#!/usr/bin/env python3
"""Watch which upc code touches the AES S-box during a fresh activation."""

import os
import subprocess
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher_OFF\upc.exe"
GAME = r"E:\Games\WATCH_DOGS2\bin\WatchDogs2.exe"
CACHE = os.path.join(os.environ["LOCALAPPDATA"], "Ubisoft Game Launcher",
                     "cache", "activations",
                     "1ae5ff50-ea9d-4b3d-a9e0-d33625791ffe")


def main():
    try:
        os.remove(CACHE)
    except OSError:
        pass
    dev = frida.get_local_device()
    upc = subprocess.Popen([EXE], cwd=os.path.dirname(EXE))
    time.sleep(6)
    s = dev.attach(upc.pid)
    sc = s.create_script(open(os.path.join(HERE, "sbox_watch2.js"), encoding="utf-8").read())
    sc.on("message", lambda m, _d: print(m["payload"]["msg"] if m.get("type") == "send" else m, flush=True))
    sc.load()
    subprocess.Popen([GAME, "-eac_launcher"], cwd=r"E:\Games\WATCH_DOGS2")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
