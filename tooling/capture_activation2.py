#!/usr/bin/env python3
"""Capture one fresh activation from both ends.

- deletes the activation cache
- starts upc.exe normally and attaches capture.js (TLS plaintext -> JWE)
- starts the game and attaches game_aux_req.js (aux WriteFile -> request token)

All three artifacts (request token, demux JWE, aux response blob) then belong to
the same launch.
"""

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


def talk(script, keep=("REQ", "AUX", "ENC-RAW", "DEC-RAW")):
    def on(m, _d):
        if m.get("type") != "send":
            print(m, flush=True)
            return
        p = m["payload"]
        if p["tag"] not in keep:
            return
        if p["tag"] in ("ENC-RAW", "DEC-RAW") and "eyJlbmMi" not in p["msg"] and "hex=0a0d" not in p["msg"]:
            return
        print(f"[{p['tag']}] {p['msg'][:1500]}", flush=True)
    script.on("message", on)
    script.load()


def main():
    try:
        os.remove(CACHE)
        print("[*] cache deleted", flush=True)
    except OSError as e:
        print(f"[!] {e}", flush=True)

    dev = frida.get_local_device()
    upc = subprocess.Popen([EXE], cwd=os.path.dirname(EXE))
    print(f"[*] upc pid={upc.pid}", flush=True)
    time.sleep(6)
    s = dev.attach(upc.pid)
    talk(s.create_script(open(os.path.join(HERE, "capture.js"), encoding="utf-8").read()))
    talk(s.create_script(open(os.path.join(HERE, "sched_hook.js"), encoding="utf-8").read()),
         keep=("SCHED", "init"))

    game = subprocess.Popen([GAME, "-eac_launcher"], cwd=r"E:\Games\WATCH_DOGS2")
    seen = set()
    deadline = time.time() + 60
    src = open(os.path.join(HERE, "game_aux_req.js"), encoding="utf-8").read()
    while time.time() < deadline:
        for p in dev.enumerate_processes():
            if p.name == "WatchDogs2.exe" and p.pid not in seen:
                seen.add(p.pid)
                try:
                    gs = dev.attach(p.pid)
                    talk(gs.create_script(src))
                    print(f"[*] hooked game pid={p.pid}", flush=True)
                except Exception as e:
                    print(f"[skip] {p.pid} {e}", flush=True)
        time.sleep(0.1)


if __name__ == "__main__":
    sys.exit(main())
