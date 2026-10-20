#!/usr/bin/env python3
"""Capture one *fresh* activation end to end, for conversion analysis.

Deletes the launcher's activation cache, starts upc.exe under Frida with the aux
trace plus the TLS plaintext hooks, then launches the game. The service mints a
new gameToken; reqTok, demux JWE and the aux response blob all belong to the
same launch.
"""

import os
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
        print("[*] activation cache deleted", flush=True)
    except OSError as e:
        print(f"[!] cache delete: {e}", flush=True)

    aux = open(os.path.join(HERE, "aux_convert_trace.js"), encoding="utf-8").read()
    tls = open(os.path.join(HERE, "capture.js"), encoding="utf-8").read()
    dev = frida.get_local_device()
    pid = frida.spawn([EXE], cwd=os.path.dirname(EXE))
    session = dev.attach(pid)
    aux_script = session.create_script(aux)
    tls_script = session.create_script(tls)

    def log(m, _d):
        if m.get("type") != "send":
            print(m, flush=True)
            return
        p = m["payload"]
        msg = p["msg"]
        if p["tag"] == "STACK":
            return
        if p["tag"] == "REQ" and "Bg" not in msg:
            return
        if p["tag"] in ("REQ", "RSP", "AUX", "ENC-RAW", "DEC-RAW"):
            print(f"[{p['tag']}] {msg[:2000]}", flush=True)

    aux_script.on("message", log)
    tls_script.on("message", log)
    aux_script.load()
    tls_script.load()
    frida.resume(pid)
    print(f"[*] upc pid={pid}", flush=True)
    time.sleep(8)
    import subprocess
    subprocess.Popen([GAME, "-eac_launcher"], cwd=r"E:\Games\WATCH_DOGS2")
    print("[*] game started", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
