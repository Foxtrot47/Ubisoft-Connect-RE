#!/usr/bin/env python3
"""Capture the launcher <-> game pipe handshake (the ticket exchange).

Usage:
    python pipe_capture.py            # attach to a running launcher
    python pipe_capture.py --spawn    # start upc.exe under Frida (recommended:
                                      # pipe creation happens at launch)

Then press Play in the client. Output -> pipe_capture.log
"""

import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\upc.exe"
CWD = os.path.dirname(EXE)
OUT = open(os.path.join(HERE, "pipe_capture.log"), "w", encoding="utf-8", buffering=1)
TARGETS = ["upc.exe"]


def on_message(label):
    def handler(message, _data):
        if message.get("type") == "send":
            p = message["payload"]
            line = f"[{label}|{p['tag']}] {p['msg']}"
        elif message.get("type") == "error":
            line = f"[{label}|error] {message.get('description')}"
        else:
            line = repr(message)
        print(line, flush=True)
        OUT.write(line + "\n")
    return handler


def main():
    src = open(os.path.join(HERE, "pipe_capture.js"), encoding="utf-8").read()
    sessions = {}

    if "--spawn" in sys.argv:
        if not os.path.exists(EXE):
            alt = EXE.replace("Ubisoft Game Launcher", "_Ubisoft Game Launcher")
            if os.path.exists(alt):
                globals()["EXE"] = alt
                globals()["CWD"] = os.path.dirname(alt)
            else:
                sys.exit("launcher not found at " + EXE)
        pid = frida.spawn([EXE], cwd=CWD)
        s = frida.attach(pid)
        sc = s.create_script(src)
        sc.on("message", on_message("upc.exe"))
        sc.load()
        frida.resume(pid)
        sessions["upc.exe"] = (pid, s)
        print(f"[*] spawned upc.exe pid={pid}", flush=True)
    else:
        procs = frida.get_local_device().enumerate_processes()
        pid = next((p.pid for p in procs if p.name == "upc.exe"), None)
        if pid is None:
            sys.exit("upc.exe not running (use --spawn)")
        s = frida.attach(pid)
        sc = s.create_script(src)
        sc.on("message", on_message("upc.exe"))
        sc.load()
        sessions["upc.exe"] = (pid, s)
        print(f"[*] attached to upc.exe pid={pid}", flush=True)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] detaching", flush=True)
        for _pid, s in sessions.values():
            try:
                s.detach()
            except Exception:
                pass
        OUT.close()


if __name__ == "__main__":
    main()
