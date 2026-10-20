#!/usr/bin/env python3
"""Attach launch-flow instrumentation to the Ubisoft Connect launcher.

Usage:
    python launch_capture.py            # capture only (game will start)
    python launch_capture.py --block    # never let the game run (safe mode)

Then press Play in the client. Output streams to launch_capture.log.
"""

import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = open(os.path.join(HERE, "launch_capture.log"), "w", encoding="utf-8", buffering=1)
TARGETS = ["upc.exe", "UbisoftGameLauncher64.exe", "UbisoftGameLauncher.exe"]


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
    block = "--block" in sys.argv
    src = open(os.path.join(HERE, "launch_capture.js"), encoding="utf-8").read()
    if block:
        src = src.replace("var BLOCK_SPAWN = false;", "var BLOCK_SPAWN = true;", 1)

    sessions = {}
    print(f"[*] safe mode: {block}", flush=True)
    try:
        while True:
            procs = frida.get_local_device().enumerate_processes()
            names = {p.name: p.pid for p in procs}
            for t in TARGETS:
                if t in names:
                    pid = names[t]
                    if t not in sessions or sessions[t][0] != pid:
                        try:
                            s = frida.attach(pid)
                            sc = s.create_script(src)
                            sc.on("message", on_message(t))
                            sc.load()
                            sessions[t] = (pid, s)
                            print(f"[*] hooked {t} pid={pid}", flush=True)
                        except Exception as e:
                            print(f"[*] attach {t} failed: {e}", flush=True)
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
