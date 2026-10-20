#!/usr/bin/env python3
"""Spawn Ubisoft Connect (upc.exe) under Frida and capture config/download crypto + URLs."""
import os
import sys
import time

import frida

EXE = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\upc.exe"
CWD = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher"

OUT = open("capture_output.log", "w", encoding="utf-8", buffering=1)


def on_message(message, data):
    line = ""
    if message.get("type") == "send":
        p = message["payload"]
        line = f"[{p['tag']}] {p['msg']}"
    elif message.get("type") == "error":
        line = f"[frida-error] {message.get('description')}"
    else:
        line = repr(message)
    print(line, flush=True)
    OUT.write(line + "\n")


def main():
    pid = frida.spawn([EXE], cwd=CWD)
    print(f"[*] spawned pid={pid}, attaching...", flush=True)
    session = frida.attach(pid)
    js = open("capture.js", encoding="utf-8").read()
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print("[*] hooks loaded, resuming process...", flush=True)
    frida.resume(pid)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] stopping...", flush=True)
        try:
            session.detach()
        except Exception:
            pass
        OUT.close()


if __name__ == "__main__":
    main()
