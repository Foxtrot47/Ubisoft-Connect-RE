#!/usr/bin/env python3
"""Capture the cloud-save upload body (POST /v1/profiles/{pid}/entities).

Spawns the **real** launcher under Frida (works with the renamed folder too) and
logs the plaintext HTTP conversation inside its custom TLS, including request
bodies (which arrive in a separate TLS record and show up as ENC-RAW).

Then: press Play in the client, let the game run, and exit the game.
The launcher uploads the save on exit.

Usage: python cloudsave_capture.py
"""

import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [
    r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\upc.exe",
    r"C:\Program Files (x86)\Ubisoft\_Ubisoft Game Launcher\upc.exe",
]
OUT = open(os.path.join(HERE, "cloudsave_capture.log"), "w", encoding="utf-8", buffering=1)


def main():
    exe = next((p for p in CANDIDATES if os.path.exists(p)), None)
    if not exe:
        sys.exit("upc.exe not found in either launcher folder")

    src = open(os.path.join(HERE, "capture.js"), encoding="utf-8").read()
    pid = frida.spawn([exe], cwd=os.path.dirname(exe))
    session = frida.attach(pid)
    script = session.create_script(src)

    def on_message(message, _data):
        if message.get("type") == "send":
            p = message["payload"]
            line = f"[{p['tag']}] {p['msg']}"
        elif message.get("type") == "error":
            line = f"[error] {message.get('description')}"
        else:
            line = repr(message)
        print(line, flush=True)
        OUT.write(line + "\n")

    script.on("message", on_message)
    script.load()
    print(f"[*] spawned {exe} pid={pid}", flush=True)
    frida.resume(pid)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] detaching", flush=True)
        try:
            session.detach()
        except Exception:
            pass
        OUT.close()


if __name__ == "__main__":
    main()
