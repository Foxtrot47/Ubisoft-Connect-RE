#!/usr/bin/env python3
"""Attach Frida to upc.exe AND UplayService.exe (the download worker), streaming hooks.

Usage: python download_capture.py
Attaches to any running ubisoft client process, and keeps watching for
UplayService.exe to spawn (it is the elevated download/install worker).
"""
import os
import sys
import time

import frida

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS = ["upc.exe", "UplayService.exe", "UplayWebCore.exe"]
OUT = open(os.path.join(SCRIPT_DIR, "download_capture.log"), "w", encoding="utf-8", buffering=1)


def on_message(tag_prefix):
    def handler(message, data):
        line = ""
        if message.get("type") == "send":
            p = message["payload"]
            line = f"[{tag_prefix}|{p['tag']}] {p['msg']}"
        elif message.get("type") == "error":
            line = f"[{tag_prefix}|error] {message.get('description')}"
        else:
            line = repr(message)
        print(line, flush=True)
        OUT.write(line + "\n")
    return handler


def attach_and_hook(session, label):
    js = open(os.path.join(SCRIPT_DIR, "capture.js"), encoding="utf-8").read()
    script = session.create_script(js)
    script.on("message", on_message(label))
    script.load()
    print(f"[*] hooked {label} pid={session._impl.pid}", flush=True)
    return session


def main():
    sessions = {}  # name -> (pid, frida.Session)

    print("[*] looking for ubisoft processes...", flush=True)
    try:
        while True:
            procs = frida.get_local_device().enumerate_processes()
            names = {p.name: p.pid for p in procs}
            for t in TARGETS:
                if t in names:
                    pid = names[t]
                    # (re)attach when a new PID appears (e.g. after sign-out restart)
                    if t not in sessions or sessions[t][0] != pid:
                        try:
                            s = frida.attach(pid)
                            sessions[t] = (pid, attach_and_hook(s, t))
                        except Exception as e:
                            print(f"[*] attach {t} failed: {e}", flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] detaching...", flush=True)
        for _pid, s in sessions.values():
            try:
                s.detach()
            except Exception:
                pass
        OUT.close()


if __name__ == "__main__":
    main()
