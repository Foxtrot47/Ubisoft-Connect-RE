#!/usr/bin/env python3
"""Attach Frida to a Ubisoft Connect process and stream hook output.

Usage: python capture.py <pid|name>
"""
import sys
import time

import frida


def on_message(message, data):
    if message.get("type") == "send":
        p = message["payload"]
        print(f"[{p['tag']}] {p['msg']}", flush=True)
    elif message.get("type") == "error":
        import json
        print(f"[frida-error] {message.get('description')}", flush=True)
        if message.get('stack'):
            print(f"[frida-stack] {message['stack']}", flush=True)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "upc.exe"
    try:
        pid = int(target)
        session = frida.attach(pid)
    except ValueError:
        # by name
        try:
            session = frida.attach(target)
        except frida.ProcessNotFoundError:
            # try to find a matching process
            for proc in frida.get_local_device().enumerate_processes():
                if target.lower() in proc.name.lower():
                    print(f"attaching to {proc.name} (pid {proc.pid})", flush=True)
                    session = frida.attach(proc.pid)
                    break
            else:
                print(f"process {target!r} not found", file=sys.stderr)
                sys.exit(1)

    js = open("capture.js", encoding="utf-8").read()
    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    print(f"[*] hooked pid={session._impl.pid} — press Ctrl+C to stop", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] detaching...", flush=True)
        session.detach()


if __name__ == "__main__":
    main()
