#!/usr/bin/env python3
"""Attach to both the real game and its UbisoftGameLauncher parent.

    python trace_real_game.py

`exit_trace.js` runs in WatchDogs2.exe (pipes + exit calls), `launcher_trace.js`
in UbisoftGameLauncher.exe (TerminateProcess/CreateProcess). Neither process is
ours, so both are found by fast polling.
"""

import sys
import time

import frida

TARGETS = {
    "WatchDogs2.exe": "exit_trace.js",
    "UbisoftGameLauncher.exe": "launcher_trace.js",
}


def main():
    sources = {name: open(path, encoding="utf-8").read() for name, path in TARGETS.items()}
    dev = frida.get_local_device()
    seen = set()
    print("[waiting] launch the game now", flush=True)
    deadline = time.time() + 240
    while time.time() < deadline:
        try:
            procs = dev.enumerate_processes()
        except Exception:
            procs = []
        for p in procs:
            if p.name not in TARGETS or p.pid in seen:
                continue
            seen.add(p.pid)
            try:
                s = frida.attach(p.pid)
            except Exception as e:
                print(f"[skip] {p.name} pid={p.pid} {e}", flush=True)
                continue
            script = s.create_script(sources[p.name])

            def on_message(m, _d, name=p.name):
                if m.get("type") == "send":
                    print(f"[{name}|{m['payload']['tag']}] {m['payload']['msg']}", flush=True)
                else:
                    print(f"[{name}|frida] {m}", flush=True)

            script.on("message", on_message)
            script.load()
            print(f"[attached] {p.name} pid={p.pid}", flush=True)
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    sys.exit(main())
