#!/usr/bin/env python3
"""Spawn upc.exe under the aux conversion trace and dump its main module.

    python trace_conversion.py

1. starts upc.exe suspended, loads aux_convert_trace.js, resumes it
2. dumps the unpacked upc.exe image to upc_dump.bin once the pipes exist
3. prints the request token and the response blob with a backtrace

Start a game afterwards (any way that uses these pipes).
"""

import os
import sys
import time

import frida

EXE = r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher_OFF\upc.exe"
CWD = os.path.dirname(EXE)
DUMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upc_dump.bin")


def extract(script, off, length, step=1 << 20):
    import base64
    out = bytearray()
    while length > 0:
        n = min(length, step)
        out += base64.b64decode(script.exports_sync.chunk(off + len(out), n))
        length -= n
    return bytes(out)


def main():
    js = open("aux_convert_trace.js", encoding="utf-8").read()
    dev = frida.get_local_device()
    pid = frida.spawn([EXE], cwd=CWD)
    session = dev.attach(pid)
    script = session.create_script(js)

    def on_message(m, _d):
        if m.get("type") != "send":
            print(m, flush=True)
            return
        p = m["payload"]
        print(f"[{p['tag']}] {p['msg']}", flush=True)

    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print(f"[*] upc pid={pid}; waiting for the game", flush=True)

    # Give the packer time to unpack, then dump the image for IDA.
    time.sleep(8)
    res = script.exports_sync.ranges()
    size = int(res["size"])
    image = bytearray(size)
    total = 0
    for off, length in res["ranges"]:
        chunk = extract(script, off, length)
        image[off:off + length] = chunk
        total += length
    with open(DUMP, "wb") as f:
        f.write(image)
    print(f"[*] dumped {total}B of {size} across {len(res['ranges'])} ranges, base={res['base']}", flush=True)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
