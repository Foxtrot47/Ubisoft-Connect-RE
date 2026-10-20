#!/usr/bin/env python3
"""Wait for the second WatchDogs2.exe (the real game) and report its exit code."""
import time

import win32api
import win32con
import win32event
import win32process

SYNCHRONIZE = 0x00100000
QUERY = 0x0400
IMAGE = "WatchDogs2.exe"


def pids():
    out = set()
    for pid in win32process.EnumProcesses():
        try:
            h = win32api.OpenProcess(QUERY | 0x10, False, pid)
            try:
                exe = win32process.GetModuleFileNameEx(h, 0)
            finally:
                win32api.CloseHandle(h)
        except Exception:
            continue
        if exe.lower().endswith(IMAGE.lower()):
            out.add(pid)
    return out


def main():
    first = set()
    t0 = time.time()
    while not first and time.time() - t0 < 90:
        first = pids()
        time.sleep(0.1)
    print("first", first, flush=True)
    deadline = time.time() + 120
    while time.time() < deadline:
        new = pids() - first
        if new:
            pid = new.pop()
            print("second", pid, flush=True)
            h = win32api.OpenProcess(SYNCHRONIZE | QUERY, False, pid)
            win32event.WaitForSingleObject(h, 120000)
            print("exit", win32process.GetExitCodeProcess(h), flush=True)
            return
        time.sleep(0.1)


if __name__ == "__main__":
    main()
