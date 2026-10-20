"""Local binary launcher capture; never prints captured payloads.

Run --self-test first. Then --spawn starts the official launcher suspended,
loads hooks, and resumes it. Without --spawn, attaches to existing launchers.
A capture is NOT complete merely because this collector is running.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from datetime import datetime, timezone

import frida
import win32api
import win32event
import win32process

MiB = 1024 * 1024
MAX_CAPTURE_BYTES = 512 * MiB
MAX_CACHE_BYTES = MiB
MAX_COLLECTOR_BYTES = 256 * MiB
MAX_TARGET_GROWTH = 512 * MiB


class SingleCollector:
    """A Windows kernel mutex also excludes elevated/unelevated duplicates."""
    def __enter__(self):
        self.handle = win32event.CreateMutex(None, False, r"Local\UbisoftPoCActivationCapture")
        if win32api.GetLastError() == 183:
            self.handle.Close()
            raise SystemExit("Another activation collector is running; refusing duplicate instrumentation.")
        return self

    def __exit__(self, *_):
        self.handle.Close()


def private_bytes(pid):
    handle = win32api.OpenProcess(0x0400 | 0x0010, False, pid)
    try:
        # pywin32 exposes PROCESS_MEMORY_COUNTERS, where PagefileUsage is
        # the process's private committed bytes (not physical working set).
        return win32process.GetProcessMemoryInfo(handle)["PagefileUsage"]
    finally:
        handle.Close()


HERE = Path(__file__).resolve().parent
TARGETS = {"upc.exe", "uplayservice.exe"}
REQUIRED = {"bcrypt.dll!BCryptEncrypt", "bcrypt.dll!BCryptDecrypt",
            "kernel32.dll!CreateNamedPipeW", "kernel32.dll!ReadFile",
            "kernel32.dll!WriteFile"}


def fixture():
    # Known plaintext only: validates binary transport without using an account.
    time.sleep(2)
    import win32file
    import win32pipe
    b = ctypes.WinDLL("bcrypt")
    algorithm, key = ctypes.c_void_p(), ctypes.c_void_p()
    def ok(status):
        if status < 0:
            raise RuntimeError(f"CNG fixture failed: {status}")
    ok(b.BCryptOpenAlgorithmProvider(ctypes.byref(algorithm), "AES", None, 0))
    secret = ctypes.create_string_buffer(bytes(16))
    ok(b.BCryptGenerateSymmetricKey(algorithm, ctypes.byref(key), None, 0, secret, 16, 0))
    marker = b"CAPTURE-TEST-123"
    source = ctypes.create_string_buffer(marker)
    encrypted, decrypted = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
    iv = ctypes.create_string_buffer(bytes(16))
    length = ctypes.c_ulong()
    ok(b.BCryptEncrypt(key, source, 16, None, iv, 16, encrypted, 32, ctypes.byref(length), 0))
    iv = ctypes.create_string_buffer(bytes(16))
    ok(b.BCryptDecrypt(key, encrypted, length.value, None, iv, 16, decrypted, 32, ctypes.byref(length), 0))
    assert decrypted.raw[:16] == marker
    b.BCryptDestroyKey(key)
    b.BCryptCloseAlgorithmProvider(algorithm, 0)
    name = rf"\\.\pipe\activation_capture_test_{os.getpid()}"
    server = win32pipe.CreateNamedPipe(name, 3, 0, 1, 4096, 4096, 0, None)
    client = win32file.CreateFile(name, 0xC0000000, 0, None, 3, 0, None)
    win32file.WriteFile(client, marker)
    assert win32file.ReadFile(server, 4096)[1] == marker
    win32file.CloseHandle(client)
    win32file.CloseHandle(server)
    import pywintypes
    server = win32pipe.CreateNamedPipe(name, 3 | 0x40000000, 0, 1, 4096, 4096, 0, None)
    client = win32file.CreateFile(name, 0xC0000000, 0, None, 3, 0, None)
    port = win32file.CreateIoCompletionPort(server, None, 123, 1)
    overlap = pywintypes.OVERLAPPED()
    buffer = win32file.AllocateReadBuffer(4096)
    error, buffer = win32file.ReadFile(server, buffer, overlap)
    assert error == 997
    win32file.WriteFile(client, marker)
    error, length, key_value, completed = win32file.GetQueuedCompletionStatus(port, 5000)
    assert error == 0 and length == len(marker) and key_value == 123
    assert bytes(buffer)[:length] == marker
    win32file.CloseHandle(client)
    win32file.CloseHandle(server)
    win32file.CloseHandle(port)
    # Regression for the actual incident: Frida-named pipes must be ignored.
    name = rf"\\.\pipe\frida-capture-regression-{os.getpid()}"
    server = win32pipe.CreateNamedPipe(name, 3, 0, 1, 4096, 4096, 0, None)
    client = win32file.CreateFile(name, 0xC0000000, 0, None, 3, 0, None)
    for _ in range(1000):
        win32file.WriteFile(client, marker)
        win32file.ReadFile(server, 4096)
    win32file.CloseHandle(client)
    win32file.CloseHandle(server)
    time.sleep(3)


class Collector:
    def __init__(self, out):
        self.out = out
        self.lock = threading.RLock()
        self.events = (out / "events.jsonl").open("x", encoding="utf-8", buffering=1)
        self.blobs = (out / "payloads.bin").open("xb", buffering=0)
        self.sessions = {}
        self.health = {}
        self.errors = 0
        self.record_count = 0
        self.start = time.time()
        self.stopped = threading.Event()
        self.failure = None
        self.closed = False
        self.target_baselines = {}

    def record(self, metadata, data=None):
        with self.lock:
            if self.closed:
                return
            if data is not None and self.blobs.tell() + len(data) > MAX_CAPTURE_BYTES:
                self.failure = "capture-byte-limit"
                self.stopped.set()
                raise RuntimeError("Capture size limit reached; coverage is incomplete.")
            entry = {"received_ns": time.time_ns(), **metadata}
            try:
                if data is not None:
                    entry.update(offset=self.blobs.tell(), size=len(data),
                                 sha256=hashlib.sha256(data).hexdigest())
                    self.blobs.write(data)
                self.events.write(json.dumps(entry) + "\n")
                self.record_count += 1
            except OSError:
                self.failure = "capture-write-failed"
                self.stopped.set()
                raise

    def message(self, pid, script, message, data):
        if message.get("type") == "send":
            entry = message["payload"]
            with self.lock:
                if entry["kind"] == "health":
                    previous = self.health.get(pid, {}).get("counts", {})
                    for counter in ("dropped_events", "send_errors"):
                        self.errors += max(0, entry["counts"].get(counter, 0) - previous.get(counter, 0))
                    self.health[pid] = {**entry, "received_at": time.time()}
                if entry["kind"] in {"gap", "hook-error"}:
                    self.errors += 1
            try:
                self.record(entry, data)
                script.post({"type": "capture-ack", "payload": {"sequence": entry["sequence"]}})
            except Exception as error:
                self.failure = f"message-persistence-or-ack-failed: {type(error).__name__}"
                self.stopped.set()
        else:
            with self.lock:
                self.errors += 1
            self.record({"kind": "script-error", "pid": pid, "message": message})

    def attach(self, device, pid, name):
        baseline = private_bytes(pid)
        session = device.attach(pid)
        session.on("detached", lambda reason, crash: self.detached(pid, reason))
        try:
            script = session.create_script((HERE / "activation_capture.js").read_text(encoding="utf-8"))
            script.on("message", lambda message, data: self.message(pid, script, message, data))
            with self.lock:
                self.sessions[pid] = (session, script, name)
                self.target_baselines[pid] = baseline
            script.load()
        except Exception:
            session.detach()
            raise
        self.record({"kind": "attached", "pid": pid, "name": name})

    def detached(self, pid, reason):
        with self.lock:
            self.health.pop(pid, None)
            self.sessions.pop(pid, None)
            self.target_baselines.pop(pid, None)
        self.record({"kind": "detached", "pid": pid, "reason": reason})

    def status(self):
        with self.lock:
            processes = []
            for pid, health in self.health.items():
                hooks = set(health.get("hooks", []))
                processes.append({"pid": pid, "name": self.sessions.get(pid, (None, None, "unknown"))[2],
                                  "health_age_seconds": round(time.time() - health["received_at"], 1),
                                  "missing_required_hooks": sorted(REQUIRED - hooks),
                                  "counts": health["counts"], "pending_io": health["pending_io"]})
            status = {"collector_pid": os.getpid(), "elapsed_seconds": round(time.time() - self.start),
                      "records": self.record_count, "payload_bytes": self.blobs.tell(),
                      "capture_errors": self.errors, "failure": self.failure,
                      "resource_limits": {"max_capture_bytes": MAX_CAPTURE_BYTES,
                                          "max_collector_private_bytes": MAX_COLLECTOR_BYTES,
                                          "max_target_growth_bytes": MAX_TARGET_GROWTH},
                      "processes": processes}
            temporary = self.out / "status.tmp"
            temporary.write_text(json.dumps(status, indent=2), encoding="utf-8")
            temporary.replace(self.out / "status.json")
            return status

    def watchdog(self):
        while not self.stopped.wait(0.5):
            try:
                if private_bytes(os.getpid()) > MAX_COLLECTOR_BYTES:
                    self.failure = "collector-memory-limit"
                with self.lock:
                    baselines = dict(self.target_baselines)
                for pid, baseline in baselines.items():
                    try:
                        if private_bytes(pid) - baseline > MAX_TARGET_GROWTH:
                            self.failure = f"target-memory-growth-limit: {pid}"
                    except OSError:
                        continue  # The detach callback removes exited processes.
                if self.failure:
                    self.stopped.set()
                    # Detach even if the main thread is waiting inside attach().
                    self.detach_all()
            except Exception as error:
                self.failure = f"watchdog-failed: {type(error).__name__}"
                self.stopped.set()
                self.detach_all()

    def detach_all(self):
        with self.lock:
            sessions = list(self.sessions.values())
        for session, _, _ in sessions:
            if not session.is_detached:
                session.detach()

    def close(self):
        self.stopped.set()
        for session, _, _ in list(self.sessions.values()):
            if not session.is_detached:
                session.detach()
        self.record({"kind": "collector-stopped"})
        with self.lock:
            self.closed = True
            self.events.close()
            self.blobs.close()


def snapshot_cache(collector, seen):
    root = Path(os.environ["LOCALAPPDATA"]) / "Ubisoft Game Launcher/cache/activations"
    for path in root.glob("*"):
        if not path.is_file():
            continue
        try:
            before = path.stat()
            if before.st_size > MAX_CACHE_BYTES:
                raise RuntimeError("Activation cache exceeds safe capture size; refusing unbounded read.")
            with path.open("rb") as source:
                data = source.read(MAX_CACHE_BYTES + 1)
            if len(data) > MAX_CACHE_BYTES:
                raise RuntimeError("Activation cache grew beyond safe capture size.")
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                collector.record({"kind": "cache-unstable-read", "name": path.name})
                continue
            digest = hashlib.sha256(data).hexdigest()
            if seen.get(path.name) == digest:
                continue
            seen[path.name] = digest
            collector.record({"kind": "activation-cache-snapshot", "name": path.name,
                              "mtime_ns": after.st_mtime_ns}, data)
        except OSError as error:
            collector.record({"kind": "cache-read-error", "error": str(error)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spawn", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--fixture", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture:
        fixture()
        return
    device = frida.get_local_device()
    if args.spawn and any(p.name.lower() == "upc.exe" for p in device.enumerate_processes()):
        raise SystemExit("Exit Ubisoft Connect through its tray menu before using --spawn.")
    out = HERE / "captures" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out.mkdir(parents=True, exist_ok=False)
    collector = Collector(out)
    print(f"Capture directory: {out}", flush=True)
    collector.record({"kind": "collector-start", "frida_version": frida.__version__,
                      "python": sys.version, "mode": "self-test" if args.self_test else "spawn" if args.spawn else "attach",
                      "limitations": ["Polling can miss early activity in independently started workers",
                                      "CNG plaintext only; other TLS engines not covered",
                                      "ReadFileEx completion routines/direct native I/O not captured",
                                      "Cache polling does not capture every intermediate write"]})
    cache_seen = {}
    cache_root = Path(os.environ["LOCALAPPDATA"]) / "Ubisoft Game Launcher/cache/activations"
    if not args.self_test:
        collector.record({"kind": "activation-cache-baseline", "directory_exists": cache_root.exists()})
        snapshot_cache(collector, cache_seen)
    spawned = None
    retry_after = {}
    monitor = threading.Thread(target=collector.watchdog, daemon=True)
    monitor.start()
    try:
        if args.self_test or args.spawn:
            exe = Path(os.environ["ProgramFiles(x86)"]) / "Ubisoft/Ubisoft Game Launcher/upc.exe"
            argv = [sys.executable, str(Path(__file__).resolve()), "--fixture"] if args.self_test else [str(exe)]
            spawned = device.spawn(argv, cwd=str(HERE if args.self_test else exe.parent))
            try:
                collector.attach(device, spawned, "capture-fixture" if args.self_test else "upc.exe")
            finally:
                # Never leave a launcher suspended if attachment fails.
                device.resume(spawned)
        deadline = time.monotonic() + 12 if args.self_test else None
        last_status = 0
        while not collector.stopped.is_set() and not (out / "STOP").exists():
            if deadline and time.monotonic() > deadline:
                break
            if not args.self_test:
                processes = device.enumerate_processes()
                live_pids = {process.pid for process in processes}
                retry_after = {pid: deadline for pid, deadline in retry_after.items() if pid in live_pids}
                for process in processes:
                    if process.name.lower() not in TARGETS:
                        continue
                    existing = collector.sessions.get(process.pid)
                    if existing and not existing[0].is_detached:
                        continue
                    if time.monotonic() < retry_after.get(process.pid, 0):
                        continue
                    try:
                        collector.attach(device, process.pid, process.name)
                    except Exception as error:
                        retry_after[process.pid] = time.monotonic() + 5
                        collector.errors += 1
                        collector.record({"kind": "attach-error", "pid": process.pid, "error": str(error)})
                snapshot_cache(collector, cache_seen)
            if time.monotonic() - last_status >= 2:
                collector.status()
                last_status = time.monotonic()
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        collector.status()
        collector.close()
        monitor.join(timeout=2)
    if collector.failure:
        raise SystemExit(f"Capture stopped: {collector.failure}; coverage is incomplete.")
    if args.self_test:
        marker = b"CAPTURE-TEST-123"
        events = [json.loads(line) for line in (out / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        data = (out / "payloads.bin").read_bytes()
        expected = {"encrypt-input", "decrypt-output", "pipe-write-input", "pipe-read-output"}
        observed = {e["kind"] for e in events if "offset" in e and data[e["offset"]:e["offset"] + e["size"]] == marker}
        missing = expected - observed
        iocp = any(e.get("via") == "IOCP" and e["kind"] == "pipe-read-output"
                   and data[e["offset"]:e["offset"] + e["size"]] == marker for e in events)
        transport_captured = any("frida-capture-regression" in e.get("name", "") for e in events)
        if missing or collector.errors or not iocp or transport_captured:
            raise SystemExit(f"SELF-TEST FAILED: missing={sorted(missing)}, errors={collector.errors}, IOCP={iocp}, transport_captured={transport_captured}")
        print("SELF-TEST PASSED: exact CNG, synchronous pipe and IOCP bytes; 1000 Frida-pipe writes excluded.", flush=True)


if __name__ == "__main__":
    if "--fixture" in sys.argv:
        main()
    else:
        with SingleCollector():
            main()
