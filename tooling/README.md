# Tooling — Frida capture scripts

These produced the evidence in [`../docs`](../docs). They are research instruments, not
part of the client.

## Traffic capture (custom TLS)

| File | Purpose |
|------|---------|
| `capture.js` / `capture.py` | Attach to `upc.exe`; logs plaintext HTTP (requests + bodies + responses) via `BCrypt*`, DPAPI calls, socket connects. Used for sign-in, entitlements, playsession, cloud saves. |
| `download_capture.py` | Attaches to `upc.exe` **and** `UplayService.exe`, re-attaches on PID change (survives sign-out restarts). Used for the download/demux work. |
| `spawn_capture.py` | Spawns `upc.exe` under Frida so startup traffic (catalog, `connecturls`) is caught. |

```bash
python capture.py upc.exe
python download_capture.py
python spawn_capture.py
```

## Launch / pipe capture

| File | Purpose |
|------|---------|
| `pipe_capture.js` / `pipe_capture.py` | Maps pipe handle→name on `CreateNamedPipe*`, logs I/O on Uplay pipes, and every `RegSetValueEx`. Use `--spawn` — pipes are created at launcher start. |
| `launch_capture.js` / `launch_capture.py` | Spawns, named-pipe traffic, registry writes, plaintext HTTP. `--block` prevents the game from starting (safe mode). |
| `cloudsave_capture.py` | Spawns the real launcher with the traffic hooks, for cloud-save upload/download captures. |
| `diag_loader.js` | Diagnoses why a game exits early (`RegOpenKeyExW` / `LoadLibrary` / `CreateFile`). |

```bash
python pipe_capture.py --spawn
python launch_capture.py --block
python cloudsave_capture.py
```

## Collector design

Frida self-transport is the failure mode to avoid: an unrestricted collector reached
4.4 GB while its companion hit 1.55 GB, because the tool's own pipe traffic was being
captured as input.

Current collector guards: explicit allowlists instead of "every pipe", ACK
backpressure, 128-message / 8 MiB in-flight limits, 1 MiB per payload, bounded pending
state, a single-collector mutex and resource watchdogs. It settles around 70 MB.

Fixtures covering CNG, synchronous and IOCP paths exclude the collector's own
Frida-named pipe writes. Sustained runs still log dropped events and pipe gaps — treat
per-event completeness as unproven unless health reports say otherwise.

## Notes

- **Sensitivity:** captures can contain session tokens and, for the session-push pipe, a
  credential-like field. Treat output as sensitive and delete it after analysis.
- Output files are written next to the script (`*.log`).
- `capture.js` reads the plaintext inside the client's CNG-based TLS, which is why no
  proxy or certificate work is required.
- Filtering matters: `capture.js` labels some protobuf replies as `HTTP-RESP` when they
  contain a URL. Check the payload, not just the tag.
