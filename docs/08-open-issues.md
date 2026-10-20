# 08: Open issues

What is still missing, plus design notes worth keeping. The launch sequence is in
[09](09-fresh-activation.md) and activation in [10](10-denuvo.md).

## Open

- **Persistent activation cache.** Strict mode re-issues every launch. Storage,
  invalidation and expiry are unimplemented, and the effect of repeated issuance on
  activation or rate quotas is unknown.
- **Permanent cloud sync.** Temporary-slot transfer is byte-exact; publishing to real
  slots, save-header markers, revision conflicts and rollback are not done.
- **Installer completeness.** Success, empty chunk catalog and `en-US` are enough for
  an installed title. Real chunk metadata and language selection are not implemented.
- **Hardware scores.** `InitRsp.f16` sends constants instead of measuring the machine.
- **Stale phase label.** `phase` stays `game-exited` when a later game PID registers
  during EAC-enabled process transitions.
- **Isolation restore.** Three launcher directories are still renamed aside; the
  mapping is `tooling/independent-runs/isolation-elevated.json`.
- **Auth longevity.** Long-lived refresh is unverified; remember-me tickets have
  already been observed failing with HTTP 401.
- **EAC init-log verification.** EAC-on gameplay is confirmed behaviourally (no skip
  flag, no disabled-EAC warning); nobody has read `EAC.log` for that run.
- **Untested titles and machines.** Only WD2 and only a machine that once had Connect
  installed.

Resolved: live activation issuance, generated-session launch, EAC-enabled gameplay
with multiplayer session joined, and cloud transport.

## Intermittent slice URL

The demux occasionally withholds a signed URL for a slice — one occurrence in three
files. Three retries with backoff are in place. A full 71 GB download wants longer
backoff and resume support.

## Not implemented

| Area | Status |
|------|--------|
| Achievements / player stats | `uplay_protocol_ipc_pipe_` exists, not served |
| Friends / presence | Same |
| Overlay injection | `uplay_overlay_ipc_pipe_` not served; the game runs without it |
| Download optimisation | Single sequential connection, no resume, no parallelism |

## Hygiene

The launcher's session push carries a credential-like value in `f2.f5` — it hands the
account password to legacy titles. Handling:

- `pipe_capture*.log` and `session_msg.bin` deleted after they were found to contain it
- account emails redacted from older HTTP captures
- `fake_launcher.py` sends that field empty (`$UPLAY_PASSWORD` if set)
- token-bearing artifacts removed; only a few signed URLs remain as a scheme sample

## Notes kept from the investigation

These are still accurate and explain why the working design looks the way it does.

### `UplayService.exe` attests its peer

| Property | Value |
|---|---|
| Bitness | 32-bit |
| Packing | Ubisoft protector: `.text`/`.rdata`/`.ubx0` raw size 0, `.ubx2` = 11.3 MB at entropy 7.97 |
| Service-control imports | none, so exit code 6 is not an elevation failure |

| Experiment | Result |
|---|---|
| Run with each of the three captured argument variants | opens `\\.\pipe\terminal_1_uplay_service_icp_pipe_`, exits 6 |
| Who serves that pipe | nobody; `upc.exe` neither creates nor opens it |
| Serve it ourselves, then run the service | connects, sends 0 bytes, exits 6 |
| Behaviour after connecting | `GetNamedPipeServerProcessId` → `OpenProcess` ×3 → exit 6 |
| `WinVerifyTrust` | never called |

It identifies the process serving the pipe and rejects it — lineage attestation
rather than a signature check. The working path does not need it: Denuvo talks to the
launcher over the aux pipe directly.

### `uplay_service_ipc_pipe_` is a cache sink

The 1084-byte message a working launch produces there decodes as an HTTP cache record
(method, status, 18 headers, URL) reported by a client into the launcher, and
`upc.exe` answers with nothing. `fake_launcher.py` serves it the same way: hwscore path
notice on connect, unframed record parsing, no reply.

### Registry prerequisites

The WD2 install was missing keys the game needs, and one had been corrupted by an
earlier helper script:

| Key | Found | Fix |
|-----|-------|-----|
| `SOFTWARE\Ubisoft\Launcher\InstallDir` | `D:\…\runtime" /f`, malformed | point at a real directory in both views |
| `SOFTWARE\Ubisoft\WatchDogs2\InstallDir` | missing, installer step failed | `E:\Games\WATCH_DOGS2` |

64-bit games read the 64-bit view, which `reg add` writes by default, so the 32-bit
view needs `/reg:32`. `fix_registry.cmd` repairs both.
