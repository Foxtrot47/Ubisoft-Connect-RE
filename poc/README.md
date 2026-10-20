# PoC implementation

| File | Behaviour |
|------|-----------|
| `fake_launcher.py` | Named pipes, generated sessions, installer initialization, live activation, process lifecycle tracking |
| `ubisoft_gui.py` | Login/2FA, library, download helpers, shared services client |
| `ubisoft_poc.py` | Earlier CLI/research implementation |
| `cloudsave.py` | Ownership-authenticated cloud GET/PUT/DELETE URL issuance |
| `../tooling/login_poc.py` | Login-only dialog; stores tickets and closes |
| `../tooling/run_independent_launcher.py` | PoC auth, explicit game path, generated IPC, live tickets, replay inputs rejected |

## Launcher

WD2 reaches gameplay with the copied runtime and the official install/cache folders
isolated. Session `f22` carries the live entitlement's application ID; installer
request `f13` is answered with `f10` rather than another session message; the password
field is empty. `20261022T155009.643936Z` ran with EAC skipped, and
`20261022T182133.554861Z` reached gameplay, joined a multiplayer session and saved
without the skip flag.

The runner forces fresh activation. An identical challenge reuses its answer inside
one launcher process; nothing is persisted between launches. Startup and real-game
exit codes are tracked separately. The input guard blocks known official-state and
capture paths, and the tests isolate those directories physically.

Run metadata and per-run save roots live under `tooling/independent-runs/`.

## Cloud

`CloudSaveClient` issues authorized URLs from supplied credentials. Two temporary-slot
readbacks matched their local snapshots byte-for-byte and cleanup was verified.
Publication to real slots and automatic sync are not wired up.

## Environment

CPython 3.12.10 with requests, zstandard, pywin32 and Tkinter. The launcher runs
through the renamed `poc/bin-fresh/upc.exe` interpreter. Frida is not a launch
dependency.

44 PoC tests and 4 input-guard tests pass. Protocol details are in
[09](../docs/09-fresh-activation.md) and
[10](../docs/10-denuvo.md).
