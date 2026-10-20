# 06: Launch and the fake launcher

WD2 launches from this launcher with freshly generated session/installer messages and
live tickets. Copied runtime DLLs and starters remain required. Gameplay is confirmed
with EAC enabled, alongside a multiplayer session. See
[09](09-fresh-activation.md).

The game never holds a ticket. It asks the launcher for one over **named pipes**. That
is the whole obstacle to running a game without Ubisoft Connect: and the whole reason a
fake launcher works.

## Spawn recipe

The launcher starts the game as a plain process: **no arguments**:

```
CreateProcessW
    app = E:\Games\Child of Light\ChildofLight.exe
    cmd = "E:\Games\Child of Light\ChildofLight.exe"
    cwd = E:\Games\Child of Light\
```

Everything else comes from the per-game configuration:

| Element | Source |
|---------|--------|
| executable | `start_game.online.executables[].path.relative` |
| working dir | `working_directory.register` → `HKLM\…\Installs\{pid}\InstallDir` |
| arguments | `arguments:` (empty for CoL; WD2 trial uses `-eac_launcher_settings settings_plus.json`) |

## Launch sequence (from the launcher log)

```
PlayCheckEdisonGameInstallers  UplayServices completed successfully.
PlayGame                       Launch Game
GameStartPipe                  Accepted connection → Starting game session
UplayServicePipeHandler        Accepted connection
CloudSaveSyncGameStart         Migrate to new cloud save system
CloudSaveMigration             There's no savegames to migrate
ApiProcessConnection           Game with process id N connected
ApiProcessConnection           … started with product id 609 (branch: 'default')
UplayGameConnectionHandler     … connected (API version: 1.0.0)
PlaySession                    Play session (1) started for game 609 (refresh in 330 s)
```

Cloud-save sync runs **before** the game connects.

## Pipes

`upc.exe` is the server:

| Pipe (`\\.\pipe\` + …) | Role |
|---|---|
| `terminal_1_game_start_ipc_pipe_` | launch request → launch parameters |
| `terminal_1_uplay_api_process_ipc_pipe_` | game announces `{productId, gamePid}` |
| `terminal_1_uplay_ipc_pipe_` | **session push containing the ticket** |
| `terminal_1_uplay_service_ipc_pipe_` | launcher ⇄ `UplayService` |
| `terminal_1_uplay_aux_ipc_pipe_` | **Denuvo activation** (see below) |
| `…orbit…`, `…uplay_protocol…`, `…overlay…`, `…crash_reporter…` | auxiliary |

All are created at launcher start, which is why attaching *after* startup misses them.

## The three conversations

**game_start** request (76 B, note the double `f1`):

```
f1 { f1 { f1: 13389 (build), f2: 609 (productId), f4: 1,
          f10: "<exe path>", f11: "", f12: <timestamp>, f17: 1 } }
```

response (108 B, reproduced byte-exactly):

```
f2 { f1 { f1: 1, f2: 0, f3: <exe, forward slashes>, f4: <cwd>,
           f8: 2, f9 { f1 {1,113,0,1,0} f1 {3,123,0,0,0} } } }
```

**uplay_api_process**: request `f2{f1: productId, f2: gamePid, f5: 1}`,
response `f13{f1:1, f3:1, f4:2, f6:0}`.

**uplay_ipc** (the session push, 5,012 B):

| Field | Meaning |
|-------|---------|
| `f1` | 1 |
| `f2` | profile `{userId, username, nameOnPlatform, email, <?>, country}` |
| `f4` | `productId` |
| `f5` (repeated) | owned product ids |
| `f6` | `{productId, ""}` |
| `f8` | **the ticket**: 4,307-byte JWE |
| `f17` | `{1: "<savegames path>"}` |
| `f22` | `{1: <applicationId>}` |

`f17` is **string-concatenated** with the filename by the game, so it must end with
`<userId>\<productId>\`.

## Fake launcher

`poc/fake_launcher.py` creates the pipes, answers the handshake, serves the cached
activation, pushes a session minted from our own login and spawns the game.

```bash
python poc/fake_launcher.py 609                 # serves + spawns
python poc/fake_launcher.py 609 --no-launch     # serve only
python poc/fake_launcher.py 609 --eac           # skip EAC
```

Verified on 2026-10-21 with the Connect install directory **renamed away**:

```
[launch] spawned pid=5640 cwd=E:\Games\WATCH_DOGS2
[game_start] launch parameters returned
[aux] req 357B rid=2 activate
[aux] gameToken from cache (1576B)
[session] using minted denuvo token (620B, 3-part JWE)
[uplay_ipc] session pushed (1326B), ticket 4307B
[uplay_ipc] replayed 16 follow-up push(es)
[launch] wait event signaled
```

`WatchDogs2.exe` window "Watch_Dogs 2" responding, in-game, `1.save` written,
`WD2_GamerProfile.xml` written, and `UbisoftGameLauncher.exe` resolved from
`runtime/` (no `upc.exe` from the client in the process tree).

The EAC path was verified too (no `--eac`): `EasyAntiCheat.exe` runs, `EAC.log` is
written with `Successfully initialized EAC`, and the game loads. EAC's own back end
may still report `Connection attempt to the back-end failed` and retry: that is EAC's
network, not the launcher handshake.

## Running with the client uninstalled

The game reads `HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\InstallDir` and exits
**before loading any DLL** if that directory is missing. The directory must exist: but
it does not need the client.

Dependency analysis (`pefile`) gives the complete set:

| File | Why |
|------|-----|
| `uplay_r1.dll` | the real IPC client |
| `uplay_aux_r1.dll`, `uplay_aux_r164.dll` | Denuvo activation (`UPLAY_GetActivate`): protected titles |
| `UbisoftGameLauncher.exe` | 32-bit game starter the game re-execs into |
| `discord-rpc.x86.dll`, `steam_api.dll` | starter imports |

`runtime/` holds those (10 files, **12.3 MB**): no `upc.exe`, no CEF, no 195 MB
`libcef.dll`. One elevated step repoints the registry:

```cmd
reg add "HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher" /v InstallDir /t REG_SZ ^
        /d "D:\Projects\ubisoft-re\runtime\" /f
```

## Denuvo titles: the activation channel

`uplay_aux_ipc_pipe_` carries Denuvo activation, not a handshake probe. Denuvo
(`dbdata.dll`) asks the in-game `uplay_aux_r164.dll` for a `gameToken` bound to a
challenge the game generates each launch, and the launcher must answer on that pipe.
Without an answer the aux provider sleeps and retries forever and the Denuvo VM thread
spins with no window — the "hang" this project chased for a day.

Two fields of the session push get substituted at send time:

| Field | Captured value | Needed |
|-------|----------------|--------|
| `f8` | token from the capture launch | freshly minted PC ticket (620 B) |
| `f17` | `<Connect install>\savegames\<uid>\<pid>\` | any writable root ending in a separator, e.g. `<repo>/savegames/<uid>/<pid>/` |

`f17` must end with a separator: the game appends its save filename to it directly.
Point it at a directory the launcher can write, which is why the launcher supplies its
own save root rather than a path inside the client install.

`f8` is the PC ticket from `GetUplayPCTicket`, **not** the aux activation answer.
Sending one where the other belongs breaks the launch.

Protocol, token roles, live issuance and result codes: [10: Denuvo activation](10-denuvo.md).

## Session and installer fields

Shapes from the `proto_uplaydll/UplayDll.proto` descriptor embedded in
`runtime/uplay_r164.dll`:

| Field | Meaning |
|---|---|
| `InitRsp.f22.f1` | `UbiServices.appId`, from the selected entitlement's `applicationId` |
| `Req.f13` | `InstallerReq`; `6a020a00` asks for installer initialization |
| `Rsp.f10.f1` | `InstallerRsp.initInstallerRsp` — the reply to `f13` |
| `InitRsp.f16` | CPU score, GPU score, GPU confidence (currently constants) |
| `Account.f5` | password field, sent empty |
| `InitRsp.f17` | storage path; the game concatenates its save filename onto it |

## Process lifecycle

WD2 runs three processes: a bootstrap executable, `UbisoftGameLauncher.exe` (the
starter), then the real game. The bootstrap exits 0 as a matter of course — that is
normal, not a failure.

The real game PID is announced over game IPC, and the starter hands it an inherited
wait event. Exit codes are tracked per process and normalized to unsigned 32-bit,
because Win32 reports an access violation as `-1073741819` while the rest of the world
writes `0xC0000005`. An absent Windows application-error event does not mean a clean
exit.

## Spawning the game properly

`upc.exe` does not `ShellExecute` the game. It creates an inheritable event, spawns
the launcher starter with inheritance on, and the starter passes the handle to
`UbisoftGameLauncher.exe` (`-gamelauncher_wait_handle`). Without that inherited event
the starter waits out its timeout and the job takes the game down after ~15 s.
`fake_launcher.launch()` reproduces this:

```
CreateEvent + SetHandleInformation(HANDLE_FLAG_INHERIT)
CreateProcessW(game exe, cwd=<install root>, inherit_handles=TRUE)
... on uplay_api_process: SetEvent      # releases the starter
```

`--launch` is the default; `--no-launch` serves the pipes only.

## Boundaries

- The game and Ubisoft's own DLLs are unmodified; we impersonate the launcher service.
- `uplay_r1.dll` and (for protected titles) `uplay_aux_r1/r164.dll` must be present
  locally; nothing Ubisoft ships is redistributed.
- Not implemented: achievements, friends, overlay.
- **DRM / anti-cheat titles work**: Watch Dogs 2 launches through the full Denuvo +
  EAC stack with no Connect client, reaching gameplay and a multiplayer session. EAC
  can be skipped with `--eac`. Activation is issued live per launch, so no client
  cache is needed; see [09](09-fresh-activation.md).

### Launch arguments ride in the request, not the reply

`game_start` carries the game's command line in request field **f11** (`0x5a`).
With `-eac_launcher` set, the request grows 75 B → 88 B and f11 holds
`"-eac_launcher"`. The launcher's **reply is byte-identical either way** (105 B), so
arguments propagate game → starter → game and never through our reply.

### `-eac_launcher` skips EasyAntiCheat entirely

Passing `-eac_launcher` (as a client launch argument) makes the game skip its own
EAC bootstrap:

| | without flag | with flag |
|---|---|---|
| `EAC.exe -eac_launcher` spawned by the game | yes | **no** |
| `EasyAntiCheatSys` driver loaded | yes | no |
| `EAC.log` "Successfully initialized EAC" | written | **never written** |
| Game plays | yes | **yes** |

The game also becomes debuggable in this configuration, which is how the Denuvo
findings in [Open issues](08-open-issues.md#notes-kept-from-the-investigation)
were obtained.

## Next

→ [07: Cloud saves](07-cloud-saves.md)
