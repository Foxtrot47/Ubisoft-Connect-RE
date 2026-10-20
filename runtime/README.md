# Minimal launcher runtime

The game refuses to start if `HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\InstallDir`
points at a missing directory — it reads that key and exits before loading any DLL.

The directory must exist, but it does **not** need the Ubisoft Connect client. Import
analysis shows the whole dependency set is these files (copied from a normal install):

| File | Why |
|------|-----|
| `uplay_r1.dll`, `uplay_r164.dll` | the real Uplay IPC client |
| `uplay_aux_r1.dll`, `uplay_aux_r164.dll` | Denuvo/activation channel (`UPLAY_GetActivate`); **required by protected titles** |
| `UbisoftGameLauncher.exe`, `UbisoftGameLauncher64.exe` | game starter the game re-execs into |
| `discord-rpc.x86.dll`, `discord-rpc.x64.dll`, `steam_api.dll`, `steam_api64.dll` | starter imports |

Total: 10 files, **~12.3 MB**. No `upc.exe`, no CEF, no 195 MB `libcef.dll`.

## Point the registry here (one elevated step)

```cmd
reg add "HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher" /v InstallDir /t REG_SZ ^
        /d "D:\Projects\ubisoft-re\runtime\" /f
```

Or run [`../set_runtime_dir.cmd`](../set_runtime_dir.cmd) as administrator.

## Undo

```cmd
reg add "HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher" /v InstallDir /t REG_SZ ^
        /d "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\" /f
```

## Notes

- These files are copied from your own installation; nothing is redistributed.
- The fake launcher also writes here (logs, `savegames/`) because the client derives its
  data paths from `InstallDir`.
- Nothing in this folder is required unless you want to run games **without** the
  Connect client.
