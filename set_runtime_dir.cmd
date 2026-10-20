@echo off
REM Point the Ubisoft launcher "install dir" at the minimal runtime.
REM Right-click -> "Run as administrator".
REM
REM This is ONLY needed to run games without the Ubisoft Connect client.
REM It writes both registry views because 32-bit and 64-bit games read different ones.
REM To undo, run this with LAUNCHER set to the real client folder and drop the /d value.

set "RUNTIME=%~dp0runtime"

if not exist "%RUNTIME%\uplay_aux_r164.dll" (
  echo ERROR: %RUNTIME% is missing the runtime files.
  echo Copy uplay_r1.dll, uplay_r164.dll, uplay_aux_r1.dll, uplay_aux_r164.dll,
  echo UbisoftGameLauncher*.exe and the discord-rpc / steam_api DLLs there first.
  echo The uplay_aux pair is what Denuvo titles need.
  pause
  exit /b 1
)

reg add "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir /t REG_SZ /d "%RUNTIME%" /f
reg add "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir /t REG_SZ /d "%RUNTIME%" /f /reg:32

echo.
echo Now points at: %RUNTIME%
reg query "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir
echo.
echo To restore the official client, run fix_registry.cmd.
pause
