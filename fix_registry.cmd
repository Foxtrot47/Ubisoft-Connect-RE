@echo off
REM Repair the Ubisoft registry entries used by the games and the launcher.
REM Right-click -> "Run as administrator".
REM
REM Puts the official client back in charge:
REM   1. un-renames "Ubisoft Game Launcher_OFF" if set_runtime_dir.cmd was used
REM   2. repairs the Launcher\InstallDir value (must point at a real directory)
REM   3. recreates the missing per-game InstallDir keys the WD2 installer never created

set "LAUNCHER=C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher"

if not exist "%LAUNCHER%" if exist "%LAUNCHER%_OFF" ren "%LAUNCHER%_OFF" "Ubisoft Game Launcher"
set "WD2=E:\Games\WATCH_DOGS2"

echo [1/4] Launcher InstallDir (64-bit view)
reg add "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir /t REG_SZ /d "%LAUNCHER%" /f
echo [2/4] Launcher InstallDir (32-bit view)
reg add "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir /t REG_SZ /d "%LAUNCHER%" /f /reg:32

echo [3/4] WatchDogs2 working-directory key (64-bit view)
reg add "HKLM\SOFTWARE\Ubisoft\WatchDogs2" /v InstallDir /t REG_SZ /d "%WD2%" /f
echo [4/4] WatchDogs2 working-directory key (32-bit view)
reg add "HKLM\SOFTWARE\Ubisoft\WatchDogs2" /v InstallDir /t REG_SZ /d "%WD2%" /f /reg:32

echo.
echo --- resulting values ---
reg query "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir
reg query "HKLM\SOFTWARE\Ubisoft\Launcher" /v InstallDir /reg:32
reg query "HKLM\SOFTWARE\Ubisoft\WatchDogs2" /v InstallDir
reg query "HKLM\SOFTWARE\Ubisoft\WatchDogs2" /v InstallDir /reg:32
echo.
pause
