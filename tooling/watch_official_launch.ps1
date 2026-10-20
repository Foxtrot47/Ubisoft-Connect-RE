# Record an official Ubisoft Connect launch with extra launch arguments.
#
# Catches: new processes + command lines, every window owned by anything under the
# game folder (SplashScreen.exe included - that is the "banner"), EAC.log updates,
# and GPU utilisation for the game pids.
param([int]$Minutes = 25)

$out = "D:\Projects\ubisoft-re\evidence\official_flag_test.log"
$eacLog = "C:\Users\foxtrot47\Documents\My Games\Watch_Dogs 2\EAC.log"

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class Win {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  public struct RECT { public int L, T, R, B; }
  public static string Dump(HashSet<string> pids) {
    var sb = new StringBuilder();
    EnumWindows((h,l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      if (pids.Contains(pid.ToString())) {
        var t = new StringBuilder(256); GetWindowTextW(h, t, 256);
        var c = new StringBuilder(256); GetClassNameW(h, c, 256);
        RECT r; GetWindowRect(h, out r);
        sb.AppendLine("    pid=" + pid + " hwnd=0x" + h.ToString("X") + " vis=" + IsWindowVisible(h)
          + " size=" + (r.R-r.L) + "x" + (r.B-r.T) + " class='" + c + "' title='" + t + "'");
      }
      return true;
    }, IntPtr.Zero);
    return sb.ToString();
  }
}
"@

function Log($m) { $line = (Get-Date -Format "HH:mm:ss.fff") + "  " + $m; Add-Content -Path $out -Value $line -Encoding utf8; Write-Output $line }

"# watcher started $(Get-Date -Format 'HH:mm:ss') - waiting for an official launch" | Out-File -FilePath $out -Encoding utf8

$eacBefore = if (Test-Path $eacLog) { (Get-Item $eacLog).LastWriteTime } else { [datetime]::MinValue }
$known = @{}
$gamePids = @{}
$seenWins = @{}
$end = (Get-Date).AddMinutes($Minutes)

while ((Get-Date) -lt $end) {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $id = [uint32]$_.ProcessId
        if (-not $known.ContainsKey($id)) {
            $known[$id] = $true
            $exe = $_.ExecutablePath
            $isGameFile = $exe -and $exe.StartsWith("E:\Games\WATCH_DOGS2", "OrdinalIgnoreCase")
            if ($isGameFile -or $_.Name -match '^(WatchDogs2|SplashScreen|EAC|EasyAntiCheat|UbisoftGameLauncher|upc)$') {
                Log ("proc pid=" + $id + " ppid=" + $_.ParentProcessId + " " + $_.Name + " | " + $_.CommandLine)
                if ($isGameFile) { $gamePids["$id"] = $true }
            }
            # also catch the official launcher passing arguments
            if ($_.CommandLine -and $_.CommandLine -match 'eac_launcher|-eac') {
                Log ("ARGS! pid=" + $id + " " + $_.Name + " | " + $_.CommandLine)
            }
        }
    }
    if ($gamePids.Count -gt 0) {
        $w = [Win]::Dump([System.Collections.Generic.HashSet[string]]$gamePids.Keys)
        if ($w) {
            foreach ($ln in ($w -split "`r?`n")) {
                if ($ln.Trim() -and -not $seenWins.ContainsKey($ln)) { $seenWins[$ln] = $true; Log ("WINDOW" + $ln) }
            }
        }
    }
    if ((Test-Path $eacLog) -and (Get-Item $eacLog).LastWriteTime -gt $eacBefore) {
        $eacBefore = (Get-Item $eacLog).LastWriteTime
        Log "*** EAC.log UPDATED (EAC initialised) ***"
    }
    Start-Sleep -Milliseconds 500
}
"# watcher ended $(Get-Date -Format 'HH:mm:ss')" | Add-Content -Path $out -Encoding utf8
