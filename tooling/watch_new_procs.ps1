# Poll for newly created processes and log their full command line.
# Used to capture exactly how the Ubisoft client bootstraps the game and EasyAntiCheat,
# without relying on hooks in a single process.
param([int]$Seconds = 900)

$out = "D:\Projects\ubisoft-re\evidence\wd2_launch_procs.log"
$known = @{}
Get-CimInstance Win32_Process | ForEach-Object { $known[[uint32]$_.ProcessId] = $true }

$deadline = (Get-Date).AddSeconds($Seconds)
"# watch started " + (Get-Date -Format "HH:mm:ss") | Out-File -FilePath $out -Encoding utf8
while ((Get-Date) -lt $deadline) {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $id = [uint32]$_.ProcessId
        if (-not $known.ContainsKey($id)) {
            $known[$id] = $true
            $line = (Get-Date -Format "HH:mm:ss.fff") + "  pid=" + $id + "  ppid=" + $_.ParentProcessId + "  " + $_.Name + "  |  " + $_.CommandLine
            if ($_.Name -match 'WatchDogs|EAC|EasyAnti|Ubisoft|upc|uplay|dllhost|GameStarter') {
                Add-Content -Path $out -Value $line -Encoding utf8
            }
        }
    }
    Start-Sleep -Milliseconds 200
}
"# watch ended " + (Get-Date -Format "HH:mm:ss") | Add-Content -Path $out -Encoding utf8
