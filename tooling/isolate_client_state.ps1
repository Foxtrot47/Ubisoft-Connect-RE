param(
    [Parameter(Mandatory=$true)][ValidateSet('Isolate','Restore')][string]$Action,
    [Parameter(Mandatory=$true)][string]$Journal
)
$ErrorActionPreference = 'Stop'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
if ($Action -eq 'Restore') {
    $state = Get-Content -LiteralPath $Journal -Raw | ConvertFrom-Json
    $generated = @()
    $reverse = @($state.directories)
    [array]::Reverse($reverse)
    foreach ($item in $reverse) {
        if (!(Test-Path -LiteralPath $item.backup)) { continue }
        if (Test-Path -LiteralPath $item.original) {
            $fresh = $item.original + '_POC_GENERATED_' + $stamp
            Move-Item -LiteralPath $item.original -Destination $fresh
            $generated += $fresh
        }
        Move-Item -LiteralPath $item.backup -Destination $item.original
    }
    $state.restore_needed = $false
    $state | Add-Member -NotePropertyName preserved_generated_directories -NotePropertyValue $generated -Force
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Journal -Encoding UTF8
    exit 0
}
$paths = @(
    (Join-Path $env:LOCALAPPDATA 'Ubisoft Game Launcher'),
    (Join-Path $env:APPDATA 'Ubisoft Game Launcher'),
    (Join-Path $env:PROGRAMDATA 'Ubisoft\Ubisoft Game Launcher'),
    (Join-Path ${env:ProgramFiles(x86)} 'Ubisoft\Ubisoft Game Launcher'),
    (Join-Path $env:ProgramFiles 'Ubisoft\Ubisoft Game Launcher')
) | Select-Object -Unique
$state = [ordered]@{status='preparing'; restore_needed=$false; directories=@()}
try {
    foreach ($path in $paths) {
        if (!(Test-Path -LiteralPath $path -PathType Container)) { continue }
        $backup = $path + '_POC_ISOLATED_' + $stamp
        Move-Item -LiteralPath $path -Destination $backup
        $state.directories += @{original=$path; backup=$backup}
        $state.restore_needed = $true
        $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Journal -Encoding UTF8
    }
    $state.status = 'isolated'
} catch {
    $state.status = 'failed'
    $state.error_type = $_.Exception.GetType().Name
    $rollbackFailed = $false
    $reverse = @($state.directories)
    [array]::Reverse($reverse)
    foreach ($item in $reverse) {
        if ((Test-Path -LiteralPath $item.backup) -and !(Test-Path -LiteralPath $item.original)) {
            try { Move-Item -LiteralPath $item.backup -Destination $item.original }
            catch { $rollbackFailed = $true }
        }
    }
    $state.restore_needed = $rollbackFailed
}
$state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Journal -Encoding UTF8
if ($state.status -ne 'isolated') { exit 1 }
