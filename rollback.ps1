<#
.SYNOPSIS
    Restores the original LibreHardwareMonitorLib (and any DLL it overwrote) from the most recent
    backup made by install.ps1, and removes the DLLs that install.ps1 added.
    Run from an elevated PowerShell.
    Note: the original library will reinstall the vulnerable WinRing0 driver on next start.
#>
[CmdletBinding()]
param([string]$TrafficMonitorPath)
$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
[Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::InvariantCulture

function Test-SafePath([string]$PathValue, [string]$ParamName = 'Path') {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { Write-Host "[X] Invalid ${ParamName}: path cannot be empty." -ForegroundColor Red; exit 1 }
    if ($PathValue -match '[\x00-\x1f]') { Write-Host "[X] Invalid ${ParamName}: control characters are not allowed." -ForegroundColor Red; exit 1 }
    if ($PathValue -match '(^|[\\/])\.\.([\\/]|$)') { Write-Host "[X] Invalid ${ParamName}: path traversal ('..') is not allowed." -ForegroundColor Red; exit 1 }
    return $PathValue.Trim()
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host '[X] Run from an elevated PowerShell.' -ForegroundColor Red; exit 1 }

if (-not $TrafficMonitorPath) {
    $proc = Get-Process TrafficMonitor -ErrorAction SilentlyContinue | Select-Object -First 1
    $exePath = $null
    if ($proc) { try { $exePath = $proc.Path } catch {} }
    $TrafficMonitorPath = if ($exePath) { Split-Path $exePath } else { 'C:\Program Files\TrafficMonitor' }
}
$TrafficMonitorPath = Test-SafePath $TrafficMonitorPath 'TrafficMonitorPath'
$tmDirFull = [IO.Path]::GetFullPath($TrafficMonitorPath).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar

$backup = Get-ChildItem -LiteralPath $TrafficMonitorPath -Directory -Filter '_backup_lhm_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
if (-not $backup) { Write-Host "[X] No _backup_lhm_* folder in $TrafficMonitorPath" -ForegroundColor Red; exit 1 }
Write-Host "[*] Restoring from $($backup.FullName)"

$wasRunning = [bool](Get-Process TrafficMonitor -ErrorAction SilentlyContinue)
if ($wasRunning) {
    taskkill /im TrafficMonitor.exe | Out-Null
    for ($i = 0; $i -lt 20 -and (Get-Process TrafficMonitor -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
    if (Get-Process TrafficMonitor -ErrorAction SilentlyContinue) { Stop-Process -Name TrafficMonitor -Force }
}

# Remove DLLs that were added (not present before), then restore the saved originals
$listFile = Join-Path $backup.FullName 'installed-files.txt'
if (Test-Path -LiteralPath $listFile) {
    foreach ($rawName in (Get-Content -LiteralPath $listFile)) {
        $name = ([string]$rawName).Trim()
        if (-not $name) { continue }
        if ($name -notmatch '^[A-Za-z0-9._-]+\.dll$') {
            Write-Host "[!] Skipping unsafe entry in installed-files.txt: '$name'" -ForegroundColor Yellow
            continue
        }
        $targetPath = [IO.Path]::GetFullPath((Join-Path $TrafficMonitorPath $name))
        if (-not $targetPath.StartsWith($tmDirFull, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "[!] Skipping out-of-directory entry in installed-files.txt: '$name'" -ForegroundColor Yellow
            continue
        }
        if (-not (Test-Path -LiteralPath (Join-Path $backup.FullName $name))) {
            Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
        }
    }
}
Get-ChildItem -LiteralPath $backup.FullName -Filter '*.dll' | ForEach-Object {
    if ($_.Name -notmatch '^[A-Za-z0-9._-]+\.dll$') { return }
    Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $TrafficMonitorPath $_.Name) -Force
}
Write-Host ("[OK] LibreHardwareMonitorLib {0} restored" -f (Get-Item -LiteralPath (Join-Path $TrafficMonitorPath 'LibreHardwareMonitorLib.dll')).VersionInfo.FileVersion) -ForegroundColor Green

if ($wasRunning) { Start-Process -FilePath (Join-Path $TrafficMonitorPath 'TrafficMonitor.exe') }
