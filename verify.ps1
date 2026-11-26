<#
.SYNOPSIS
    Checks that TrafficMonitor no longer uses WinRing0 and that sensors are read through PawnIO.
    Run from an elevated PowerShell for the full check (sensor reading needs admin rights).
    Use -Json to emit structured diagnostic output for automated health monitors.
#>
[CmdletBinding()]
param(
    [string]$TrafficMonitorPath,
    [switch]$Json
)

function Ok($m)   { if (-not $Json) { Write-Host "[OK] $m" -ForegroundColor Green } }
function Bad($m)  { if (-not $Json) { Write-Host "[X]  $m" -ForegroundColor Red }; $script:failed = $true; $script:errors += $m }
function Info($m) { if (-not $Json) { Write-Host "[*]  $m" } }
$failed = $false
$errors = @()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$proc = Get-Process TrafficMonitor -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $TrafficMonitorPath) {
    $exePath = $null
    if ($proc) { try { $exePath = $proc.Path } catch {} }
    $TrafficMonitorPath = if ($exePath) { Split-Path $exePath } else { 'C:\Program Files\TrafficMonitor' }
}

$tmExe = Join-Path $TrafficMonitorPath 'TrafficMonitor.exe'
$tmExePresent = Test-Path $tmExe
$tmExeVersion = if ($tmExePresent) { (Get-Item $tmExe).VersionInfo.FileVersion } else { $null }
$backups = @(Get-ChildItem $TrafficMonitorPath -Directory -Filter '_backup_lhm_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
$latestBackup = if ($backups.Count -gt 0) { $backups[0].FullName } else { $null }

$lhm = Join-Path $TrafficMonitorPath 'LibreHardwareMonitorLib.dll'
if (-not (Test-Path $lhm)) {
    Bad "LibreHardwareMonitorLib.dll not found in $TrafficMonitorPath"
    if ($Json) {
        [ordered]@{
            ok = $false
            is_admin = $isAdmin
            traffic_monitor = [ordered]@{
                path = $TrafficMonitorPath
                exe_present = $tmExePresent
                exe_version = $tmExeVersion
                running = [bool]$proc
                lhm_present = $false
                lhm_version = $null
                embeds_winring0 = $null
            }
            winring0 = [ordered]@{
                service_present = $false
                driver_file_present = (Test-Path (Join-Path $TrafficMonitorPath 'TrafficMonitor.sys'))
            }
            pawnio = [ordered]@{
                installed = $false
                state = $null
            }
            backup = [ordered]@{
                present = ($backups.Count -gt 0)
                count = $backups.Count
                latest_path = $latestBackup
            }
            errors = $errors
        } | ConvertTo-Json -Depth 4
    }
    exit 1
}
$ver = (Get-Item $lhm).VersionInfo.FileVersion
$raw = [IO.File]::ReadAllBytes($lhm)
$txt = [Text.Encoding]::ASCII.GetString($raw) + [Text.Encoding]::Unicode.GetString($raw)
$embedsWinRing0 = [bool]($txt -match 'WinRing0')
if ($embedsWinRing0) { Bad "LibreHardwareMonitorLib $ver still embeds WinRing0 (TrafficMonitor update reverted the fix?)" }
else { Ok "LibreHardwareMonitorLib $ver does not embed WinRing0" }

$r0ServicePresent = [bool](Get-CimInstance Win32_SystemDriver -Filter "Name='R0TrafficMonitor'" -ErrorAction SilentlyContinue)
if ($r0ServicePresent) { Bad 'WinRing0 service R0TrafficMonitor exists' }
else { Ok 'No WinRing0 service (R0TrafficMonitor)' }

$sysFilePresent = Test-Path (Join-Path $TrafficMonitorPath 'TrafficMonitor.sys')
if ($sysFilePresent) { Bad 'WinRing0 driver file TrafficMonitor.sys present' }
else { Ok 'No WinRing0 driver file (TrafficMonitor.sys)' }

$pawn = Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue
if ($pawn) { Ok "PawnIO driver installed ($($pawn.State))" } else { Bad 'PawnIO driver not installed' }

$sensorReadings = @()
if (-not $isAdmin) {
    Info 'Not elevated: skipping sensor test. Re-run as administrator for the full check.'
} else {
    # Read sensors with a copy of the installed library (does not lock TrafficMonitor's files)
    $tmp = Join-Path $env:TEMP ('tm-verify-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    Copy-Item (Join-Path $TrafficMonitorPath '*.dll') $tmp -Force
    $test = @'
param($dir)
Add-Type -Path (Join-Path $dir 'LibreHardwareMonitorLib.dll')
$c = New-Object LibreHardwareMonitor.Hardware.Computer
$c.IsCpuEnabled = $true; $c.IsGpuEnabled = $true; $c.IsStorageEnabled = $true
$c.Open()
foreach ($h in $c.Hardware) {
  $h.Update()
  $t = $h.Sensors | Where-Object { $_.SensorType -eq [LibreHardwareMonitor.Hardware.SensorType]::Temperature -and $_.Value } | Select-Object -First 2
  foreach ($s in $t) { '{0} | {1} | {2} = {3:N1} C' -f $h.HardwareType, $h.Name.Trim(), $s.Name, $s.Value }
}
$c.Close()
'@
    $tf = Join-Path $tmp 'test.ps1'; Set-Content $tf $test -Encoding UTF8
    $res = & powershell -NoProfile -ExecutionPolicy Bypass -File $tf $tmp 2>&1
    $sensorReadings = @($res | ForEach-Object { "$_" })
    if ($res | Where-Object { $_ -match '^Cpu \|' }) { Ok 'CPU temperature read through PawnIO:'; if (-not $Json) { $res | ForEach-Object { Write-Host "       $_" } } }
    else { Bad 'Could not read CPU temperature'; if (-not $Json) { $res | ForEach-Object { Write-Host "       $_" } } }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Get-CimInstance Win32_SystemDriver -Filter "Name='R0TrafficMonitor'" -ErrorAction SilentlyContinue) {
        $r0ServicePresent = $true
        Bad 'WinRing0 service was recreated during the test'
    }
}

if ($Json) {
    [ordered]@{
        ok = (-not $failed)
        is_admin = $isAdmin
        traffic_monitor = [ordered]@{
            path = $TrafficMonitorPath
            exe_present = $tmExePresent
            exe_version = $tmExeVersion
            running = [bool]$proc
            lhm_present = $true
            lhm_version = $ver
            embeds_winring0 = $embedsWinRing0
        }
        winring0 = [ordered]@{
            service_present = $r0ServicePresent
            driver_file_present = $sysFilePresent
        }
        pawnio = [ordered]@{
            installed = [bool]$pawn
            state = if ($pawn) { "$($pawn.State)" } else { $null }
        }
        backup = [ordered]@{
            present = ($backups.Count -gt 0)
            count = $backups.Count
            latest_path = $latestBackup
        }
        sensors = $sensorReadings
        errors = $errors
    } | ConvertTo-Json -Depth 4
    if ($failed) { exit 1 }
    exit 0
}

if ($failed) { Write-Host "`nSome checks failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green

