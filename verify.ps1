<#
.SYNOPSIS
    Checks that TrafficMonitor no longer uses WinRing0 and that sensors are read through PawnIO.
    Run from an elevated PowerShell for the full check (sensor reading needs admin rights).
#>
[CmdletBinding()]
param([string]$TrafficMonitorPath)

function Ok($m)   { Write-Host "[OK] $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[X]  $m" -ForegroundColor Red; $script:failed = $true }
function Info($m) { Write-Host "[*]  $m" }
$failed = $false
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $TrafficMonitorPath) {
    $proc = Get-Process TrafficMonitor -ErrorAction SilentlyContinue | Select-Object -First 1
    $exePath = $null
    if ($proc) { try { $exePath = $proc.Path } catch {} }
    $TrafficMonitorPath = if ($exePath) { Split-Path $exePath } else { 'C:\Program Files\TrafficMonitor' }
}

$lhm = Join-Path $TrafficMonitorPath 'LibreHardwareMonitorLib.dll'
if (-not (Test-Path $lhm)) { Bad "LibreHardwareMonitorLib.dll not found in $TrafficMonitorPath"; exit 1 }
$ver = (Get-Item $lhm).VersionInfo.FileVersion
$raw = [IO.File]::ReadAllBytes($lhm)
$txt = [Text.Encoding]::ASCII.GetString($raw) + [Text.Encoding]::Unicode.GetString($raw)
if ($txt -match 'WinRing0') { Bad "LibreHardwareMonitorLib $ver still embeds WinRing0 (TrafficMonitor update reverted the fix?)" }
else { Ok "LibreHardwareMonitorLib $ver does not embed WinRing0" }

if (Get-CimInstance Win32_SystemDriver -Filter "Name='R0TrafficMonitor'" -ErrorAction SilentlyContinue) { Bad 'WinRing0 service R0TrafficMonitor exists' }
else { Ok 'No WinRing0 service (R0TrafficMonitor)' }
if (Test-Path (Join-Path $TrafficMonitorPath 'TrafficMonitor.sys')) { Bad 'WinRing0 driver file TrafficMonitor.sys present' }
else { Ok 'No WinRing0 driver file (TrafficMonitor.sys)' }

$pawn = Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue
if ($pawn) { Ok "PawnIO driver installed ($($pawn.State))" } else { Bad 'PawnIO driver not installed' }

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
    if ($res | Where-Object { $_ -match '^Cpu \|' }) { Ok 'CPU temperature read through PawnIO:'; $res | ForEach-Object { Write-Host "       $_" } }
    else { Bad 'Could not read CPU temperature'; $res | ForEach-Object { Write-Host "       $_" } }
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Get-CimInstance Win32_SystemDriver -Filter "Name='R0TrafficMonitor'" -ErrorAction SilentlyContinue) { Bad 'WinRing0 service was recreated during the test' }
}

if ($failed) { Write-Host "`nSome checks failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green
