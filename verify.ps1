<#
.SYNOPSIS
    Checks that TrafficMonitor no longer uses WinRing0 and that sensors are read through PawnIO.
    Run from an elevated PowerShell for the full check (sensor reading needs admin rights).
    Use -Json to emit structured diagnostic output for automated health monitors.
    Use -ExportReport <path> to write an HTML (.html) or Markdown (.md) diagnostic health card.
#>
[CmdletBinding()]
param(
    [string]$TrafficMonitorPath,
    [switch]$Json,
    [switch]$SelfTest,
    [string]$ExportReport
)

function Ok($m)   { if (-not $Json) { Write-Host "[OK] $m" -ForegroundColor Green } }
function Bad($m)  { if (-not $Json) { Write-Host "[X]  $m" -ForegroundColor Red }; $script:failed = $true; $script:errors += $m }
function Info($m) { if (-not $Json) { Write-Host "[*]  $m" } }
$failed = $false
$errors = @()

function Export-HealthReport($report, [string]$outPath) {
    if (-not $outPath) { return }
    $parent = Split-Path -Path $outPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $statusLabel = if ($report.ok) { 'HEALTHY' } else { 'ACTION REQUIRED' }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    if ($outPath -match '\.(md|markdown)$') {
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add('# TrafficMonitor PawnIO Diagnostic Health Card')
        [void]$lines.Add('')
        [void]$lines.Add("- **Status:** $statusLabel")
        [void]$lines.Add("- **Generated:** $ts")
        if ($report.self_test) {
            [void]$lines.Add('- **Mode:** SelfTest')
            [void]$lines.Add("- **Clean DLL Passes:** $($report.checks.clean_dll_passes)")
            [void]$lines.Add("- **WinRing0 DLL Detected:** $($report.checks.winring0_dll_detected)")
        } else {
            [void]$lines.Add("- **Admin Elevated:** $($report.is_admin)")
            [void]$lines.Add("- **Install Path:** ``$($report.traffic_monitor.path)``")
            [void]$lines.Add("- **LibreHardwareMonitorLib Version:** $($report.traffic_monitor.lhm_version)")
            [void]$lines.Add("- **Embeds WinRing0:** $($report.traffic_monitor.embeds_winring0)")
            [void]$lines.Add("- **R0TrafficMonitor Service:** $($report.winring0.service_present)")
            [void]$lines.Add("- **TrafficMonitor.sys Present:** $($report.winring0.driver_file_present)")
            [void]$lines.Add("- **PawnIO Installed:** $($report.pawnio.installed) ($($report.pawnio.state))")
            [void]$lines.Add("- **Backup Count:** $($report.backup.count)")
        }
        if ($report.sensors -and $report.sensors.Count -gt 0) {
            [void]$lines.Add('')
            [void]$lines.Add('## Sensor Readings')
            foreach ($s in $report.sensors) { [void]$lines.Add("- $s") }
        }
        if ($report.errors -and $report.errors.Count -gt 0) {
            [void]$lines.Add('')
            [void]$lines.Add('## Errors')
            foreach ($e in $report.errors) { [void]$lines.Add("- $e") }
        }
        ($lines -join "`n") | Out-File -LiteralPath $outPath -Encoding utf8
        return
    }
    $badgeBg = if ($report.ok) { '#065f46' } else { '#991b1b' }
    $rows = New-Object System.Collections.ArrayList
    if ($report.self_test) {
        [void]$rows.Add('<tr><td>Mode</td><td>SelfTest</td></tr>')
        [void]$rows.Add("<tr><td>Clean DLL Passes</td><td>$($report.checks.clean_dll_passes)</td></tr>")
        [void]$rows.Add("<tr><td>WinRing0 DLL Detected</td><td>$($report.checks.winring0_dll_detected)</td></tr>")
    } else {
        [void]$rows.Add("<tr><td>Install Path</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$report.traffic_monitor.path))</td></tr>")
        [void]$rows.Add("<tr><td>LibreHardwareMonitorLib</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$report.traffic_monitor.lhm_version))</td></tr>")
        [void]$rows.Add("<tr><td>Embeds WinRing0</td><td>$($report.traffic_monitor.embeds_winring0)</td></tr>")
        [void]$rows.Add("<tr><td>R0TrafficMonitor Service</td><td>$($report.winring0.service_present)</td></tr>")
        [void]$rows.Add("<tr><td>TrafficMonitor.sys</td><td>$($report.winring0.driver_file_present)</td></tr>")
        [void]$rows.Add("<tr><td>PawnIO Driver</td><td>$($report.pawnio.installed) ($([System.Net.WebUtility]::HtmlEncode([string]$report.pawnio.state)))</td></tr>")
        [void]$rows.Add("<tr><td>Backups</td><td>$($report.backup.count)</td></tr>")
    }
    if ($report.sensors -and $report.sensors.Count -gt 0) {
        $sensorTxt = ($report.sensors | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) }) -join '<br>'
        [void]$rows.Add("<tr><td>Sensors</td><td>$sensorTxt</td></tr>")
    }
    if ($report.errors -and $report.errors.Count -gt 0) {
        $errTxt = ($report.errors | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) }) -join '; '
        [void]$rows.Add("<tr><td>Errors</td><td>$errTxt</td></tr>")
    }
    $rowHtml = $rows -join "`n"
    $html = "<!doctype html><html><head><meta charset='utf-8'><title>TrafficMonitor PawnIO Health Card</title><style>body{font-family:sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border:1px solid #334155;padding:8px;text-align:left;font-size:13px}th{background:#1e293b}.badge{display:inline-block;padding:6px 12px;border-radius:6px;background:$badgeBg;color:#fff;font-weight:bold}</style></head><body><h1>TrafficMonitor PawnIO Diagnostic Health Card</h1><div class='badge'>$statusLabel | $ts</div><table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>$rowHtml</tbody></table></body></html>"
    $html | Out-File -LiteralPath $outPath -Encoding utf8
}

if ($SelfTest) {
    $cleanBytes = [Text.Encoding]::ASCII.GetBytes('LibreHardwareMonitor.PawnIO.Driver')
    $dirtyBytes = [Text.Encoding]::ASCII.GetBytes('LibreHardwareMonitor.WinRing0.Driver')
    $cleanTxt = [Text.Encoding]::ASCII.GetString($cleanBytes) + [Text.Encoding]::Unicode.GetString($cleanBytes)
    $dirtyTxt = [Text.Encoding]::ASCII.GetString($dirtyBytes) + [Text.Encoding]::Unicode.GetString($dirtyBytes)
    $cleanPass = -not [bool]($cleanTxt -match 'WinRing0')
    $dirtyPass = [bool]($dirtyTxt -match 'WinRing0')
    $selfTestOk = [bool]($cleanPass -and $dirtyPass)
    if (-not $selfTestOk) { Bad 'SelfTest WinRing0 signature detection failed' }
    else { Ok 'SelfTest WinRing0 signature detection passed' }
    $selfReport = [ordered]@{
        ok = $selfTestOk
        self_test = $true
        checks = [ordered]@{
            clean_dll_passes = $cleanPass
            winring0_dll_detected = $dirtyPass
        }
        errors = $errors
    }
    if ($ExportReport) {
        Export-HealthReport $selfReport $ExportReport
        Info "Diagnostic health card exported to $ExportReport"
    }
    if ($Json) {
        $selfReport | ConvertTo-Json -Depth 4
    }
    if ($selfTestOk) { exit 0 } else { exit 1 }
}

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
    $missingReport = [ordered]@{
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
    }
    if ($ExportReport) {
        Export-HealthReport $missingReport $ExportReport
        Info "Diagnostic health card exported to $ExportReport"
    }
    if ($Json) {
        $missingReport | ConvertTo-Json -Depth 4
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

$fullReport = [ordered]@{
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
}

if ($ExportReport) {
    Export-HealthReport $fullReport $ExportReport
    Info "Diagnostic health card exported to $ExportReport"
}

if ($Json) {
    $fullReport | ConvertTo-Json -Depth 4
    if ($failed) { exit 1 }
    exit 0
}

if ($failed) { Write-Host "`nSome checks failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green

