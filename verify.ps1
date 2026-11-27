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

[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
[Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::InvariantCulture

function Ok($m)   { if (-not $Json) { Write-Host "[OK] $m" -ForegroundColor Green } }
function Bad($m)  { if (-not $Json) { Write-Host "[X]  $m" -ForegroundColor Red }; $script:failed = $true; $script:errors += $m }
function Info($m) { if (-not $Json) { Write-Host "[*]  $m" } }
$failed = $false
$errors = @()

function Test-SafePath([string]$PathValue, [string]$ParamName = 'Path') {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { throw "Invalid ${ParamName}: path cannot be empty." }
    if ($PathValue -match '[\x00-\x1f]') { throw "Invalid ${ParamName}: control characters are not allowed." }
    if ($PathValue -match '(^|[\\/])\.\.([\\/]|$)') { throw "Invalid ${ParamName}: path traversal ('..') is not allowed." }
    $trimmed = $PathValue.Trim()
    if ($trimmed -match '^\\\\[.?]\\') { throw "Invalid ${ParamName}: Windows device paths are not allowed." }
    return $trimmed
}

function ConvertTo-SafeHtml([object]$Value) {
    if ($null -eq $Value) { return '' }
    $clean = ([string]$Value -replace '[\x00-\x08\x0b\x0c\x0e-\x1f]', '')
    $encoded = [System.Net.WebUtility]::HtmlEncode($clean)
    return ($encoded -replace "'", '&#39;')
}

function ConvertTo-SafeMarkdown([object]$Value) {
    if ($null -eq $Value) { return '' }
    $s = ([string]$Value -replace '[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]', ' ').Trim()
    $s = $s -replace '\\', '\\'
    $s = $s -replace '([`*_[\]<>|])', '\$1'
    return $s
}

function Get-DriverStatus([string[]]$Names) {
    foreach ($name in $Names) {
        if ($name -notmatch '^[A-Za-z0-9._-]+$') { continue }
        $drv = Get-CimInstance Win32_SystemDriver -Filter "Name='$name'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($drv) { return $drv }
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc) { return [pscustomobject]@{ Name = $svc.Name; State = "$($svc.Status)" } }
    }
    return $null
}

if ($ExportReport) {
    $ExportReport = Test-SafePath $ExportReport 'ExportReport'
}

function Export-HealthReport($report, [string]$outPath) {
    if (-not $outPath) { return }
    $outPath = Test-SafePath $outPath 'ExportReport'
    $resolvedInput = if (-not [IO.Path]::IsPathRooted($outPath) -and $PWD -and $PWD.Provider.Name -eq 'FileSystem') { Join-Path $PWD.ProviderPath $outPath } else { $outPath }
    $fullOutPath = [IO.Path]::GetFullPath($resolvedInput)
    if (([IO.File]::Exists($fullOutPath) -or [IO.Directory]::Exists($fullOutPath)) -and (([IO.File]::GetAttributes($fullOutPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Invalid ExportReport: symbolic links and reparse points are not allowed."
    }
    if ([IO.Directory]::Exists($fullOutPath)) {
        throw "Invalid ExportReport: expected a file path, got a directory ($fullOutPath)."
    }
    $parent = Split-Path -Path $fullOutPath -Parent
    if ($parent -and [IO.Directory]::Exists($parent) -and (([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Invalid ExportReport: parent directory cannot be a symbolic link or reparse point."
    }
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $statusLabel = if ($report.ok) { 'HEALTHY' } else { 'ACTION REQUIRED' }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
    $computerName = if ($report.computer_name) { $report.computer_name } elseif ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'unknown' }
    if ($fullOutPath -match '\.(md|markdown)$') {
        $lines = New-Object System.Collections.ArrayList
        [void]$lines.Add('# TrafficMonitor PawnIO Diagnostic Health Card')
        [void]$lines.Add('')
        [void]$lines.Add("- **Status:** $(ConvertTo-SafeMarkdown $statusLabel)")
        [void]$lines.Add("- **Computer:** $(ConvertTo-SafeMarkdown $computerName)")
        [void]$lines.Add("- **Generated:** $(ConvertTo-SafeMarkdown $ts)")
        if ($report.self_test) {
            [void]$lines.Add('- **Mode:** SelfTest')
            [void]$lines.Add("- **Clean DLL Passes:** $([bool]$report.checks.clean_dll_passes)")
            [void]$lines.Add("- **WinRing0 DLL Detected:** $([bool]$report.checks.winring0_dll_detected)")
        } else {
            [void]$lines.Add("- **Admin Elevated:** $([bool]$report.is_admin)")
            [void]$lines.Add("- **Install Path:** ``$(ConvertTo-SafeMarkdown $report.traffic_monitor.path)``")
            [void]$lines.Add("- **TrafficMonitor Version:** $(ConvertTo-SafeMarkdown $report.traffic_monitor.exe_version)")
            [void]$lines.Add("- **LibreHardwareMonitorLib Version:** $(ConvertTo-SafeMarkdown $report.traffic_monitor.lhm_version)")
            [void]$lines.Add("- **Embeds WinRing0:** $(ConvertTo-SafeMarkdown $report.traffic_monitor.embeds_winring0)")
            $r0SvcMdDetail = if ($report.winring0.service_name) { " ($(ConvertTo-SafeMarkdown $report.winring0.service_name))" } else { '' }
            [void]$lines.Add("- **R0TrafficMonitor Service:** $([bool]$report.winring0.service_present)$r0SvcMdDetail")
            [void]$lines.Add("- **TrafficMonitor.sys Present:** $([bool]$report.winring0.driver_file_present)")
            [void]$lines.Add("- **PawnIO Installed:** $([bool]$report.pawnio.installed) ($(ConvertTo-SafeMarkdown $report.pawnio.state))")
            [void]$lines.Add("- **Backup Count:** $([int]$report.backup.count)")
            if ($report.backup.latest_path) {
                [void]$lines.Add("- **Latest Backup:** ``$(ConvertTo-SafeMarkdown $report.backup.latest_path)``")
            }
        }
        if ($report.sensors -and $report.sensors.Count -gt 0) {
            [void]$lines.Add('')
            [void]$lines.Add('## Sensor Readings')
            foreach ($s in $report.sensors) { [void]$lines.Add("- $(ConvertTo-SafeMarkdown $s)") }
        }
        if ($report.errors -and $report.errors.Count -gt 0) {
            [void]$lines.Add('')
            [void]$lines.Add('## Errors')
            foreach ($e in $report.errors) { [void]$lines.Add("- $(ConvertTo-SafeMarkdown $e)") }
        }
        ($lines -join "`n") | Out-File -LiteralPath $fullOutPath -Encoding utf8
        return
    }
    $badgeBg = if ($report.ok) { '#065f46' } else { '#991b1b' }
    $rows = New-Object System.Collections.ArrayList
    [void]$rows.Add("<tr><td>Computer Name</td><td>$(ConvertTo-SafeHtml $computerName)</td></tr>")
    if ($report.self_test) {
        [void]$rows.Add('<tr><td>Mode</td><td>SelfTest</td></tr>')
        [void]$rows.Add("<tr><td>Clean DLL Passes</td><td>$(ConvertTo-SafeHtml $report.checks.clean_dll_passes)</td></tr>")
        [void]$rows.Add("<tr><td>WinRing0 DLL Detected</td><td>$(ConvertTo-SafeHtml $report.checks.winring0_dll_detected)</td></tr>")
    } else {
        [void]$rows.Add("<tr><td>Admin Elevated</td><td>$(ConvertTo-SafeHtml $report.is_admin)</td></tr>")
        [void]$rows.Add("<tr><td>Install Path</td><td>$(ConvertTo-SafeHtml $report.traffic_monitor.path)</td></tr>")
        [void]$rows.Add("<tr><td>TrafficMonitor Version</td><td>$(ConvertTo-SafeHtml $report.traffic_monitor.exe_version)</td></tr>")
        [void]$rows.Add("<tr><td>LibreHardwareMonitorLib</td><td>$(ConvertTo-SafeHtml $report.traffic_monitor.lhm_version)</td></tr>")
        [void]$rows.Add("<tr><td>Embeds WinRing0</td><td>$(ConvertTo-SafeHtml $report.traffic_monitor.embeds_winring0)</td></tr>")
        $r0SvcDetail = if ($report.winring0.service_name) { " ($(ConvertTo-SafeHtml $report.winring0.service_name))" } else { '' }
        [void]$rows.Add("<tr><td>R0TrafficMonitor Service</td><td>$(ConvertTo-SafeHtml $report.winring0.service_present)$r0SvcDetail</td></tr>")
        [void]$rows.Add("<tr><td>TrafficMonitor.sys</td><td>$(ConvertTo-SafeHtml $report.winring0.driver_file_present)</td></tr>")
        [void]$rows.Add("<tr><td>PawnIO Driver</td><td>$(ConvertTo-SafeHtml $report.pawnio.installed) ($(ConvertTo-SafeHtml $report.pawnio.state))</td></tr>")
        [void]$rows.Add("<tr><td>Backups</td><td>$(ConvertTo-SafeHtml $report.backup.count)</td></tr>")
        if ($report.backup.latest_path) {
            [void]$rows.Add("<tr><td>Latest Backup</td><td>$(ConvertTo-SafeHtml $report.backup.latest_path)</td></tr>")
        }
    }
    if ($report.sensors -and $report.sensors.Count -gt 0) {
        $sensorTxt = ($report.sensors | ForEach-Object { ConvertTo-SafeHtml $_ }) -join '<br>'
        [void]$rows.Add("<tr><td>Sensors</td><td>$sensorTxt</td></tr>")
    }
    if ($report.errors -and $report.errors.Count -gt 0) {
        $errTxt = ($report.errors | ForEach-Object { ConvertTo-SafeHtml $_ }) -join '; '
        [void]$rows.Add("<tr><td>Errors</td><td>$errTxt</td></tr>")
    }
    $rowHtml = $rows -join "`n"
    $safeBadge = "$(ConvertTo-SafeHtml $statusLabel) | $(ConvertTo-SafeHtml $ts)"
    $cspMeta = "<meta http-equiv=`"Content-Security-Policy`" content=`"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none';`">"
    $html = "<!doctype html><html><head><meta charset=`"utf-8`">$cspMeta<title>TrafficMonitor PawnIO Health Card</title><style>body{font-family:sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border:1px solid #334155;padding:8px;text-align:left;font-size:13px}th{background:#1e293b}.badge{display:inline-block;padding:6px 12px;border-radius:6px;background:$badgeBg;color:#fff;font-weight:bold}</style></head><body><h1>TrafficMonitor PawnIO Diagnostic Health Card</h1><div class=`"badge`">$safeBadge</div><table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>$rowHtml</tbody></table></body></html>"
    $html | Out-File -LiteralPath $fullOutPath -Encoding utf8
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
        computer_name = $env:COMPUTERNAME
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
$TrafficMonitorPath = Test-SafePath $TrafficMonitorPath 'TrafficMonitorPath'

$tmExe = Join-Path $TrafficMonitorPath 'TrafficMonitor.exe'
$tmExePresent = Test-Path -LiteralPath $tmExe
$tmExeVersion = if ($tmExePresent) { (Get-Item -LiteralPath $tmExe).VersionInfo.FileVersion } else { $null }
$backups = @(Get-ChildItem -LiteralPath $TrafficMonitorPath -Directory -Filter '_backup_lhm_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
$latestBackup = if ($backups.Count -gt 0) { $backups[0].FullName } else { $null }

$r0Driver = Get-DriverStatus @('R0TrafficMonitor', 'WinRing0_1_2_0')
$r0ServicePresent = [bool]$r0Driver
$sysFilePresent = Test-Path -LiteralPath (Join-Path $TrafficMonitorPath 'TrafficMonitor.sys')
$pawn = Get-DriverStatus @('PawnIO')

$lhm = Join-Path $TrafficMonitorPath 'LibreHardwareMonitorLib.dll'
if (-not (Test-Path -LiteralPath $lhm)) {
    Bad "LibreHardwareMonitorLib.dll not found in $TrafficMonitorPath"
    if ($r0ServicePresent) { Bad "WinRing0 service ($($r0Driver.Name)) exists" }
    else { Ok 'No WinRing0 service (R0TrafficMonitor / WinRing0_1_2_0)' }
    if ($sysFilePresent) { Bad 'WinRing0 driver file TrafficMonitor.sys present' }
    else { Ok 'No WinRing0 driver file (TrafficMonitor.sys)' }
    if ($pawn) { Ok "PawnIO driver installed ($($pawn.State))" }
    else { Bad 'PawnIO driver not installed' }
    $missingReport = [ordered]@{
        ok = $false
        computer_name = $env:COMPUTERNAME
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
            service_present = $r0ServicePresent
            service_name = if ($r0Driver) { "$($r0Driver.Name)" } else { $null }
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
$ver = (Get-Item -LiteralPath $lhm).VersionInfo.FileVersion
$raw = [IO.File]::ReadAllBytes($lhm)
$txt = [Text.Encoding]::ASCII.GetString($raw) + [Text.Encoding]::Unicode.GetString($raw)
$embedsWinRing0 = [bool]($txt -match 'WinRing0')
if ($embedsWinRing0) { Bad "LibreHardwareMonitorLib $ver still embeds WinRing0 (TrafficMonitor update reverted the fix?)" }
else { Ok "LibreHardwareMonitorLib $ver does not embed WinRing0" }

if ($r0ServicePresent) { Bad "WinRing0 service ($($r0Driver.Name)) exists" }
else { Ok 'No WinRing0 service (R0TrafficMonitor / WinRing0_1_2_0)' }

if ($sysFilePresent) { Bad 'WinRing0 driver file TrafficMonitor.sys present' }
else { Ok 'No WinRing0 driver file (TrafficMonitor.sys)' }

if ($pawn) { Ok "PawnIO driver installed ($($pawn.State))" } else { Bad 'PawnIO driver not installed' }

$sensorReadings = @()
if (-not $isAdmin) {
    Info 'Not elevated: skipping sensor test. Re-run as administrator for the full check.'
} else {
    # Read sensors with a copy of the installed library (does not lock TrafficMonitor's files)
    $tmp = Join-Path $env:TEMP ('tm-verify-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        Copy-Item -Path (Join-Path $TrafficMonitorPath '*.dll') -Destination $tmp -Force
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
        $tf = Join-Path $tmp 'test.ps1'; Set-Content -LiteralPath $tf -Value $test -Encoding UTF8
        $res = & powershell -NoProfile -ExecutionPolicy Bypass -File "$tf" "$tmp" 2>&1
        $sensorReadings = @($res | ForEach-Object { "$_" })
        if ($res | Where-Object { $_ -match '^Cpu \|' }) { Ok 'CPU temperature read through PawnIO:'; if (-not $Json) { $res | ForEach-Object { Write-Host "       $_" } } }
        else { Bad 'Could not read CPU temperature'; if (-not $Json) { $res | ForEach-Object { Write-Host "       $_" } } }
    } finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $recreatedR0 = Get-DriverStatus @('R0TrafficMonitor', 'WinRing0_1_2_0')
    if ($recreatedR0) {
        $r0Driver = $recreatedR0
        $r0ServicePresent = $true
        Bad 'WinRing0 service was recreated during the test'
    }
}

$fullReport = [ordered]@{
    ok = (-not $failed)
    computer_name = $env:COMPUTERNAME
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
        service_name = if ($r0Driver) { "$($r0Driver.Name)" } else { $null }
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

