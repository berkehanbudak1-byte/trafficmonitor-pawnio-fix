<#
.SYNOPSIS
    Replaces the WinRing0-based LibreHardwareMonitorLib bundled with TrafficMonitor
    by an official LibreHardwareMonitorLib build that uses the PawnIO driver instead.

.DESCRIPTION
    - Downloads LibreHardwareMonitorLib and its .NET Framework 4.7.2 dependencies from nuget.org
    - Verifies every package against the SHA-512 published in the nuget.org catalog
    - Checks that PawnIO is installed and that the public API used by TrafficMonitor is unchanged
    - Backs up the original DLL, closes TrafficMonitor, removes the WinRing0 service/driver file
    - Copies the new DLLs and restarts TrafficMonitor

    Nothing is redistributed by this repository: all binaries come from nuget.org.

.PARAMETER TrafficMonitorPath
    TrafficMonitor install folder. Auto-detected from the running process, else
    "C:\Program Files\TrafficMonitor".

.PARAMETER LhmVersion
    LibreHardwareMonitorLib version to install (default 0.9.6, tested with TrafficMonitor 1.86).

.PARAMETER DryRun
    Download, verify and check compatibility only. Does not modify anything. No admin needed.

.EXAMPLE
    # Simulation (nothing is changed)
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -DryRun

.EXAMPLE
    # Real install (run from an elevated PowerShell)
    powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$TrafficMonitorPath,
    [string]$LhmVersion = '0.9.6',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
[Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::InvariantCulture
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Info($m) { Write-Host "[*] $m" }
function Ok($m)   { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[X] $m" -ForegroundColor Red; exit 1 }

function Test-SafePath([string]$PathValue, [string]$ParamName = 'Path') {
    if ([string]::IsNullOrWhiteSpace($PathValue)) { Fail "Invalid ${ParamName}: path cannot be empty." }
    if ($PathValue -match '[\x00-\x1f]') { Fail "Invalid ${ParamName}: control characters are not allowed." }
    if ($PathValue -match '(^|[\\/])\.\.([\\/]|$)') { Fail "Invalid ${ParamName}: path traversal ('..') is not allowed." }
    return $PathValue.Trim()
}

function Test-SafeHttpsUrl([string]$Url, [string[]]$AllowedHosts = @('api.nuget.org')) {
    if ([string]::IsNullOrWhiteSpace($Url) -or $Url -match '[\x00-\x1f]') { Fail "Invalid URL: '$Url'." }
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { Fail "Malformed URL: '$Url'." }
    if ($uri.Scheme -ne 'https') { Fail "Insecure URL scheme '$($uri.Scheme)' rejected (HTTPS required): $Url" }
    $hostLower = $uri.Host.ToLowerInvariant()
    if ($AllowedHosts -notcontains $hostLower) { Fail "Untrusted download host '$hostLower' rejected: $Url" }
    return $uri.AbsoluteUri
}

function Get-FileSha256Hex([string]$FilePath) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash([IO.File]::ReadAllBytes($FilePath))
        return ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

# ---------------------------------------------------------------- 0. Pre-checks
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $DryRun -and -not $isAdmin) { Fail 'Run this script from an elevated (administrator) PowerShell, or use -DryRun.' }

if ($LhmVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$') {
    Fail "Invalid LhmVersion format: '$LhmVersion'."
}

if (-not $TrafficMonitorPath) {
    $proc = Get-Process TrafficMonitor -ErrorAction SilentlyContinue | Select-Object -First 1
    $exePath = $null
    if ($proc) { try { $exePath = $proc.Path } catch {} }
    $TrafficMonitorPath = if ($exePath) { Split-Path $exePath } else { 'C:\Program Files\TrafficMonitor' }
}
$TrafficMonitorPath = Test-SafePath $TrafficMonitorPath 'TrafficMonitorPath'
$tmExe = Join-Path $TrafficMonitorPath 'TrafficMonitor.exe'
$tmLhm = Join-Path $TrafficMonitorPath 'LibreHardwareMonitorLib.dll'
if (-not (Test-Path -LiteralPath $tmExe)) { Fail "TrafficMonitor.exe not found in '$TrafficMonitorPath'. Use -TrafficMonitorPath." }
if (-not (Test-Path -LiteralPath $tmLhm)) { Fail "LibreHardwareMonitorLib.dll not found in '$TrafficMonitorPath' (build without temperature support?)." }
Info "TrafficMonitor: $tmExe ($((Get-Item -LiteralPath $tmExe).VersionInfo.FileVersion))"
Info "Current LibreHardwareMonitorLib: $((Get-Item -LiteralPath $tmLhm).VersionInfo.FileVersion)"

# Architecture of TrafficMonitor.exe -> runtime folder of the NuGet package
$bytes = [IO.File]::ReadAllBytes($tmExe)
$machine = [BitConverter]::ToUInt16($bytes, [BitConverter]::ToInt32($bytes, 0x3C) + 4)
$rid = switch ($machine) { 0x8664 { 'win-x64' } 0x014C { 'win-x86' } 0xAA64 { 'win-arm64' } default { $null } }
if (-not $rid) { Fail ("Unknown PE machine type 0x{0:X4}" -f $machine) }
Info "Architecture: $rid"

# PawnIO must be installed (the new library talks to it instead of WinRing0)
$pawn = Get-CimInstance Win32_SystemDriver -Filter "Name='PawnIO'" -ErrorAction SilentlyContinue
if (-not $pawn) {
    Fail "PawnIO is not installed. Install it first: 'winget install --id namazso.PawnIO -e' or https://github.com/namazso/PawnIO.Setup/releases"
}
Ok "PawnIO driver present ($($pawn.State))"

# ---------------------------------------------------------------- 1. Download + verify
$work = Join-Path $env:TEMP ("tm-pawnio-fix-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$pkgDir = Join-Path $work 'pkg'; $outDir = Join-Path $work 'out'
$keepDryRunOut = $false
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$tfmPref = 'net472', 'net471', 'net47', 'net462', 'net461', 'net46', 'net45', 'netstandard2.0'
function Normalize-Tfm([string]$t) {
    $t = $t -replace '^\.NETFramework', 'net' -replace '^\.NETStandard', 'netstandard'
    if ($t -match '^net(\d)\.(\d)(\.(\d))?$') { return 'net' + $Matches[1] + $Matches[2] + $Matches[4] }
    return $t
}
function Get-CatalogHash([string]$id, [string]$ver) {
    $regUrl = Test-SafeHttpsUrl "https://api.nuget.org/v3/registration5-semver1/$($id.ToLowerInvariant())/$($ver.ToLowerInvariant()).json"
    $leaf = Invoke-RestMethod -Uri $regUrl -UseBasicParsing
    $catUrl = Test-SafeHttpsUrl ([string]$leaf.catalogEntry)
    $catalog = Invoke-RestMethod -Uri $catUrl -UseBasicParsing
    if ($catalog.packageHashAlgorithm -and $catalog.packageHashAlgorithm -ne 'SHA512') {
        Fail "Unexpected NuGet hash algorithm '$($catalog.packageHashAlgorithm)' for $id $ver."
    }
    if ([string]::IsNullOrWhiteSpace([string]$catalog.packageHash)) {
        Fail "NuGet catalog did not return a packageHash for $id $ver."
    }
    return [string]$catalog.packageHash
}

try {
    New-Item -ItemType Directory -Force -Path $pkgDir, $outDir | Out-Null

    $done = @{}
    $extractedSha256 = @{}
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@('LibreHardwareMonitorLib', $LhmVersion))
    while ($queue.Count) {
        $id, $ver = $queue.Dequeue()
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or $ver -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$') {
            Fail "Invalid NuGet package identifier or version: '$id' '$ver'."
        }
        $lid = $id.ToLowerInvariant(); $lver = $ver.ToLowerInvariant()
        if ($done.ContainsKey($lid)) { continue }
        $done[$lid] = $ver
        $nupkg = Join-Path $pkgDir "$lid.$lver.nupkg"
        $pkgUrl = Test-SafeHttpsUrl "https://api.nuget.org/v3-flatcontainer/$lid/$lver/$lid.$lver.nupkg"
        Invoke-WebRequest -Uri $pkgUrl -OutFile $nupkg -UseBasicParsing

        $sha = [Security.Cryptography.SHA512]::Create()
        try { $local = [Convert]::ToBase64String($sha.ComputeHash([IO.File]::ReadAllBytes($nupkg))) } finally { $sha.Dispose() }
        $expectedHash = Get-CatalogHash $id $ver
        if ($local -ne $expectedHash) { Fail "Hash mismatch for $id $ver - aborting." }
        $pkgSha256 = Get-FileSha256Hex $nupkg

        $zip = [IO.Compression.ZipFile]::OpenRead($nupkg)
        try {
            $nuspecEntry = ($zip.Entries | Where-Object { $_.FullName -like '*.nuspec' }) | Select-Object -First 1
            if (-not $nuspecEntry) { Fail "Missing .nuspec in $id $ver." }
            $xmlSettings = New-Object System.Xml.XmlReaderSettings
            $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
            $xmlSettings.XmlResolver = $null
            $entryStream = $nuspecEntry.Open()
            $xmlReader = [System.Xml.XmlReader]::Create($entryStream, $xmlSettings)
            try {
                $nuspec = New-Object System.Xml.XmlDocument
                $nuspec.XmlResolver = $null
                $nuspec.Load($xmlReader)
            } finally {
                $xmlReader.Dispose()
                $entryStream.Dispose()
            }
            $groups = @($nuspec.package.metadata.dependencies.group)
            $group = $null
            foreach ($t in $tfmPref) { $group = $groups | Where-Object { $_ -and (Normalize-Tfm $_.targetFramework) -eq $t } | Select-Object -First 1; if ($group) { break } }
            if ($group) { foreach ($d in @($group.dependency)) { if ($d) { $queue.Enqueue(@($d.id, (($d.version -replace '[\[\]\(\) ]', '').Split(',')[0]))) } } }

            # LibreHardwareMonitorLib ships per-RID builds under runtimes/<rid>/lib/<tfm>/, others under lib/<tfm>/
            $libRoots = @("runtimes/$rid/lib", 'lib')
            $copied = $false
            $outDirFull = [IO.Path]::GetFullPath($outDir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
            foreach ($root in $libRoots) {
                foreach ($t in $tfmPref) {
                    # "_._" = placeholder: the assembly is provided by .NET Framework itself, nothing to copy
                    if ($zip.Entries | Where-Object { $_.FullName -eq "$root/$t/_._" }) { $copied = $null; break }
                    $entries = $zip.Entries | Where-Object { $_.FullName -like "$root/$t/*.dll" }
                    if ($entries) {
                        foreach ($e in $entries) {
                            if ($e.Name -notmatch '^[A-Za-z0-9._-]+\.dll$') { Fail "Unsafe DLL entry name rejected: '$($e.Name)'" }
                            $destDll = [IO.Path]::GetFullPath((Join-Path $outDir $e.Name))
                            if (-not $destDll.StartsWith($outDirFull, [StringComparison]::OrdinalIgnoreCase)) { Fail "Zip-slip extraction path rejected: '$($e.FullName)'" }
                            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $destDll, $true)
                            $extractedSha256[$e.Name] = Get-FileSha256Hex $destDll
                        }
                        $copied = $true; break
                    }
                }
                if ($copied -ne $false) { break }
            }
            Info ("{0} {1}: SHA-512 OK | SHA-256={2}{3}" -f $id, $ver, $pkgSha256.Substring(0, 16), $(if ($copied) { '' } else { ' (no DLL needed on .NET Framework)' }))
        } finally { $zip.Dispose() }
    }
    $newLhm = Join-Path $outDir 'LibreHardwareMonitorLib.dll'
    if (-not (Test-Path -LiteralPath $newLhm)) { Fail 'LibreHardwareMonitorLib.dll was not extracted.' }
    Ok "Downloaded and verified $($done.Count) packages from nuget.org"

    # ---------------------------------------------------------------- 2. Compatibility checks
    $raw = [IO.File]::ReadAllBytes($newLhm)
    $txt = [Text.Encoding]::ASCII.GetString($raw) + [Text.Encoding]::Unicode.GetString($raw)
    if ($txt -match 'WinRing0') { Fail 'The downloaded library still references WinRing0 - aborting.' }
    if ($txt -notmatch 'PawnIO') { Fail 'The downloaded library does not reference PawnIO - aborting.' }
    Ok 'New library uses PawnIO and contains no WinRing0'

    # Compare the API surface TrafficMonitor relies on (run in child processes: same assembly name)
    $probe = @'
param($p)
$a = [Reflection.Assembly]::ReflectionOnlyLoadFrom($p)
function E($n) { $t = $a.GetType($n); ($t.GetFields('Public,Static') | Where-Object { $_.Name -in 'Cpu','GpuNvidia','GpuAmd','GpuIntel','Storage','Motherboard','Clock','Load','Temperature' } | ForEach-Object { $_.Name + '=' + [int]$_.GetRawConstantValue() }) -join ';' }
'HW:' + (E 'LibreHardwareMonitor.Hardware.HardwareType')
'ST:' + (E 'LibreHardwareMonitor.Hardware.SensorType')
'IV:' + (($a.GetType('LibreHardwareMonitor.Hardware.IVisitor').GetMethods() | ForEach-Object { $_.Name + '(' + (($_.GetParameters() | ForEach-Object { $_.ParameterType.Name }) -join ',') + ')' } | Sort-Object) -join ';')
'CO:' + (($a.GetType('LibreHardwareMonitor.Hardware.Computer').GetProperties() | Where-Object { $_.Name -in 'Hardware','IsCpuEnabled','IsGpuEnabled','IsStorageEnabled','IsMotherboardEnabled' } | ForEach-Object { $_.Name + ':' + $_.PropertyType.Name } | Sort-Object) -join ';')
'IH:' + (($a.GetType('LibreHardwareMonitor.Hardware.IHardware').GetProperties() | Where-Object { $_.Name -in 'HardwareType','Sensors','SubHardware','Name' } | ForEach-Object { $_.Name + ':' + $_.PropertyType.Name } | Sort-Object) -join ';')
'IS:' + (($a.GetType('LibreHardwareMonitor.Hardware.ISensor').GetProperties() | Where-Object { $_.Name -in 'SensorType','Name','Value' } | ForEach-Object { $_.Name + ':' + $_.PropertyType.Name } | Sort-Object) -join ';')
'@
    $probeFile = Join-Path $work 'probe.ps1'
    try {
        Set-Content -LiteralPath $probeFile -Value $probe -Encoding UTF8
        $oldApi = & powershell -NoProfile -ExecutionPolicy Bypass -File "$probeFile" "$tmLhm"
        $newApi = & powershell -NoProfile -ExecutionPolicy Bypass -File "$probeFile" "$newLhm"
    } finally {
        if (Test-Path -LiteralPath $probeFile) {
            Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
        }
    }
    $diff = Compare-Object $oldApi $newApi
    if ($diff) { $diff | Format-Table | Out-String | Write-Host; Fail 'API used by TrafficMonitor differs between versions - aborting.' }
    Ok 'API used by TrafficMonitor is identical (enums Clock/Load/Temperature, Computer, IVisitor, IHardware, ISensor)'

    if ($DryRun) {
        $keepDryRunOut = $true
        Ok "Dry run finished. Files ready in: $outDir"
        Get-ChildItem -LiteralPath $outDir | Select-Object Name, @{ n = 'Version'; e = { $_.VersionInfo.FileVersion } }, @{ n = 'SHA256'; e = { $extractedSha256[$_.Name] } } | Format-Table -AutoSize | Out-String | Write-Host
        exit 0
    }

    # ---------------------------------------------------------------- 3. Backup
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = Join-Path $TrafficMonitorPath "_backup_lhm_$stamp"
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    Copy-Item -LiteralPath $tmLhm -Destination $backup -Force
    Get-ChildItem -LiteralPath $outDir -Filter '*.dll' | ForEach-Object {
        $existing = Join-Path $TrafficMonitorPath $_.Name
        if (Test-Path -LiteralPath $existing) { Copy-Item -LiteralPath $existing -Destination $backup -Force }
    }
    Get-ChildItem -LiteralPath $outDir -Filter '*.dll' | Select-Object -ExpandProperty Name | Set-Content -LiteralPath (Join-Path $backup 'installed-files.txt') -Encoding UTF8
    Ok "Backup: $backup"

    # ---------------------------------------------------------------- 4. Close TrafficMonitor, remove WinRing0
    $wasRunning = [bool](Get-Process TrafficMonitor -ErrorAction SilentlyContinue)
    if ($wasRunning) {
        taskkill /im TrafficMonitor.exe | Out-Null          # graceful close (saves traffic history)
        for ($i = 0; $i -lt 20 -and (Get-Process TrafficMonitor -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
        if (Get-Process TrafficMonitor -ErrorAction SilentlyContinue) { Stop-Process -Name TrafficMonitor -Force }
        Ok 'TrafficMonitor closed'
    }
    # The old library installs WinRing0 as service "R0<exe name>" with driver file "<exe name>.sys"
    $svc = 'R0TrafficMonitor'
    if (Get-CimInstance Win32_SystemDriver -Filter "Name='$svc'" -ErrorAction SilentlyContinue) {
        sc.exe stop "$svc" | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete "$svc" | Out-Null
        Ok "WinRing0 service '$svc' removed"
    }
    $sys = Join-Path $TrafficMonitorPath 'TrafficMonitor.sys'
    if (Test-Path -LiteralPath $sys) { Remove-Item -LiteralPath $sys -Force; Ok 'WinRing0 driver file TrafficMonitor.sys deleted' }

    # ---------------------------------------------------------------- 5. Install
    Get-ChildItem -LiteralPath $outDir -Filter '*.dll' | ForEach-Object {
        $currentSha256 = Get-FileSha256Hex $_.FullName
        if ($extractedSha256.ContainsKey($_.Name) -and $currentSha256 -ne $extractedSha256[$_.Name]) {
            Fail "SHA-256 integrity check failed for staged file '$($_.Name)' - aborting."
        }
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $TrafficMonitorPath $_.Name) -Force
    }
    Ok ("LibreHardwareMonitorLib {0} installed" -f (Get-Item -LiteralPath $tmLhm).VersionInfo.FileVersion)

    if ($wasRunning) { Start-Process -FilePath $tmExe; Ok 'TrafficMonitor restarted' }
} finally {
    if (-not $keepDryRunOut -and $work -and (Test-Path -LiteralPath $work)) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host ''
Ok 'Done. Run .\verify.ps1 (as administrator) to check the result.'
