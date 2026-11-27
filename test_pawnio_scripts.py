import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


class TestPawnIOScripts(unittest.TestCase):
    def test_verify_ps1_supports_json_structured_diagnostics(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$Json", verify_src)
        self.assertIn("ConvertTo-Json", verify_src)

        for section in ("traffic_monitor", "winring0", "pawnio", "backup"):
            self.assertIn(section, verify_src)

        for field in (
            "exe_present",
            "exe_version",
            "lhm_version",
            "embeds_winring0",
            "service_present",
            "driver_file_present",
            "installed",
            "latest_path",
        ):
            self.assertIn(field, verify_src)

    def test_install_and_rollback_integrity_checks(self):
        install_src = (ROOT / "install.ps1").read_text(encoding="utf-8")
        rollback_src = (ROOT / "rollback.ps1").read_text(encoding="utf-8")

        self.assertIn("SHA512", install_src)
        self.assertIn("Get-CatalogHash", install_src)
        self.assertIn("_backup_lhm_", install_src)
        self.assertIn("R0TrafficMonitor", install_src)
        self.assertIn("PawnIO", install_src)

        self.assertIn("_backup_lhm_*", rollback_src)
        self.assertIn("installed-files.txt", rollback_src)

    def test_powershell_braces_balanced_across_all_scripts(self):
        for name in ("install.ps1", "verify.ps1", "rollback.ps1"):
            src = (ROOT / name).read_text(encoding="utf-8")
            # Strip comments and here-strings before checking brace balance
            cleaned = re.sub(r"<#.*?#>", "", src, flags=re.S)
            cleaned = re.sub(r"@'.*?'@", "", cleaned, flags=re.S)
            self.assertEqual(cleaned.count("{"), cleaned.count("}"), f"Unbalanced braces in {name}")

    def test_verify_ps1_supports_selftest_mode(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$SelfTest", verify_src)
        self.assertIn("if ($SelfTest)", verify_src)
        self.assertIn("self_test = $true", verify_src)
        self.assertIn("clean_dll_passes", verify_src)
        self.assertIn("winring0_dll_detected", verify_src)

    def test_verify_ps1_supports_export_report_html_and_markdown(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("[string]$ExportReport", verify_src)
        self.assertIn("function Export-HealthReport($report, [string]$outPath)", verify_src)
        self.assertIn(r"\.(md|markdown)$", verify_src)
        self.assertIn("# TrafficMonitor PawnIO Diagnostic Health Card", verify_src)
        self.assertIn("<!doctype html>", verify_src)
        self.assertIn("HtmlEncode", verify_src)
        self.assertIn("HEALTHY", verify_src)
        self.assertIn("ACTION REQUIRED", verify_src)
        self.assertEqual(verify_src.count("Export-HealthReport $"), 3)

    def test_path_validation_and_literal_path_across_all_scripts(self):
        for name in ("install.ps1", "verify.ps1", "rollback.ps1"):
            src = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("function Test-SafePath(", src, name)
            self.assertIn(r"[\x00-\x1f]", src, name)
            self.assertIn(r"\.\.", src, name)
            self.assertIn("-LiteralPath", src, name)

    def test_install_ps1_tls12_https_url_validation_and_checksums(self):
        install_src = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("[Net.SecurityProtocolType]::Tls12", install_src)
        self.assertIn("function Test-SafeHttpsUrl(", install_src)
        self.assertIn("$uri.Scheme -ne 'https'", install_src)
        self.assertIn("'api.nuget.org'", install_src)
        self.assertGreaterEqual(install_src.count("Test-SafeHttpsUrl "), 3)
        self.assertIn("function Get-FileSha256Hex(", install_src)
        self.assertIn("[Security.Cryptography.SHA256]::Create()", install_src)
        self.assertIn("$sha256.Dispose()", install_src)
        self.assertIn("SHA-256 integrity check failed", install_src)
        self.assertIn("DtdProcessing]::Prohibit", install_src)
        self.assertIn("Zip-slip extraction path rejected", install_src)
        self.assertIn("packageHashAlgorithm", install_src)

    def test_verify_ps1_html_and_markdown_escaping_and_csp(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("function ConvertTo-SafeHtml(", verify_src)
        self.assertIn("function ConvertTo-SafeMarkdown(", verify_src)
        self.assertIn("[System.Net.WebUtility]::HtmlEncode", verify_src)
        self.assertIn("Content-Security-Policy", verify_src)
        self.assertIn("ConvertTo-SafeMarkdown $report.traffic_monitor.path", verify_src)
        self.assertIn("ConvertTo-SafeMarkdown $s", verify_src)
        self.assertIn("ConvertTo-SafeMarkdown $e", verify_src)
        self.assertIn("ConvertTo-SafeHtml $report.traffic_monitor.path", verify_src)
        self.assertIn("ConvertTo-SafeHtml $statusLabel", verify_src)

    def test_rollback_ps1_prevents_path_traversal_on_installed_files(self):
        rollback_src = (ROOT / "rollback.ps1").read_text(encoding="utf-8")
        self.assertIn(r"^[A-Za-z0-9._-]+\.dll$", rollback_src)
        self.assertIn("StartsWith($tmDirFull", rollback_src)
        self.assertIn("Remove-Item -LiteralPath $targetPath", rollback_src)
        self.assertIn("Start-Process -FilePath", rollback_src)

    def test_safe_parameter_quoting_and_no_invoke_expression(self):
        install_src = (ROOT / "install.ps1").read_text(encoding="utf-8")
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn('-File "$probeFile" "$tmLhm"', install_src)
        self.assertIn('-File "$probeFile" "$newLhm"', install_src)
        self.assertIn('sc.exe stop "$svc"', install_src)
        self.assertIn('sc.exe delete "$svc"', install_src)
        self.assertIn('-File "$tf" "$tmp"', verify_src)

        for name in ("install.ps1", "verify.ps1", "rollback.ps1"):
            src = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotRegex(src, r"(?i)\b(Invoke-Expression|iex)\b", name)

    def test_turkish_locale_safety_invariant_casing_and_culture(self):
        for name in ("install.ps1", "verify.ps1", "rollback.ps1"):
            src = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("InvariantCulture", src, f"{name} must force InvariantCulture")
            self.assertNotRegex(src, r"\.To(Lower|Upper)\(", f"{name} must not use locale-sensitive ToLower/ToUpper")

        install_src = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("$id.ToLowerInvariant()", install_src)
        self.assertIn("$ver.ToLowerInvariant()", install_src)

    def test_verify_ps1_queries_drivers_even_when_dll_missing(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("function Get-DriverStatus(", verify_src)
        self.assertIn("Win32_SystemDriver", verify_src)
        self.assertIn("Get-Service", verify_src)
        self.assertIn("'WinRing0_1_2_0'", verify_src)
        self.assertIn("'R0TrafficMonitor'", verify_src)
        self.assertIn("'PawnIO'", verify_src)

        # Driver queries must happen before the missing-DLL early-return block
        driver_query_pos = verify_src.find("$r0Driver = Get-DriverStatus")
        missing_dll_pos = verify_src.find("if (-not (Test-Path -LiteralPath $lhm))")
        self.assertGreater(driver_query_pos, 0)
        self.assertGreater(missing_dll_pos, driver_query_pos)

        # $missingReport must use real queried driver status, never hardcoded $false
        m = re.search(r"\$missingReport\s*=\s*\[ordered\]@\{.*?\n    \}", verify_src, flags=re.S)
        self.assertIsNotNone(m)
        missing_block = m.group(0)
        self.assertIn("service_present = $r0ServicePresent", missing_block)
        self.assertIn("installed = [bool]$pawn", missing_block)
        self.assertNotIn("service_present = $false", missing_block)
        self.assertNotIn("installed = $false", missing_block)

    def test_try_finally_temp_script_and_dir_cleanup(self):
        install_src = (ROOT / "install.ps1").read_text(encoding="utf-8")
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")

        # install.ps1 must clean up both probe.ps1 and $work inside finally blocks
        self.assertRegex(
            install_src,
            r"finally\s*\{[^}]*Remove-Item\s+-LiteralPath\s+\$probeFile",
        )
        self.assertRegex(
            install_src,
            r"finally\s*\{[^}]*Remove-Item\s+-LiteralPath\s+\$work\s+-Recurse\s+-Force",
        )
        # verify.ps1 must clean up elevated $tmp inside a finally block
        self.assertRegex(
            verify_src,
            r"finally\s*\{[^}]*Remove-Item\s+-LiteralPath\s+\$tmp\s+-Recurse\s+-Force",
        )
        # PowerShell here-string terminators '@ must be at column 0
        for name, src in (("install.ps1", install_src), ("verify.ps1", verify_src)):
            self.assertNotRegex(src, r"(?m)^[ \t]+'@$", f"Indented here-string terminator in {name}")

    def test_readme_documents_verify_flags(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for flag in ("-Json", "-SelfTest", "-ExportReport"):
            self.assertIn(flag, readme, f"README.md must document {flag}")

    def test_verify_ps1_strict_csp_meta_and_head_injection(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        expected_csp = (
            "<meta http-equiv=`\"Content-Security-Policy`\" "
            "content=`\"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
            "base-uri 'none'; form-action 'none';`\">"
        )
        self.assertIn(expected_csp, verify_src)
        self.assertIn(f'$cspMeta = "{expected_csp}"', verify_src)
        self.assertIn('<head><meta charset=`"utf-8`">$cspMeta<title>', verify_src)
        self.assertNotIn("unsafe-eval", verify_src)

    def test_verify_ps1_html_escapes_all_dynamic_report_fields(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")

        # Verify ConvertTo-SafeHtml handles null, strips control chars, HTML-encodes, and encodes single quotes
        fn_match = re.search(r"function ConvertTo-SafeHtml\([^\n]*\)\s*\{.*?\n\}", verify_src, flags=re.S)
        self.assertIsNotNone(fn_match)
        fn_body = fn_match.group(0)
        self.assertIn("if ($null -eq $Value) { return '' }", fn_body)
        self.assertIn("[System.Net.WebUtility]::HtmlEncode", fn_body)
        self.assertIn("-replace \"'\", '&#39;'", fn_body)

        # Verify every dynamic field rendered into HTML goes through ConvertTo-SafeHtml
        required_escaped_exprs = (
            "ConvertTo-SafeHtml $computerName",
            "ConvertTo-SafeHtml $statusLabel",
            "ConvertTo-SafeHtml $ts",
            "ConvertTo-SafeHtml $report.checks.clean_dll_passes",
            "ConvertTo-SafeHtml $report.checks.winring0_dll_detected",
            "ConvertTo-SafeHtml $report.is_admin",
            "ConvertTo-SafeHtml $report.traffic_monitor.path",
            "ConvertTo-SafeHtml $report.traffic_monitor.exe_version",
            "ConvertTo-SafeHtml $report.traffic_monitor.lhm_version",
            "ConvertTo-SafeHtml $report.traffic_monitor.embeds_winring0",
            "ConvertTo-SafeHtml $report.winring0.service_present",
            "ConvertTo-SafeHtml $report.winring0.service_name",
            "ConvertTo-SafeHtml $report.winring0.driver_file_present",
            "ConvertTo-SafeHtml $report.pawnio.installed",
            "ConvertTo-SafeHtml $report.pawnio.state",
            "ConvertTo-SafeHtml $report.backup.count",
            "ConvertTo-SafeHtml $report.backup.latest_path",
            "ForEach-Object { ConvertTo-SafeHtml $_ }",
        )
        for expr in required_escaped_exprs:
            self.assertIn(expr, verify_src, f"Missing HTML escaping expression: {expr}")

        # Audit the HTML construction section so no raw $report/$computerName/$statusLabel/$ts slips in unescaped
        export_match = re.search(
            r"\$badgeBg\s*=.*?\n\}",
            verify_src,
            flags=re.S,
        )
        self.assertIsNotNone(export_match)
        html_section = export_match.group(0)
        row_strings = re.findall(r'\[void\]\$rows\.Add\("([^"]*)"\)', html_section)
        self.assertGreaterEqual(len(row_strings), 10)
        for row_html in row_strings:
            # Strip valid $(ConvertTo-SafeHtml ...) calls and known pre-escaped local vars
            stripped = re.sub(r"\$\(ConvertTo-SafeHtml\s+[^)]+\)", "", row_html)
            for safe_var in ("$r0SvcDetail", "$sensorTxt", "$errTxt"):
                stripped = stripped.replace(safe_var, "")
            self.assertNotIn("$", stripped, f"Unescaped variable interpolation in HTML row: {row_html}")

        html_line_match = re.search(r'^\s*\$html\s*=\s*".*"$', html_section, flags=re.M)
        self.assertIsNotNone(html_line_match)
        html_line = html_line_match.group(0)
        # Only pre-sanitized / constant variables allowed inside $html template
        interpolated_vars = set(re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", html_line.split("=", 1)[1]))
        self.assertEqual(
            interpolated_vars,
            {"$cspMeta", "$badgeBg", "$safeBadge", "$rowHtml"},
            f"Unexpected variables interpolated in $html: {interpolated_vars}",
        )

    def test_verify_ps1_export_report_path_and_symlink_guards(self):
        verify_src = (ROOT / "verify.ps1").read_text(encoding="utf-8")
        self.assertIn("[IO.FileAttributes]::ReparsePoint", verify_src)
        self.assertIn("symbolic links and reparse points are not allowed", verify_src)
        self.assertIn("parent directory cannot be a symbolic link or reparse point", verify_src)
        self.assertIn("[IO.Directory]::Exists($fullOutPath)", verify_src)
        self.assertIn("^\\\\\\\\[.?]\\\\", verify_src)
        self.assertIn("Out-File -LiteralPath $fullOutPath -Encoding utf8", verify_src)

    def test_ci_workflow_runs_unittest_discover(self):
        ci = ROOT / ".github" / "workflows" / "ci.yml"
        self.assertTrue(ci.exists(), ".github/workflows/ci.yml missing")
        self.assertIn("unittest discover", ci.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
