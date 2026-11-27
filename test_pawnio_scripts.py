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


if __name__ == "__main__":
    unittest.main()
