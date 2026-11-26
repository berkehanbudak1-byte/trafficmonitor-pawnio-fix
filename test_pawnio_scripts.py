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


if __name__ == "__main__":
    unittest.main()
