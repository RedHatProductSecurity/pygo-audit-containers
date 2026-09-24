from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pygo_audit.models import BinaryReport
from pygo_audit.scanner import ELF_MAGIC, _reconciliation_issue, scan_root


class ScannerReconciliationTests(unittest.TestCase):
    def test_reconciliation_mismatch_is_visible_but_informational(self) -> None:
        binary = BinaryReport(
            paths=["/bin/app"],
            size=1,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
        )

        with patch(
            "pygo_audit.scanner.reconcile_binary",
            return_value=[
                "SBOM example.test/library@v2.0.0 does not match "
                "go version -m example.test/library@v1.0.0"
            ],
        ):
            issue = _reconciliation_issue(binary, "/bin/app")

        self.assertIsNotNone(issue)
        self.assertEqual(issue.stage, "reconciliation-difference")
        self.assertTrue(issue.is_informational)
        self.assertIn("does not match", issue.message)


@unittest.skipUnless(shutil.which("go"), "Go toolchain is required")
class ScannerIntegrationTests(unittest.TestCase):
    def test_finds_go_binary_groups_hardlinks_and_skips_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            source = temporary / "source"
            root = temporary / "rootfs"
            source.mkdir()
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "etc").mkdir()

            fake_govulncheck = temporary / "govulncheck"
            fake_govulncheck.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-version\" ]; then\n"
                "  echo 'Scanner: govulncheck@test'\n"
                "  exit 0\n"
                "fi\n"
                "echo '{\"config\":{\"protocol_version\":\"v1.0.0\","
                "\"scanner_name\":\"govulncheck\",\"scanner_version\":\"test\","
                "\"db\":\"https://vuln.example\",\"scan_level\":\"symbol\","
                "\"scan_mode\":\"binary\"}}'\n"
            )
            fake_govulncheck.chmod(0o755)

            (source / "go.mod").write_text(
                "module example.test/auditfixture\n\ngo 1.26\n"
            )
            (source / "main.go").write_text(
                'package main\n\nimport "fmt"\n\n'
                'func main() { fmt.Println("fixture") }\n'
            )
            binary = root / "usr" / "bin" / "fixture"
            environment = os.environ.copy()
            environment.update(
                {
                    "CGO_ENABLED": "0",
                    "GOCACHE": os.fspath(temporary / "go-cache"),
                    "GOENV": "off",
                    "GOMODCACHE": os.fspath(temporary / "go-mod-cache"),
                    "GOPATH": os.fspath(temporary / "go-path"),
                    "GOTOOLCHAIN": "local",
                }
            )
            build = subprocess.run(
                ["go", "build", "-buildvcs=false", "-o", binary, "."],
                cwd=source,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            os.link(binary, root / "usr" / "bin" / "fixture-hardlink")
            binary.chmod(0o644)
            os.symlink("/bin/fixture", root / "usr" / "bin" / "fixture-symlink")
            (root / "etc" / "not-a-binary").write_text("configuration")
            expected_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

            report = scan_root(root, govulncheck_command=os.fspath(fake_govulncheck))

            self.assertEqual(report.stats.go_binaries, 1)
            self.assertEqual(report.stats.go_binary_paths, 2)
            self.assertEqual(binary.stat().st_mode & 0o111, 0)
            self.assertEqual(report.stats.symlinks_skipped, 1)
            self.assertEqual(
                report.binaries[0].paths,
                ["/usr/bin/fixture", "/usr/bin/fixture-hardlink"],
            )
            self.assertEqual(
                report.binaries[0].main_package,
                "example.test/auditfixture",
            )
            self.assertEqual(report.binaries[0].sha256, expected_sha256)
            self.assertFalse(report.binaries[0].cgo_enabled)
            self.assertEqual(report.binaries[0].vulnerability_scan.status, "complete")
            self.assertEqual(report.binaries[0].vulnerability_scan.vulnerabilities, [])
            self.assertTrue(report.scan_started_at.endswith("Z"))
            self.assertTrue(report.scan_completed_at.endswith("Z"))
            self.assertLessEqual(report.scan_started_at, report.scan_completed_at)
            self.assertEqual(report.producer_name, "pygo-audit")
            self.assertTrue(report.producer_version)
            self.assertEqual(
                report.vulnerability_databases(),
                [{"url": "https://vuln.example", "last_modified": ""}],
            )
            self.assertEqual(report.issues, [])

    def test_non_go_elf_is_not_reported_as_an_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fake = root / "fake"
            fake.write_bytes(ELF_MAGIC + b"\x00" * 64)
            fake.chmod(0o755)

            report = scan_root(root, govulncheck_command=None)

            self.assertEqual(report.stats.unique_elf_files, 1)
            self.assertEqual(report.stats.go_binaries, 0)
            self.assertEqual(report.issues, [])


if __name__ == "__main__":
    unittest.main()
