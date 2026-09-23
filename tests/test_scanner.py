from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from pygo_audit.scanner import ELF_MAGIC, scan_root


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

            (source / "go.mod").write_text("module example.test/auditfixture\n\ngo 1.26\n")
            (source / "main.go").write_text(
                'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("fixture") }\n'
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

            report = scan_root(root, govulncheck_command=os.fspath(fake_govulncheck))

            self.assertEqual(report.stats.go_binaries, 1)
            self.assertEqual(report.stats.go_binary_paths, 2)
            self.assertEqual(binary.stat().st_mode & 0o111, 0)
            self.assertEqual(report.stats.symlinks_skipped, 1)
            self.assertEqual(
                report.binaries[0].paths,
                ["/usr/bin/fixture", "/usr/bin/fixture-hardlink"],
            )
            self.assertEqual(report.binaries[0].main_package, "example.test/auditfixture")
            self.assertFalse(report.binaries[0].cgo_enabled)
            self.assertEqual(report.binaries[0].vulnerability_scan.status, "complete")
            self.assertEqual(report.binaries[0].vulnerability_scan.vulnerabilities, [])
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
