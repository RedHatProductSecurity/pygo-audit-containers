from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pygo_audit import models, scanner
from pygo_audit.result_cache import ResultCacheError
from pygo_audit.scanner import (
    ELF_MAGIC,
    _inspect_vulnerabilities,
    _resolve_go_tool,
    _resolve_govulncheck_tool,
    _sha256_descriptor,
    resolve_symlink_path,
    ScanConfigurationError,
    scan_root,
)


class ScannerReconciliationTests(unittest.TestCase):
    def test_discovery_records_failed_stage_and_continues_with_other_files(self):
        for stage in ("stat", "readlink", "open", "read", "walk"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                good, bad = root / "good", root / "bad"
                good.write_bytes(ELF_MAGIC)
                if stage == "readlink":
                    bad.symlink_to("good")
                elif stage == "walk":
                    bad.mkdir()
                else:
                    bad.write_bytes(ELF_MAGIC)
                report = models.AuditReport(
                    models.ContainerMetadata(str(root)), "go", "test"
                )
                descriptors = {}
                original_open = scanner._open_regular_file
                original_pread, original_readlink, original_scandir = (
                    os.pread,
                    os.readlink,
                    os.scandir,
                )

                def denied(*args, **kwargs):
                    raise PermissionError(13, "Permission denied")

                def open_file(path, **kwargs):
                    if stage == "open" and path == bad:
                        denied()
                    descriptor = original_open(path, **kwargs)
                    descriptors[descriptor] = path
                    return descriptor

                def pread(descriptor, *args):
                    if stage == "read" and descriptors[descriptor] == bad:
                        denied()
                    return original_pread(descriptor, *args)

                def readlink(path):
                    if stage == "readlink" and path == bad:
                        denied()
                    return original_readlink(path)

                @contextmanager
                def scandir(path):
                    if stage == "walk" and path == bad:
                        denied()
                    with original_scandir(path) as entries:
                        yield [
                            SimpleNamespace(path=entry.path, stat=denied)
                            if stage == "stat" and Path(entry.path) == bad
                            else entry
                            for entry in entries
                        ]

                with (
                    patch.object(scanner, "_open_regular_file", side_effect=open_file),
                    patch.object(os, "pread", side_effect=pread),
                    patch.object(os, "readlink", side_effect=readlink),
                    patch.object(os, "scandir", side_effect=scandir),
                ):
                    binaries = scanner._discover_elf_files(root, report)
                self.assertEqual([binary.paths for binary in binaries], [["/good"]])
                self.assertEqual(report.stats.unique_elf_files, 1)
                self.assertEqual(
                    report.issues,
                    [models.ScanIssue("/bad", stage, "Permission denied")],
                )
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_regular_file_open_rejects_identity_changes_and_closes_descriptors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            first.write_bytes(ELF_MAGIC)
            second.write_bytes(ELF_MAGIC)
            expected = first.stat()
            for path, reason in (
                (second, "changed during scan"),
                (root, "no longer regular"),
            ):
                descriptors = []
                original_open = os.open

                def open_file(*args, **kwargs):
                    descriptor = original_open(*args, **kwargs)
                    descriptors.append(descriptor)
                    return descriptor

                with (
                    self.subTest(path=path),
                    patch.object(os, "open", side_effect=open_file),
                    self.assertRaisesRegex(OSError, reason),
                ):
                    scanner._open_regular_file(
                        path,
                        expected_device=expected.st_dev,
                        expected_inode=expected.st_ino,
                    )
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)

    def test_symlink_resolution_stays_inside_the_subject(self) -> None:
        self.assertEqual(
            resolve_symlink_path(
                "/usr/local/tool",
                {"/usr/local/tool": "/bin/tool", "/bin": "usr/bin"},
            ),
            "/usr/bin/tool",
        )
        self.assertIsNone(resolve_symlink_path("/escape", {"/escape": "../host"}))
        self.assertIsNone(resolve_symlink_path("/a", {"/a": "/b", "/b": "/a"}))

    def test_findings_are_results_and_execution_errors_preserve_partial_evidence(self):
        messages = [
            {"config": {"scan_mode": "binary", "scan_level": "symbol"}},
            {"osv": {"id": "GO-2026-0001", "aliases": ["CVE-2026-0001"]}},
            {
                "finding": {
                    "osv": "GO-2026-0001",
                    "trace": [
                        {
                            "module": "example.test/lib",
                            "package": "example.test/lib",
                            "version": "v1.0.0",
                            "function": "Vulnerable",
                        }
                    ],
                }
            },
        ]
        output = "\n".join(json.dumps(message) for message in messages)
        for returncode, status in ((0, "complete"), (1, "failed")):
            with self.subTest(returncode=returncode):
                completed = subprocess.CompletedProcess(
                    [], returncode, output, "tool failed" if returncode else ""
                )
                with patch(
                    "pygo_audit.scanner.subprocess.run", return_value=completed
                ) as run:
                    scan, issue = _inspect_vulnerabilities(
                        "/proc/self/fd/7",
                        descriptor=7,
                        display_path="/app",
                        govulncheck_command="govulncheck",
                        timeout=10,
                        environment={},
                    )
                self.assertEqual(scan.status, status)
                self.assertEqual(scan.vulnerabilities[0].id, "GO-2026-0001")
                self.assertEqual(issue is None, returncode == 0)
                self.assertEqual(
                    run.call_args.args[0],
                    [
                        "govulncheck",
                        "-mode",
                        "binary",
                        "-format",
                        "json",
                        "/proc/self/fd/7",
                    ],
                )
                if issue:
                    self.assertEqual(issue.message, "tool failed")

    def test_scan_failures_share_the_recorded_diagnostic(self):
        cases = [
            (subprocess.TimeoutExpired("govulncheck", 10), "timed out after 10 seconds"),
            (PermissionError(13, "Permission denied"), "Permission denied"),
            (subprocess.CompletedProcess([], 1, "invalid", "tool failed"), "tool failed"),
            (
                subprocess.CompletedProcess([], 0, "{}", ""),
                "govulncheck JSON does not contain a config message",
            ),
            (subprocess.CompletedProcess([], 2, '{"config": {}}', ""), "exit status 2"),
        ]
        for outcome, message in cases:
            with self.subTest(message=message):
                with patch("pygo_audit.scanner.subprocess.run", side_effect=[outcome]):
                    scan, issue = _inspect_vulnerabilities(
                        "/proc/self/fd/7",
                        descriptor=7,
                        display_path="/app",
                        govulncheck_command="govulncheck",
                        timeout=10,
                        environment={},
                    )
                self.assertEqual(scan.status, "failed")
                self.assertEqual(scan.error, message)
                self.assertEqual(scan.vulnerabilities, [])
                self.assertIsNotNone(issue)
                self.assertEqual((issue.path, issue.stage), ("/app", "govulncheck"))
                self.assertEqual(issue.message, scan.error)

    def test_tool_probes_preserve_version_and_capability_requirements(self):
        with patch("pygo_audit.scanner.shutil.which", return_value="/tools/go"):
            with patch(
                "pygo_audit.scanner.subprocess.run",
                return_value=subprocess.CompletedProcess([], 1, "go version", "failed"),
            ):
                with self.assertRaisesRegex(ScanConfigurationError, "failed"):
                    _resolve_go_tool("go", 10, {})
            with patch(
                "pygo_audit.scanner.subprocess.run",
                side_effect=[
                    subprocess.CompletedProcess([], 0, "go version", ""),
                    subprocess.CompletedProcess([], 0, "version -m", ""),
                ],
            ):
                with self.assertRaisesRegex(ScanConfigurationError, "does not support"):
                    _resolve_go_tool("go", 10, {})
        with (
            patch("pygo_audit.scanner.shutil.which", return_value="/tools/govulncheck"),
            patch(
                "pygo_audit.scanner.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    [], 1, "Scanner: govulncheck@test", "no package patterns provided"
                ),
            ),
        ):
            self.assertEqual(
                _resolve_govulncheck_tool("govulncheck", 10, {}),
                ("/tools/govulncheck", "Scanner: govulncheck@test"),
            )

    def test_cache_symlink_resolving_inside_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "root"
            root.mkdir()
            (root / "cache").mkdir()
            cache_alias = temporary / "cache-alias"
            cache_alias.symlink_to(root / "cache", target_is_directory=True)

            with self.assertRaisesRegex(
                ScanConfigurationError, "must not be inside a scan root"
            ):
                scan_root(root, govulncheck_command=None, binary_cache_dir=cache_alias)

    def test_cache_write_failure_is_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            (root / "app").write_bytes(ELF_MAGIC)
            completed = subprocess.CompletedProcess(
                [], 0, '{"GoVersion": "go1.26"}', ""
            )
            with (
                patch(
                    "pygo_audit.scanner._resolve_go_tool", return_value=("go", "test")
                ),
                patch("pygo_audit.scanner.subprocess.run", return_value=completed),
                patch(
                    "pygo_audit.scanner.BinaryResultCache.store",
                    side_effect=ResultCacheError("disk full"),
                ),
                self.assertRaisesRegex(ResultCacheError, "disk full"),
            ):
                scan_root(root, govulncheck_command=None)

    def test_reconciliation_mismatch_is_visible_but_informational(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            root.mkdir()
            (root / "app").write_bytes(ELF_MAGIC)
            observed = "\n".join(
                json.dumps(item)
                for item in [
                    {"config": {"go_version": "go1.25"}},
                    {
                        "SBOM": {
                            "go_version": "go1.25",
                            "modules": [
                                {"path": "stdlib", "version": "go1.25"},
                            ],
                        }
                    },
                ]
            )
            with (
                patch("pygo_audit.scanner._resolve_go_tool", return_value=("go", "test")),
                patch(
                    "pygo_audit.scanner._resolve_govulncheck_tool",
                    return_value=("govulncheck", "test"),
                ),
                patch(
                    "pygo_audit.scanner.subprocess.run",
                    side_effect=[
                        subprocess.CompletedProcess([], 0, '{"GoVersion": "go1.26"}', ""),
                        subprocess.CompletedProcess([], 0, observed, ""),
                    ],
                ),
            ):
                report = scan_root(root)
            self.assertEqual(report.binaries[0].reconciliation.status, "mismatch")
            self.assertEqual(
                report.binaries[0].reconciliation.go_version_status, "mismatch"
            )
            self.assertEqual(report.coverage_state, "complete")
            self.assertEqual(report.result_state, "clean")
            self.assertEqual(report.issues, [])

    def test_hashes_descriptor_in_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            first_file = Path(temporary_directory) / "first"
            first_file.write_bytes(b"prefix\x00.symtab\x00suffix")
            second_file = Path(temporary_directory) / "second"
            second_file.write_bytes(b"different bytes")

            first_fd = os.open(first_file, os.O_RDONLY)
            second_fd = os.open(second_file, os.O_RDONLY)
            try:
                first_digest = _sha256_descriptor(first_fd, chunk_size=4)
                second_digest = _sha256_descriptor(second_fd, chunk_size=4)
                self.assertEqual(
                    first_digest,
                    hashlib.sha256(first_file.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    second_digest,
                    hashlib.sha256(second_file.read_bytes()).hexdigest(),
                )
            finally:
                os.close(first_fd)
                os.close(second_fd)


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
            govulncheck_count = temporary / "govulncheck-count"
            fake_govulncheck.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "-version" ]; then\n'
                "  echo 'Scanner: govulncheck@test'\n"
                "  exit 0\n"
                "fi\n"
                f"printf 'x\\n' >> {shlex.quote(os.fspath(govulncheck_count))}\n"
                'echo \'{"config":{"protocol_version":"v1.0.0",'
                '"scanner_name":"govulncheck","scanner_version":"test",'
                '"db":"https://vuln.example","scan_level":"symbol",'
                '"scan_mode":"binary"}}\'\n'
            )
            fake_govulncheck.chmod(0o755)

            real_go = shutil.which("go")
            assert real_go is not None
            fake_go = temporary / "go"
            go_version_count = temporary / "go-version-m-count"
            fake_go.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = version ] && [ "$2" = -m ]; then\n'
                f"  printf 'x\\n' >> {shlex.quote(os.fspath(go_version_count))}\n"
                "fi\n"
                f'exec {shlex.quote(real_go)} "$@"\n'
            )
            fake_go.chmod(0o755)

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
            shutil.copyfile(binary, root / "usr" / "bin" / "fixture-copy")
            binary.chmod(0o644)
            os.symlink("usr/bin", root / "bin")
            os.symlink("/bin/fixture", root / "usr" / "bin" / "fixture-symlink")
            (root / "etc" / "not-a-binary").write_text("configuration")
            expected_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

            report = scan_root(
                root,
                go_command=os.fspath(fake_go),
                govulncheck_command=os.fspath(fake_govulncheck),
                binary_cache_dir=temporary / "binary-cache",
                run_id="batch-run",
                jobs=2,
            )
            second_root = temporary / "second-root"
            shutil.copytree(root, second_root, symlinks=True)
            second_report = scan_root(
                second_root,
                go_command=os.fspath(fake_go),
                govulncheck_command=os.fspath(fake_govulncheck),
                binary_cache_dir=temporary / "binary-cache",
                run_id="batch-run",
                jobs=2,
            )

            self.assertEqual(len(report.binaries), 2)
            self.assertEqual(len(second_report.binaries), 3)
            self.assertEqual(sum(len(binary.paths) for binary in report.binaries), 3)
            self.assertEqual(
                len(govulncheck_count.read_text(encoding="utf-8").splitlines()),
                1,
            )
            self.assertEqual(
                len(go_version_count.read_text(encoding="utf-8").splitlines()),
                1,
            )
            self.assertEqual(binary.stat().st_mode & 0o111, 0)
            self.assertEqual(report.stats.symlinks_skipped, 2)
            self.assertEqual(
                [binary.paths for binary in report.binaries],
                [
                    ["/usr/bin/fixture", "/usr/bin/fixture-hardlink"],
                    ["/usr/bin/fixture-copy"],
                ],
            )
            self.assertEqual(
                report.binaries[0].symlinks,
                [
                    "/bin/fixture",
                    "/bin/fixture-hardlink",
                    "/usr/bin/fixture-symlink",
                ],
            )
            self.assertEqual(report.binaries[1].symlinks, ["/bin/fixture-copy"])
            for binary_report in report.binaries:
                self.assertEqual(binary_report.runtime_disposition, "runtime")
                self.assertEqual(
                    binary_report.main_package,
                    "example.test/auditfixture",
                )
                self.assertEqual(binary_report.sha256, expected_sha256)
                self.assertFalse(binary_report.cgo_enabled)
                self.assertEqual(
                    binary_report.vulnerability_scan.status,
                    "complete",
                )
                self.assertEqual(binary_report.vulnerability_scan.vulnerabilities, [])
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

            # A new invocation reuses embedded metadata but refreshes vulnerability data.
            refreshed = scan_root(
                second_root,
                go_command=os.fspath(fake_go),
                govulncheck_command=os.fspath(fake_govulncheck),
                binary_cache_dir=temporary / "binary-cache",
                jobs=2,
            )
            self.assertEqual(refreshed.issues, [])
            self.assertEqual(len(govulncheck_count.read_text().splitlines()), 2)
            self.assertEqual(len(go_version_count.read_text().splitlines()), 1)

            cache_object = next((temporary / "binary-cache" / "objects").glob("*.json"))
            cache_object.write_bytes(b"corrupt")
            repaired_report = scan_root(
                second_root,
                go_command=os.fspath(fake_go),
                govulncheck_command=os.fspath(fake_govulncheck),
                binary_cache_dir=temporary / "binary-cache",
                jobs=2,
            )
            self.assertEqual(repaired_report.issues, [])
            self.assertEqual(len(govulncheck_count.read_text().splitlines()), 3)
            self.assertEqual(len(go_version_count.read_text().splitlines()), 2)
            self.assertNotEqual(cache_object.read_bytes(), b"corrupt")

    def test_non_go_elf_is_not_reported_as_an_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fake = root / "fake"
            fake.write_bytes(ELF_MAGIC + b"\x00" * 64)
            fake.chmod(0o755)

            report = scan_root(root, govulncheck_command=None)

            self.assertEqual(report.stats.unique_elf_files, 1)
            self.assertEqual(report.binaries, [])
            self.assertEqual(report.issues, [])


if __name__ == "__main__":
    unittest.main()
