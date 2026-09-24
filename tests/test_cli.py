from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from pygo_audit.cli import (
    build_check_parser,
    build_report_parser,
    build_scan_parser,
    main,
)
from pygo_audit.models import ScanIssue, ScanReport


class CliTests(unittest.TestCase):
    def test_scan_parser_defaults_to_repository_sandbox(self) -> None:
        arguments = build_scan_parser().parse_args([])

        self.assertEqual(arguments.root, Path("sandbox"))
        self.assertFalse(hasattr(arguments, "format"))

    def test_scan_parser_accepts_identity_and_artifact_options(self) -> None:
        arguments = build_scan_parser().parse_args(
            [
                "/tmp/rootfs",
                "--snapshot-dir",
                "/tmp/snapshots",
                "--output-dir",
                "/tmp/artifacts",
                "--image-ref",
                "registry.example.test/team/app:v1",
                "--image-digest",
                "sha256:" + "a" * 64,
                "--platform",
                "linux/amd64",
                "--extractor",
                "oc image extract",
            ]
        )

        self.assertEqual(arguments.root, Path("/tmp/rootfs"))
        self.assertEqual(arguments.snapshot_dir, Path("/tmp/snapshots"))
        self.assertEqual(arguments.output_dir, Path("/tmp/artifacts"))
        self.assertEqual(arguments.image_reference, "registry.example.test/team/app:v1")
        self.assertEqual(arguments.platform, "linux/amd64")

    def test_report_parser_uses_explicit_views(self) -> None:
        arguments = build_report_parser().parse_args(
            [
                "findings",
                "/tmp/report.json",
                "--group-by",
                "package",
                "--output-dir",
                "/tmp/artifacts",
            ]
        )

        self.assertEqual(arguments.view, "findings")
        self.assertEqual(arguments.snapshot_path, Path("/tmp/report.json"))
        self.assertEqual(arguments.group_by, "package")
        self.assertEqual(arguments.output_dir, Path("/tmp/artifacts"))

        diagnostics = build_report_parser().parse_args(
            ["diagnostics", "/tmp/report.json"]
        )
        self.assertEqual(diagnostics.view, "diagnostics")
        self.assertEqual(diagnostics.snapshot_path, Path("/tmp/report.json"))

    def test_check_parser_accepts_one_or_more_identifiers(self) -> None:
        arguments = build_check_parser().parse_args(
            [
                "/tmp/report.json",
                "CVE-2026-0001",
                "GO-2026-0002",
                "--output-dir",
                "/tmp/artifacts",
            ]
        )

        self.assertEqual(arguments.snapshot_path, Path("/tmp/report.json"))
        self.assertEqual(
            arguments.identifiers,
            ["CVE-2026-0001", "GO-2026-0002"],
        )
        self.assertEqual(arguments.output_dir, Path("/tmp/artifacts"))

    def test_format_interface_is_not_accepted(self) -> None:
        errors = io.StringIO()

        with redirect_stderr(errors):
            with self.assertRaises(SystemExit) as raised:
                build_scan_parser().parse_args(["/tmp/rootfs", "--format", "json"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unrecognized arguments: --format json", errors.getvalue())

    def test_strict_ignores_informational_reconciliation_differences(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.issues.append(
            ScanIssue(
                "/bin/app",
                "reconciliation-difference",
                "equivalent version representations",
            )
        )

        with patch("pygo_audit.cli.scan_root", return_value=report):
            with redirect_stdout(io.StringIO()):
                status = main(["scan", "/tmp/root", "--strict"])

        self.assertEqual(status, 0)

    def test_scan_writes_snapshot_and_bundle_without_rescanning(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        output = io.StringIO()
        errors = io.StringIO()

        with patch("pygo_audit.cli.scan_root", return_value=report) as scan:
            with patch(
                "pygo_audit.cli.write_snapshot",
                return_value=Path("/tmp/snapshots/report.json"),
            ) as write_snapshot:
                with patch("pygo_audit.cli.write_artifacts") as write_artifacts:
                    with patch("pygo_audit.cli.validate_artifact_directory"):
                        with redirect_stdout(output), redirect_stderr(errors):
                            status = main(
                                [
                                    "scan",
                                    "/tmp/root",
                                    "--snapshot-dir",
                                    "/tmp/snapshots",
                                    "--output-dir",
                                    "/tmp/artifacts",
                                    "--image-ref",
                                    "registry.example.test/team/app:v1",
                                    "--platform",
                                    "linux/amd64",
                                ]
                            )

        self.assertEqual(status, 0)
        scan.assert_called_once()
        write_snapshot.assert_called_once_with(report, Path("/tmp/snapshots"))
        write_artifacts.assert_called_once_with(
            report,
            Path("/tmp/artifacts"),
        )
        self.assertEqual(
            report.image_identity.reference,
            "registry.example.test/team/app:v1",
        )
        self.assertIn("PYGO-AUDIT OVERVIEW", output.getvalue())
        self.assertIn("Snapshot: /tmp/snapshots/report.json", errors.getvalue())
        self.assertIn("Artifacts: /tmp/artifacts", errors.getvalue())

    def test_report_view_renders_snapshot_without_scanning(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        output = io.StringIO()

        with patch("pygo_audit.cli.load_snapshot", return_value=report) as load:
            with patch("pygo_audit.cli.scan_root") as scan:
                with redirect_stdout(output):
                    status = main(
                        ["report", "overview", "/tmp/report.json"]
                    )

        self.assertEqual(status, 0)
        load.assert_called_once_with(Path("/tmp/report.json"))
        scan.assert_not_called()
        self.assertIn("PYGO-AUDIT OVERVIEW", output.getvalue())
        self.assertIn("AFFECTED PACKAGES (0)", output.getvalue())

    def test_diagnostics_view_renders_snapshot_without_scanning(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.issues.append(ScanIssue("/bin/app", "open", "permission denied"))
        output = io.StringIO()

        with patch("pygo_audit.cli.load_snapshot", return_value=report) as load:
            with patch("pygo_audit.cli.scan_root") as scan:
                with redirect_stdout(output):
                    status = main(
                        ["report", "diagnostics", "/tmp/report.json"]
                    )

        self.assertEqual(status, 0)
        load.assert_called_once_with(Path("/tmp/report.json"))
        scan.assert_not_called()
        self.assertIn("PYGO-AUDIT DIAGNOSTICS", output.getvalue())
        self.assertIn("permission denied", output.getvalue())

    def test_check_command_outputs_and_saves_only_targeted_results(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        output = io.StringIO()
        errors = io.StringIO()

        with patch("pygo_audit.cli.load_snapshot", return_value=report):
            with patch("pygo_audit.cli.write_check_artifacts") as write_checks:
                with patch("pygo_audit.cli.write_artifacts") as write_bundle:
                    with patch("pygo_audit.cli.validate_artifact_directory"):
                        with redirect_stdout(output), redirect_stderr(errors):
                            status = main(
                                [
                                    "check",
                                    "/tmp/report.json",
                                    "CVE-2026-0001",
                                    "--output-dir",
                                    "/tmp/artifacts",
                                ]
                            )

        self.assertEqual(status, 0)
        write_checks.assert_called_once_with(
            report,
            Path("/tmp/artifacts"),
            ["CVE-2026-0001"],
        )
        write_bundle.assert_not_called()
        self.assertIn("VULNERABILITY CHECK", output.getvalue())
        self.assertIn("CVE-2026-0001", output.getvalue())
        self.assertNotIn("PYGO-AUDIT OVERVIEW", output.getvalue())
        self.assertNotIn("PYGO-AUDIT FINDINGS", output.getvalue())
        self.assertIn("Checks: /tmp/artifacts/checks", errors.getvalue())

    def test_root_level_scan_syntax_is_not_accepted(self) -> None:
        errors = io.StringIO()

        with patch("pygo_audit.cli.scan_root") as scan:
            with redirect_stderr(errors):
                status = main(["/tmp/rootfs"])

        self.assertEqual(status, 2)
        scan.assert_not_called()
        self.assertIn("usage: pygo-audit COMMAND", errors.getvalue())

    def test_snapshot_and_artifact_directories_must_be_different(self) -> None:
        errors = io.StringIO()
        with patch("pygo_audit.cli.scan_root") as scan:
            with redirect_stderr(errors):
                status = main(
                    [
                        "scan",
                        "--snapshot-dir",
                        "/tmp/results",
                        "--output-dir",
                        "/tmp/results",
                    ]
                )

        self.assertEqual(status, 2)
        scan.assert_not_called()
        self.assertIn("must be different", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
