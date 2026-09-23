from __future__ import annotations

from contextlib import redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from pygo_audit.cli import build_parser, main
from pygo_audit.models import ScanIssue, ScanReport


class CliTests(unittest.TestCase):
    def test_defaults_to_repository_sandbox(self) -> None:
        arguments = build_parser().parse_args([])

        self.assertEqual(arguments.root, Path("sandbox"))

    def test_accepts_explicit_root(self) -> None:
        arguments = build_parser().parse_args(["/tmp/rootfs"])

        self.assertEqual(arguments.root, Path("/tmp/rootfs"))

    def test_accepts_container_output_format(self) -> None:
        arguments = build_parser().parse_args(["--format", "container"])

        self.assertEqual(arguments.format, "container")

    def test_accepts_summary_output_format(self) -> None:
        arguments = build_parser().parse_args(["--format", "summary"])

        self.assertEqual(arguments.format, "summary")

    def test_accepts_repeatable_checks_and_grouping(self) -> None:
        arguments = build_parser().parse_args(
            [
                "--check",
                "CVE-2026-0001",
                "--check",
                "GO-2026-0002",
                "--group-by",
                "package",
            ]
        )

        self.assertEqual(
            arguments.check,
            ["CVE-2026-0001", "GO-2026-0002"],
        )
        self.assertEqual(arguments.group_by, "package")

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
                status = main(["/tmp/root", "--strict"])

        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
