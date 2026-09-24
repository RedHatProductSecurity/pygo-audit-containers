from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.artifacts import (
    ArtifactError,
    write_artifacts,
    write_check_artifacts,
)
from pygo_audit.models import ScanReport
from pygo_audit.snapshot import load_snapshot


class ArtifactTests(unittest.TestCase):
    def test_writes_portable_bundle_from_one_report(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="/usr/bin/go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "artifacts"

            paths = write_artifacts(report, output_directory)
            loaded = load_snapshot(output_directory / "audit.json")

            self.assertEqual(
                [path.name for path in paths],
                [
                    "audit.json",
                    "overview.txt",
                    "findings.txt",
                    "binaries.txt",
                    "diagnostics.txt",
                ],
            )
            self.assertEqual(loaded.to_dict(), report.to_dict())
            self.assertEqual(
                json.loads((output_directory / "audit.json").read_text()),
                report.to_dict(),
            )
            self.assertIn(
                "PYGO-AUDIT FINDINGS",
                (output_directory / "findings.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT OVERVIEW",
                (output_directory / "overview.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT DIAGNOSTICS",
                (output_directory / "diagnostics.txt").read_text(),
            )

    def test_refuses_to_overwrite_different_generated_artifact(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            existing = output_directory / "overview.txt"
            existing.write_text("analyst-owned\n", encoding="utf-8")

            with self.assertRaisesRegex(ArtifactError, "different content"):
                write_artifacts(report, output_directory)

            self.assertEqual(existing.read_text(encoding="utf-8"), "analyst-owned\n")
            self.assertFalse((output_directory / "audit.json").exists())

    def test_reuses_identical_artifacts_and_adds_saved_check(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "artifacts"

            initial_paths = write_artifacts(report, output_directory)
            initial_contents = {
                path: path.read_bytes() for path in initial_paths
            }
            paths = write_artifacts(
                report,
                output_directory,
                checks=["CVE-2026-46595", "cve-2026-46595"],
            )

            self.assertEqual(
                {path: path.read_bytes() for path in initial_paths},
                initial_contents,
            )
            self.assertEqual(len(paths), 6)
            check_path = output_directory / "checks" / "CVE-2026-46595.txt"
            self.assertIn(check_path, paths)
            check_output = check_path.read_text(encoding="utf-8")
            self.assertIn("VULNERABILITY CHECK", check_output)
            self.assertIn("\nCVE-2026-46595\n", check_output)
            self.assertNotIn("Identifier:", check_output)
            self.assertIn("Result:                 NO GO BINARIES", check_output)
            self.assertIn("Snapshot SHA-256:", check_output)
            self.assertLess(
                check_output.index("Result:"),
                check_output.index("SCAN CONTEXT"),
            )
            self.assertNotIn("PROVENANCE", check_output)

    def test_writes_only_check_artifacts_for_check_command(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="go",
            go_tool_version="go version go1.26.8 linux/amd64",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "artifacts"

            paths = write_check_artifacts(
                report,
                output_directory,
                ["CVE-2026-46595"],
            )

            self.assertEqual(
                paths,
                [output_directory / "checks" / "CVE-2026-46595.txt"],
            )
            self.assertFalse((output_directory / "audit.json").exists())
            self.assertFalse((output_directory / "overview.txt").exists())
            self.assertTrue(paths[0].is_file())


if __name__ == "__main__":
    unittest.main()
