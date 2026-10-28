from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit.artifacts import (
    ArtifactError,
    publish_audit,
    write_artifacts,
    write_check_artifacts,
    write_comparison_artifacts,
    write_report_artifacts,
)
from pygo_audit.models import AuditReport, BinaryReport, ContainerMetadata, Module
from pygo_audit.audit import AuditError, load_audit
from pygo_audit.storage import atomic_write_text, directory_lock


class ArtifactTests(unittest.TestCase):
    def test_comparison_pair_failure_restores_previous_files(self) -> None:
        for name in ("comparison", "aggregate"):
            for existing in (False, True):
                with (
                    self.subTest(name=name, existing=existing),
                    TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary)
                    paths = [root / f"{name}.json", root / f"{name}.txt"]
                    (root / "notes.txt").write_text("analyst notes\n")
                    if existing:
                        for path in paths:
                            path.write_text("previous report\n")
                    before = {path: path.read_bytes() for path in root.iterdir()}

                    def publish(path, content, **options):
                        if path == paths[1]:
                            raise OSError("second file failed")
                        atomic_write_text(path, content, **options)

                    with (
                        patch(
                            "pygo_audit.artifacts.atomic_write_text", side_effect=publish
                        ),
                        self.assertRaisesRegex(OSError, "second file failed"),
                    ):
                        write_comparison_artifacts(
                            root, name, {"new": True}, "new report", inputs=[]
                        )
                    self.assertEqual(
                        {path: path.read_bytes() for path in root.iterdir()}, before
                    )

    def test_comparison_publication_rejects_an_active_directory_lock(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("comparison", "aggregate"):
                with self.subTest(name=name), directory_lock(root):
                    with self.assertRaisesRegex(ValueError, "output is already in use"):
                        write_comparison_artifacts(root, name, {}, "report", inputs=[])
                self.assertEqual(list(root.iterdir()), [])

    def test_text_refresh_rolls_back_existing_and_new_files(self) -> None:
        report = AuditReport(ContainerMetadata("/rootfs"), "go", "test")
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            overview = root / "overview.txt"
            overview.write_text("previous overview\n")

            def publish(path, content, **options):
                if path.name == "vulnerability-findings.txt":
                    raise OSError("simulated replacement failure")
                atomic_write_text(path, content, **options)

            with (
                patch("pygo_audit.artifacts.atomic_write_text", side_effect=publish),
                self.assertRaisesRegex(ArtifactError, "simulated replacement failure"),
            ):
                write_report_artifacts(report, root)
            self.assertEqual(overview.read_text(), "previous overview\n")
            self.assertEqual(list(root.iterdir()), [overview])

    def test_refresh_failure_restores_previous_current_views(self):
        report = AuditReport(
            metadata=ContainerMetadata("/subject"),
            go_command="go",
            go_tool_version="old",
            producer_name="pygo-audit",
            producer_version="test",
            run_id="prior-run",
            scan_completed_at="2026-10-24T12:00:00Z",
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, history = root / "work", root / "history"
            work.mkdir()
            paths = write_artifacts(report, root)
            old = {path: path.read_bytes() for path in paths}
            report.go_tool_version = "new"
            failed = False

            def publish(path, content, **options):
                nonlocal failed
                if path == root / "binary-findings.txt" and not failed:
                    failed = True
                    raise OSError("simulated failed replacement")
                atomic_write_text(path, content, **options)

            with (
                patch("pygo_audit.artifacts.atomic_write_text", side_effect=publish),
                self.assertRaises(OSError),
            ):
                publish_audit(report, root, history, work)
            self.assertEqual({path: path.read_bytes() for path in paths}, old)
            self.assertEqual(
                next(history.glob("audit-*.json")).read_bytes(),
                old[root / "audit.json"],
            )

    def test_failed_publication_rolls_back_only_new_artifacts(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="test version",
        )
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            sentinel = output / "analyst.txt"
            sentinel.write_text("keep me", encoding="utf-8")

            def publish(destination: Path, content: str, **options: object) -> None:
                if destination.name == "overview.txt":
                    raise OSError("publication failed")
                atomic_write_text(destination, content, **options)

            with patch("pygo_audit.artifacts.atomic_write_text", side_effect=publish):
                with self.assertRaisesRegex(ArtifactError, "publication failed"):
                    write_artifacts(report, output)
            self.assertEqual(list(output.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep me")

    def test_writes_portable_artifacts_from_one_report(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="/usr/bin/go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        report.binaries.append(
            BinaryReport(
                paths=["/usr/bin/example"],
                size=1_000_000,
                go_version="go1.26.8",
                main_package="example.test/cmd",
                main_module=None,
                dependencies=[
                    Module(f"example.test/dependency{index:02d}", "v1.0.0")
                    for index in range(12)
                ],
                build_settings=[],
                sha256="a" * 64,
            )
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "artifacts"

            paths = write_artifacts(report, output_directory)
            loaded = load_audit(output_directory / "audit.json")

            self.assertEqual(
                [path.name for path in paths],
                [
                    "overview.txt",
                    "binary-findings.txt",
                    "vulnerability-findings.txt",
                    "module-reconciliation.txt",
                    "diagnostics.txt",
                    "audit.json",
                ],
            )
            self.assertEqual(loaded.to_dict(), report.to_dict())
            self.assertEqual(
                json.loads((output_directory / "audit.json").read_text()),
                report.to_dict(),
            )
            self.assertIn(
                "PYGO-AUDIT VULNERABILITY FINDINGS",
                (output_directory / "vulnerability-findings.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT OVERVIEW",
                (output_directory / "overview.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT BINARY FINDINGS",
                (output_directory / "binary-findings.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT MODULE RECONCILIATION",
                (output_directory / "module-reconciliation.txt").read_text(),
            )
            self.assertIn(
                "PYGO-AUDIT DIAGNOSTICS",
                (output_directory / "diagnostics.txt").read_text(),
            )
            binary_findings = (output_directory / "binary-findings.txt").read_text()
            modules = (output_directory / "module-reconciliation.txt").read_text()
            self.assertIn("SHA-256:                " + "a" * 64, binary_findings)
            self.assertIn("example.test/dependency11", modules)
            self.assertNotIn(" omitted;", modules)
            self.assertFalse((output_directory / "full.txt").exists())

    def test_writes_derived_reports_without_copying_audit_json(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="test",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "reports"

            paths = write_report_artifacts(report, output_directory)

            self.assertEqual(
                [path.name for path in paths],
                [
                    "overview.txt",
                    "binary-findings.txt",
                    "vulnerability-findings.txt",
                    "module-reconciliation.txt",
                    "diagnostics.txt",
                ],
            )
            self.assertFalse((output_directory / "audit.json").exists())

    def test_overwrites_different_generated_artifact(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory)
            existing = output_directory / "overview.txt"
            existing.write_text("analyst-owned\n", encoding="utf-8")

            write_artifacts(report, output_directory)

            self.assertNotEqual(existing.read_text(encoding="utf-8"), "analyst-owned\n")
            self.assertTrue((output_directory / "audit.json").exists())

    def test_reuses_identical_artifacts_and_adds_saved_check(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
        )
        with TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "artifacts"

            initial_paths = write_artifacts(report, output_directory)
            initial_contents = {path: path.read_bytes() for path in initial_paths}
            paths = write_artifacts(
                report,
                output_directory,
                checks=["CVE-2026-46595", "cve-2026-46595"],
            )

            self.assertEqual(
                {path: path.read_bytes() for path in initial_paths},
                initial_contents,
            )
            self.assertEqual(len(paths), 7)
            check_path = output_directory / "checks" / "CVE-2026-46595.txt"
            self.assertIn(check_path, paths)
            check_output = check_path.read_text(encoding="utf-8")
            self.assertIn("VULNERABILITY CHECK", check_output)
            self.assertIn("\nCVE-2026-46595\n", check_output)
            self.assertNotIn("Identifier:", check_output)
            self.assertIn("Result:                 NO GO BINARIES", check_output)
            self.assertIn("Audit SHA-256:", check_output)
            self.assertLess(
                check_output.index("Result:"),
                check_output.index("PROVENANCE"),
            )
            self.assertEqual(check_output.count("PROVENANCE"), 1)
            self.assertNotIn("More information:", check_output)

    def test_invalid_scan_cannot_replace_current_audit_or_views(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/subject"),
            go_command="go",
            go_tool_version="test",
            producer_name="pygo-audit",
            producer_version="test",
            run_id="completed-run",
            scan_completed_at="2026-10-24T12:00:00Z",
        )
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, history = root / "work", root / "history"
            work.mkdir()
            paths = write_artifacts(report, root)
            original = {path: path.read_bytes() for path in paths}
            report.metadata.root = ""
            with self.assertRaisesRegex(AuditError, r"audit\.metadata\.root"):
                publish_audit(report, root, history, work)
            self.assertEqual({path: path.read_bytes() for path in paths}, original)
            self.assertFalse(history.exists())
            self.assertEqual(list(work.iterdir()), [])

    def test_writes_only_check_artifacts_for_check_command(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
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
