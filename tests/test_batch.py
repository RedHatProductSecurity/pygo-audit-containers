from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import Future
import csv
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit.cli import main
from pygo_audit.models import ContainerMetadata, AuditReport, ScanIssue


class BatchAuditTests(unittest.TestCase):
    def test_outcomes_record_published_failed_and_missing_evidence(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("complete", "incomplete", "error"):
                (root / name / "rootfs").mkdir(parents=True)

            def scan(subject, layers, **options):
                name = subject.parent.name
                if name == "error":
                    raise ValueError("inspection failed")
                return AuditReport(
                    ContainerMetadata(str(subject)),
                    "go",
                    "test",
                    producer_name="pygo-audit",
                    producer_version="test",
                    scan_completed_at="2026-10-24T12:00:00Z",
                    issues=[ScanIssue("/app", "open", "denied")]
                    if name == "incomplete"
                    else [],
                )

            with (
                patch("pygo_audit.scanner.scan_root", side_effect=scan),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(["audit", str(root)]), 1)
            with (root / "progress.tsv").open() as stream:
                rows = {
                    row["name"]: row for row in csv.DictReader(stream, delimiter="\t")
                }
            self.assertEqual(rows["complete"]["status"], "COMPLETE")
            self.assertEqual(
                Path(rows["complete"]["audit_file"]), root / "complete" / "audit.json"
            )
            failed = Path(rows["incomplete"]["audit_file"])
            self.assertEqual(rows["incomplete"]["status"], "FAILED")
            self.assertTrue(failed.is_file())
            self.assertTrue(failed.is_relative_to(root / "work"))
            self.assertEqual(
                json.loads(failed.read_text())["issues"][0]["message"], "denied"
            )
            self.assertFalse((root / "incomplete" / "audit.json").exists())
            self.assertEqual(rows["error"]["status"], "FAILED")
            self.assertEqual(rows["error"]["audit_file"], "")
            self.assertEqual(rows["error"]["detail"], "inspection failed")
            summary = (root / "reports" / "container-summary.txt").read_text()
            self.assertFalse((root / "container-summary.txt").exists())
            self.assertIn(str(failed), summary)
            self.assertIn("inspection failed", summary)

    def test_fail_fast_records_cancelled_targets_without_audit_paths(self):
        failed, queued = Future(), Future()
        failed.set_exception(ValueError("inspection failed"))
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("first", "queued"):
                (root / name / "rootfs").mkdir(parents=True)
            with (
                patch("pygo_audit.batch.ThreadPoolExecutor") as executor,
                patch(
                    "pygo_audit.batch.as_completed",
                    side_effect=lambda pending: iter(pending),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                executor.return_value.__enter__.return_value.submit.side_effect = [
                    failed,
                    queued,
                ]
                self.assertEqual(main(["audit", str(root), "--fail-fast"]), 1)
            with (root / "progress.tsv").open() as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
            self.assertEqual(
                rows[1],
                {
                    "name": "queued",
                    "status": "CANCELLED",
                    "audit_file": "",
                    "detail": "not started",
                },
            )

    def test_prepared_children_share_run_and_cache_and_keep_subjects(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("alpha", "beta"):
                (root / name / "rootfs").mkdir(parents=True)
                (root / name / "rootfs" / "sentinel").write_text(name)
            calls = []

            def scan(subject, layers, **options):
                calls.append((subject, options))
                return AuditReport(
                    metadata=ContainerMetadata(str(subject)),
                    go_command="go",
                    go_tool_version="test",
                    producer_name="pygo-audit",
                    producer_version="test",
                    scan_completed_at="2026-10-24T12:00:00Z",
                )

            with (
                patch("pygo_audit.scanner.scan_root", side_effect=scan),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(["audit", str(root)]), 0)
                first_ids = {options["run_id"] for _, options in calls}
                self.assertEqual(len(first_ids), 1)
                self.assertTrue(
                    all(
                        options["binary_cache_dir"] == root / "cache"
                        for _, options in calls
                    )
                )
                self.assertEqual(main(["audit", str(root)]), 0)
            self.assertNotEqual(calls[0][1]["run_id"], calls[2][1]["run_id"])
            for name in ("alpha", "beta"):
                self.assertTrue((root / name / "audit.json").is_file())
                self.assertEqual(
                    (root / name / "rootfs" / "sentinel").read_text(), name
                )
                self.assertEqual(len(list((root / name / "history").glob("*.json"))), 1)
                self.assertFalse((root / name / "cache").exists())
            self.assertTrue((root / "cache").is_dir())

    def test_batch_and_child_settings_obey_cli_precedence(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "child" / "rootfs").mkdir(parents=True)
            (root / "pygo-audit.json").write_text(json.dumps({"jobs": 1}))
            (root / "child" / "pygo-audit.json").write_text(json.dumps({"jobs": 2}))
            result = AuditReport(
                metadata=ContainerMetadata("root"),
                go_command="go",
                go_tool_version="test",
                producer_name="pygo-audit",
                producer_version="test",
            )
            with (
                patch("pygo_audit.scanner.scan_root", return_value=result) as scan,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(["audit", str(root), "--jobs", "3"]), 0)
            self.assertEqual(scan.call_args.kwargs["jobs"], 3)

    def test_missing_explicit_target_fails_before_scanning(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            targets = root / "targets"
            targets.write_text("missing\n")
            with (
                patch("pygo_audit.scanner.scan_root") as scan,
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    main(["audit", str(root), "--targets", str(targets)]), 1
                )
            scan.assert_not_called()
            self.assertFalse((root / "cache").exists())

    def test_unexpected_scan_error_is_not_hidden_as_target_failure(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "child" / "rootfs").mkdir(parents=True)
            with (
                patch(
                    "pygo_audit.scanner.scan_root",
                    side_effect=RuntimeError("implementation bug"),
                ),
                self.assertRaisesRegex(RuntimeError, "implementation bug"),
            ):
                main(["audit", str(root)])
