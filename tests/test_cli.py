from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout, chdir
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit.cli import main
from pygo_audit.models import (
    AuditReport,
    BinaryReport,
    ContainerMetadata,
    Module,
    ScanIssue,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.audit import load_audit
from pygo_audit.report import (
    render_binaries,
    render_diagnostics,
    render_by_vulnerability,
    render_json,
    render_module_reconciliation,
    render_overview,
)
from pygo_audit.text_layout import DETAILED_POLICY, FULL_POLICY
from pygo_audit.storage import atomic_write_json, directory_lock


def report(root: Path) -> AuditReport:
    return AuditReport(
        metadata=ContainerMetadata(str(root / "rootfs")),
        go_command="go",
        go_tool_version="test",
        producer_name="pygo-audit",
        producer_version="test",
        scan_completed_at="2026-10-23T12:00:00Z",
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "rootfs").mkdir()

    def invoke(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(list(args))

    def test_default_cwd_scan_saves_and_archives_previous_report(self):
        first = report(self.root)
        with (
            chdir(self.root),
            patch("pygo_audit.scanner.scan_root", return_value=first),
        ):
            self.assertEqual(self.invoke("scan"), 0)
        previous = (self.root / "audit.json").read_bytes()
        second = report(self.root)
        second.go_tool_version = "updated"
        with patch("pygo_audit.scanner.scan_root", return_value=second):
            self.assertEqual(self.invoke("scan", str(self.root)), 0)
        historical = list((self.root / "history").glob("audit-*-*.json"))
        self.assertEqual(len(historical), 1)
        self.assertEqual(historical[0].read_bytes(), previous)
        self.assertEqual(
            load_audit(self.root / "audit.json").go_tool_version, "updated"
        )
        self.assertTrue((self.root / "reports" / "overview.txt").is_file())
        self.assertFalse((self.root / "overview.txt").exists())
        self.assertNotEqual(first.run_id, second.run_id)

    def test_scan_reports_use_saved_evidence_even_if_scanner_result_changes(
        self,
    ) -> None:
        for strict in (False, True):
            with self.subTest(strict=strict):
                scanned = report(self.root)
                if strict:
                    scanned.issues.append(ScanIssue("/binary", "open", "denied"))

                def serialize(result: AuditReport) -> str:
                    payload = render_json(result)
                    scanned.go_tool_version = "unsaved change"
                    return payload

                with (
                    patch("pygo_audit.scanner.scan_root", return_value=scanned),
                    patch("pygo_audit.artifacts.render_json", side_effect=serialize),
                    redirect_stdout(io.StringIO()) as output,
                    redirect_stderr(io.StringIO()),
                ):
                    arguments = ["scan", str(self.root)]
                    if strict:
                        arguments.append("--strict")
                    self.assertEqual(main(arguments), int(strict))

                saved = (
                    next((self.root / "work").glob("failed-*/audit.json"))
                    if strict
                    else self.root / "audit.json"
                )
                saved_report = load_audit(saved)
                self.assertEqual(output.getvalue(), render_overview(saved_report) + "\n")
                self.assertEqual(
                    (saved.parent / "reports" / "overview.txt").read_text(),
                    render_overview(saved_report, FULL_POLICY) + "\n",
                )
                self.assertNotIn("unsaved change", output.getvalue())

    def test_optional_layers_are_automatic_and_have_no_inferred_chronology(self):
        for name in ("layer-10", "layer-2"):
            (self.root / "layers" / name).mkdir(parents=True)
        with patch(
            "pygo_audit.scanner.scan_root", return_value=report(self.root)
        ) as scan:
            self.assertEqual(
                self.invoke("scan", str(self.root), "--layer-sort", "numeric"), 0
            )
        self.assertEqual(
            [p.name for p in scan.call_args.args[1]], ["layer-2", "layer-10"]
        )
        self.assertFalse(scan.call_args.kwargs["layers_ordered"])
        with patch(
            "pygo_audit.scanner.scan_root", return_value=report(self.root)
        ) as scan:
            self.assertEqual(self.invoke("scan", str(self.root), "--no-layers"), 0)
        scan.assert_called_once()

    def test_explicit_layers_preserve_order(self):
        layers = [self.root / name for name in ("z-base", "a-new")]
        for path in layers:
            path.mkdir()
        with patch(
            "pygo_audit.scanner.scan_root", return_value=report(self.root)
        ) as scan:
            self.assertEqual(
                self.invoke(
                    "scan",
                    str(self.root),
                    "--layer-dir",
                    str(layers[0]),
                    "--layer-dir",
                    str(layers[1]),
                ),
                0,
            )
        self.assertEqual(scan.call_args.args[1], layers)
        self.assertTrue(scan.call_args.kwargs["layers_ordered"])

    def test_sidecar_identity_and_cli_override(self):
        labels = self.root / "rootfs/usr/share/buildinfo/labels.json"
        labels.parent.mkdir(parents=True, exist_ok=True)
        labels.write_text('{"name": "base", "cpe": "cpe:/a:example:base:1"}')
        (self.root / ".pygo-audit-image.json").write_text(
            json.dumps({"image": {
                "name": "image-sidecar",
                "vendor_image_name": "vendor/service",
                "image_build_release": "sidecar-build",
            }, "products": [{"name": "supplied-base", "cpes": ["cpe:/a:example:supplied:2"]}]})
        )
        (self.root / "pygo-audit.json").write_text(
            json.dumps({"image-name": "workspace", "jobs": 2})
        )
        result = report(self.root)
        with patch("pygo_audit.scanner.scan_root", return_value=result) as scan:
            self.assertEqual(
                self.invoke(
                    "scan", str(self.root), "--image-name", "explicit",
                    "--image-build-release", "explicit-build", "--jobs", "3"
                ),
                0,
            )
        self.assertEqual(result.metadata.image.name, "explicit")
        saved = load_audit(self.root / "audit.json").metadata.image
        self.assertEqual(len(saved.products), 1)
        self.assertEqual(saved.products[0].name, "supplied-base")
        self.assertEqual(saved.products[0].cpes, ("cpe:/a:example:supplied:2",))
        self.assertEqual(saved.vendor_image_name, "vendor/service")
        self.assertEqual(saved.image_build_release, "explicit-build")
        self.assertEqual(scan.call_args.kwargs["jobs"], 3)

    def test_strict_failure_saves_diagnostics_without_replacing_current_audit(self):
        with patch("pygo_audit.scanner.scan_root", return_value=report(self.root)):
            self.assertEqual(self.invoke("scan", str(self.root)), 0)
        original = (self.root / "audit.json").read_bytes()
        failed = report(self.root)
        failed.issues.append(ScanIssue("/binary", "open", "denied"))
        with patch("pygo_audit.scanner.scan_root", return_value=failed):
            self.assertEqual(self.invoke("scan", str(self.root), "--strict"), 1)
        self.assertEqual((self.root / "audit.json").read_bytes(), original)
        self.assertEqual(len(list((self.root / "work").glob("failed-*/audit.json"))), 1)

    def test_output_cannot_be_inside_subject_or_a_symlink(self):
        bad = self.root / "bad-output"
        bad.symlink_to(self.root / "rootfs", target_is_directory=True)
        for destination in (self.root / "rootfs" / "output", bad):
            with patch("pygo_audit.scanner.scan_root") as scan:
                self.assertEqual(
                    self.invoke(
                        "scan", str(self.root), "--output-dir", str(destination)
                    ),
                    1,
                )
            scan.assert_not_called()

    def test_first_scan_overwrites_existing_generated_report_files(self):
        sentinel = self.root / "reports" / "overview.txt"
        sentinel.parent.mkdir()
        sentinel.write_text("analyst notes")
        with patch("pygo_audit.scanner.scan_root", return_value=report(self.root)) as scan:
            self.assertEqual(self.invoke("scan", str(self.root)), 0)
        scan.assert_called_once()
        self.assertNotEqual(sentinel.read_text(), "analyst notes")

    def test_scan_overwrites_current_evidence_without_archive_provenance(self):
        saved = report(self.root)
        for field in ("run_id", "scan_completed_at"):
            saved.run_id = "completed-run"
            saved.scan_completed_at = "2026-10-24T12:00:00Z"
            setattr(saved, field, "")
            path = self.root / "audit.json"
            atomic_write_json(path, saved.to_dict(), overwrite=True)
            original = path.read_bytes()
            with (
                self.subTest(field=field),
                patch("pygo_audit.scanner.scan_root", return_value=report(self.root)) as scan,
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(main(["scan", str(self.root)]), 0)
            self.assertIn("Audit: ", errors.getvalue())
            scan.assert_called_once()
            self.assertNotEqual(path.read_bytes(), original)

    def test_lock_rejects_simultaneous_scan(self):
        with (
            directory_lock(self.root),
            patch("pygo_audit.scanner.scan_root") as scan,
        ):
            self.assertEqual(self.invoke("scan", str(self.root)), 1)
        scan.assert_not_called()
        self.assertFalse((self.root / "audit.lock").exists())

    def test_report_and_check_read_saved_data_without_scanning(self):
        with patch("pygo_audit.scanner.scan_root", return_value=report(self.root)):
            self.assertEqual(self.invoke("scan", str(self.root)), 0)
        (self.root / "rootfs").rmdir()
        (self.root / "pygo-audit.json").write_text(
            json.dumps(
                {
                    "image-name": "changed-after-scan",
                    "image-metadata": "missing-identity.json",
                    "go": "missing-go",
                }
            )
        )
        with patch(
            "pygo_audit.scanner.scan_root", side_effect=AssertionError("must not scan")
        ):
            for view in (
                "overview",
                "binary-findings",
                "vulnerability-findings",
                "module-reconciliation",
                "diagnostics",
                "cves",
                "modules",
                "packages",
                "json",
            ):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(
                        main(["report", str(self.root), "--view", view]), 0
                    )
                artifact = (
                    self.root / "audit.json"
                    if view == "json"
                    else self.root / "reports" / f"{view}.txt"
                )
                saved_output = artifact.read_text()
                if view in {"json", "cves", "modules", "packages"}:
                    self.assertEqual(output.getvalue(), saved_output)
                    if view != "json":
                        self.assertEqual(output.getvalue(), "")
                else:
                    self.assertEqual(
                        output.getvalue().splitlines()[0],
                        saved_output.splitlines()[0],
                    )
                    self.assertLessEqual(len(output.getvalue()), len(saved_output))
            self.assertEqual(
                self.invoke("check", str(self.root), "--id", "CVE-2026-0001"), 0
            )

    def test_identifier_views_write_only_complete_lists(self):
        saved = report(self.root)
        saved.binaries = [
            BinaryReport(
                paths=["/usr/bin/example"],
                size=1,
                go_version="go1.26",
                main_package="example.test/app/cmd",
                main_module=Module("example.test/app", "v1.2.3"),
                dependencies=[
                    Module(f"example.test/library{index:02d}", "v2.0.0")
                    for index in range(12)
                ],
                build_settings=[],
                vulnerability_scan=VulnerabilityScan(
                    status="complete",
                    vulnerabilities=[
                        Vulnerability(id="GO-2026-0001", aliases=["CVE-2026-0001"]),
                    ],
                ),
            )
        ]
        atomic_write_json(self.root / "audit.json", saved.to_dict())
        expected = {
            "cves": "CVE-2026-0001\n",
            "modules": "example.test/app@v1.2.3\n"
            + "".join(
                f"example.test/library{index:02d}@v2.0.0\n" for index in range(12)
            ),
            "packages": "example.test/app/cmd@v1.2.3\n",
        }
        for view, content in expected.items():
            with self.subTest(view=view), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["report", str(self.root), "--view", view]), 0)
                self.assertEqual(output.getvalue(), content)
            for option in ("-v", "-vv", "-vvv", "--wide"):
                with (
                    self.subTest(view=view, option=option),
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        main(["report", str(self.root), "--view", view, option])
                    self.assertEqual(raised.exception.code, 2)

    def test_check_verbosity_and_saved_details_use_vulnerability_layout(self):
        saved = report(self.root)
        saved.binaries = [
            BinaryReport(
                paths=["/bin/app"],
                size=100,
                go_version="go1.26",
                main_package="example/app",
                main_module=None,
                dependencies=[],
                build_settings=[],
                sha256="a" * 64,
                vulnerability_scan=VulnerabilityScan(
                    status="complete",
                    vulnerabilities=[
                        Vulnerability(
                            id="GO-2026-0001",
                            aliases=["CVE-2026-0001"],
                            findings=[
                                VulnerabilityFinding(
                                    module="example/library",
                                    package="example/library/decoder",
                                    found_version="v1.0.0",
                                    fixed_version="v1.1.0",
                                    evidence="symbol",
                                    symbol=f"Decode{index:02}",
                                )
                                for index in range(12)
                            ],
                        )
                    ],
                ),
            ),
        ]
        atomic_write_json(self.root / "audit.json", saved.to_dict())
        outputs = []
        with patch(
            "pygo_audit.scanner.scan_root", side_effect=AssertionError("must not scan")
        ):
            for flag in ("", "-v", "-vv", "-vvv"):
                with redirect_stdout(io.StringIO()) as output:
                    args = ["check", str(self.root), "--id", "cve-2026-0001"]
                    self.assertEqual(main([*args, *([flag] if flag else [])]), 0)
                outputs.append(output.getvalue())
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(
                    main(
                        [
                            *args,
                            "-vvv",
                            "--wide",
                            "--output-dir",
                            str(self.root / "reports"),
                        ]
                    ),
                    0,
                )
            wide = output.getvalue()
        for level, output in enumerate(outputs):
            with self.subTest(level=level):
                self.assertIn("Result:                 DETECTED", output)
                self.assertIn("Coverage:               COMPLETE (1 of 1 binaries)", output)
                self.assertEqual("MODULE:" in output, level >= 1)
                self.assertEqual("Fixed version:" in output, level >= 2)
                self.assertEqual("BINARY: app" in output, level >= 2)
                self.assertEqual("Symbols (" in output, level == 3)
                self.assertEqual("PROVENANCE" in output, level == 3)
                self.assertEqual("More information:" in output, level < 3)
        self.assertIn("Additional symbols:     2 omitted", outputs[3])
        self.assertIn("Aliases:                GO-2026-0001", outputs[1])
        self.assertNotIn("Decode11", outputs[3])
        self.assertIn("example/library/decoder.Decode11", wide)
        self.assertIn("SHA-256:                " + "a" * 64, wide)
        self.assertNotIn(" omitted;", wide)
        self.assertGreater(wide.index("PROVENANCE"), wide.index("Decode11"))
        self.assertIn("Audit SHA-256:", wide)
        artifact = self.root / "reports/checks/CVE-2026-0001.txt"
        self.assertEqual(artifact.read_text(), wide)

    def test_saved_report_selection_respects_sidecar_and_explicit_file(self):
        current = report(self.root)
        previous = report(self.root)
        previous.go_tool_version = "previous"
        historical = self.root / "history" / "audit-abc-date.json"
        historical.parent.mkdir()
        atomic_write_json(self.root / "audit.json", current.to_dict())
        atomic_write_json(historical, previous.to_dict())
        (self.root / "pygo-audit.json").write_text(
            json.dumps({"audit-file": "history/audit-abc-date.json"})
        )
        for arguments, expected in (
            ([str(self.root)], "previous"),
            ([str(historical)], "previous"),
            ([str(self.root), "--audit-file", str(self.root / "audit.json")], "test"),
        ):
            with (
                self.subTest(arguments=arguments),
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(main(["report", *arguments, "--view", "json"]), 0)
            self.assertEqual(json.loads(output.getvalue())["go_tool_version"], expected)

    def test_detailed_views_render_the_loaded_audit_model(self):
        saved = report(self.root)
        atomic_write_json(self.root / "audit.json", saved.to_dict())
        for view, renderer in (
            (
                "vulnerability-findings",
                lambda value: render_by_vulnerability(value, DETAILED_POLICY),
            ),
            ("binary-findings", lambda value: render_binaries(value, DETAILED_POLICY)),
            (
                "module-reconciliation",
                lambda value: render_module_reconciliation(value, DETAILED_POLICY),
            ),
            ("diagnostics", lambda value: render_diagnostics(value, DETAILED_POLICY)),
        ):
            with self.subTest(view=view), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["report", str(self.root), "--view", view, "-vv"]), 0)
            self.assertEqual(output.getvalue(), renderer(saved) + "\n")

    def test_report_verbosity_and_wide_are_independent(self) -> None:
        saved = report(self.root)
        saved.binaries.append(
            BinaryReport(
                paths=["/usr/bin/example"],
                size=12_500_000,
                go_version="go1.26",
                main_package="example.test/cmd",
                main_module=Module("example.test/main", "v1.0.0"),
                dependencies=[
                    Module(f"example.test/dependency{index:02d}", "v1.0.0")
                    for index in range(12)
                ],
                build_settings=[],
                sha256="a" * 64,
            )
        )
        atomic_write_json(self.root / "audit.json", saved.to_dict())
        original_audit = (self.root / "audit.json").read_bytes()

        def output(*options: str) -> str:
            with redirect_stdout(io.StringIO()) as rendered:
                self.assertEqual(
                    main(
                        [
                            "report",
                            str(self.root),
                            "--view",
                            "module-reconciliation",
                            *options,
                        ]
                    ),
                    0,
                )
            return rendered.getvalue()

        summary = output()
        expanded = output("-v")
        detailed = output("-vv")
        forensic = output("-vvv")
        wide = output("-vvv", "--wide")

        self.assertNotIn("Location:", summary)
        self.assertIn("Location:               usr/bin/example", expanded)
        self.assertNotIn("BUILD SETTINGS", expanded)
        self.assertIn("BUILD SETTINGS", detailed)
        self.assertNotIn("example.test/dependency10", forensic)
        self.assertIn("Additional dependencies: 2 omitted", forensic)
        self.assertIn("example.test/dependency11", wide)
        self.assertIn("SHA-256:                " + "a" * 64, wide)
        self.assertEqual((self.root / "audit.json").read_bytes(), original_audit)

    def test_binary_report_does_not_depend_on_csaf_comparison(self) -> None:
        saved = report(self.root)
        atomic_write_json(self.root / "audit.json", saved.to_dict())
        comparison = self.root / "reports" / "comparison.json"
        comparison.parent.mkdir()
        atomic_write_json(
            comparison,
            {
                "audit_sha256": "0" * 64,
                "assessments": [],
            },
        )

        self.assertEqual(
            self.invoke("report", str(self.root), "--view", "binary-findings"),
            0,
        )

    def test_help_lists_commands_in_workflow_order(self):
        with (
            redirect_stdout(io.StringIO()) as output,
            self.assertRaises(SystemExit) as raised,
        ):
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        names = ("scan", "report", "audit", "aggregate", "check", "csaf")
        listed = [
            line.split()[0]
            for line in output.getvalue().splitlines()
            if line.split() and line.split()[0] in names
        ]
        self.assertEqual(listed, list(names))

    def test_report_and_check_file_inputs_use_workspace_settings(self):
        saved = report(self.root)
        saved.issues.append(ScanIssue("/binary", "open", "denied"))
        (self.root / "pygo-audit.json").write_text(json.dumps({"strict": True}))
        caller = self.root / "caller"
        caller.mkdir()
        (caller / "pygo-audit.json").write_text(json.dumps({"strict": False}))
        for relative in ("audit.json", "history/audit-prior-date.json"):
            selected = self.root / relative
            selected.parent.mkdir(exist_ok=True)
            atomic_write_json(selected, saved.to_dict())
            for selection in ([str(selected)], ["--audit-file", str(selected)]):
                for command, extra in (
                    ("report", []),
                    ("check", ["--id", "CVE-2026-0001"]),
                ):
                    with (
                        self.subTest(command=command, selection=selection),
                        chdir(caller),
                    ):
                        self.assertEqual(self.invoke(command, *selection, *extra), 1)

    def test_each_command_has_its_own_help(self):
        for command in ("scan", "report", "audit", "aggregate", "check", "csaf"):
            with (
                self.subTest(command=command),
                redirect_stdout(io.StringIO()) as output,
            ):
                with self.assertRaises(SystemExit) as raised:
                    main([command, "--help"])
            self.assertEqual(raised.exception.code, 0)
            self.assertIn(f"usage: pygo-audit {command}", output.getvalue())
            self.assertIn("AUDIT_ROOT", output.getvalue())

    def test_report_and_check_default_to_current_directory(self):
        with patch("pygo_audit.scanner.scan_root", return_value=report(self.root)):
            self.assertEqual(self.invoke("scan", str(self.root)), 0)
        with chdir(self.root), patch("pygo_audit.scanner.scan_root") as scan:
            self.assertEqual(self.invoke("report"), 0)
            self.assertEqual(
                self.invoke("check", "--id", "CVE-2026-0001", "GO-2026-0001"), 0
            )
        scan.assert_not_called()

    def test_standard_numeric_conversion_and_workspace_validation(self):
        for option, value in (
            ("--jobs", "0"),
            ("--jobs", "-1"),
            ("--timeout", "0"),
            ("--timeout", "nan"),
            ("--timeout", "inf"),
        ):
            with (
                self.subTest(option=option, value=value),
                patch("pygo_audit.scanner.scan_root") as scan,
            ):
                errors = io.StringIO()
                with redirect_stderr(errors):
                    self.assertEqual(main(["scan", str(self.root), option, value]), 1)
                self.assertIn("positive and finite", errors.getvalue())
                scan.assert_not_called()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["scan", str(self.root), "--jobs", "not-an-integer"])
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse((self.root / "cache").exists())

    def test_omitted_options_and_explicit_false_preserve_precedence(self):
        (self.root / "pygo-audit.json").write_text(
            json.dumps({"jobs": 2, "vulncheck": True, "strict": True})
        )
        result = report(self.root)
        result.issues.append(ScanIssue("/app", "open", "denied"))
        with patch("pygo_audit.scanner.scan_root", return_value=result) as scan:
            self.assertEqual(
                self.invoke("scan", str(self.root), "--no-vulncheck", "--no-strict"), 0
            )
        self.assertEqual(scan.call_args.kwargs["jobs"], 2)
        self.assertIsNone(scan.call_args.kwargs["govulncheck_command"])
        self.assertEqual(self.invoke("report", str(self.root)), 1)
        self.assertEqual(self.invoke("report", str(self.root), "--no-strict"), 0)

    def test_invalid_syntax_fails_explicitly(self):
        for arguments in (
            ["check", str(self.root)],
            ["report", str(self.root), "--group-by", "binary"],
            [
                "report", str(self.root), "--view", "vulnerability-findings",
                "--group-by", "package",
            ],
            ["report", str(self.root), "--view", "json", "--group-by", "vulnerability"],
            ["report", str(self.root), "--view", "json", "--wide"],
            ["report", str(self.root), "-vvvv"],
            ["scan", str(self.root), "--layer-dir", "a", "--layers-dir", "b"],
            ["unknown-command"],
        ):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(arguments)
            self.assertEqual(raised.exception.code, 2)

    def test_saved_json_as_scan_root_is_rejected_instead_of_scanning_its_parent(self):
        saved = self.root / "audit.json"
        saved.write_text("{}")
        with patch("pygo_audit.scanner.scan_root") as scan:
            self.assertEqual(self.invoke("scan", str(saved)), 1)
        scan.assert_not_called()
        self.assertEqual(saved.read_text(), "{}")

    def test_unexpected_programming_error_is_not_converted_to_a_scan_failure(self):
        with patch(
            "pygo_audit.scanner.scan_root",
            side_effect=RuntimeError("implementation bug"),
        ):
            with self.assertRaisesRegex(RuntimeError, "implementation bug"):
                self.invoke("scan", str(self.root))
