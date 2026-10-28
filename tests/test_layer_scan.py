from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pygo_audit.audit import load_audit
from pygo_audit.layer_scan import (
    compose_reports,
    discover_layer_directories,
)
from pygo_audit.models import (
    BinaryReport,
    ContainerMetadata,
    Module,
    ScanIssue,
    AuditReport,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.reconciliation import reconcile_binary
from pygo_audit.scanner import ELF_MAGIC, ScanConfigurationError, scan_root
from pygo_audit.storage import atomic_write_json


def _binary(
    path: str,
    digest: str,
    *,
    runtime_disposition: str,
    vulnerability_id: str = "",
) -> BinaryReport:
    vulnerabilities = []
    if vulnerability_id:
        vulnerabilities.append(
            Vulnerability(
                id=vulnerability_id,
                findings=[VulnerabilityFinding(module="example.test/app")],
            )
        )
    return BinaryReport(
        paths=[path],
        size=1,
        go_version="go1.26",
        main_package="example.test/app",
        main_module=None,
        dependencies=[],
        build_settings=[],
        sha256=digest,
        runtime_disposition=runtime_disposition,
        vulnerability_scan=VulnerabilityScan(
            status="complete",
            vulnerabilities=vulnerabilities,
        ),
    )


def _report(root: Path, binaries: list[BinaryReport]) -> AuditReport:
    return AuditReport(
        metadata=ContainerMetadata(root=str(root)),
        binaries=binaries,
        go_command="go",
        go_tool_version="go",
        producer_name="pygo-audit",
        producer_version="0.1.0",
    )


def _analyzed_binary(
    path: str, identifier: str, *, module: str = "example.test/app"
) -> BinaryReport:
    binary = _binary(path, "a" * 64, runtime_disposition="runtime")
    binary.main_module = Module(path="example.test/app", version="v1.0.0")
    binary.vulnerability_scan = VulnerabilityScan(
        status="complete",
        scanner_name="govulncheck",
        scanner_version="current",
        database="https://vuln.example.test/current",
        go_version=binary.go_version,
        scan_mode="binary",
        scan_level="module",
        sbom={
            "go_version": binary.go_version,
            "roots": ["example.test/app"],
            "modules": [
                {"path": "stdlib", "version": binary.go_version},
                {"path": "example.test/app", "version": "v1.0.0"},
            ],
        },
        vulnerabilities=[
            Vulnerability(
                id=identifier,
                findings=[VulnerabilityFinding(module=module, found_version="v1.0.0")],
            )
        ],
    )
    reconcile_binary(binary)
    return binary


class LayerScanTests(unittest.TestCase):
    def test_failed_and_complete_observations_preserve_success_and_failures(
        self,
    ) -> None:
        for failed_first in (True, False):
            with (
                self.subTest(failed_first=failed_first),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                layer = root / "layer-000"
                layer.mkdir()
                failed = _binary(
                    "/failed-path", "a" * 64, runtime_disposition="unknown"
                )
                failed.vulnerability_scan = VulnerabilityScan(
                    status="failed",
                    scanner_version="failed-version",
                    database="https://vuln.example.test/old",
                    error="scanner timed out",
                    vulnerabilities=[
                        Vulnerability(
                            id="GO-2026-partial",
                            findings=[
                                VulnerabilityFinding(
                                    module="example.test/app",
                                    found_version="v1.0.0",
                                )
                            ],
                        )
                    ],
                )
                failed.main_module = Module(path="example.test/app", version="v1.0.0")
                complete = _analyzed_binary("/complete-path", "GO-2026-complete")
                # A partial attempt can report the same finding before reconciliation.
                failed.vulnerability_scan.vulnerabilities.append(
                    Vulnerability(
                        id="GO-2026-complete",
                        findings=[
                            VulnerabilityFinding(
                                module="example.test/app",
                                found_version="v1.0.0",
                            )
                        ],
                    )
                )
                failed_report = _report(root / "failed", [failed])
                failed_report.issues.append(
                    ScanIssue("/failed-path", "govulncheck", "scanner timed out")
                )
                complete_report = _report(root / "complete", [complete])
                reports = (
                    [failed_report, complete_report]
                    if failed_first
                    else [complete_report, failed_report]
                )
                report = compose_reports(reports, [layer])
                merged = report.binaries[0]
                self.assertEqual(merged.vulnerability_scan.status, "complete")
                self.assertEqual(merged.vulnerability_scan.error, "")
                self.assertEqual(merged.vulnerability_scan.scanner_version, "current")
                self.assertEqual(
                    merged.vulnerability_scan.database,
                    "https://vuln.example.test/current",
                )
                self.assertEqual(
                    merged.vulnerability_scan.sbom, complete.vulnerability_scan.sbom
                )
                self.assertEqual(merged.finding_statuses, {"exact": 2})
                self.assertEqual(merged.paths, ["/complete-path", "/failed-path"])
                self.assertEqual(len(merged.layer_history), 1)
                self.assertTrue(
                    any(
                        issue.stage == "govulncheck"
                        and issue.message == "scanner timed out"
                        for issue in report.issues
                    )
                )
                path = root / "audit.json"
                atomic_write_json(path, report.to_dict())
                self.assertEqual(load_audit(path).to_dict(), report.to_dict())

    def test_complete_observation_union_reconciles_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layer = root / "layer-000"
            layer.mkdir()
            left = _analyzed_binary("/app", "GO-2026-shared")
            right = _analyzed_binary(
                "/old-app", "GO-2026-shared", module="example.test/missing"
            )
            report = compose_reports(
                [_report(root, [left]), _report(layer, [right])], [layer]
            )
            binary = report.binaries[0]
            self.assertEqual(len(binary.vulnerability_scan.vulnerabilities[0].findings), 2)
            self.assertEqual(binary.finding_statuses, {"exact": 1, "mismatch": 1})
            self.assertEqual(report.issues, [])
            path = root / "audit.json"
            atomic_write_json(path, report.to_dict())
            self.assertEqual(load_audit(path).to_dict(), report.to_dict())

    def test_discovers_arbitrary_names_with_lexicographic_or_numeric_sort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            for name in ("layer-2", "layer-10", "layer-02", "base image", "应用"):
                (parent / name).mkdir()
            (parent / "readme.txt").touch()
            (parent / "base image" / "nested").mkdir()

            self.assertEqual(
                [path.name for path in discover_layer_directories(parent)],
                ["base image", "layer-02", "layer-10", "layer-2", "应用"],
            )
            self.assertEqual(
                [
                    path.name
                    for path in discover_layer_directories(parent, sort="numeric")
                ],
                ["base image", "layer-02", "layer-2", "layer-10", "应用"],
            )

    def test_discovery_rejects_missing_empty_and_symlink_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            with self.assertRaisesRegex(ValueError, "must be a directory"):
                discover_layer_directories(parent / "missing")
            with self.assertRaisesRegex(ValueError, "no layer directories"):
                discover_layer_directories(parent)
            (parent / "real").mkdir()
            (parent / "link").symlink_to(parent / "real", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "must not be symlinks"):
                discover_layer_directories(parent)
            with self.assertRaisesRegex(ValueError, "must be a directory"):
                discover_layer_directories(parent / "link")

    def test_unified_scan_preserves_explicit_layer_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            root = parent / "rootfs"
            layers = [parent / "z-base", parent / "a-new"]
            for directory in (root, *layers):
                directory.mkdir()
            for layer in layers:
                (layer / "app").write_bytes(ELF_MAGIC)
            digests = {layers[0]: "a" * 64, layers[1]: "b" * 64}

            def inspect(elf_file, **options):
                return _binary(
                    "/app",
                    digests[elf_file.path.parent],
                    runtime_disposition=options["runtime_disposition"],
                ), []

            with (
                patch(
                    "pygo_audit.scanner._resolve_go_tool", return_value=("go", "test")
                ),
                patch("pygo_audit.scanner._inspect_elf_file", side_effect=inspect),
            ):
                for supplied in (layers, list(reversed(layers))):
                    with self.subTest(supplied=supplied):
                        result = scan_root(root, supplied, govulncheck_command=None)
                        binaries = {binary.sha256: binary for binary in result.binaries}
                        self.assertEqual(
                            binaries[digests[supplied[0]]].runtime_disposition,
                            "replaced",
                        )
                        self.assertEqual(
                            binaries[digests[supplied[1]]].runtime_disposition,
                            "unaccounted",
                        )
                        self.assertEqual(
                            binaries[digests[supplied[0]]].layer_history[0].layer_index,
                            0,
                        )
                        self.assertEqual(
                            binaries[digests[supplied[1]]].layer_history[0].layer_index,
                            1,
                        )

    def test_explicit_layers_must_exist_and_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            for layers in ([root / "missing"], [root]):
                with (
                    self.subTest(layers=layers),
                    self.assertRaises(ScanConfigurationError),
                ):
                    scan_root(root, layers)
            self.assertFalse((root.parent / "work").exists())

    def test_discovery_order_does_not_infer_deletion_or_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            base, later = parent / "base", parent / "later"
            base.mkdir()
            later.mkdir()
            (later / ".wh.old").touch()
            for ordered in (False, True):
                with self.subTest(layers_ordered=ordered):
                    report = compose_reports(
                        [
                            _report(
                                parent / "rootfs",
                                [
                                    _binary(
                                        "/app", "a" * 64, runtime_disposition="runtime"
                                    ),
                                ],
                            ),
                            _report(
                                base,
                                [
                                    _binary(
                                        "/app", "b" * 64, runtime_disposition="unknown"
                                    ),
                                    _binary(
                                        "/old", "c" * 64, runtime_disposition="unknown"
                                    ),
                                ],
                            ),
                            _report(
                                later,
                                [
                                    _binary(
                                        "/app", "a" * 64, runtime_disposition="unknown"
                                    ),
                                ],
                            ),
                        ],
                        [base, later],
                        layers_ordered=ordered,
                    )
                    binaries = {binary.sha256: binary for binary in report.binaries}
                    self.assertEqual(binaries["a" * 64].runtime_disposition, "runtime")
                    self.assertEqual(
                        binaries["b" * 64].runtime_disposition,
                        "replaced" if ordered else "unaccounted",
                    )
                    self.assertEqual(
                        binaries["c" * 64].runtime_disposition,
                        "deleted" if ordered else "unaccounted",
                    )
                    if not ordered:
                        self.assertTrue(
                            all(
                                event.status == "found"
                                for binary in binaries.values()
                                for event in binary.layer_history
                            )
                        )

    def test_merges_identical_binaries_and_marks_whiteout_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "rootfs"
            layer_zero = temporary / "layer-000"
            layer_one = temporary / "layer-001"
            layer_zero.mkdir()
            layer_one.mkdir()
            (layer_one / "usr" / "bin").mkdir(parents=True)
            (layer_one / "usr" / "bin" / ".wh.old-app").touch()

            runtime = _binary(
                "/usr/bin/app",
                "a" * 64,
                runtime_disposition="runtime",
                vulnerability_id="CVE-2026-0001",
            )
            historical_copy = _binary(
                "/usr/bin/app",
                "a" * 64,
                runtime_disposition="unknown",
            )
            historical_copy.symlinks = ["/bin/app"]
            deleted_binary = _binary(
                "/usr/bin/old-app",
                "b" * 64,
                runtime_disposition="unknown",
                vulnerability_id="CVE-2026-0002",
            )
            unaccounted_binary = _binary(
                "/usr/bin/orphan",
                "c" * 64,
                runtime_disposition="unknown",
                vulnerability_id="CVE-2026-0003",
            )

            report = compose_reports(
                [
                    _report(root, [runtime]),
                    _report(
                        layer_zero,
                        [historical_copy, deleted_binary, unaccounted_binary],
                    ),
                    _report(layer_one, []),
                ],
                [layer_zero, layer_one],
            )

            app = next(
                binary for binary in report.binaries if binary.sha256 == "a" * 64
            )
            old_app = next(
                binary for binary in report.binaries if binary.sha256 == "b" * 64
            )
            orphan = next(
                binary for binary in report.binaries if binary.sha256 == "c" * 64
            )

            self.assertEqual(app.runtime_disposition, "runtime")
            self.assertEqual(app.paths, ["/usr/bin/app"])
            self.assertEqual(app.symlinks, ["/bin/app"])
            self.assertEqual(
                [(event.layer_index, event.status) for event in app.layer_history],
                [(0, "found")],
            )
            self.assertEqual(app.layer_history[0].symlinks, ("/bin/app",))
            self.assertEqual(old_app.runtime_disposition, "deleted")
            self.assertEqual(orphan.runtime_disposition, "unaccounted")
            self.assertEqual(
                [(event.layer_index, event.status) for event in old_app.layer_history],
                [(0, "found"), (1, "deleted")],
            )
            self.assertEqual(report.unaccounted_historical_binaries, [orphan])
            self.assertEqual(len(report.unaccounted_historical_findings()), 1)
            old_occurrence = next(
                occurrence
                for occurrence in report.finding_occurrences()
                if occurrence.vulnerability_id == "CVE-2026-0002"
            )
            self.assertEqual(old_occurrence.layer_history[-1].status, "deleted")


if __name__ == "__main__":
    unittest.main()
