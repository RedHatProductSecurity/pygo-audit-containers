from __future__ import annotations

import unittest

from pygo_audit.models import (
    BinaryReport,
    Module,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.reconciliation import reconcile_binary


class ReconciliationTests(unittest.TestCase):
    def test_reconciles_exact_replacement_and_stdlib_components(self) -> None:
        binary = self._binary()
        binary.vulnerability_scan = VulnerabilityScan(
            status="complete",
            go_version="go1.26.8",
            sbom={
                "go_version": "go1.26.8",
                "modules": [
                    {"path": "example.test/app", "version": "v2.0.0"},
                    {"path": "example.test/library", "version": "v1.2.3"},
                    {"path": "example.test/fork", "version": "v1.2.4"},
                    {"path": "stdlib", "version": "go1.26.8"},
                ],
                "roots": ["example.test/app"],
            },
            vulnerabilities=[
                Vulnerability(
                    id="GO-2026-0001",
                    findings=[
                        VulnerabilityFinding(
                            module="example.test/library",
                            found_version="v1.2.3",
                        ),
                        VulnerabilityFinding(
                            module="example.test/fork",
                            found_version="v1.2.4",
                        ),
                        VulnerabilityFinding(
                            module="example.test/original",
                            found_version="v1.2.3",
                        ),
                        VulnerabilityFinding(
                            module="stdlib",
                            found_version="go1.26.8 X:vendor-feature",
                        ),
                    ],
                )
            ],
        )

        reconcile_binary(binary)

        self.assertEqual(binary.reconciliation.status, "matched")
        statuses = [
            finding.reconciliation.status
            for finding in binary.vulnerability_scan.vulnerabilities[0].findings
            if finding.reconciliation is not None
        ]
        self.assertEqual(
            statuses,
            ["exact", "replacement", "replacement", "stdlib"],
        )
        replacement = binary.vulnerability_scan.vulnerabilities[0].findings[1]
        self.assertIsNotNone(replacement.reconciliation)
        self.assertEqual(
            replacement.reconciliation.inventory_entry.declared_path,
            "example.test/original",
        )

    def test_retains_and_reports_finding_and_sbom_mismatches(self) -> None:
        binary = self._binary()
        finding = VulnerabilityFinding(
            module="example.test/unknown",
            found_version="v9.9.9",
        )
        binary.vulnerability_scan = VulnerabilityScan(
            status="complete",
            go_version="go1.25.0",
            sbom={
                "go_version": "go1.25.0",
                "modules": [
                    {"path": "example.test/app", "version": "v2.0.0"},
                    {"path": "stdlib", "version": "go1.25.0"},
                    {"path": "example.test/extra", "version": "v1.0.0"},
                ],
                "roots": ["example.test/app"],
            },
            vulnerabilities=[Vulnerability(id="GO-2026-0002", findings=[finding])],
        )

        reconcile_binary(binary)

        self.assertEqual(binary.reconciliation.status, "mismatch")
        retained = binary.vulnerability_scan.vulnerabilities[0].findings[0]
        self.assertEqual(retained.module, "example.test/unknown")
        self.assertIsNotNone(retained.reconciliation)
        self.assertEqual(retained.reconciliation.status, "mismatch")
        self.assertEqual(binary.reconciliation.go_version_status, "mismatch")
        mismatches = {
            item.govulncheck_path: item
            for item in binary.reconciliation.sbom_modules
            if item.govulncheck_path
        }
        self.assertEqual(mismatches["example.test/extra"].status, "mismatch")
        self.assertEqual(mismatches["stdlib"].status, "mismatch")
        self.assertIn("versions differ", mismatches["stdlib"].detail)
        self.assertTrue(
            any(
                not item.govulncheck_path
                and item.inventory_entry.declared_path == "example.test/library"
                for item in binary.reconciliation.sbom_modules
                if item.inventory_entry is not None
            )
        )

    def test_marks_development_versions_unverifiable_without_an_issue(self) -> None:
        binary = BinaryReport(
            paths=["/bin/app"],
            size=1,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=Module(path="example.test/app", version="(devel)"),
            dependencies=[],
            build_settings=[],
            vulnerability_scan=VulnerabilityScan(
                status="complete",
                go_version="go1.26.8",
                sbom={
                    "go_version": "go1.26.8",
                    "modules": [
                        {"path": "example.test/app", "version": "(devel)"},
                        {"path": "stdlib", "version": "go1.26.8"},
                    ],
                    "roots": ["example.test/app"],
                },
            ),
        )

        reconcile_binary(binary)

        self.assertEqual(binary.reconciliation.status, "limited")
        self.assertEqual(binary.reconciliation.sbom_statuses["unverifiable"], 1)

    def test_reports_equivalent_standard_library_version_representations(self) -> None:
        binary = BinaryReport(
            paths=["/bin/app"],
            size=1,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
            vulnerability_scan=VulnerabilityScan(
                status="complete",
                go_version="go1.26.8",
                sbom={
                    "go_version": "go1.26.8",
                    "modules": [{"path": "stdlib", "version": "v1.26.8"}],
                    "roots": ["example.test/app"],
                },
                vulnerabilities=[
                    Vulnerability(
                        id="GO-2026-0003",
                        findings=[
                            VulnerabilityFinding(
                                module="stdlib",
                                found_version="v1.26.8",
                            )
                        ],
                    )
                ],
            ),
        )

        reconcile_binary(binary)

        self.assertEqual(binary.reconciliation.status, "matched_with_differences")
        finding = binary.vulnerability_scan.vulnerabilities[0].findings[0]
        self.assertIsNotNone(finding.reconciliation)
        self.assertEqual(
            finding.reconciliation.status,
            "representation_difference",
        )
        self.assertEqual(
            finding.reconciliation.inventory_entry.effective_version,
            "go1.26.8",
        )
        self.assertEqual(finding.reconciliation.govulncheck_version, "v1.26.8")
        self.assertIn("same Go release", finding.reconciliation.detail)

    @staticmethod
    def _binary() -> BinaryReport:
        return BinaryReport(
            paths=["/bin/app"],
            size=1,
            go_version="go1.26.8 X:vendor-feature",
            main_package="example.test/app",
            main_module=Module(path="example.test/app", version="v2.0.0"),
            dependencies=[
                Module(path="example.test/library", version="v1.2.3"),
                Module(
                    path="example.test/original",
                    version="v1.2.3",
                    replace=Module(path="example.test/fork", version="v1.2.4"),
                ),
            ],
            build_settings=[],
        )


if __name__ == "__main__":
    unittest.main()
