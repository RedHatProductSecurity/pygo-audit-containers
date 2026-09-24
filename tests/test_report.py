from __future__ import annotations

import json
import unittest

from pygo_audit.models import (
    BinaryReconciliation,
    BinaryReport,
    BuildSetting,
    ImageIdentity,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
    ScanIssue,
    ScanReport,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.report import (
    render_checks,
    render_container,
    render_diagnostics,
    render_grouped,
    render_json,
    render_summary,
    render_text,
)
from pygo_audit.text_report import tail_string


class ContainerReportTests(unittest.TestCase):
    def test_aggregates_duplicate_findings_across_binaries(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        output = render_container(report)

        self.assertIn("PYGO-AUDIT FINDINGS", output)
        self.assertIn("Name:                   example.test/library/decoder", output)
        self.assertIn("Name:                   example.test/library/parser", output)
        self.assertIn("Current version:        v1.0.0", output)
        self.assertEqual(output.count("CVE-2026-0001"), 2)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", output)
        self.assertNotIn("GO-2026-0001", output)
        self.assertIn("Coverage:               COMPLETE (2 of 2 binaries)", output)
        self.assertIn("Vulnerability scans:    COMPLETE=2", output)
        self.assertIn("Vulnerabilities:        1", output)
        self.assertNotIn("PACKAGE 1 OF", output)
        self.assertNotIn("v1.1.0", output)

        text_output = render_text(report)
        self.assertEqual(text_output.count("\nBINARY\n"), 2)
        self.assertEqual(text_output.count("CVE-2026-0001"), 2)
        _, one_section, two_section = text_output.split("\nBINARY\n")
        self.assertIn("Path:                   /bin/one", one_section)
        self.assertIn("example.test/library/decoder", one_section)
        self.assertNotIn("example.test/library/parser", one_section)
        self.assertIn("Path:                   /bin/two", two_section)
        self.assertIn("example.test/library/parser", two_section)
        self.assertNotIn("example.test/library/decoder", two_section)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", text_output)
        self.assertNotIn("GO-2026-0001", text_output)
        self.assertEqual(text_output.count("DECLARED DEPENDENCIES (0)"), 2)

        summary_output = render_summary(report)
        self.assertIn("PYGO-AUDIT OVERVIEW", summary_output)
        self.assertIn(f"SUBJECT\n{'-' * 100}\n", summary_output)
        self.assertIn(f"PROVENANCE\n{'-' * 100}\n", summary_output)
        self.assertIn(f"RESULT\n{'-' * 100}\n", summary_output)
        self.assertIn(f"AFFECTED PACKAGES (2)\n{'-' * 100}\n", summary_output)
        self.assertIn("AFFECTED PACKAGES (2)", summary_output)
        self.assertIn("  - example.test/library/decoder", summary_output)
        self.assertIn("  - example.test/library/parser", summary_output)
        self.assertIn("VULNERABILITIES (1)", summary_output)
        self.assertIn("  - CVE-2026-0001", summary_output)
        self.assertLess(summary_output.index("RESULT"), summary_output.index("SUBJECT"))
        self.assertLess(
            summary_output.index("VULNERABILITIES (1)"),
            summary_output.index("AFFECTED PACKAGES (2)"),
        )
        self.assertLess(
            summary_output.index("SUBJECT"), summary_output.index("PROVENANCE")
        )

    def test_warns_when_a_scan_is_incomplete(self) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        binary.vulnerability_scan = VulnerabilityScan(
            status="failed", error="scanner unavailable"
        )
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(binary)

        output = render_container(report)

        self.assertIn("Vulnerability scans:    FAILED=1", output)
        self.assertIn("No vulnerability findings detected.", output)
        self.assertIn("COVERAGE WARNING", output)
        self.assertIn("did not complete for 1 of 1 binaries", output)

        text_output = render_text(report)
        self.assertIn("Path:                   /bin/one", text_output)
        self.assertIn("Scan status:            FAILED", text_output)
        self.assertIn("Scan error:             scanner unavailable", text_output)

        summary_output = render_summary(report)
        self.assertIn("AFFECTED PACKAGES (0)", summary_output)
        self.assertIn("VULNERABILITIES (0)", summary_output)
        self.assertIn("COVERAGE WARNING", summary_output)

    def test_renders_evidence_rich_groupings_from_normalized_findings(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        container_output = render_grouped(report, "container")
        self.assertIn("Status:                 VULNERABILITIES DETECTED", container_output)
        self.assertIn(
            "Coverage:               COMPLETE (2 of 2 binaries)",
            container_output,
        )
        self.assertIn("/bin/one", container_output)
        self.assertIn("Evidence: symbol", container_output)
        self.assertNotIn("Decode", container_output)

        binary_output = render_grouped(report, "binary")
        self.assertIn("Path:                   /bin/one", binary_output)
        self.assertIn("Path:                   /bin/two", binary_output)

        package_output = render_grouped(report, "package")
        self.assertIn("Name:                   example.test/library/decoder", package_output)
        self.assertIn("Name:                   example.test/library/parser", package_output)

        vulnerability_output = render_grouped(report, "vulnerability")
        self.assertEqual(
            vulnerability_output.count("Identifier:             CVE-2026-0001"),
            1,
        )
        self.assertNotIn("VULNERABILITY 1 OF", vulnerability_output)

    def test_targeted_checks_match_aliases_and_explain_coverage(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        output = render_checks(
            report,
            ["CVE-2026-0001", "CVE-2026-9999"],
        )

        self.assertTrue(output.startswith("VULNERABILITY CHECKS\n"))
        self.assertIn("\nCVE-2026-0001\n", output)
        self.assertIn(f"\nCVE-2026-0001\n{'-' * 100}\n", output)
        self.assertIn("Result:                 DETECTED", output)
        self.assertIn("/bin/one", output)
        self.assertIn("\nCVE-2026-9999\n", output)
        self.assertIn("Result:                 NOT DETECTED IN THIS SNAPSHOT", output)
        self.assertIn("detected in this snapshot with complete scan coverage", output)
        self.assertIn("Coverage:               COMPLETE (1 of 1 binaries)", output)
        self.assertIn("AFFECTED PACKAGE", output)
        self.assertNotIn(" OF ", output)
        self.assertEqual(output.count("CVE-2026-0001"), 1)
        self.assertEqual(output.count("CVE-2026-9999"), 1)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", output)
        self.assertNotIn("GO-2026-0001", output)
        self.assertEqual(output.count("SCAN CONTEXT"), 1)
        self.assertIn(f"SCAN CONTEXT\n{'-' * 100}\n", output)
        self.assertNotIn("Identifier:", output)
        self.assertLess(output.index("\nCVE-2026-0001\n"), output.index("SCAN CONTEXT"))
        self.assertNotIn("PROVENANCE", output)
        self.assertNotIn("SUBJECT\n", output)

        report.binaries[0].vulnerability_scan = VulnerabilityScan(status="failed")
        incomplete_output = render_checks(report, ["CVE-2026-9999"])
        self.assertTrue(incomplete_output.startswith("VULNERABILITY CHECK\n"))
        self.assertIn("\nCVE-2026-9999\n", incomplete_output)
        self.assertIn("Result:                 INDETERMINATE", incomplete_output)
        self.assertIn("Coverage:               INCOMPLETE (0 of 1 binaries)", incomplete_output)
        self.assertIn("coverage is incomplete", incomplete_output)

    def test_reports_reconciliation_differences_only_when_present(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        self.assertNotIn("Reconciliation", render_container(report))

        difference = (
            "finding stdlib@v1.26.8 versus stdlib@go1.26.8 "
            "(Vendor build) X:strictfipsruntime: identifies the same Go "
            "release using a different version representation"
        )
        report.issues.extend(
            (
                ScanIssue("/bin/one", "reconciliation-difference", difference),
                ScanIssue("/bin/two", "reconciliation-difference", difference),
            )
        )
        output = render_container(report)
        self.assertIn("Recon. differences:     1 difference", output)
        self.assertNotIn("RECONCILIATION DIFFERENCES (1)", output)
        self.assertNotIn("stdlib@v1.26.8", output)

        diagnostics = render_diagnostics(report)
        self.assertIn("RECONCILIATION DIFFERENCES (1)", diagnostics)
        self.assertIn(
            "Comparison:             go version -m versus govulncheck",
            diagnostics,
        )
        self.assertIn(
            "Effect:                 informational; does not affect coverage or exit status",
            diagnostics,
        )
        self.assertIn("stdlib@v1.26.8", diagnostics)
        self.assertIn("Finding:                stdlib@v1.26.8 versus", diagnostics)
        self.assertIn(
            "Description:            identifies the same Go release",
            diagnostics,
        )
        self.assertIn("AFFECTED BINARIES (2)", diagnostics)
        self.assertIn("  - /bin/one", diagnostics)
        self.assertIn("  - /bin/two", diagnostics)
        self.assertNotIn("\nBINARY\n", diagnostics)
        self.assertNotIn("Stage:                  reconciliation-difference", diagnostics)

    def test_diagnostics_groups_operational_issues_and_ends_with_context(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.issues.extend(
            (
                ScanIssue("/bin/one", "govulncheck", "timed out"),
                ScanIssue("/restricted", "open", "permission denied"),
            )
        )

        output = render_diagnostics(report)

        self.assertIn("Status:                 ATTENTION REQUIRED", output)
        self.assertIn("Operational issues:     2", output)
        self.assertIn("OPERATIONAL ISSUES (2)", output)
        self.assertIn("STAGE: GOVULNCHECK\n", output)
        self.assertIn("STAGE: OPEN\n", output)
        self.assertIn("Path:                   /restricted", output)
        self.assertNotIn("RECONCILIATION DIFFERENCES", output)
        self.assertLess(output.index("OPERATIONAL ISSUES"), output.index("SUBJECT"))
        self.assertLess(output.index("SUBJECT"), output.index("PROVENANCE"))

    def test_diagnostics_groups_unverifiable_reconciliation_components(self) -> None:
        inventory = ModuleInventoryEntry(
            source="dependency",
            declared_path="github.com/operator-framework/api",
            declared_version="v0.23.0",
            effective_path="./staging/api",
            effective_version="(devel)",
        )
        component = ModuleReconciliation(
            status="unverifiable",
            govulncheck_path="./staging/api",
            govulncheck_version="(devel)",
            inventory_entry=inventory,
            detail="module path matches but at least one version is not verifiable",
        )
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=False),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        for binary in binaries:
            binary.reconciliation = BinaryReconciliation(
                status="partial",
                go_version_status="exact",
                sbom_modules=[component],
                sbom_statuses={"unverifiable": 1},
            )
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        diagnostics = render_diagnostics(report)
        overview = render_summary(report)

        self.assertIn("Status:                 INFORMATIONAL LIMITATIONS", diagnostics)
        self.assertIn("Reconciliation:         PARTIAL (2 of 2 binaries)", diagnostics)
        self.assertIn("Unverifiable:           1 component", diagnostics)
        self.assertIn("RECONCILIATION LIMITATIONS (1)", diagnostics)
        self.assertIn(
            "Declared component:     github.com/operator-framework/api@v0.23.0",
            diagnostics,
        )
        self.assertIn("Effective component:    ./staging/api@(devel)", diagnostics)
        self.assertIn("AFFECTED BINARIES (2)", diagnostics)
        self.assertIn("  - /bin/one", diagnostics)
        self.assertIn("  - /bin/two", diagnostics)
        self.assertNotIn("COVERAGE WARNING", diagnostics)
        self.assertIn("Reconciliation:         PARTIAL (2 of 2 binaries)", overview)

    def test_reports_explicit_image_identity(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="go",
            go_tool_version="go",
            image_identity=ImageIdentity(
                reference="registry.example.test/team/app:v1",
                digest="sha256:" + "a" * 64,
                platform="linux/amd64",
                extractor="oc image extract",
            ),
        )

        output = render_container(report)

        self.assertIn("Image reference:        registry.example.test/team/app:v1", output)
        self.assertIn("Image digest:           sha256:", output)
        self.assertIn("Platform:               linux/amd64", output)
        self.assertIn("Extractor:              oc image extract", output)

    def test_reports_snapshot_toolchain_and_database_provenance(self) -> None:
        report = ScanReport(
            root="/tmp/root",
            go_command="/usr/bin/go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
            govulncheck_status="available",
            govulncheck_command="/usr/bin/govulncheck",
            govulncheck_tool_version="govulncheck@v1.2.3",
            scan_completed_at="2026-09-23T12:00:01Z",
        )
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        output = render_container(report)

        self.assertIn("Scanner:                pygo-audit 0.1.0", output)
        self.assertIn(
            "Go toolchain:           go version go1.26.8 linux/amd64",
            output,
        )
        self.assertIn(
            "govulncheck version:    govulncheck@v1.2.3",
            output,
        )
        self.assertIn("govulncheck command:    /usr/bin/govulncheck", output)
        self.assertIn("Scan completed:         2026-09-23T12:00:01Z", output)
        self.assertIn(
            "Database:               https://vuln.example.test",
            output,
        )
        self.assertIn("Database updated:       2026-09-18T00:00:00Z", output)

    def test_binary_report_lists_declared_dependencies_and_preserves_suffixes(self) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        long_path = "example.test/" + "very-long-segment/" * 8 + "critical/end"
        binary.dependencies.append(
            Module(
                path=long_path,
                version="v1.2.3",
                sum="h1:declared",
                replace=Module(
                    path="replacement.example.test/team/critical/end",
                    version="v1.2.4",
                    sum="h1:replacement",
                ),
            )
        )
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(binary)

        output = render_text(report)

        self.assertIn(f"INVENTORY\n{'-' * 100}\n", output)
        self.assertEqual(output.count(f"BINARY\n{'-' * 100}\n"), 1)
        self.assertIn("DECLARED DEPENDENCIES (1)", output)
        self.assertIn(
            "DECLARED DEPENDENCIES (1)\n" + "-" * len("DECLARED DEPENDENCIES (1)"),
            output,
        )
        self.assertIn("Declared version:       v1.2.3", output)
        self.assertIn("Checksum:               h1:declared", output)
        self.assertIn("Replacement path:       replacement.example.test/team/critical/end", output)
        self.assertIn("Replacement version:    v1.2.4", output)
        dependency_line = next(
            line for line in output.splitlines() if line.startswith("Dependency 1:")
        )
        displayed_path = dependency_line.split(":", 1)[1].strip()
        self.assertTrue(displayed_path.startswith("..."))
        self.assertTrue(displayed_path.endswith("critical/end"))
        self.assertNotIn(long_path, output)
        self.assertEqual(tail_string("prefix-useful-end", 10), "...ful-end")

    def test_json_queries_retain_machine_readable_check_evidence(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        self.assertNotIn("query", json.loads(render_json(report)))

        document = json.loads(
            render_json(
                report,
                group_by="vulnerability",
                checks=["CVE-2026-0001", "CVE-2026-9999"],
            )
        )

        self.assertEqual(document["query"]["group_by"], "vulnerability")
        self.assertEqual(document["query"]["groups"][0]["key"], "CVE-2026-0001")
        detected, absent = document["query"]["checks"]
        self.assertEqual(detected["status"], "detected")
        self.assertEqual(detected["matches"][0]["binary_paths"], ["/bin/one"])
        self.assertEqual(detected["matches"][0]["fixed_version"], "v1.1.0")
        self.assertEqual(absent["status"], "not_detected")

    @staticmethod
    def _binary(path: str, package: str, *, cgo: bool) -> BinaryReport:
        scan = VulnerabilityScan(
            status="complete",
            database="https://vuln.example.test",
            database_last_modified="2026-09-18T00:00:00Z",
            vulnerabilities=[
                Vulnerability(
                    id="GO-2026-0001",
                    aliases=["GHSA-aaaa-bbbb-cccc", "CVE-2026-0001"],
                    findings=[
                        VulnerabilityFinding(
                            module="example.test/library",
                            found_version="v1.0.0",
                            fixed_version="v1.1.0",
                            package=package,
                            symbol="Decode",
                            evidence="symbol",
                        )
                    ],
                )
            ],
        )
        return BinaryReport(
            paths=[path],
            size=1,
            go_version="go1.26",
            main_package=path,
            main_module=None,
            dependencies=[],
            build_settings=[
                BuildSetting(key="CGO_ENABLED", value="1" if cgo else "0")
            ],
            vulnerability_scan=scan,
        )


if __name__ == "__main__":
    unittest.main()
