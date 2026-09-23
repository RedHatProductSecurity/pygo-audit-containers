from __future__ import annotations

import json
import unittest

from pygo_audit.models import (
    BinaryReport,
    BuildSetting,
    ScanIssue,
    ScanReport,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.report import (
    render_checks,
    render_container,
    render_grouped,
    render_json,
    render_summary,
    render_text,
)


_TABLE_HEADER = "PACKAGES | CURRENT VERSION | VULNERABILITY"


class ContainerReportTests(unittest.TestCase):
    def test_aggregates_duplicate_findings_across_binaries(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        output = render_container(report)

        self.assertIn(
            "example.test/library/decoder | example.test/library@v1.0.0 | "
            "CVE-2026-0001",
            output,
        )
        self.assertIn(
            "example.test/library/parser | example.test/library@v1.0.0 | "
            "CVE-2026-0001",
            output,
        )
        self.assertEqual(output.count("CVE-2026-0001"), 2)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", output)
        self.assertNotIn("GO-2026-0001", output)
        self.assertIn("Go binaries: 2; CGO enabled: 1", output)
        self.assertIn("Vulnerability scans: complete=2", output)
        self.assertIn("Unique vulnerabilities: 1", output)
        self.assertIn(
            "PACKAGES | CURRENT VERSION | VULNERABILITY",
            output,
        )
        self.assertLess(output.index("PACKAGES |"), output.index("CVE-2026-0001"))
        self.assertNotIn("2 binaries", output)
        self.assertNotIn("v1.1.0", output)
        self.assertNotIn("packages:", output)
        self.assertNotIn("dependencies", output)

        text_output = render_text(report)
        self.assertEqual(text_output.count(_TABLE_HEADER), 2)
        self.assertEqual(text_output.count("CVE-2026-0001"), 2)
        one_section, two_section = text_output.split("Binary findings for /bin/two")
        self.assertIn("Binary findings for /bin/one", one_section)
        self.assertIn("example.test/library/decoder", one_section)
        self.assertNotIn("example.test/library/parser", one_section)
        self.assertIn("example.test/library/parser", two_section)
        self.assertNotIn("example.test/library/decoder", two_section)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", text_output)
        self.assertNotIn("GO-2026-0001", text_output)
        self.assertNotIn("dependencies", text_output)

        summary_output = render_summary(report)
        self.assertEqual(
            summary_output,
            "\n".join(
                (
                    "PACKAGES (2)",
                    "example.test/library/decoder",
                    "example.test/library/parser",
                    "",
                    "VULNERABILITIES (1)",
                    "CVE-2026-0001",
                )
            ),
        )

    def test_warns_when_a_scan_is_incomplete(self) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        binary.vulnerability_scan = VulnerabilityScan(
            status="failed", error="scanner unavailable"
        )
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(binary)

        output = render_container(report)

        self.assertIn("Vulnerability scans: failed=1", output)
        self.assertIn("No container-level vulnerability findings.", output)
        self.assertIn("Warning: 1 vulnerability scan(s) incomplete.", output)

        text_output = render_text(report)
        self.assertIn("Binary findings for /bin/one", text_output)
        self.assertIn(
            "Warning: vulnerability scan incomplete: scanner unavailable",
            text_output,
        )

        summary_output = render_summary(report)
        self.assertIn("PACKAGES (0)\nnone", summary_output)
        self.assertIn("VULNERABILITIES (0)\nnone", summary_output)
        self.assertIn("WARNING: 1 vulnerability scan(s) incomplete.", summary_output)

    def test_renders_evidence_rich_groupings_from_normalized_findings(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        container_output = render_grouped(report, "container")
        self.assertIn("Result: vulnerable", container_output)
        self.assertIn("Coverage: complete (2/2 binary scans complete)", container_output)
        self.assertIn(
            "BINARY | PACKAGE | CURRENT VERSION | VULNERABILITY | EVIDENCE",
            container_output,
        )
        self.assertIn("/bin/one", container_output)
        self.assertIn(" | symbol", container_output)
        self.assertNotIn("Decode", container_output)

        binary_output = render_grouped(report, "binary")
        self.assertIn("Binary: /bin/one", binary_output)
        self.assertIn("Binary: /bin/two", binary_output)

        package_output = render_grouped(report, "package")
        self.assertIn("Package: example.test/library/decoder", package_output)
        self.assertIn("Package: example.test/library/parser", package_output)

        vulnerability_output = render_grouped(report, "vulnerability")
        self.assertEqual(
            vulnerability_output.count("Vulnerability: CVE-2026-0001"),
            1,
        )

    def test_targeted_checks_match_aliases_and_explain_coverage(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        output = render_checks(
            report,
            ["CVE-2026-0001", "CVE-2026-9999"],
        )

        self.assertIn("CVE-2026-0001: DETECTED", output)
        self.assertIn("/bin/one", output)
        self.assertIn("CVE-2026-9999: NO MATCHING FINDING DETECTED", output)

        report.binaries[0].vulnerability_scan = VulnerabilityScan(status="failed")
        incomplete_output = render_checks(report, ["CVE-2026-9999"])
        self.assertIn("CVE-2026-9999: INDETERMINATE", incomplete_output)
        self.assertIn("coverage is incomplete", incomplete_output)

    def test_reports_reconciliation_differences_only_when_present(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        self.assertNotIn("Reconciliation", render_container(report))

        report.issues.append(
            ScanIssue(
                "/bin/one",
                "reconciliation-difference",
                "stdlib@v1.26.8 versus stdlib@go1.26.8",
            )
        )
        output = render_container(report)
        self.assertIn("Reconciliation differences:", output)
        self.assertIn("stdlib@v1.26.8", output)
        self.assertNotIn("Issues: 1", output)

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
