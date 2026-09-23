from __future__ import annotations

import unittest

from pygo_audit.models import (
    BinaryReport,
    Module,
    ScanIssue,
    ScanReport,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)


class BinaryReportTests(unittest.TestCase):
    def test_parses_go_json_with_dependency_replacement(self) -> None:
        report = BinaryReport.from_go_json(
            {
                "GoVersion": "go1.26.8",
                "Path": "example.test/app",
                "Main": {"Path": "example.test/app", "Version": "(devel)"},
                "Deps": [
                    {
                        "Path": "example.test/library",
                        "Version": "v1.2.3",
                        "Sum": "h1:abc",
                        "Replace": {
                            "Path": "example.test/fork",
                            "Version": "v1.2.4",
                            "Sum": "h1:def",
                        },
                    }
                ],
                "Settings": [
                    {"Key": "GOARCH", "Value": "amd64"},
                    {"Key": "CGO_ENABLED", "Value": "1"},
                ],
            },
            container_path="/usr/bin/app",
            size=123,
        )

        self.assertEqual(report.go_version, "go1.26.8")
        self.assertEqual(report.main_package, "example.test/app")
        self.assertEqual(report.dependencies[0].path, "example.test/library")
        self.assertIsNotNone(report.dependencies[0].replace)
        self.assertEqual(report.dependencies[0].replace.path, "example.test/fork")
        self.assertEqual(report.build_settings[0].value, "amd64")
        self.assertTrue(report.cgo_enabled)

    def test_rejects_json_without_go_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "GoVersion"):
            BinaryReport.from_go_json({}, container_path="/bin/app", size=1)


class ScanReportTests(unittest.TestCase):
    def test_dependency_summary_groups_binary_paths(self) -> None:
        dependency = Module(path="example.test/library", version="v1.0.0")
        binaries = [
            BinaryReport(
                paths=[path],
                size=1,
                go_version="go1.26",
                main_package=path,
                main_module=None,
                dependencies=[dependency],
                build_settings=[],
            )
            for path in ("/bin/one", "/bin/two")
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        summary = report.dependency_summary()

        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["used_by"], ["/bin/one", "/bin/two"])

    def test_normalizes_findings_without_losing_binary_evidence(self) -> None:
        binary = BinaryReport(
            paths=["/bin/app", "/usr/bin/app"],
            size=1,
            go_version="go1.26",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
            vulnerability_scan=VulnerabilityScan(
                status="complete",
                vulnerabilities=[
                    Vulnerability(
                        id="GO-2026-0001",
                        aliases=["GHSA-aaaa-bbbb-cccc", "CVE-2026-0001"],
                        advisory_url="https://vuln.example.test/GO-2026-0001",
                        findings=[
                            VulnerabilityFinding(
                                module="example.test/library",
                                found_version="v1.0.0",
                                fixed_version="v1.1.0",
                                package="example.test/library/decoder",
                                symbol="Decode",
                                evidence="symbol",
                                reachability="unknown",
                            )
                        ],
                    )
                ],
            ),
        )
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(binary)

        occurrences = report.finding_occurrences()

        self.assertEqual(len(occurrences), 1)
        occurrence = occurrences[0]
        self.assertEqual(occurrence.binary_paths, ("/bin/app", "/usr/bin/app"))
        self.assertEqual(occurrence.current_version, "v1.0.0")
        self.assertEqual(occurrence.fixed_version, "v1.1.0")
        self.assertEqual(occurrence.package, "example.test/library/decoder")
        self.assertEqual(occurrence.symbol, "Decode")
        self.assertEqual(occurrence.evidence, "symbol")
        self.assertTrue(occurrence.matches_identifier("cve-2026-0001"))
        self.assertEqual(report.vulnerability_scan_counts(), {"complete": 1})
        self.assertEqual(report.coverage_state, "complete")
        self.assertEqual(report.result_state, "vulnerable")

    def test_coverage_and_result_do_not_treat_information_as_failure(self) -> None:
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.append(
            BinaryReport(
                paths=["/bin/app"],
                size=1,
                go_version="go1.26",
                main_package="example.test/app",
                main_module=None,
                dependencies=[],
                build_settings=[],
                vulnerability_scan=VulnerabilityScan(status="complete"),
            )
        )
        report.issues.append(
            ScanIssue(
                "/bin/app",
                "reconciliation-difference",
                "equivalent version representations",
            )
        )

        self.assertEqual(report.coverage_state, "complete")
        self.assertEqual(report.result_state, "clean")
        self.assertEqual(report.actionable_issues, [])


if __name__ == "__main__":
    unittest.main()
