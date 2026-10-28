from __future__ import annotations

from dataclasses import replace
import unittest

from pygo_audit.models import (
    BinaryLayerObservation,
    BinaryReconciliation,
    BinaryReport,
    BuildSetting,
    ContainerMetadata,
    ImageIdentity,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
    ScanIssue,
    AuditReport,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.report_views import index_cve_evidence, iter_binary_vulnerabilities


class ModelInvariantTests(unittest.TestCase):
    def test_invalid_values_fail_during_direct_construction(self) -> None:
        cases = (
            ("key", lambda: BuildSetting("", "amd64")),
            ("id", lambda: Vulnerability(id="")),
            ("root", lambda: ContainerMetadata("")),
            ("source", lambda: ModuleInventoryEntry("other", "", "", "", "")),
            ("status", lambda: ModuleReconciliation("other", "", "")),
            ("status", lambda: BinaryReconciliation(status="other")),
            (
                "go_version_status",
                lambda: BinaryReconciliation(go_version_status="other"),
            ),
            ("evidence", lambda: VulnerabilityFinding(evidence="other")),
            ("reachability", lambda: VulnerabilityFinding(reachability="reachable")),
            ("status", lambda: VulnerabilityScan(status="other")),
            ("status", lambda: BinaryLayerObservation(0, "other", ())),
            (
                "govulncheck_status",
                lambda: AuditReport(
                    metadata=ContainerMetadata("/root"),
                    go_command="go",
                    go_tool_version="go1.26",
                    govulncheck_status="other",
                ),
            ),
        )
        for name, construct in cases:
            with (
                self.subTest(field=name),
                self.assertRaisesRegex(ValueError, f"^{name} "),
            ):
                construct()

    def test_binary_specific_hook_keeps_shared_invariants(self) -> None:
        binary = BinaryReport(["/app"], 1, "go1.26", "", None, [], [])
        for name, value in (
            ("paths", []),
            ("go_version", ""),
            ("runtime_disposition", "other"),
            ("sha256", "a" * 63),
            ("sha256", "A" * 64),
            ("sha256", "z" * 64),
        ):
            with self.subTest(field=name, value=value):
                with self.assertRaisesRegex(ValueError, f"^{name} "):
                    replace(binary, **{name: value})
        for digest in ("", "0123456789abcdef" * 4):
            self.assertEqual(replace(binary, sha256=digest).sha256, digest)
        self.assertEqual(binary.runtime_disposition, "unknown")

    def test_replace_revalidates_frozen_models_without_serializing_constraints(
        self,
    ) -> None:
        setting = BuildSetting("GOARCH", "amd64")
        self.assertEqual(
            replace(setting, value="arm64").to_dict(),
            {
                "key": "GOARCH",
                "value": "arm64",
            },
        )
        with self.assertRaisesRegex(ValueError, "^key must not be empty"):
            replace(setting, key="")
        finding = VulnerabilityFinding()
        self.assertEqual(replace(finding, evidence="symbol").evidence, "symbol")
        with self.assertRaisesRegex(ValueError, "^evidence has unsupported value"):
            replace(finding, evidence="other")
        self.assertNotIn("required_values", finding.to_dict())
        self.assertNotIn("field_choices", finding.to_dict())


class BinaryReportTests(unittest.TestCase):
    def test_shared_cve_index_preserves_original_and_empty_observations(self) -> None:
        cve = "CVE-2026-0001"
        advisory = Vulnerability(
            "GO-2026-0001",
            aliases=[cve, cve.lower(), "GHSA-example"],
            findings=[
                VulnerabilityFinding(
                    module="example/lib",
                    found_version="v1",
                    evidence="symbol",
                    reconciliation=ModuleReconciliation("exact", "example/lib", "v1"),
                ),
            ],
        )
        empty = Vulnerability(cve, aliases=[cve])
        runtime = BinaryReport(
            ["/app"],
            1,
            "go1.26",
            "",
            None,
            [],
            [],
            sha256="a" * 64,
            runtime_disposition="runtime",
            vulnerability_scan=VulnerabilityScan(vulnerabilities=[advisory]),
        )
        historical = BinaryReport(
            ["/old/app"],
            1,
            "go1.26",
            "",
            None,
            [],
            [],
            sha256="b" * 64,
            runtime_disposition="deleted",
            vulnerability_scan=VulnerabilityScan(vulnerabilities=[empty]),
        )
        report = AuditReport(
            ContainerMetadata("/root"), "go", "test", binaries=[runtime, historical]
        )
        indexed = index_cve_evidence(report)
        self.assertEqual(list(indexed), [cve])
        evidence = indexed[cve]
        self.assertEqual(len(evidence.observations), 2)
        self.assertIs(evidence.observations[0][0], runtime)
        self.assertIs(evidence.observations[0][1], advisory)
        self.assertEqual(evidence.binary_paths, {"/app", "/old/app"})
        self.assertEqual(evidence.binary_sha256, {"a" * 64, "b" * 64})
        self.assertEqual(evidence.runtime_dispositions, {"runtime", "deleted"})
        self.assertEqual(evidence.evidence_types, {"symbol"})
        self.assertEqual(len(evidence.to_dict()["findings"]), 1)
        other = replace(report, binaries=[historical])
        other_evidence = index_cve_evidence(other)[cve]
        self.assertEqual(other_evidence.runtime_dispositions, {"deleted"})
        self.assertEqual(other_evidence.evidence_types, set())
        self.assertEqual(other_evidence.to_dict()["findings"], [])
        self.assertEqual(evidence.runtime_dispositions, {"runtime", "deleted"})

    def test_derived_values_follow_evidence_changes_and_are_not_serialized(
        self,
    ) -> None:
        binary = BinaryReport(["/app"], 1, "go1.26", "", None, [], [])
        container = AuditReport(
            metadata=ContainerMetadata("/subject"),
            binaries=[binary],
            go_command="go",
            go_tool_version="test",
        )
        self.assertEqual(binary.finding_statuses, {})
        self.assertEqual(binary.reconciliation.sbom_statuses, {})

        comparison = ModuleReconciliation("mismatch", "example/lib", "v1")
        binary.paths.append("/alias")
        binary.vulnerability_scan.vulnerabilities.append(
            Vulnerability(
                "GO-2026-0001",
                findings=[
                    VulnerabilityFinding(reconciliation=comparison),
                    VulnerabilityFinding(),
                ],
            )
        )
        binary.reconciliation.sbom_modules.extend([comparison, comparison])
        container.binaries.append(BinaryReport(["/other"], 2, "go1.26", "", None, [], []))
        self.assertEqual(binary.finding_statuses, {"mismatch": 1})
        self.assertEqual(binary.reconciliation.sbom_statuses, {"mismatch": 2})
        for field in ("go_binaries", "go_binary_paths"):
            self.assertNotIn(field, container.stats.to_dict())
        for field in ("finding_statuses", "sbom_statuses"):
            self.assertNotIn(field, binary.reconciliation.to_dict())
        self.assertNotIn("finding_statuses", binary.to_dict())

        image = ImageIdentity(digest="sha256:" + "a" * 64)
        self.assertEqual(image.digest_short, "a" * 12)
        self.assertEqual(replace(image, digest="sha256:" + "b" * 64).digest_short, "b" * 12)
        self.assertEqual(ImageIdentity().digest_short, "")
        self.assertNotIn("digest_short", image.to_dict())

    def test_shared_vulnerability_iterator_keeps_original_evidence_and_empty_findings(
        self,
    ) -> None:
        binary = BinaryReport(
            paths=["/app"],
            size=1,
            go_version="go1.26",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
        )
        empty = Vulnerability(id="CVE-2026-0001")
        observed = Vulnerability(
            id="CVE-2026-0002",
            findings=[VulnerabilityFinding(module="example.test/app")],
        )
        binary.vulnerability_scan.vulnerabilities = [empty, observed]
        report = AuditReport(
            metadata=ContainerMetadata("/subject"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go1.26",
        )
        pairs = list(iter_binary_vulnerabilities(report))
        self.assertEqual(pairs, [(binary, empty), (binary, observed)])
        self.assertIs(pairs[0][0], binary)
        self.assertIs(pairs[1][1], observed)

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


class AuditReportTests(unittest.TestCase):
    def test_container_is_the_top_level_scan_subject(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )

        document = report.to_dict()

        self.assertEqual(document["metadata"]["root"], "/tmp/root")
        self.assertNotIn("type", document["metadata"])
        self.assertIn("binaries", document)
        self.assertIn("issues", document)
        self.assertIn("stats", document)
        self.assertNotIn("subject", document)

    def test_empty_report_keeps_explicit_defaults_in_the_evidence_contract(
        self,
    ) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go1.26",
        )

        document = report.to_dict()

        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["go_command"], "go")
        self.assertEqual(document["go_tool_version"], "go1.26")
        self.assertEqual(document["govulncheck_status"], "disabled")
        for field in (
            "producer_name",
            "producer_version",
            "govulncheck_command",
            "govulncheck_tool_version",
            "scan_started_at",
            "scan_completed_at",
            "run_id",
        ):
            with self.subTest(field=field):
                self.assertEqual(document[field], "")
        self.assertEqual(
            document["metadata"]["image"],
            {
                "reference": "",
                "digest": "",
                "platform": "",
                "extractor": "",
                "name": "",
                "component": "",
                "source_git_url": "",
                "product_version": "",
                "component_version": "",
                "product_component": "",
                "cpe": "",
            },
        )
        self.assertEqual(document["binaries"], [])
        self.assertEqual(document["issues"], [])
        for field in ("producer", "scan", "toolchain", "vulnerability_toolchain"):
            self.assertNotIn(field, document)
        for field in (
            "dependency_summary",
            "vulnerability_databases",
            "runtime_dispositions",
            "unaccounted_historical",
        ):
            self.assertNotIn(field, document)

    def test_nested_defaults_and_tuples_are_json_values(self) -> None:
        binary = BinaryReport(
            paths=["/app"],
            size=1,
            go_version="go1.26",
            main_package="example.test/app",
            main_module=Module(path="example.test/app"),
            dependencies=[],
            build_settings=[],
            layer_history=[BinaryLayerObservation(0, "found", ("/old-app", "/app"))],
            vulnerability_scan=VulnerabilityScan(
                vulnerabilities=[Vulnerability(id="GO-2026-0001")],
            ),
        )

        document = binary.to_dict()

        self.assertEqual(
            document["main_module"],
            {
                "path": "example.test/app",
                "version": "",
                "checksum": "",
                "replace": None,
            },
        )
        self.assertEqual(
            document["layer_history"],
            [
                {
                    "layer_index": 0,
                    "status": "found",
                    "paths": ["/old-app", "/app"],
                    "symlinks": [],
                }
            ],
        )
        self.assertIsNone(document["vulnerability_scan"]["sbom"])
        self.assertEqual(document["vulnerability_scan"]["scanner_name"], "")
        self.assertEqual(document["vulnerability_scan"]["database"], "")
        self.assertEqual(document["vulnerability_scan"]["database_last_modified"], "")
        self.assertEqual(
            document["vulnerability_scan"]["vulnerabilities"][0]["withdrawn"], ""
        )
        self.assertEqual(
            document["vulnerability_scan"]["vulnerabilities"][0]["findings"], []
        )
        self.assertEqual(document["reconciliation"]["go_version_status"], "not_checked")
        self.assertEqual(binary.finding_statuses, {})
        self.assertNotIn("cgo_enabled", document)

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
                                evidence="symbol",
                                reachability="unspecified",
                            )
                        ],
                    )
                ],
            ),
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(binary)

        occurrences = report.finding_occurrences()

        self.assertEqual(len(occurrences), 1)
        occurrence = occurrences[0]
        self.assertEqual(occurrence.binary_paths, ("/bin/app", "/usr/bin/app"))
        self.assertEqual(occurrence.runtime_disposition, "unknown")
        self.assertEqual(occurrence.current_version, "v1.0.0")
        self.assertEqual(occurrence.fixed_version, "v1.1.0")
        self.assertEqual(occurrence.package, "example.test/library/decoder")
        self.assertEqual(occurrence.evidence, "symbol")
        self.assertEqual(report.coverage_state, "complete")
        self.assertEqual(report.result_state, "vulnerable")

        binary.runtime_disposition = "runtime"
        occurrence = report.finding_occurrences()[0]
        self.assertEqual(occurrence.runtime_disposition, "runtime")
        self.assertEqual(occurrence.to_dict()["runtime_disposition"], "runtime")

    def test_coverage_and_result_do_not_treat_information_as_failure(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
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

    def test_identifies_unaccounted_historical_binaries_and_findings(self) -> None:
        binary = BinaryReport(
            paths=["/layer-000/usr/bin/app"],
            size=1,
            go_version="go1.26",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
            runtime_disposition="unaccounted",
            vulnerability_scan=VulnerabilityScan(
                status="complete",
                vulnerabilities=[
                    Vulnerability(
                        id="CVE-2026-0001",
                        findings=[VulnerabilityFinding(module="example.test/app")],
                    )
                ],
            ),
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="test",
        )

        self.assertEqual(report.unaccounted_historical_binaries, [binary])
        self.assertEqual(len(report.unaccounted_historical_findings()), 1)
        self.assertNotIn("unaccounted_historical", report.to_dict())
        self.assertEqual(report.actionable_issues, [])


if __name__ == "__main__":
    unittest.main()
