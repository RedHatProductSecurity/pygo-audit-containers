from __future__ import annotations

import json
import unittest
from dataclasses import replace

from pygo_audit.models import (
    AuditReport,
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
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)
from pygo_audit.report import (
    REPORT_VIEWS,
    render_binaries,
    render_checks,
    render_diagnostics,
    render_by_vulnerability,
    render_json,
    render_module_reconciliation,
    render_overview,
)
from pygo_audit.report_views import reconciliation_diagnostics
from pygo_audit.text_layout import (
    DETAILED_POLICY,
    EXPANDED_POLICY,
    FORENSIC_POLICY,
    FULL_POLICY,
    RenderPolicy,
    TextLayout,
    Verbosity,
    preview_items,
)


class AuditReportTests(unittest.TestCase):
    def test_cve_export_includes_aliases_and_advisories_without_findings(self) -> None:
        binary = self._binary("/bin/main", "example.test/library", cgo=False)
        binary.vulnerability_scan.vulnerabilities.extend(
            Vulnerability(
                id=f"GO-2026-{index:04d}",
                aliases=[f" cve-2026-{index:04d} ", "GHSA-aaaa-bbbb-cccc"],
            )
            for index in reversed(range(12))
        )
        binary.vulnerability_scan.vulnerabilities.append(
            Vulnerability(id="CVE-2026-12345", aliases=["CVE-2026-0001"])
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary, binary],
            go_command="go",
            go_tool_version="test",
        )
        self.assertEqual(
            REPORT_VIEWS["cves"].render(report).splitlines(),
            [*(f"CVE-2026-{index:04d}" for index in range(12)), "CVE-2026-12345"],
        )

    def test_inventory_exports_use_recorded_paths_and_exclude_advisory_claims(self):
        binary = self._binary("/bin/main", "example.test/library/decoder", cgo=False)
        binary.main_package = "example.test/app/cmd"
        binary.main_module = Module("example.test/app", "v1.0.0")
        binary.dependencies = [
            Module(
                "example.test/library", "v1.0.0", replace=Module("example.test/fork")
            ),
            Module("example.test/unaffected", "v2.0.0"),
            Module("example.test/library", "v2.0.0"),
        ]
        binary.vulnerability_scan.sbom = {
            "go_version": "go1.26",
            "modules": [{"path": "example.test/scanner-only", "version": "v1.0.0"}],
            "roots": [binary.main_package, "example.test/other/cmd", ""],
        }
        binary.reconciliation.effective_module_inventory = [
            ModuleInventoryEntry("stdlib", "stdlib", "go1.26", "stdlib", "go1.26")
        ]
        binary.vulnerability_scan.vulnerabilities[0].affected = [
            {"module": "advisory-only", "packages": [{"path": "advisory-only/pkg"}]}
        ]
        other = self._binary("/bin/other", "example.test/finding-only/pkg", cgo=False)
        other.main_package = ""
        other.vulnerability_scan.vulnerabilities[0].findings = [
            VulnerabilityFinding(
                module="example.test/finding-only",
                package="example.test/finding-only/pkg",
            ),
            VulnerabilityFinding(),
        ]
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary, other],
            go_command="go",
            go_tool_version="test",
        )
        self.assertEqual(
            REPORT_VIEWS["modules"].render(report).splitlines(),
            [
                "example.test/app@v1.0.0",
                "example.test/finding-only@unknown",
                "example.test/fork@unknown",
                "example.test/library@v1.0.0",
                "example.test/library@v2.0.0",
                "example.test/scanner-only@v1.0.0",
                "example.test/unaffected@v2.0.0",
                "stdlib@go1.26",
            ],
        )
        self.assertEqual(
            REPORT_VIEWS["packages"].render(report).splitlines(),
            [
                "example.test/app/cmd@v1.0.0",
                "example.test/finding-only/pkg@unknown",
                "example.test/library/decoder@v1.0.0",
                "example.test/other/cmd@unknown",
            ],
        )

    def test_package_versions_stay_with_their_binary_and_apply_replacements(self):
        binaries = []
        for version in ("v1.0.0", "v2.0.0"):
            binary = self._binary("/bin/main", "", cgo=False)
            binary.main_package = "example.test/app/cmd"
            binary.main_module = Module("example.test/app", version)
            binary.dependencies = [
                Module(
                    "example.test/lib",
                    "v0.1.0",
                    replace=Module("example.test/fork", version),
                ),
                Module("example.test/lib/sub", "v3.0.0"),
                Module("example.test/local", "v0.1.0", replace=Module("../local")),
                Module("example.test/conflict", "v1.0.0"),
            ]
            binary.vulnerability_scan.sbom = {
                "go_version": "go1.26",
                "modules": [{"path": "example.test/conflict", "version": "v2.0.0"}],
                "roots": [
                    "example.test/lib/decoder",
                    "example.test/lib/sub/pkg",
                    "example.test/libextra/pkg",
                    "example.test/local/pkg",
                    "example.test/conflict/pkg",
                ],
            }
            binary.vulnerability_scan.vulnerabilities[0].findings = [
                VulnerabilityFinding(
                    module="example.test/lib", package="example.test/lib/parser"
                ),
                VulnerabilityFinding(
                    module="stdlib", package="net/http", found_version="v1.26.0"
                ),
                VulnerabilityFinding(
                    module="example.test/conflict",
                    package="example.test/conflict/observed",
                    found_version="v2.0.0",
                ),
            ]
            binaries.append(binary)
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=binaries,
            go_command="go",
            go_tool_version="test",
        )
        self.assertEqual(
            REPORT_VIEWS["packages"].render(report).splitlines(),
            [
                "example.test/app/cmd@v1.0.0",
                "example.test/app/cmd@v2.0.0",
                "example.test/conflict/observed@v2.0.0",
                "example.test/conflict/pkg@unknown",
                "example.test/lib/decoder@v1.0.0",
                "example.test/lib/decoder@v2.0.0",
                "example.test/lib/parser@v1.0.0",
                "example.test/lib/parser@v2.0.0",
                "example.test/lib/sub/pkg@v3.0.0",
                "example.test/libextra/pkg@unknown",
                "example.test/local/pkg@unknown",
                "net/http@v1.26.0",
            ],
        )

    def test_shared_preview_reports_omitted_items(self) -> None:
        self.assertEqual(preview_items(range(12)), (list(range(10)), 2))
        self.assertEqual(preview_items(range(3), None), ([0, 1, 2], 0))
        policy = RenderPolicy()
        self.assertEqual(policy.preview(range(12)), (list(range(10)), 2))
        self.assertEqual(
            RenderPolicy(wide=True).preview(range(12)), (list(range(12)), 0)
        )
        self.assertTrue(RenderPolicy(Verbosity.DETAILED).shows(Verbosity.EXPANDED))
        self.assertEqual(policy.hash("a" * 64), "a" * 12 + "...")
        self.assertEqual(RenderPolicy(wide=True).hash("a" * 64), "a" * 64)

    def test_optional_layout_fields_preserve_zero_and_empty_values(self) -> None:
        lines = TextLayout()
        lines.fields(("Absent", None), ("Count", 0), ("Blank", ""))
        self.assertEqual(
            lines, ["Count:                  0", "Blank:                  "]
        )

    def test_layout_applies_shared_preview_and_wrapped_bullet_rules(self) -> None:
        lines = TextLayout()
        lines.preview_field("Values", range(12))
        lines.bullets(["segment " * 30], wrap=True)

        self.assertIn("Values:                 0, 1, 2, 3, 4, 5, 6, 7, 8, 9", lines)
        self.assertIn("Additional values:      2 omitted; use --wide to show all", lines)
        self.assertTrue(lines[2].startswith("  - segment"))
        self.assertTrue(all(line.startswith("    segment") for line in lines[3:]))

    def test_layout_aligns_variable_width_columns(self) -> None:
        lines = TextLayout()
        lines.columns((("short", "RUNTIME", "one"), ("much-longer", "HISTORICAL", "two")))
        self.assertEqual(lines[0].index("RUNTIME"), lines[1].index("HISTORICAL"))
        self.assertEqual(lines[0].index("one"), lines[1].index("two"))

    def test_multiline_values_preserve_identifiers_and_table_alignment(self):
        identifiers = ["component;with,punctuation", "platform:component (variant)"]
        lines = TextLayout(policy=FULL_POLICY)
        lines.list_field("IDs", identifiers)
        self.assertEqual(lines, ["IDs:", *("  - " + value for value in identifiers)])
        lines = TextLayout(policy=RenderPolicy(entry_limit=1))
        lines.list_field("IDs", identifiers)
        self.assertIn(identifiers[0], lines[0])
        self.assertIn("1 omitted", lines[-1])
        rows = [
            ("BINARY", "CGO", "LOCATION"),
            ("app", ("Enabled", "Unknown"), ("one/path", "two/path", "three/path")),
            ("empty", (), ()),
        ]
        lines = TextLayout(policy=FULL_POLICY)
        lines.columns(rows)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[1].index("Enabled"), lines[2].index("Unknown"))
        self.assertEqual({lines[index].index(path) for index, path in enumerate(("one/path", "two/path", "three/path"), 1)}, {lines[0].index("LOCATION")})
        self.assertEqual(lines[3].strip(), "three/path")
        self.assertEqual(lines[4], "empty")

    def test_wrapped_layout_preserves_long_tokens_and_normalizes_multiline_values(
        self,
    ) -> None:
        path = "/" + "long-\u00e9vidence-path-" * 12
        lines = TextLayout()
        lines.field("Path", path, wrap=True)
        lines.field("Detail", " first line \n\n second line ", wrap=True)
        self.assertEqual(lines[0], "Path:                   " + path)
        self.assertEqual(lines[1], "Detail:                 first line; second line")

    def test_aggregates_duplicate_findings_across_binaries(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        binaries[0].runtime_disposition = "runtime"
        binaries[1].runtime_disposition = "unaccounted"
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.extend(binaries)

        text_output = render_binaries(report, DETAILED_POLICY)
        self.assertEqual(text_output.count("\nBINARY: "), 2)
        self.assertEqual(text_output.count("CVE-2026-0001"), 2)
        _, one_section, two_section = text_output.split("\nBINARY: ")
        self.assertIn("Location:               bin/one", one_section)
        self.assertIn("example.test/library/decoder", one_section)
        self.assertNotIn("example.test/library/parser", one_section)
        self.assertIn("Location:               bin/two", two_section)
        self.assertIn("example.test/library/parser", two_section)
        self.assertNotIn("example.test/library/decoder", two_section)
        self.assertIn("GHSA-aaaa-bbbb-cccc", text_output)
        self.assertIn("GO-2026-0001", text_output)
        self.assertNotIn("DEPENDENCY INVENTORY", text_output)

        summary_output = render_overview(report)
        self.assertNotIn("Runtime dispositions:", summary_output)
        self.assertIn("PYGO-AUDIT OVERVIEW", summary_output)
        self.assertIn("SUBJECT: /tmp/root", summary_output)
        self.assertNotIn(f"PROVENANCE\n{'-' * 100}\n", summary_output)
        self.assertIn(f"RESULT: COMPLETE (2 of 2 binaries)\n{'-' * 100}\n", summary_output)
        self.assertIn("Vulnerabilities:        1", summary_output)
        self.assertIn("Unique CVEs:            1", summary_output)
        self.assertIn("NEXT REVIEW", summary_output)
        self.assertIn("Full, unabridged reports are under reports/", summary_output)
        self.assertLess(summary_output.index("SUBJECT"), summary_output.index("RESULT"))
        detailed_overview = render_overview(report, FORENSIC_POLICY)
        self.assertIn(f"PROVENANCE\n{'-' * 100}\n", detailed_overview)
        self.assertGreater(
            detailed_overview.index("PROVENANCE"), detailed_overview.index("NEXT REVIEW")
        )

        inventory = render_binaries(report)
        self.assertIn("PYGO-AUDIT BINARY FINDINGS", inventory)
        self.assertNotIn("DEPENDENCY INVENTORY", inventory)

        modules = render_module_reconciliation(report, FULL_POLICY)
        self.assertIn("PYGO-AUDIT MODULE RECONCILIATION", modules)
        self.assertIn("DEPENDENCY INVENTORY", modules)

    def test_binary_views_preserve_paths_wrapping_and_historical_evidence(self) -> None:
        binary = self._binary("/bin/main", "example.test/library", cgo=False)
        additional_paths = ["/usr/local/" + "long/" * 12 + name for name in ("one", "two")]
        binary.paths.extend(reversed(additional_paths))
        binary.symlinks = ["/bin/main-link"]
        binary.runtime_disposition = "unaccounted"
        binary.layer_history = [BinaryLayerObservation(1, "found", ("/bin/main",))]
        binary.vulnerability_scan = VulnerabilityScan(
            status="failed", error="scanner could not finish checking this binary " * 3
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )
        summary = render_binaries(report)
        self.assertIn("Name:                          main", summary)
        self.assertIn("Number affected packages:      0", summary)
        self.assertIn("Number vulnerabilities:        0", summary)
        self.assertIn(f"{'Recorded modules:':<31}0", summary)
        self.assertIn("Size:                          0.00 MB", summary)
        self.assertIn("Location:                      bin/main", summary)
        for field in ("Scan error:", "BUILD\n"):
            self.assertNotIn(field, summary)

        expanded = render_binaries(report, policy=EXPANDED_POLICY)
        self.assertIn("Location:               bin/main", expanded)
        self.assertIn("Runtime disposition:    UNACCOUNTED HISTORICAL", expanded)
        self.assertIn("Scan error:", expanded)
        self.assertNotIn("BUILD SETTINGS", expanded)
        for path in additional_paths:
            self.assertNotIn(path.removeprefix("/"), expanded)

        detailed = render_binaries(report, DETAILED_POLICY)
        self.assertIn("VULNERABILITY EVIDENCE", detailed)
        self.assertNotIn("DEPENDENCY INVENTORY", detailed)
        self.assertNotIn("Layer observations", detailed)
        for output in (summary, expanded, detailed):
            for field in ("Hardlinks:", "Symlinks:", "Layers:", "Layer observations"):
                self.assertNotIn(field, output)

        forensic = render_binaries(report, FORENSIC_POLICY)
        for path in additional_paths:
            self.assertIn(path.removeprefix("/"), forensic)
        self.assertIn("Hardlinks:", forensic)
        self.assertIn("Symlinks:               bin/main-link", forensic)
        self.assertIn("layer-001 FOUND: files=bin/main", forensic)
        self.assertIn("PYGO-AUDIT BINARY FINDINGS", forensic)

    def test_binary_summary_ranks_and_limits_packages_and_vulnerabilities(self) -> None:
        binary = self._binary("/bin/main", "unused", cgo=False)
        vulnerabilities = []
        for index in range(12):
            findings = [
                VulnerabilityFinding(
                    module="example.test/module",
                    package=f"example.test/package{index:02d}",
                    evidence="symbol",
                )
            ]
            vulnerabilities.append(
                Vulnerability(f"CVE-2026-{index:04d}", findings=findings)
            )
        binary.vulnerability_scan.vulnerabilities = vulnerabilities
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )
        output = render_binaries(report, EXPANDED_POLICY)
        packages = output.split("AFFECTED PACKAGES (12)", 1)[1].split(
            "VULNERABILITIES (12)", 1
        )[0]
        vulnerabilities = output.split("VULNERABILITIES (12)", 1)[1]

        self.assertIn("example.test/package00 (1 finding)", packages)
        self.assertIn("Additional packages:    2 omitted", packages)
        self.assertIn("Additional packages:    2 omitted", packages)
        self.assertLess(
            vulnerabilities.index("CVE-2026-0000"),
            vulnerabilities.index("CVE-2026-0001"),
        )
        self.assertLess(
            vulnerabilities.index("CVE-2026-0001"),
            vulnerabilities.index("CVE-2026-0002"),
        )
        self.assertIn("Additional vulnerabilities: 2 omitted", vulnerabilities)
        wide = render_binaries(
            report, RenderPolicy(Verbosity.EXPANDED, wide=True)
        )
        self.assertIn("example.test/package10", wide)
        self.assertNotIn(" omitted;", wide)

    def test_forensic_wide_removes_limits_and_preserves_full_hashes(self) -> None:
        binary = self._binary("/bin/main", "example.test/library", cgo=False)
        binary.sha256 = "a" * 64
        binary.dependencies = [
            Module(path=f"example.test/dependency{index:02d}", version="v1.0.0")
            for index in range(12)
        ]
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )

        forensic = render_module_reconciliation(report, FORENSIC_POLICY)
        self.assertIn("Additional dependencies: 2 omitted", forensic)
        self.assertIn("SHA-256:                aaaaaaaaaaaa...", forensic)
        self.assertNotIn("example.test/dependency10", forensic)

        wide = "\n\n".join(view.render(report, FULL_POLICY) for view in REPORT_VIEWS.values())
        self.assertNotIn(" omitted;", wide)
        self.assertIn("SHA-256:                " + "a" * 64, wide)
        self.assertIn("example.test/dependency11", wide)

    def test_check_view_keeps_component_versions_separate(self) -> None:
        binaries = [
            self._binary(path, "example.test/library/decoder", cgo=False)
            for path in ("/bin/old-one", "/bin/old-two", "/bin/new")
        ]
        old_findings = binaries[1].vulnerability_scan.vulnerabilities[0].findings
        old_findings[0] = replace(old_findings[0], evidence="package")
        new_findings = binaries[2].vulnerability_scan.vulnerabilities[0].findings
        new_findings[0] = replace(new_findings[0], found_version="v2.0.0")
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=binaries,
            go_command="go",
            go_tool_version="go",
        )
        output = render_checks(report, ["CVE-2026-0001"], FORENSIC_POLICY)
        _, old, new = output.split("\nMODULE: example.test/library\n")
        self.assertIn("Current version:        v1.0.0", old)
        self.assertIn("Current version:        v2.0.0", new)
        self.assertIn("Location:               bin/old-one", old)
        self.assertIn("Location:               bin/old-two", old)
        self.assertNotIn("bin/new", old)
        self.assertIn("Finding kind:           package", old)
        self.assertIn("Finding kind:           symbol", old)
        self.assertIn("Location:               bin/new", new)
        self.assertNotIn("bin/old", new)

    def test_warns_when_a_scan_is_incomplete(self) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        binary.vulnerability_scan = VulnerabilityScan(
            status="failed", error="scanner unavailable"
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(binary)

        output = render_by_vulnerability(report, DETAILED_POLICY)
        self.assertIn("No vulnerability findings detected.", output)
        self.assertIn("COVERAGE WARNING", output)
        self.assertIn("did not complete for 1 of 1 binaries", output)

        text_output = render_binaries(report, DETAILED_POLICY)
        self.assertIn("Location:               bin/one", text_output)
        self.assertIn("Affected packages:      0", text_output)
        self.assertIn("Vulnerabilities:        0", text_output)
        self.assertNotIn("RISK", text_output)
        self.assertIn("Scan error:             scanner unavailable", text_output)

        summary_output = render_overview(report)
        self.assertIn("Vulnerabilities:        0", summary_output)
        self.assertIn("RESULT: INCOMPLETE (0 of 1 binaries)", summary_output)
        self.assertNotIn("Runtime dispositions:", summary_output)
        self.assertNotIn("Unaccounted historical", summary_output)
        self.assertIn("COVERAGE WARNING", summary_output)

    def test_supported_views_render_normalized_findings(self) -> None:
        binaries = [
            self._binary("/bin/one", "example.test/library/decoder", cgo=True),
            self._binary("/bin/two", "example.test/library/parser", cgo=False),
        ]
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.extend(binaries)

        binary_output = render_binaries(report, policy=EXPANDED_POLICY)
        self.assertIn("Name:                   one", binary_output)
        self.assertIn("Name:                   two", binary_output)
        self.assertIn("Location:               bin/one", binary_output)
        self.assertIn("Location:               bin/two", binary_output)

        vulnerability_output = render_by_vulnerability(report)
        self.assertEqual(
            vulnerability_output.count("  - CVE-2026-0001"),
            1,
        )
        self.assertNotIn("VULNERABILITY 1 OF", vulnerability_output)

    def test_targeted_checks_match_aliases_and_explain_coverage(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        output = render_checks(
            report,
            ["CVE-2026-0001", "CVE-2026-9999"],
            EXPANDED_POLICY,
        )

        self.assertTrue(output.startswith("VULNERABILITY CHECKS\n"))
        self.assertIn("\nCVE-2026-0001\n", output)
        self.assertIn(f"\nCVE-2026-0001\n{'-' * 100}\n", output)
        self.assertIn("Result:                 DETECTED", output)
        self.assertIn("bin/one", output)
        self.assertIn("\nCVE-2026-9999\n", output)
        self.assertIn("Result:                 NOT DETECTED IN THIS AUDIT", output)
        self.assertIn("detected in this audit with complete scan coverage", output)
        self.assertIn("Coverage:               COMPLETE (1 of 1 binaries)", output)
        self.assertIn("MODULE: example.test/library", output)
        self.assertNotIn(" OF ", output)
        self.assertEqual(output.count("CVE-2026-0001"), 1)
        self.assertEqual(output.count("CVE-2026-9999"), 1)
        self.assertIn("GHSA-aaaa-bbbb-cccc", output)
        self.assertIn("GO-2026-0001", output)
        self.assertNotIn("SCAN CONTEXT", output)
        self.assertNotIn("PROVENANCE", output)
        self.assertNotIn("Audit SHA-256", output)
        self.assertIn("INVENTORY: root", output)

        report.binaries[0].vulnerability_scan = VulnerabilityScan(status="failed")
        incomplete_output = render_checks(report, ["CVE-2026-9999"])
        self.assertTrue(incomplete_output.startswith("VULNERABILITY CHECK\n"))
        self.assertIn("\nCVE-2026-9999\n", incomplete_output)
        self.assertIn("Result:                 INDETERMINATE", incomplete_output)
        self.assertIn(
            "Coverage:               INCOMPLETE (0 of 1 binaries)", incomplete_output
        )
        self.assertIn("coverage is incomplete", incomplete_output)

    def test_vulnerability_view_groups_modules_and_expands_package_evidence(
        self,
    ) -> None:
        first = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        first.paths.append("/usr/bin/one")
        first.symlinks.append("/sbin/one")
        first.layer_history.append(
            BinaryLayerObservation(2, "found", ("/usr/bin/one",), ("/sbin/one",))
        )
        second = self._binary("/bin/two", "example.test/library/parser", cgo=False)
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[first, second],
            go_command="go",
            go_tool_version="go",
        )

        output = render_by_vulnerability(report)

        self.assertNotIn("Affected binaries:", output)
        self.assertNotIn("Affected modules:", output)
        self.assertNotIn("Affected packages:", output)
        self.assertNotIn("Aliases:", output)
        self.assertNotIn("GO-2026-0001", output)
        self.assertNotIn("GHSA-aaaa-bbbb-cccc", output)
        self.assertIn("CVES (1)", output)
        self.assertEqual(output.count("  - CVE-2026-0001"), 1)
        self.assertIn("Vulnerabilities:        1", output)
        self.assertIn("Unique CVEs:            1", output)
        self.assertNotIn("\nMODULE:", output)
        self.assertNotIn("\nBINARIES", output)
        self.assertNotIn("PROVENANCE", output)

        expanded = render_by_vulnerability(report, EXPANDED_POLICY)
        self.assertIn("VULNERABILITY: CVE-2026-0001", expanded)
        self.assertIn("Affected binaries:      2", expanded)
        self.assertNotIn("Affected modules:", expanded)
        self.assertNotIn("Affected packages:", expanded)
        self.assertNotIn("SHA-256:", expanded)
        self.assertNotIn("Hardlinks:", expanded)
        self.assertNotIn("Layer observations", expanded)
        self.assertIn("Aliases:", expanded)
        self.assertIn("GHSA-aaaa-bbbb-cccc", expanded)
        self.assertIn("one:layer-002", expanded)
        self.assertIn("two:runtime", expanded)
        self.assertIn("\nMODULE: example.test/library\n", expanded)
        self.assertIn("Current version:        v1.0.0", expanded)
        self.assertIn("Current version:        v1.0.0\nPackages (2)", expanded)
        self.assertNotIn("Fixed version:", expanded)
        self.assertLess(expanded.index("\nMODULE:"), expanded.index("\nBINARIES"))
        self.assertIn("VULNERABILITY: CVE-2026-0001\n" + "=" * 100, expanded)

        grouped = render_by_vulnerability(report, DETAILED_POLICY)
        self.assertEqual(grouped.count("\nMODULE: example.test/library\n"), 1)
        self.assertIn("Packages (2)\n  - example.test/library/decoder", grouped)
        self.assertNotIn("\nPACKAGES", grouped)
        self.assertIn("Fixed version:          v1.1.0", grouped)
        self.assertIn("Fixed version:          v1.1.0\nPackages (2)", grouped)
        self.assertIn("Affected modules:       1", grouped)
        self.assertIn("Affected packages:      2", grouped)
        self.assertLess(grouped.index("\nMODULE:"), grouped.index("\nBINARIES"))
        self.assertIn("  - example.test/library/decoder", grouped)
        self.assertIn("  - example.test/library/parser", grouped)
        self.assertEqual(grouped.count("GHSA-aaaa-bbbb-cccc"), 1)
        self.assertIn("BINARIES (2)", grouped)
        self.assertIn("SHA-256:", grouped)
        self.assertNotIn("Hardlinks:", grouped)
        self.assertNotIn("Symlinks:", grouped)
        self.assertNotIn("Layers:", grouped)
        self.assertNotIn("Layer observations", grouped)
        self.assertIn("\nBINARY: one\n", grouped)
        self.assertIn("\nBINARY: two\n", grouped)
        self.assertNotIn("one:layer-002", grouped)

        forensic = render_by_vulnerability(report, FORENSIC_POLICY)
        body, provenance = forensic.split("\nPROVENANCE\n")
        self.assertNotIn("BINARY PROVENANCE", forensic)
        self.assertLess(body.index("\nMODULE:"), body.index("\nBINARIES"))
        decoder, parser = body.split("PACKAGE: example.test/library/decoder", 1)[
            1
        ].split("PACKAGE: example.test/library/parser", 1)
        self.assertIn("BINARY: one", decoder)
        self.assertNotIn("BINARY: two", decoder)
        self.assertIn("BINARY: two", parser)
        self.assertNotIn("BINARY: one", parser)
        self.assertIn("Finding kind:           symbol", decoder)
        self.assertIn("SHA-256:", decoder)
        self.assertIn("Runtime disposition:    UNVERIFIED\nLayer observations (1)", decoder)
        self.assertNotIn("\nBINARY:", provenance)
        self.assertNotIn("\nMODULE:", provenance)
        self.assertNotIn("\nPACKAGE:", provenance)
        self.assertIn("Go toolchain:", provenance)
        self.assertIn("Hardlinks:              usr/bin/one", decoder)
        self.assertIn("Symlinks:               sbin/one", decoder)
        self.assertIn(
            "layer-002 FOUND: files=usr/bin/one; symlinks=sbin/one", decoder
        )

    def test_vulnerability_binary_blocks_show_only_their_observed_symbols(self) -> None:
        first = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        second = self._binary("/bin/two", "example.test/library/parser", cgo=False)
        for binary, symbol in ((first, "Decoder.Decode"), (second, "Parse")):
            findings = binary.vulnerability_scan.vulnerabilities[0].findings
            findings[0] = replace(findings[0], symbol=symbol)
        findings = first.vulnerability_scan.vulnerabilities[0].findings
        findings.append(
            replace(findings[0], evidence="module", package="", symbol=None)
        )
        findings.append(replace(findings[0], evidence="package", symbol=None))
        findings.append(replace(findings[0], symbol=None))
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[first, second],
            go_command="go",
            go_tool_version="go",
        )
        expanded = render_by_vulnerability(report, EXPANDED_POLICY)
        one_rows = [
            line for line in expanded.splitlines() if line.startswith("one:runtime")
        ]
        self.assertEqual(
            {line.split()[2] for line in one_rows}, {"module", "package", "symbol"}
        )
        self.assertNotIn("Decoder.Decode", expanded)
        for verbosity in (Verbosity.DETAILED, Verbosity.FORENSIC):
            output = render_by_vulnerability(report, RenderPolicy(verbosity))
            blocks = [
                block.split("\n\n", 1)[0]
                for block in output.split("\nBINARY: ")[1:]
            ]
            one = "\n".join(block for block in blocks if block.startswith("one\n"))
            two = "\n".join(block for block in blocks if block.startswith("two\n"))
            self.assertNotIn("parser.Parse", one)
            self.assertNotIn("Decoder.Decode", two)
            self.assertIn("Location:               bin/one", one)
            if verbosity == Verbosity.DETAILED:
                self.assertIn("Evidence:               module, package, symbol", one)
                for hidden in ("Symbols (", "Symbol names:", "Decoder.Decode", "parser.Parse"):
                    self.assertNotIn(hidden, output)
            else:
                self.assertIn("  - example.test/library/decoder.Decoder.Decode", one)
                self.assertIn("(not recorded for some findings)", one)
                self.assertIn("  - example.test/library/parser.Parse", two)
                for kind in ("module", "package", "symbol"):
                    self.assertIn(f"Evidence:               {kind}", one)

    def test_vulnerability_groups_preserve_versions_and_evidence_per_binary(
        self,
    ) -> None:
        for field, value, marker in (
            ("found_version", "v2.0.0", "Current version:        v2.0.0"),
            ("fixed_version", "v1.2.0", "Fixed version:          v1.2.0"),
            ("evidence", "package", "Finding kind:           package"),
        ):
            with self.subTest(field=field):
                first = self._binary(
                    "/bin/one", "example.test/library/decoder", cgo=False
                )
                second = self._binary(
                    "/bin/two", "example.test/library/decoder", cgo=False
                )
                findings = second.vulnerability_scan.vulnerabilities[0].findings
                findings[0] = replace(findings[0], **{field: value})
                report = AuditReport(
                    metadata=ContainerMetadata("/tmp/root"),
                    binaries=[first, second],
                    go_command="go",
                    go_tool_version="go",
                )
                output = render_by_vulnerability(report, FULL_POLICY)
                body = output.split("\nPROVENANCE\n")[0]
                changed = body.split(marker, 1)[1].split("\nMODULE:")[0]
                if field == "evidence":
                    changed = changed.split("\nFinding kind:")[0]
                self.assertIn("BINARY: two", changed)
                self.assertNotIn("BINARY: one", changed)
                module_count = 1 if field == "evidence" else 2
                self.assertEqual(body.count("\nMODULE:"), module_count)

    def test_vulnerability_module_only_evidence_does_not_invent_packages(self) -> None:
        binary = self._binary("/bin/one", "", cgo=False)
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )
        for policy in (DETAILED_POLICY, FULL_POLICY):
            with self.subTest(policy=policy):
                output = render_by_vulnerability(report, policy)
                self.assertIn("Affected packages:      0", output)
                self.assertIn("BINARY: one", output)
                self.assertIn("Current version:        v1.0.0", output)
                self.assertTrue(
                    "Package evidence:" in output or "PACKAGE: (not reported)" in output
                )

    def test_binary_details_own_repeated_vulnerabilities_under_one_package(
        self,
    ) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        original = binary.vulnerability_scan.vulnerabilities[0].findings[0]
        binary.vulnerability_scan.vulnerabilities.extend(
            [
                Vulnerability(
                    id="GO-2026-0002",
                    aliases=["CVE-2026-0002"],
                    findings=[replace(original, package="example.test/library/parser")],
                ),
                Vulnerability(
                    id="GO-2026-0003",
                    aliases=["CVE-2026-0003"],
                    findings=[original],
                ),
            ]
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )

        output = render_binaries(report, DETAILED_POLICY)

        self.assertEqual(output.count("\nPACKAGES\n"), 1)
        self.assertIn("example.test/library/decoder", output)
        self.assertIn("example.test/library/parser", output)
        self.assertIn("  - example.test/library/decoder", output)
        self.assertNotIn("Reconciliation:", output)
        for identifier in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
            self.assertEqual(output.count(identifier), 1)

    def test_compact_findings_limit_binaries_without_hiding_context(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[
                self._binary(
                    f"/bin/{index:02d}",
                    "example.test/library/decoder",
                    cgo=False,
                )
                for index in range(12)
            ],
            go_command="go",
            go_tool_version="go",
        )

        compact = render_by_vulnerability(report, EXPANDED_POLICY)
        detailed = render_by_vulnerability(report, FULL_POLICY)

        self.assertEqual(compact.count(":runtime"), 10)
        self.assertIn("Additional binaries:    2 omitted", compact)
        module_details = detailed.split("\nPROVENANCE\n")[0].split(
            "\nMODULE:", 1
        )[1]
        self.assertEqual(module_details.count("\nBINARY:"), 12)
        self.assertNotIn("Additional binaries", detailed)

    def test_reports_reconciliation_differences_only_when_present(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        self.assertNotIn("Reconciliation", render_binaries(report, DETAILED_POLICY))

        component = ModuleReconciliation(
            "representation_difference",
            "stdlib",
            "v1.26.8",
            ModuleInventoryEntry("stdlib", "stdlib", "go1.26.8", "stdlib", "go1.26.8"),
            "identifies the same Go release using a different version representation",
        )
        report.binaries.append(self._binary("/bin/two", "net/http", cgo=False))
        for binary in report.binaries:
            binary.reconciliation.sbom_modules = [component]
            binary.vulnerability_scan.vulnerabilities[0].findings = [
                VulnerabilityFinding(
                    module="stdlib",
                    package="net/http",
                    found_version="v1.26.8",
                    reconciliation=component,
                ),
            ]
        output = render_binaries(report, DETAILED_POLICY)
        self.assertIn("Recon. differences:     1 difference", output)
        self.assertNotIn("RECONCILIATION DIFFERENCES (1)", output)
        self.assertNotIn("stdlib@v1.26.8", output)

        diagnostics = render_diagnostics(report, DETAILED_POLICY)
        self.assertIn("RECONCILIATION DIFFERENCES (1)", diagnostics)
        self.assertIn(
            "Comparison:             go version -m versus govulncheck",
            diagnostics,
        )
        self.assertIn(
            "Effect:                 informational; does not affect coverage or "
            "exit status",
            diagnostics,
        )
        self.assertIn("stdlib@v1.26.8", diagnostics)
        self.assertIn(f"{'govulncheck component:':<24}stdlib@v1.26.8", diagnostics)
        self.assertIn(
            "Source:                 govulncheck SBOM, vulnerability finding", diagnostics
        )
        self.assertIn(
            "Description:            identifies the same Go release",
            diagnostics,
        )
        self.assertIn("AFFECTED BINARIES (2)", diagnostics)
        self.assertIn("Location:               bin/one", diagnostics)
        self.assertIn("Location:               bin/two", diagnostics)
        self.assertNotIn("OTHER LOCATIONS", diagnostics)
        self.assertNotIn("\nBINARY\n", diagnostics)
        self.assertNotIn("Stage:                  reconciliation-difference", diagnostics)

    def test_diagnostics_retains_every_saved_difference_and_binary_association(self):
        current = self._binary("/bin/app", "example/lib", cgo=False)
        current.runtime_disposition, current.sha256 = "runtime", "a" * 64
        historical = self._binary("/bin/app", "example/lib", cgo=False)
        historical.runtime_disposition, historical.sha256 = "replaced", "b" * 64
        historical.layer_history = [BinaryLayerObservation(1, "found", ("/bin/app",))]
        historical.reconciliation.sbom_modules = [
            ModuleReconciliation(
                "mismatch",
                f"example/module{index:02}",
                "v2.0.0",
                ModuleInventoryEntry(
                    "dependency",
                    f"example/module{index:02}",
                    "v1.0.0",
                    f"example/module{index:02}",
                    "v1.0.0",
                ),
                "versions differ: detail; retained verbatim",
            )
            for index in range(12)
        ]
        report = AuditReport(
            ContainerMetadata("/rootfs"), "go", "test", binaries=[current, historical]
        )
        original = report.to_dict()
        compact = render_diagnostics(report)
        self.assertIn("RECONCILIATION DIFFERENCES (12)", compact)
        self.assertIn("Additional differences: 2 omitted", compact)
        expanded = render_diagnostics(report, EXPANDED_POLICY)
        self.assertIn("layer-001", expanded)
        wide = render_diagnostics(report, FULL_POLICY)
        self.assertEqual(wide.count("\nDIFFERENCE:"), 12)
        self.assertIn("example/module11@v2.0.0", wide)
        self.assertIn("versions differ: detail; retained verbatim", wide)
        self.assertIn("SHA-256:                " + "b" * 64, wide)
        self.assertNotIn("SHA-256:                " + "a" * 64, wide)
        self.assertNotIn(" omitted;", wide)
        self.assertEqual(report.to_dict(), original)
        self.assertEqual(report.issues, [])

    def test_diagnostics_groups_operational_issues_and_ends_with_provenance(
        self,
    ) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.issues.extend(
            (
                ScanIssue("/bin/one", "govulncheck", "timed out"),
                ScanIssue("/restricted", "open", "permission denied"),
            )
        )

        output = render_diagnostics(report, FORENSIC_POLICY)

        self.assertIn("Status:                 ATTENTION REQUIRED", output)
        self.assertIn("Operational issues:     2", output)
        self.assertIn("OPERATIONAL ISSUES (2)", output)
        self.assertIn("STAGE: GOVULNCHECK\n", output)
        self.assertIn("STAGE: OPEN\n", output)
        self.assertIn("rootfs  restricted", output)
        self.assertNotIn("RECONCILIATION DIFFERENCES", output)
        self.assertLess(
            output.index("INVENTORY: root"), output.index("OPERATIONAL ISSUES")
        )
        self.assertLess(output.index("OPERATIONAL ISSUES"), output.index("PROVENANCE"))
        self.assertNotIn("\nSUBJECT", output)

    def test_diagnostics_groups_locations_without_confusing_historical_binaries(
        self,
    ) -> None:
        current = self._binary("/bin/app", "example.test/lib", cgo=False)
        current.runtime_disposition = "runtime"
        current.sha256 = "a" * 64
        current.layer_history = [BinaryLayerObservation(2, "found", ("/bin/app",))]
        historical = self._binary("/bin/app", "example.test/lib", cgo=False)
        historical.runtime_disposition = "replaced"
        historical.sha256 = "b" * 64
        historical.layer_history = [BinaryLayerObservation(1, "found", ("/bin/app",))]
        report = AuditReport(
            metadata=ContainerMetadata(
                "/tmp/root", image=ImageIdentity(name="demo", component="app")
            ),
            binaries=[current, historical],
            go_command="go",
            go_tool_version="go",
            issues=[
                ScanIssue(path, "open", "permission denied")
                for path in (
                    "/bin/app",
                    "layer-002:/bin/app",
                    "layer-001:/bin/app",
                    "/missing",
                )
            ],
        )
        original = report.to_dict()
        summary = render_diagnostics(report)
        self.assertIn("INVENTORY: demo", summary)
        self.assertIn("Component:              app", summary)
        self.assertEqual(summary.count("permission denied"), 1)
        self.assertNotIn("layer-001", summary)
        expanded = render_diagnostics(report, EXPANDED_POLICY)
        self.assertIn("LOCATIONS (4)", expanded)
        self.assertIn("layer-001", expanded)
        self.assertNotIn("BINARY:", expanded)
        for policy in (DETAILED_POLICY, FORENSIC_POLICY):
            output = render_diagnostics(report, policy)
            self.assertEqual(output.count("\nBINARY: app\n"), 2)
            self.assertIn("AFFECTED BINARIES (2)", output)
            self.assertIn("OTHER LOCATIONS (1)", output)
            self.assertIn("rootfs  missing", output)
            self.assertEqual(output.count("SHA-256:                aaaaaaaaaaaa..."), 1)
            self.assertEqual(output.count("SHA-256:                bbbbbbbbbbbb..."), 1)
            self.assertEqual("\nPROVENANCE\n" in output, policy == FORENSIC_POLICY)
            self.assertEqual("Layer observations" in output, policy == FORENSIC_POLICY)
            self.assertEqual("Hardlinks:" in output, policy == FORENSIC_POLICY)
        limited = render_diagnostics(
            report, RenderPolicy(Verbosity.DETAILED, entry_limit=1)
        )
        self.assertIn("Additional binaries:    1 omitted", limited)
        wide = render_diagnostics(
            report, RenderPolicy(Verbosity.FORENSIC, wide=True, entry_limit=1)
        )
        self.assertNotIn(" omitted;", wide)
        self.assertIn("Diagnostic paths:       /bin/app, layer-002:/bin/app", wide)
        self.assertIn("Diagnostic paths:       layer-001:/bin/app", wide)
        self.assertNotIn("BINARY:", wide.split("\nPROVENANCE\n")[1])
        self.assertEqual(report.to_dict(), original)

    def test_diagnostics_flags_incomplete_coverage_without_recorded_issues(
        self,
    ) -> None:
        binary = self._binary("/bin/app", "example.test/lib", cgo=False)
        binary.vulnerability_scan = VulnerabilityScan(status="failed")
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )
        output = render_diagnostics(report)
        self.assertIn("RESULT: INCOMPLETE (0 of 1 binaries)", output)
        self.assertIn("Status:                 ATTENTION REQUIRED", output)
        self.assertIn("COVERAGE WARNING", output)

    def test_diagnostic_limitations_keep_their_original_historical_binary(self) -> None:
        current = self._binary("/bin/app", "example.test/lib", cgo=False)
        current.runtime_disposition = "runtime"
        current.sha256 = "a" * 64
        historical = self._binary("/bin/app", "example.test/lib", cgo=False)
        historical.runtime_disposition = "replaced"
        historical.sha256 = "b" * 64
        historical.layer_history = [BinaryLayerObservation(1, "found", ("/bin/app",))]
        historical.reconciliation = BinaryReconciliation(
            status="limited", go_version_status="unverifiable"
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[current, historical],
            go_command="go",
            go_tool_version="go",
        )
        output = render_diagnostics(report, DETAILED_POLICY)
        self.assertIn("AFFECTED BINARIES (1)", output)
        self.assertIn("bbbbbbbbbbbb...", output)
        self.assertNotIn("aaaaaaaaaaaa...", output)
        expanded = render_diagnostics(report, EXPANDED_POLICY)
        self.assertIn("layer-001", expanded)
        self.assertNotIn("rootfs", expanded)

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
                status="limited",
                go_version_status="exact",
                sbom_modules=[component],
            )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.extend(binaries)

        diagnostics = render_diagnostics(report, DETAILED_POLICY)
        overview = render_overview(report)

        self.assertIn("Status:                 INFORMATIONAL LIMITATIONS", diagnostics)
        self.assertIn("Reconciliation:         LIMITED (2 of 2 binaries)", diagnostics)
        self.assertIn("Unverifiable:           1 component", diagnostics)
        self.assertIn("Limitation causes:      DEVELOPMENT_VERSION=1", diagnostics)
        self.assertIn("Reason:                 DEVELOPMENT_VERSION", diagnostics)
        self.assertIn("RECONCILIATION LIMITATIONS (1)", diagnostics)
        self.assertIn(
            "Declared component:     github.com/operator-framework/api@v0.23.0",
            diagnostics,
        )
        self.assertIn("Effective component:    ./staging/api@(devel)", diagnostics)
        self.assertIn("AFFECTED BINARIES (2)", diagnostics)
        self.assertIn("Location:               bin/one", diagnostics)
        self.assertIn("Location:               bin/two", diagnostics)
        self.assertNotIn("COVERAGE WARNING", diagnostics)
        self.assertNotIn("Reconciliation:", overview)
        self.assertNotIn("Unverifiable:", overview)
        self.assertNotIn("Recon. differences:", overview)
        self.assertNotIn("CGO enabled:", overview)

        binary_inventory = render_binaries(report)
        self.assertNotIn("Reconciliation:", binary_inventory)
        self.assertNotIn("Unverifiable:", binary_inventory)
        self.assertIn(
            "Reconciliation:         LIMITED (2 of 2 binaries)",
            render_module_reconciliation(report, DETAILED_POLICY),
        )

        diagnostics_summary = render_diagnostics(report)
        self.assertIn("RECONCILIATION LIMITATIONS", diagnostics_summary)
        self.assertIn("  - DEVELOPMENT_VERSION:", diagnostics_summary)
        self.assertNotIn("Declared component:", diagnostics_summary)
        self.assertNotIn("BINARY:", diagnostics_summary)
        self.assertNotIn("SUBJECT", diagnostics_summary)
        self.assertNotIn("PROVENANCE", diagnostics_summary)

    def test_reconciliation_limitations_split_reason_codes(self) -> None:
        binary = self._binary("/bin/app", "example.test/package", cgo=False)
        binary.vulnerability_scan.sbom = {"go_version": "", "modules": [], "roots": []}

        def inventory(path: str, version: str) -> ModuleInventoryEntry:
            return ModuleInventoryEntry(
                source="dependency",
                declared_path=path,
                declared_version=version,
                effective_path=path,
                effective_version=version,
            )

        binary.reconciliation = BinaryReconciliation(
            status="limited",
            go_version_status="unverifiable",
            sbom_modules=[
                ModuleReconciliation(
                    "unverifiable",
                    "",
                    "",
                    detail="govulncheck did not report a module path",
                ),
                ModuleReconciliation(
                    "unverifiable",
                    "example.test/declared-missing",
                    "v1.0.0",
                    inventory_entry=inventory("example.test/declared-missing", ""),
                ),
                ModuleReconciliation(
                    "unverifiable",
                    "example.test/observed-missing",
                    "",
                    inventory_entry=inventory("example.test/observed-missing", "v1.0.0"),
                ),
                ModuleReconciliation(
                    "unverifiable",
                    "example.test/development",
                    "(devel)",
                    inventory_entry=inventory("example.test/development", "(devel)"),
                ),
            ],
        )
        missing_sbom = self._binary("/bin/no-sbom", "example.test/package", cgo=False)
        missing_sbom.vulnerability_scan.sbom = None
        missing_sbom.reconciliation = BinaryReconciliation(status="limited")
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary, missing_sbom],
            go_command="go",
            go_tool_version="go",
        )

        for detail in (
            "",
            "No inventory returned",
            "govulncheck did not report a module path",
        ):
            with self.subTest(detail=detail):
                missing_sbom.reconciliation.sbom_modules = [
                    ModuleReconciliation("unverifiable", "", "", detail=detail)
                ]
                diagnostics = reconciliation_diagnostics(report)[0]
                self.assertEqual(
                    {item.reason for item in diagnostics},
                    {
                        "NO_SBOM",
                        "MODULE_PATH_MISSING",
                        "DECLARED_VERSION_MISSING",
                        "OBSERVED_VERSION_MISSING",
                        "DEVELOPMENT_VERSION",
                        "GO_VERSION_MISSING",
                    },
                )
                no_sbom = next(item for item in diagnostics if item.reason == "NO_SBOM")
                self.assertEqual(no_sbom.binaries, [missing_sbom])
                no_path = next(
                    item for item in diagnostics if item.reason == "MODULE_PATH_MISSING"
                )
                self.assertEqual(no_path.binaries, [binary])

    def test_reports_explicit_image_identity(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata(
                root="/tmp/root",
                image=ImageIdentity(
                    reference="registry.example.test/team/app:v1",
                    digest="sha256:" + "a" * 64,
                    platform="linux/amd64",
                    extractor="oc image extract",
                    name="openshift/example",
                    component="example-container",
                    source_git_url="https://github.com/example/project",
                    product_version="v4.20.0",
                    component_version="v1.2.3-4-gabcdef0",
                    product_component="Example",
                    cpes=("cpe:/a:redhat:openshift:4.20::el9",),
                ),
            ),
            go_command="go",
            go_tool_version="go",
        )

        output = render_binaries(report, FORENSIC_POLICY)

        self.assertIn("Image reference:        registry.example.test/team/app:v1", output)
        self.assertIn("Image digest:           sha256:", output)
        self.assertIn("Digest (short):         aaaaaaaaaaaa", output)
        self.assertIn("Image name:             openshift/example", output)
        self.assertIn("Component:              example-container", output)
        self.assertIn("CPE:                    cpe:/a:redhat:openshift:4.20::el9", output)
        self.assertIn("Product version:        v4.20.0", output)
        self.assertIn("Component version:      v1.2.3-4-gabcdef0", output)
        self.assertIn(
            "Source Git URL:         https://github.com/example/project",
            output,
        )
        self.assertIn("Product component:      Example", output)
        self.assertIn("Platform:               linux/amd64", output)
        self.assertIn("Extractor:              oc image extract", output)

        summary = render_overview(report)
        self.assertIn("SUBJECT: openshift/example", summary)
        self.assertIn("CPE:                    cpe:/a:redhat:openshift:4.20::el9", summary)
        self.assertIn("Product component:      Example", summary)
        self.assertNotIn("Digest:                 sha256:", summary)
        self.assertNotIn("Source Git URL:", summary)
        self.assertNotIn("Type:                   container image", summary)
        self.assertNotIn("Root:                   /tmp/root", summary)
        self.assertNotIn("Image digest:           sha256:", summary)
        self.assertNotIn("Platform:               linux/amd64", summary)
        self.assertNotIn("Extractor:              oc image extract", summary)

        expanded = render_overview(report, EXPANDED_POLICY)
        self.assertIn("Digest:                 sha256:", expanded)
        self.assertIn(
            "Source Git URL:         https://github.com/example/project", expanded
        )

    def test_reports_audit_toolchain_and_database_provenance(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
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

        output = render_binaries(report, FORENSIC_POLICY)

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

    def test_binary_report_lists_declared_dependencies_and_preserves_suffixes(
        self,
    ) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        binary.runtime_disposition = "runtime"
        binary.sha256 = "a" * 64
        long_path = "example.test/" + "very-long-segment/" * 8 + "critical/end"
        binary.dependencies.append(
            Module(
                path=long_path,
                version="v1.2.3",
                checksum="h1:declared",
                replace=Module(
                    path="replacement.example.test/team/critical/end",
                    version="v1.2.4",
                    checksum="h1:replacement",
                ),
            )
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(binary)

        output = render_module_reconciliation(report, FORENSIC_POLICY)

        self.assertIn(f"INVENTORY\n{'-' * 100}\n", output)
        self.assertEqual(output.count(f"BINARY\n{'-' * 100}\n"), 1)
        self.assertIn("Runtime disposition:    RUNTIME", output)
        self.assertIn("SHA-256:                aaaaaaaaaaaa...", output)
        self.assertNotIn("a" * 64, output)
        self.assertIn("Declared dependencies:  1", output)
        self.assertIn(
            "DEPENDENCY INVENTORY\n" + "-" * len("DEPENDENCY INVENTORY"),
            output,
        )
        self.assertIn(f"{long_path}@v1.2.3", output)
        self.assertIn("(h1:declared) ->", output)
        self.assertIn("replacement.example.test/team/critical/end@v1.2.4", output)
        self.assertIn("(h1:replacement)", output)
        self.assertIn(long_path, output)

    def test_binary_report_reconciles_dependencies_and_vulnerable_packages(
        self,
    ) -> None:
        binary = self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        matched_entry = ModuleInventoryEntry(
            source="dependency",
            declared_path="example.test/library",
            declared_version="v1.0.0",
            effective_path="example.test/library",
            effective_version="v1.0.0",
        )
        missing_entry = ModuleInventoryEntry(
            source="dependency",
            declared_path="example.test/missing",
            declared_version="v2.0.0",
            effective_path="example.test/missing",
            effective_version="v2.0.0",
        )
        matched = ModuleReconciliation(
            status="exact",
            govulncheck_path="example.test/library",
            govulncheck_version="v1.0.0",
            inventory_entry=matched_entry,
            detail="matches the effective go version -m module and version",
        )
        missing = ModuleReconciliation(
            status="mismatch",
            govulncheck_path="",
            govulncheck_version="",
            inventory_entry=missing_entry,
            detail=("effective go version -m module is absent from the govulncheck SBOM"),
        )
        unmatched = ModuleReconciliation(
            status="mismatch",
            govulncheck_path="example.test/undeclared",
            govulncheck_version="v3.0.0",
            detail="module is absent from the effective go version -m inventory",
        )
        binary.dependencies = [
            Module(
                path=matched_entry.declared_path, version=matched_entry.declared_version
            ),
            Module(
                path=missing_entry.declared_path, version=missing_entry.declared_version
            ),
        ]
        binary.reconciliation = BinaryReconciliation(
            status="mismatch",
            effective_module_inventory=[matched_entry, missing_entry],
            sbom_modules=[matched, missing, unmatched],
        )
        binary.vulnerability_scan.vulnerabilities[0].findings = [
            VulnerabilityFinding(
                module="example.test/library",
                found_version="v1.0.0",
                fixed_version="v1.1.0",
                package="example.test/library/decoder",
                evidence="symbol",
                reconciliation=matched,
            )
        ]
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(binary)

        output = render_module_reconciliation(report, DETAILED_POLICY)

        self.assertIn("RECONCILIATION", output)
        self.assertIn("Declared modules:       2", output)
        self.assertIn("Matched modules:        1", output)
        self.assertIn("Missing from SBOM:      1", output)
        self.assertIn("Unmatched observed:     1", output)
        self.assertIn("Status:                 MISSING FROM SBOM", output)
        self.assertIn("- example.test/undeclared@v3.0.0 [MISMATCH]", output)
        self.assertIn("Affected vulnerabilities: CVE-2026-0001", output)
        self.assertEqual(output.count("CVE-2026-0001"), 1)
        self.assertNotIn("matches the effective go version -m", output)

    def test_forensic_reconciliation_lists_normal_modules_compactly(self) -> None:
        binary = self._binary("/bin/one", "unused", cgo=False)
        binary.vulnerability_scan.vulnerabilities = []
        entries = [
            ModuleInventoryEntry(
                source="dependency",
                declared_path=f"example.test/dependency{index:02d}",
                declared_version="v1.0.0",
                effective_path=f"example.test/dependency{index:02d}",
                effective_version="v1.0.0",
            )
            for index in range(12)
        ]
        binary.dependencies = [
            Module(entry.declared_path, entry.declared_version) for entry in entries
        ]
        binary.reconciliation = BinaryReconciliation(
            status="matched",
            effective_module_inventory=entries,
            sbom_modules=[
                ModuleReconciliation(
                    status="exact",
                    govulncheck_path=entry.effective_path,
                    govulncheck_version=entry.effective_version,
                    inventory_entry=entry,
                    detail="matches the effective go version -m module and version",
                )
                for entry in entries
            ],
        )
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            binaries=[binary],
            go_command="go",
            go_tool_version="go",
        )

        detailed = render_module_reconciliation(report, DETAILED_POLICY)
        forensic = render_module_reconciliation(report, FORENSIC_POLICY)
        wide = render_module_reconciliation(report, FULL_POLICY)

        self.assertIn("No affected or anomalous reconciliation records.", detailed)
        self.assertNotIn("example.test/dependency00", detailed)
        self.assertIn("MATCHED MODULES (12)", forensic)
        self.assertIn("dependency: example.test/dependency09@v1.0.0", forensic)
        self.assertNotIn("example.test/dependency10", forensic)
        self.assertIn("Additional matched modules: 2 omitted", forensic)
        self.assertNotIn("matches the effective go version -m", forensic)
        self.assertIn("example.test/dependency11", wide)

    def test_json_view_exports_the_canonical_audit(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go",
        )
        report.binaries.append(
            self._binary("/bin/one", "example.test/library/decoder", cgo=False)
        )

        self.assertEqual(json.loads(render_json(report)), report.to_dict())

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
            build_settings=[BuildSetting(key="CGO_ENABLED", value="1" if cgo else "0")],
            vulnerability_scan=scan,
        )


if __name__ == "__main__":
    unittest.main()
