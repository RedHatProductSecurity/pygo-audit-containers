"""Visually structured plain-text reports for analysts."""

from __future__ import annotations

from collections import Counter
from operator import attrgetter
from pathlib import PurePosixPath
from collections.abc import Iterable, Sequence
from pygo_audit.models import (
    AuditReport,
    BinaryLayerObservation,
    BinaryReport,
    FindingOccurrence,
    ImageIdentity,
    FindingSummary,
    DependencyReconciliationRow,
    Module,
    ModuleReconciliation,
    ReconciliationDiagnostic,
    ScanIssue,
)
from pygo_audit.report_sections import (
    runtime_disposition_label,
    append_coverage_warning,
    append_diagnostic_counts,
    finish_report,
    append_unaccounted_historical_summary,
    coverage_label,
    result_label,
    CGO_LABELS,
    append_report_context,
    append_check_context,
    append_detail_footer,
    check_status_label,
)
from pygo_audit.report_views import (
    finding_summaries,
    group_items,
    summarize_findings,
    CheckResult,
    binary_occurrence_groups,
    evaluate_checks,
    vulnerability_occurrences,
    normalize_cve,
    component_label,
    dependency_reconciliation_rows,
    dependency_row_status,
    reconciliation_diagnostics,
)
from pygo_audit.text_layout import (
    TextLayout,
    Verbosity,
    SUMMARY_POLICY,
    RenderPolicy,
    count_phrase,
)


def render_overview(report: AuditReport, policy: RenderPolicy = SUMMARY_POLICY) -> str:
    summaries = finding_summaries(report)
    vulnerabilities = {summary.identifier for summary in summaries}
    cves = {
        identifier for identifier in vulnerabilities if identifier.startswith("CVE-")
    }
    cgo_binaries = sum(binary.cgo_enabled is True for binary in report.binaries)
    lines = TextLayout.titled("PYGO-AUDIT OVERVIEW", policy=policy)
    append_overview_subject(lines, report)
    lines.section(f"RESULT: {coverage_label(report)}")
    lines.field("Status", result_label(report.result_state))
    lines.field("Vulnerabilities", str(len(vulnerabilities)))
    lines.field("Unique CVEs", str(len(cves)))
    lines.field("Go binaries", str(len(report.binaries)))
    append_unaccounted_historical_summary(lines, report)
    append_diagnostic_counts(lines, report, include_reconciliation=False)
    if cgo_binaries:
        lines.field("CGO-enabled binaries", str(cgo_binaries))
        lines.append(
            "  Native libraries are outside the scope of this Go dependency audit."
        )

    append_vulnerability_list(lines, cves)
    append_overview_binaries(lines, report)
    append_coverage_warning(lines, report)
    lines.section("NEXT REVIEW")
    lines.append("  To use the pygo-audit tool to view the report, run these commands:")
    lines.bullets(
        (
            "Use `pygo-audit report AUDIT_ROOT --view overview` for this overview.",
            "Use `pygo-audit report AUDIT_ROOT --view binary-findings` for binary evidence.",
            "Use `pygo-audit report AUDIT_ROOT --view vulnerability-findings` for CVE evidence.",
            "Use `pygo-audit report AUDIT_ROOT --view diagnostics` for coverage and operational issues.",
        ),
        indent="    ",
    )
    lines.append("  Full, unabridged reports are under reports/:")
    lines.bullets(
        (
            "binary-findings.txt groups vulnerabilities under each binary.",
            "vulnerability-findings.txt groups binary evidence by vulnerability.",
            "module-reconciliation.txt compares observed and embedded modules.",
            "diagnostics.txt records coverage and operational issues.",
        ),
        indent="    ",
    )
    return finish_report(lines, report)


def append_overview_subject(lines: TextLayout, report: AuditReport) -> None:
    identity = report.metadata.image
    headline = identity.name or report.metadata.root or "(not recorded)"
    lines.section(f"SUBJECT: {headline}")
    if not identity.is_present:
        lines.field("Root", report.metadata.root)
        return
    append_image_identity(lines, identity)


def append_image_identity(lines: TextLayout, identity: ImageIdentity) -> None:
    for label, attribute in (
        ("CPE", "cpes"),
        ("Product component", "product_component"),
        ("Product version", "product_version"),
        ("Component", "component"),
        ("Component version", "component_version"),
        ("Vendor image name", "vendor_image_name"),
        ("Image build release", "image_build_release"),
    ):
        lines.field(
            label,
            ", ".join(identity.cpes)
            if attribute == "cpes"
            else getattr(identity, attribute),
        )
    if lines.policy.shows(Verbosity.EXPANDED):
        lines.field("Digest", identity.digest)
        lines.field("Source Git URL", identity.source_git_url)


def append_vulnerability_list(
    lines: TextLayout,
    identifiers: set[str],
    *,
    label: str = "vulnerabilities",
    empty: str = "None detected.",
) -> None:
    lines.section(f"{label.upper()} ({len(identifiers)})")
    if not identifiers:
        lines.append(f"  {empty}")
        return
    lines.preview_bullets(label, sorted(identifiers))


def append_overview_binaries(lines: TextLayout, report: AuditReport) -> None:
    binaries = sorted(report.binaries, key=lambda binary: min(binary.paths))
    lines.section(f"BINARIES ({len(binaries)})")
    if not binaries:
        lines.append("  None detected.")
        return
    with lines.preview("binaries", binaries) as visible:
        rows = []
        for binary in visible:
            runtime = (
                "RUNTIME" if binary.runtime_disposition == "runtime" else "HISTORICAL"
            )
            rows.extend(
                binary_location_rows(binary.paths, runtime, binary.layer_history)
            )
        lines.columns(rows)


def binary_location_rows(
    paths: Sequence[str],
    runtime: str,
    history: Sequence[BinaryLayerObservation],
) -> list[tuple[str, str, str]]:
    """Use the same binary, layer, and rootfs-location columns in each view."""
    name = PurePosixPath(paths[0]).name
    locations = (
        [(f"layer-{event.layer_index:03d}", event.paths) for event in history]
        if history
        else [("runtime", paths)]
    )
    return [
        (
            f"{name}:{layer}",
            runtime,
            f"({', '.join(rootfs_location(path) for path in layer_paths) or '(none)'})",
        )
        for layer, layer_paths in locations
    ]


def render_binaries(
    report: AuditReport,
    policy: RenderPolicy = SUMMARY_POLICY,
) -> str:
    binaries = sorted(report.binaries, key=lambda binary: min(binary.paths))
    title = "PYGO-AUDIT BINARY FINDINGS"
    lines = TextLayout.titled(title, policy=policy)
    append_inventory_identity(lines, report)
    lines.field("Go binaries", str(len(binaries)))
    summaries = finding_summaries(report)
    lines.field("Affected packages", str(len({item.package for item in summaries})))
    lines.field("Vulnerabilities", str(len({item.identifier for item in summaries})))
    append_unaccounted_historical_summary(lines, report)
    append_diagnostic_counts(
        lines,
        report,
        include_reconciliation=policy.shows(Verbosity.DETAILED),
    )
    append_coverage_warning(lines, report)
    if not binaries:
        lines.append("")
        lines.append("  No recognized Go binaries found.")
    for binary in lines.limited("binaries", binaries):
        if policy.shows(Verbosity.EXPANDED):
            append_binary_findings(lines, binary)
        else:
            append_binary_inventory_summary(lines, binary)
    if policy.shows(Verbosity.DETAILED):
        append_report_context(lines, report)
    return finish_report(lines, report)


def append_inventory_identity(lines: TextLayout, report: AuditReport) -> None:
    subject = report.metadata.image.name or PurePosixPath(report.metadata.root).name
    lines.section(f"INVENTORY: {subject or '(not recorded)'}")
    if report.metadata.image.is_present:
        append_image_identity(lines, report.metadata.image)


def append_binary_inventory_summary(lines: TextLayout, binary: BinaryReport) -> None:
    lines.section(f"BINARY: {PurePosixPath(binary.paths[0]).name}")
    summaries = summarize_findings(binary.finding_occurrences())
    sbom = binary.vulnerability_scan.sbom
    modules = sbom["modules"] if sbom is not None else binary.dependencies
    paths = sorted(set(binary.paths))
    lines.fields(
        ("Name", PurePosixPath(paths[0]).name),
        ("Size", f"{binary.size / 1_000_000:.2f} MB"),
        ("Location", rootfs_location(paths[0])),
        ("Runtime disposition", runtime_disposition_label(binary.runtime_disposition)),
        ("CGO", CGO_LABELS[binary.cgo_enabled]),
        ("Number vulnerabilities", len({item.identifier for item in summaries})),
        ("Number affected packages", len({item.package for item in summaries})),
        ("Recorded modules", len(modules)),
        label_width=31,
    )


def append_binary_findings(
    lines: TextLayout,
    binary: BinaryReport,
) -> None:
    findings = summarize_findings(binary.finding_occurrences())
    lines.section(f"BINARY: {PurePosixPath(binary.paths[0]).name}")
    append_binary_identity(lines, binary)
    lines.field("CGO", CGO_LABELS[binary.cgo_enabled])
    lines.field("Scan status", binary.vulnerability_scan.status.upper())

    if lines.policy.shows(Verbosity.EXPANDED) and binary.vulnerability_scan.error:
        lines.field("Scan error", binary.vulnerability_scan.error, wrap=True)
    if not lines.policy.shows(Verbosity.DETAILED) and findings:
        append_binary_finding_summary(lines, findings)

    if lines.policy.shows(Verbosity.DETAILED):
        lines.section("VULNERABILITY EVIDENCE", rule_width=None)
        if findings:
            append_binary_vulnerability_evidence(lines, findings)
        else:
            lines.append("  No vulnerability findings for this binary.")


def render_module_reconciliation(
    report: AuditReport, policy: RenderPolicy = SUMMARY_POLICY
) -> str:
    """Render build metadata and module comparisons without finding duplication."""
    binaries = sorted(report.binaries, key=lambda binary: min(binary.paths))
    lines = TextLayout.titled("PYGO-AUDIT MODULE RECONCILIATION", policy=policy)
    lines.section("INVENTORY")
    lines.field("Go binaries", str(len(binaries)))
    lines.field("Coverage", coverage_label(report))
    append_diagnostic_counts(lines, report, include_reconciliation=True)
    append_coverage_warning(lines, report)
    for binary in lines.limited("binaries", binaries):
        lines.section("BINARY")
        append_binary_identity(lines, binary)
        lines.section("BUILD", rule_width=None)
        lines.field("Main package", binary.main_package or "(unknown)", wrap=True)
        lines.field("Main module", module_label(binary.main_module))
        lines.field("Compiled with", binary.go_version)
        lines.field("CGO", CGO_LABELS[binary.cgo_enabled])
        lines.field("Dependencies", str(len(binary.dependencies)))
        if policy.shows(Verbosity.DETAILED):
            append_build_settings(lines, binary)
            lines.section("RECONCILIATION", rule_width=None)
            append_dependency_reconciliation(lines, binary)
        if policy.shows(Verbosity.FORENSIC):
            lines.section("DEPENDENCY INVENTORY", rule_width=None)
            append_dependencies(lines, binary)
    return finish_report(lines, report)


def append_binary_identity(lines: TextLayout, binary: BinaryReport) -> None:
    """Render one binary's paths, aliases, digest, and layer provenance."""
    append_binary_paths(
        lines,
        binary.paths,
        binary.symlinks,
        size=binary.size,
        include_locations=lines.policy.shows(Verbosity.EXPANDED),
    )
    if lines.policy.shows(Verbosity.EXPANDED):
        lines.field(
            "Runtime disposition",
            runtime_disposition_label(binary.runtime_disposition),
        )
        lines.field("SHA-256", lines.policy.hash(binary.sha256) or "(not recorded)")
    if lines.policy.shows(Verbosity.FORENSIC) and binary.layer_history:
        append_layer_observations(lines, binary.layer_history)


def append_binary_paths(
    lines: TextLayout,
    paths: Iterable[str],
    symlinks: Iterable[str],
    *,
    size: int | None = None,
    include_locations: bool = True,
) -> None:
    """Render regular-file identity and aliases relative to rootfs/."""
    regular_paths = sorted(set(paths))
    primary_path = regular_paths[0]
    lines.field("Name", PurePosixPath(primary_path).name or primary_path)
    if size is not None:
        lines.field("Size", f"{size / 1_000_000:.2f} MB")
    if include_locations:
        lines.field("Location", rootfs_location(primary_path))
    if include_locations and lines.policy.shows(Verbosity.FORENSIC):
        lines.preview_field(
            "Hardlinks",
            [rootfs_location(path) for path in regular_paths[1:]],
        )
        lines.preview_field(
            "Symlinks",
            [rootfs_location(path) for path in sorted(set(symlinks))],
        )


def rootfs_location(path: str) -> str:
    return path.removeprefix("/") or "."


def append_binary_finding_summary(
    lines: TextLayout,
    findings: Sequence[FindingSummary],
) -> None:
    """Show the most active packages and recorded vulnerabilities."""
    package_counts: Counter[str] = Counter()
    for finding in findings:
        package_counts[finding.package] += finding.observation_count
    packages = sorted(package_counts.items(), key=lambda item: (-item[1], item[0]))
    lines.section(f"AFFECTED PACKAGES ({len(packages)})", rule_width=None)
    lines.preview_bullets(
        "packages",
        (
            f"{package} ({count_phrase(count, 'finding')})"
            for package, count in packages
        ),
    )

    identifiers = sorted({finding.identifier for finding in findings})
    lines.section(f"VULNERABILITIES ({len(identifiers)})", rule_width=None)
    lines.preview_bullets("vulnerabilities", identifiers)


def render_diagnostics(
    report: AuditReport, policy: RenderPolicy = SUMMARY_POLICY
) -> str:
    actionable = sorted(
        report.actionable_issues, key=attrgetter("stage", "path", "message")
    )
    limitations, difference_groups = reconciliation_diagnostics(report)
    lines = TextLayout.titled("PYGO-AUDIT DIAGNOSTICS", policy=policy)
    append_inventory_identity(lines, report)
    lines.field("Go binaries", len(report.binaries))
    lines.section(f"RESULT: {coverage_label(report)}", rule_char="=")
    if actionable or report.incomplete_vulnerability_scans:
        status = "ATTENTION REQUIRED"
    elif limitations and difference_groups:
        status = "INFORMATIONAL LIMITATIONS AND DIFFERENCES"
    elif limitations:
        status = "INFORMATIONAL LIMITATIONS"
    elif difference_groups:
        status = "INFORMATIONAL DIFFERENCES"
    else:
        status = "NO DIAGNOSTIC ISSUES"
    lines.field("Status", status)
    lines.fields(
        ("Operational issues", len(actionable)),
        ("Unverifiable", count_phrase(len(limitations), "component")),
        ("Recon. differences", count_phrase(len(difference_groups), "difference")),
    )
    limited_binaries = sum(
        binary.reconciliation.status == "limited" for binary in report.binaries
    )
    if limited_binaries:
        lines.field(
            "Reconciliation",
            f"LIMITED ({limited_binaries} of {len(report.binaries)} binaries)",
        )
    append_coverage_warning(lines, report)
    if actionable:
        lines.section(f"OPERATIONAL ISSUES ({len(actionable)})", rule_char="=")
        append_operational_issue_groups(lines, actionable, report)
    if limitations:
        lines.section(f"RECONCILIATION LIMITATIONS ({len(limitations)})", rule_char="=")
        causes = Counter(limitation.reason for limitation in limitations)
        lines.field(
            "Limitation causes",
            ", ".join(f"{reason}={count}" for reason, count in sorted(causes.items())),
        )
        lines.field(
            "Effect",
            "informational; does not affect vulnerability coverage or exit status",
        )
        append_reconciliation_diagnostics(lines, limitations, report)
    if difference_groups:
        lines.section(
            f"RECONCILIATION DIFFERENCES ({len(difference_groups)})", rule_char="="
        )
        lines.field("Comparison", "go version -m versus govulncheck")
        lines.field("Effect", "informational; does not affect coverage or exit status")
        append_reconciliation_diagnostics(
            lines, difference_groups, report, differences=True
        )
    return finish_report(lines, report)


def render_checks(
    report: AuditReport,
    checks: Sequence[str],
    policy: RenderPolicy = SUMMARY_POLICY,
) -> str:
    return render_check_results(report, evaluate_checks(report, checks), policy)


def render_check_results(
    report: AuditReport,
    results: Sequence[CheckResult],
    policy: RenderPolicy = SUMMARY_POLICY,
) -> str:
    title = "VULNERABILITY CHECK" if len(results) == 1 else "VULNERABILITY CHECKS"
    lines = TextLayout.titled(title, policy=policy)
    append_inventory_identity(lines, report)
    if not results:
        lines.section("RESULT")
        lines.append("  No vulnerability identifiers requested.")
    for result in lines.limited("checks", results):
        append_check(lines, report, result)
    if policy.shows(Verbosity.FORENSIC):
        append_check_context(lines, report)
    append_detail_footer(lines)
    return lines.render()


def render_by_vulnerability(
    report: AuditReport, policy: RenderPolicy = SUMMARY_POLICY
) -> str:
    lines = TextLayout.titled("PYGO-AUDIT VULNERABILITY FINDINGS", policy=policy)
    append_inventory_identity(lines, report)
    grouped = vulnerability_occurrences(report)
    occurrences = [item for values in grouped.values() for item in values]
    cves = {
        cve
        for item in occurrences
        for identifier in item.identifiers
        if (cve := normalize_cve(identifier)) is not None
    }
    lines.fields(("Vulnerabilities", len(grouped)), ("Unique CVEs", len(cves)))
    if policy.shows(Verbosity.EXPANDED):
        append_affected_counts(lines, occurrences)
        append_unaccounted_historical_summary(lines, report)
    append_coverage_warning(lines, report)
    if not policy.shows(Verbosity.EXPANDED):
        append_vulnerability_list(
            lines, cves, label="CVEs", empty="No CVE identifiers recorded."
        )
        append_detail_footer(lines)
        return lines.render()
    if not grouped:
        lines.append("")
        lines.append("  No vulnerability findings detected.")
    for identifier, findings in lines.limited("vulnerabilities", grouped.items()):
        lines.section(f"VULNERABILITY: {identifier}", rule_char="=")
        append_vulnerability_details(lines, identifier, findings)
    return finish_report(lines, report)


def append_vulnerability_details(
    lines: TextLayout,
    identifier: str,
    findings: Sequence[FindingOccurrence],
) -> None:
    """Share the evidence hierarchy between vulnerability views and checks."""
    lines.preview_field(
        "Aliases",
        sorted(
            {
                alias
                for item in findings
                for alias in item.identifiers
                if alias.upper() != identifier.upper()
            }
        ),
        wrap=True,
    )
    urls = sorted({item.advisory_url for item in findings if item.advisory_url})
    lines.preview_field(
        "Advisory URL" if len(urls) <= 1 else "Advisory URLs",
        urls,
        empty="(not reported)",
        wrap=True,
    )
    append_affected_counts(lines, findings)
    append_vulnerability_modules(lines, findings)
    if not lines.policy.shows(Verbosity.FORENSIC):
        append_affected_binaries(lines, findings, rule_width=80)


def append_affected_counts(
    lines: TextLayout, occurrences: Sequence[FindingOccurrence]
) -> None:
    lines.field("Affected binaries", len(binary_occurrence_groups(occurrences)))
    if not lines.policy.shows(Verbosity.DETAILED):
        return
    lines.fields(
        ("Affected modules", len({item.module for item in occurrences if item.module})),
        (
            "Affected packages",
            len({(item.module, item.package) for item in occurrences if item.package}),
        ),
    )


def append_affected_binaries(
    lines: TextLayout,
    occurrences: Sequence[FindingOccurrence],
    *,
    rule_width: int = 60,
) -> None:
    binary_groups = binary_occurrence_groups(occurrences)
    lines.section(f"BINARIES ({len(binary_groups)})", rule_width=rule_width)
    with lines.preview("binaries", binary_groups) as visible:
        rows: list[tuple[str, str, str, str]] = []
        for group in visible:
            if lines.policy.shows(Verbosity.DETAILED):
                append_binary_evidence(lines, group)
                continue
            binary = group[0]
            evidence = sorted({item.evidence or "(not recorded)" for item in group})
            locations = binary_location_rows(
                binary.binary_paths,
                runtime_disposition_label(binary.runtime_disposition),
                binary.layer_history,
            )
            rows.extend(
                (name, runtime, kind, location)
                for name, runtime, location in locations
                for kind in evidence
            )
        if rows:
            lines.columns(
                [("Binary:layer", "Runtime", "Evidence", "Location"), *rows],
            )


def append_binary_evidence(
    lines: TextLayout, occurrences: Sequence[FindingOccurrence]
) -> None:
    """Expand one binary's observed evidence without shortening symbol names."""
    binary = occurrences[0]
    lines.section(
        f"BINARY: {PurePosixPath(binary.binary_paths[0]).name}",
        rule_width=60,
    )
    append_binary_location(lines, binary)
    lines.preview_field("Evidence", sorted({item.evidence for item in occurrences}))
    lines.preview_field(
        "Reachability", sorted({item.reachability for item in occurrences})
    )
    if not lines.policy.shows(Verbosity.FORENSIC):
        return
    symbol_findings = [item for item in occurrences if item.evidence == "symbol"]
    symbols = sorted(
        {
            ".".join(part for part in (item.package, item.symbol) if part)
            for item in symbol_findings
            if item.symbol
        }
    )
    if symbols:
        lines.append(f"Symbols ({len(symbols)})")
        lines.preview_bullets("symbols", symbols, wrap=True)
    if any(not item.symbol for item in symbol_findings):
        lines.field(
            "Symbol names",
            "(not recorded for some findings)" if symbols else "(not recorded)",
        )


def append_vulnerability_modules(
    lines: TextLayout, occurrences: Sequence[FindingOccurrence]
) -> None:
    """Keep version and fix context attached to its exact package/binary evidence."""

    def key(item: FindingOccurrence) -> tuple[str, str, str]:
        return (
            item.module,
            item.current_version,
            item.fixed_version if lines.policy.shows(Verbosity.DETAILED) else "",
        )

    modules = group_items(occurrences, key)
    for (module, current, fixed), findings in lines.limited(
        "module/version groups", modules
    ):
        lines.section(f"MODULE: {module or '(unknown module)'}", rule_width=80)
        lines.fields(
            ("Current version", current or "(unknown)"),
            (
                "Fixed version",
                (fixed or "(not reported)")
                if lines.policy.shows(Verbosity.DETAILED)
                else None,
            ),
        )
        if len(modules) > 1 and not lines.policy.shows(Verbosity.FORENSIC):
            lines.preview_field(
                "Binaries",
                sorted(
                    {
                        rootfs_location(path)
                        for item in findings
                        for path in item.binary_paths
                    }
                ),
                wrap=True,
            )
        packages = group_items(findings, attrgetter("package"))
        if lines.policy.shows(Verbosity.FORENSIC):
            for package, package_findings in lines.limited("packages", packages):
                lines.section(
                    f"PACKAGE: {package or '(not reported)'}",
                    rule_width=60,
                )
                evidence_key = attrgetter("evidence", "reachability")
                evidence = group_items(package_findings, evidence_key)
                for (kind, reachability), matches in lines.limited(
                    "evidence", evidence
                ):
                    lines.fields(
                        ("Finding kind", kind or "(not reported)"),
                        ("Reachability", reachability or "(not reported)"),
                        ("Observations", len(matches)),
                    )
                    append_affected_binaries(lines, matches)
        else:
            package_names = [package for package, _ in packages if package]
            lines.append(f"Packages ({len(package_names)})")
            with lines.preview("packages", package_names) as names:
                lines.bullets(names)
                if any(not package for package, _ in packages):
                    lines.field(
                        "Package evidence", "Not reported for some module findings"
                    )


def append_check(
    lines: TextLayout,
    report: AuditReport,
    result: CheckResult,
) -> None:
    lines.section(result.identifier)
    lines.field("Result", check_status_label(result.status))
    lines.field("Coverage", coverage_label(report))
    if result.status == "detected":
        if lines.policy.shows(Verbosity.EXPANDED):
            append_vulnerability_details(lines, result.identifier, result.matches)
    else:
        lines.append("")
        message = (
            "  No matching finding was detected in this audit with complete scan "
            "coverage."
            if result.status == "not_detected"
            else "  No recognized Go binaries were available for evaluation."
            if result.status == "no_go_binaries"
            else "  No matching finding was detected in this audit, but scan coverage is "
            "incomplete."
        )
        lines.append(message)


def append_binary_vulnerability_evidence(
    lines: TextLayout,
    findings: Sequence[FindingSummary],
) -> None:
    """Render joined module, reconciliation, and vulnerability evidence."""
    modules = group_items(findings, attrgetter("module"))
    lines.field("Affected modules", len(modules))
    for module, module_summaries in lines.limited("modules", modules):
        lines.section("MODULE", rule_width=80)
        lines.field("Name", module, wrap=True)
        versions = sorted(
            {item.current_version or "(unknown)" for item in module_summaries}
        )
        version_label = "Current version" if len(versions) == 1 else "Current versions"
        lines.preview_field(version_label, versions, wrap=True)
        lines.field(
            "Affected packages",
            str(len({item.package for item in module_summaries})),
        )
        lines.field(
            "Vulnerabilities",
            str(len({item.identifier for item in module_summaries})),
        )
        lines.field(
            "Observations",
            str(sum(item.observation_count for item in module_summaries)),
        )
        packages = group_items(module_summaries, attrgetter("package"))
        if not lines.policy.shows(Verbosity.FORENSIC):
            lines.section("PACKAGES", rule_width=60)
            package_names = [package for package, _ in packages]
            lines.preview_bullets("packages", package_names)
            lines.section("VULNERABILITIES", rule_width=60)
            vulnerabilities = sorted(
                {
                    identifier
                    for item in module_summaries
                    for identifier in (item.identifier, *item.aliases)
                }
            )
            lines.preview_bullets("vulnerabilities", vulnerabilities)
            continue
        for package, package_summaries in lines.limited("packages", packages):
            lines.section("PACKAGE", rule_width=60)
            lines.field("Name", package, wrap=True)
            lines.field(
                "Vulnerabilities",
                str(len({item.identifier for item in package_summaries})),
            )
            lines.field(
                "Observations",
                str(sum(item.observation_count for item in package_summaries)),
            )
            for summary in lines.limited("vulnerabilities", package_summaries):
                lines.section("VULNERABILITY", rule_width=None)
                lines.field("Identifier", summary.identifier)
                if len(versions) > 1:
                    lines.field(
                        "Current version", summary.current_version or "(unknown)"
                    )
                lines.field("Fixed version", summary.fixed_version or "(not reported)")
                append_finding_evidence(lines, summary)


def append_finding_evidence(
    lines: TextLayout,
    summary: FindingSummary,
) -> None:
    """Render the evidence retained in a summarized finding."""
    lines.field("Observations", str(summary.observation_count))
    lines.preview_field("Aliases", sorted(summary.aliases))
    if summary.advisory_urls:
        label = "Advisory URL" if len(summary.advisory_urls) == 1 else "Advisory URLs"
        lines.preview_field(
            label,
            sorted(summary.advisory_urls),
            omitted_label="Additional URLs",
            wrap=True,
        )
    lines.preview_field("Finding kinds", sorted(summary.evidence))
    lines.preview_field("Reachability", sorted(summary.reachability))


def append_binary_location(lines: TextLayout, occurrence: FindingOccurrence) -> None:
    """Render binary identity once around all findings attributed to it."""
    append_binary_paths(
        lines,
        occurrence.binary_paths,
        occurrence.binary_symlinks,
    )
    lines.field(
        "SHA-256", lines.policy.hash(occurrence.binary_sha256) or "(not recorded)"
    )
    lines.field(
        "Runtime disposition",
        runtime_disposition_label(occurrence.runtime_disposition),
    )
    if lines.policy.shows(Verbosity.FORENSIC) and occurrence.layer_history:
        append_layer_observations(lines, occurrence.layer_history)


def append_layer_observations(
    lines: TextLayout,
    history: Iterable[BinaryLayerObservation],
    *,
    multiline: bool = False,
) -> None:
    """Show where a binary and its aliases were observed in supplied layers."""
    history = list(history)
    if not multiline:
        lines.append(f"Layer observations ({len(history)})")
    for event in lines.limited("layer events", history):
        if multiline:
            with lines.subsection(
                f"layer-{event.layer_index:03d} {event.status.upper()}"
            ) as layer:
                layer.list_field(
                    "Files", [rootfs_location(path) for path in event.paths]
                )
                layer.list_field(
                    "Symlinks", [rootfs_location(path) for path in event.symlinks]
                )
            continue
        paths = ", ".join(rootfs_location(path) for path in event.paths) or "(none)"
        aliases = (
            ", ".join(rootfs_location(path) for path in event.symlinks) or "(none)"
        )
        lines.append(
            f"  - layer-{event.layer_index:03d} {event.status.upper()}: "
            f"files={paths}; symlinks={aliases}"
        )


def append_build_settings(lines: TextLayout, binary: BinaryReport) -> None:
    lines.section(f"BUILD SETTINGS ({len(binary.build_settings)})", rule_width=None)
    if not binary.build_settings:
        lines.append("  None recorded in Go build information.")
        return
    for setting in lines.limited(
        "settings", sorted(binary.build_settings, key=lambda item: item.key)
    ):
        lines.field(setting.key, setting.value)


def module_label(module: Module | None) -> str:
    if module is None:
        return "(not recorded)"
    label = f"{module.path}@{module.version}" if module.version else module.path
    if module.checksum:
        label = f"{label} ({module.checksum})"
    return label or "(not recorded)"


def dependency_label(module: Module) -> str:
    label = module_label(module)
    if module.replace is not None:
        label = f"{label} -> {module_label(module.replace)}"
    return label


def append_dependencies(lines: TextLayout, binary: BinaryReport) -> None:
    dependencies = sorted(binary.dependencies, key=lambda item: item.path)
    lines.field("Declared dependencies", str(len(dependencies)))
    if not dependencies:
        lines.append("  None recorded in Go build information.")
        return
    lines.preview_bullets(
        "dependencies",
        (dependency_label(dependency) for dependency in dependencies),
        wrap=True,
    )


def append_dependency_reconciliation(lines: TextLayout, binary: BinaryReport) -> None:
    rows, unmatched_observations = dependency_reconciliation_rows(binary)
    if (
        not rows
        and not unmatched_observations
        and binary.reconciliation.status == "not_run"
    ):
        lines.append("  No dependency reconciliation data recorded.")
        return
    row_statuses = [dependency_row_status(row) for row in rows]
    normal_statuses = {"MATCHED", "MATCHED (REPLACEMENT)"}
    lines.field("Binary status", binary.reconciliation.status)
    lines.field("Declared modules", str(len(rows)))
    lines.field(
        "Matched modules",
        str(sum(status.startswith("MATCHED") for status in row_statuses)),
    )
    lines.field("Missing from SBOM", str(row_statuses.count("MISSING FROM SBOM")))
    lines.field("Version mismatches", str(row_statuses.count("VERSION MISMATCH")))
    lines.field("Unverifiable modules", str(row_statuses.count("UNVERIFIABLE")))
    lines.field("Unmatched observed", str(len(unmatched_observations)))
    pairs = sorted(
        zip(rows, row_statuses),
        key=lambda item: (
            item[1] in normal_statuses,
            item[0].entry.declared_path,
            item[0].entry.effective_path,
        ),
    )
    focused: list[tuple[DependencyReconciliationRow, str]] = []
    matched: list[tuple[DependencyReconciliationRow, str]] = []
    for pair in pairs:
        if pair[0].vulnerable_findings or pair[1] not in normal_statuses:
            focused.append(pair)
        else:
            matched.append(pair)
    if (
        not focused
        and not unmatched_observations
        and not lines.policy.shows(Verbosity.FORENSIC)
    ):
        lines.append("  No affected or anomalous reconciliation records.")
    for row, status in lines.limited("reconciliation records", focused):
        lines.section("MODULE", rule_width=None)
        lines.field("Source", row.entry.source)
        lines.field(
            "Declared",
            component_label(row.entry.declared_path, row.entry.declared_version),
        )
        lines.field(
            "Effective",
            component_label(row.entry.effective_path, row.entry.effective_version),
        )
        lines.field("Status", status)
        lines.preview_field(
            "Affected vulnerabilities",
            sorted({identifier for identifier, _ in row.vulnerable_findings}),
        )
        if status not in normal_statuses:
            append_reconciliation_difference(lines, row)
    if lines.policy.shows(Verbosity.FORENSIC) and matched:
        lines.section(f"MATCHED MODULES ({len(matched)})", rule_width=None)
        lines.preview_bullets(
            "matched modules",
            (reconciliation_module_label(row) for row, _ in matched),
            wrap=True,
        )
    if unmatched_observations:
        lines.section(
            f"UNMATCHED OBSERVED MODULES ({len(unmatched_observations)})",
            rule_width=None,
        )
        lines.preview_bullets(
            "observations",
            (unmatched_observation_label(result) for result in unmatched_observations),
            wrap=True,
        )


def append_reconciliation_difference(
    lines: TextLayout,
    row: DependencyReconciliationRow,
) -> None:
    observed = dict.fromkeys(
        component_label(result.govulncheck_path, result.govulncheck_version)
        for result in row.observations
        if result.govulncheck_path
    )
    lines.preview_field(
        "Observed in SBOM",
        observed,
        empty="(not observed)",
        omitted_label="Additional observations",
    )
    details = sorted({result.detail for result in row.observations if result.detail})
    if details:
        lines.preview_field(
            "Details",
            details,
            omitted_label="Additional details",
            wrap=True,
        )


def reconciliation_module_label(row: DependencyReconciliationRow) -> str:
    declared = component_label(row.entry.declared_path, row.entry.declared_version)
    effective = component_label(row.entry.effective_path, row.entry.effective_version)
    component = declared if declared == effective else f"{declared} -> {effective}"
    return f"{row.entry.source}: {component}"


def unmatched_observation_label(result: ModuleReconciliation) -> str:
    component = component_label(result.govulncheck_path, result.govulncheck_version)
    detail = f": {result.detail}" if result.detail else ""
    return f"{component} [{result.status.upper()}]{detail}"


def append_operational_issue_groups(
    lines: TextLayout,
    issues: Iterable[ScanIssue],
    report: AuditReport,
) -> None:
    key = attrgetter("stage", "message")
    groups = group_items(issues, key)
    for (stage, message), matches in lines.limited("issue groups", groups):
        if not lines.policy.shows(Verbosity.EXPANDED):
            lines.bullets([f"{stage.upper()}: {message}"], wrap=True)
            continue
        lines.section(f"STAGE: {stage.upper()}", rule_width=80)
        lines.field("Detail", message, wrap=True)
        append_diagnostic_locations(
            lines, report, paths={item.path for item in matches}
        )


def append_reconciliation_diagnostics(
    lines: TextLayout,
    limitations: Iterable[ReconciliationDiagnostic],
    report: AuditReport,
    *,
    differences: bool = False,
) -> None:
    for limitation in lines.limited(
        "differences" if differences else "limitations", limitations
    ):
        component = limitation.declared or limitation.observed or "(not reported)"
        if not lines.policy.shows(Verbosity.EXPANDED):
            lines.bullets(
                [f"{limitation.reason}: {component} — {limitation.description}"],
                wrap=True,
            )
            continue
        heading = "DIFFERENCE" if differences else "COMPONENT"
        lines.section(f"{heading}: {component}", rule_width=80)
        lines.field("Reason", limitation.reason)
        lines.preview_field(
            "Source",
            sorted(limitation.sources),
            empty="",
            omitted_label="Additional sources",
        )
        if limitation.kind == "go_toolchain":
            lines.field("go version -m", limitation.declared, wrap=True)
            lines.field("govulncheck", limitation.observed, wrap=True)
        else:
            if limitation.declared:
                lines.field("Declared component", limitation.declared, wrap=True)
            if limitation.effective:
                lines.field("Effective component", limitation.effective, wrap=True)
            if not limitation.effective or limitation.observed != limitation.effective:
                lines.field("govulncheck component", limitation.observed, wrap=True)
        lines.field("Description", limitation.description, wrap=True)
        append_diagnostic_locations(
            lines,
            report,
            known_binaries=limitation.binaries,
        )


def diagnostic_location(path: str) -> tuple[str, str]:
    """Keep layer-scoped diagnostic paths distinct from rootfs observations."""
    prefix, separator, location = path.partition(":")
    if separator and prefix.startswith("layer-") and prefix[6:].isdigit():
        return prefix, location
    return "rootfs", path


def diagnostic_binary_matches(path: str, binary: BinaryReport) -> bool:
    scope, location = diagnostic_location(path)
    if scope != "rootfs":
        return any(
            event.status == "found"
            and scope == f"layer-{event.layer_index:03d}"
            and location in (*event.paths, *event.symlinks)
            for event in binary.layer_history
        )
    return (
        binary.runtime_disposition == "runtime"
        or (binary.runtime_disposition == "unknown" and not binary.layer_history)
    ) and location in (*binary.paths, *binary.symlinks)


def append_diagnostic_locations(
    lines: TextLayout,
    report: AuditReport,
    *,
    paths: Iterable[str] = (),
    known_binaries: Sequence[BinaryReport] | None = None,
) -> None:
    paths = sorted(set(paths))
    known_locations = None
    if known_binaries is not None:
        known_locations = {}
        for index, binary in enumerate(known_binaries):
            historical_paths = {
                f"layer-{event.layer_index:03d}:{path}"
                for event in binary.layer_history
                if event.status == "found"
                for path in event.paths
            }
            known_locations[index] = sorted(
                historical_paths
                if historical_paths
                and binary.runtime_disposition in {"deleted", "replaced", "unaccounted"}
                else binary.paths
            )
        paths = sorted(
            {path for locations in known_locations.values() for path in locations}
        )
    unmatched = paths
    if lines.policy.shows(Verbosity.DETAILED):
        binaries = report.binaries if known_binaries is None else known_binaries
        matched: dict[int, list[str]] = {}
        unmatched = []
        if known_locations is not None:
            matched = known_locations
        else:
            for path in paths:
                candidates = [
                    index
                    for index, binary in enumerate(binaries)
                    if diagnostic_binary_matches(path, binary)
                ]
                if len(candidates) == 1:
                    matched.setdefault(candidates[0], []).append(path)
                else:
                    unmatched.append(path)
        if matched:
            lines.section(f"AFFECTED BINARIES ({len(matched)})", rule_width=60)
            for index in lines.limited(
                "binaries",
                sorted(matched, key=lambda index: min(binaries[index].paths)),
            ):
                binary = binaries[index]
                lines.section(
                    f"BINARY: {PurePosixPath(min(binary.paths)).name}",
                    rule_width=60,
                )
                append_binary_identity(lines, binary)
                lines.fields(
                    ("Scan status", binary.vulnerability_scan.status.upper()),
                    ("Reconciliation", binary.reconciliation.status.upper()),
                )
                if lines.policy.shows(Verbosity.FORENSIC):
                    lines.preview_field("Diagnostic paths", matched[index], wrap=True)
    if unmatched:
        label = (
            "OTHER LOCATIONS" if lines.policy.shows(Verbosity.DETAILED) else "LOCATIONS"
        )
        lines.section(f"{label} ({len(unmatched)})", rule_width=60)
        with lines.preview("locations", unmatched) as visible:
            rows = [
                (scope, rootfs_location(path))
                for scope, path in map(diagnostic_location, visible)
            ]
            lines.columns([("Scope", "Location"), *rows])
            if lines.policy.shows(Verbosity.DETAILED):
                lines.append(
                    "  These locations could not be linked to a unique recorded binary."
                )
