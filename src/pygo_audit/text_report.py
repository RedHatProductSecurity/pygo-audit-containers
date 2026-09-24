"""Visually structured plain-text reports for analysts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from itertools import groupby
import textwrap
from typing import Callable, Iterable, Sequence

from pygo_audit.models import (
    BinaryReport,
    ModuleReconciliation,
    ScanIssue,
    ScanReport,
)
from pygo_audit.report_views import (
    CheckResult,
    FindingRecord,
    evaluate_checks,
    finding_records,
    preferred_identifier,
)
from pygo_audit.snapshot import snapshot_digest


LINE_WIDTH = 100
LABEL_WIDTH = 24


@dataclass(slots=True)
class _ReconciliationLimitation:
    kind: str
    declared: str
    effective: str
    observed: str
    description: str
    sources: set[str] = field(default_factory=set)
    binary_paths: set[str] = field(default_factory=set)


def tail_string(value: str, max_length: int) -> str:
    """Shorten a displayed value from the left while preserving its useful end."""
    normalized = _single_line(value)
    if len(normalized) <= max_length:
        return normalized
    if max_length <= 3:
        return normalized[-max_length:]
    return "..." + normalized[-(max_length - 3) :]


def render_overview(report: ScanReport) -> str:
    records = finding_records(report.finding_occurrences())
    vulnerabilities = sorted({record.vulnerability for record in records})
    packages = sorted({record.package for record in records})
    cgo_binaries = sum(binary.cgo_enabled for binary in report.binaries)

    lines = _report_title("PYGO-AUDIT OVERVIEW")
    _start_section(lines, "RESULT")
    _field(lines, "Status", _result_label(report.result_state))
    _field(lines, "Coverage", _coverage_label(report))
    _field(lines, "Vulnerability scans", _scan_status_label(report))
    _field(lines, "Go binaries", str(len(report.binaries)))
    _field(lines, "CGO enabled", str(cgo_binaries))
    _field(lines, "Affected packages", str(len(packages)))
    _field(lines, "Vulnerabilities", str(len(vulnerabilities)))
    _append_diagnostic_counts(lines, report)

    _append_coverage_warning(lines, report)

    _start_section(lines, f"VULNERABILITIES ({len(vulnerabilities)})")
    if vulnerabilities:
        _bullets(lines, vulnerabilities)
    else:
        lines.append("  None detected.")

    _start_section(lines, f"AFFECTED PACKAGES ({len(packages)})")
    if packages:
        _bullets(lines, packages)
    else:
        lines.append("  None detected.")

    if cgo_binaries:
        _start_section(lines, "NATIVE CODE COVERAGE")
        lines.append(
            "  CGO is enabled in one or more binaries. Native libraries are outside"
        )
        lines.append("  the scope of this Go dependency audit.")
    _append_report_context(lines, report)
    return "\n".join(lines).rstrip()


def render_findings(report: ScanReport) -> str:
    records = finding_records(report.finding_occurrences())
    vulnerabilities = {record.vulnerability for record in records}
    packages = {record.package for record in records}

    lines = _report_title("PYGO-AUDIT FINDINGS")
    _start_section(lines, "RESULT")
    _field(lines, "Status", _result_label(report.result_state))
    _field(lines, "Coverage", _coverage_label(report))
    _field(lines, "Vulnerability scans", _scan_status_label(report))
    _field(lines, "Affected packages", str(len(packages)))
    _field(lines, "Vulnerabilities", str(len(vulnerabilities)))
    _field(lines, "Finding records", str(len(records)))
    _append_diagnostic_counts(lines, report)

    _append_coverage_warning(lines, report)

    if records:
        _append_package_groups(lines, records)
    else:
        _start_section(lines, "FINDINGS")
        lines.append("  No vulnerability findings detected.")
    _append_report_context(lines, report)
    return "\n".join(lines).rstrip()


def render_binaries(report: ScanReport) -> str:
    binaries = sorted(report.binaries, key=lambda binary: min(binary.paths))
    lines = _report_title("PYGO-AUDIT BINARIES")
    _start_section(lines, "INVENTORY")
    _field(lines, "Go binaries", str(len(binaries)))
    _field(lines, "CGO enabled", str(sum(binary.cgo_enabled for binary in binaries)))
    _field(lines, "Coverage", _coverage_label(report))
    _append_diagnostic_counts(lines, report)

    _append_coverage_warning(lines, report)

    if not binaries:
        lines.append("")
        lines.append("  No recognized Go binaries found.")

    for binary in binaries:
        records = finding_records(binary.finding_occurrences())
        vulnerabilities = {record.vulnerability for record in records}
        packages = {record.package for record in records}
        primary_path = min(binary.paths)

        _start_section(lines, "BINARY")
        _field(lines, "Path", primary_path)
        if binary.sha256:
            _field(lines, "SHA-256 suffix", binary.sha256[-16:])
        _field(lines, "Main package", binary.main_package or "(unknown)")
        _field(lines, "Compiled with", binary.go_version)
        _field(lines, "CGO", "ENABLED" if binary.cgo_enabled else "disabled")
        _field(lines, "Scan status", binary.vulnerability_scan.status.upper())
        _field(lines, "Dependencies", str(len(binary.dependencies)))
        _field(lines, "Affected packages", str(len(packages)))
        _field(lines, "Vulnerabilities", str(len(vulnerabilities)))

        hardlinks = sorted(path for path in binary.paths if path != primary_path)
        if hardlinks:
            lines.append("")
            lines.append(f"Hardlinks ({len(hardlinks)})")
            _bullets(lines, hardlinks)
        if binary.vulnerability_scan.error:
            _field(lines, "Scan error", binary.vulnerability_scan.error)

        _append_dependencies(lines, binary)

        if records:
            _append_package_groups(lines, records)
        else:
            lines.append("")
            lines.append("  No vulnerability findings for this binary.")

    _append_report_context(lines, report)
    return "\n".join(lines).rstrip()


def render_diagnostics(report: ScanReport) -> str:
    actionable, informational = _diagnostic_issues(report)
    reconciliation_groups = _reconciliation_groups(informational)
    reconciliation_limitations = _reconciliation_limitations(report)
    lines = _report_title("PYGO-AUDIT DIAGNOSTICS")
    _start_section(lines, "DIAGNOSTIC SUMMARY")
    if actionable:
        status = "ATTENTION REQUIRED"
    elif reconciliation_limitations and reconciliation_groups:
        status = "INFORMATIONAL LIMITATIONS AND DIFFERENCES"
    elif reconciliation_limitations:
        status = "INFORMATIONAL LIMITATIONS"
    elif informational:
        status = "INFORMATIONAL DIFFERENCES"
    else:
        status = "NO DIAGNOSTIC ISSUES"
    _field(lines, "Status", status, shorten=False)
    _field(lines, "Coverage", _coverage_label(report), shorten=False)
    _append_diagnostic_counts(lines, report)

    _append_coverage_warning(lines, report)
    if actionable:
        _start_section(lines, f"OPERATIONAL ISSUES ({len(actionable)})")
        _append_operational_issue_groups(lines, actionable)
    if reconciliation_limitations:
        _start_section(
            lines,
            f"RECONCILIATION LIMITATIONS ({len(reconciliation_limitations)})",
        )
        _field(
            lines,
            "Effect",
            "informational; does not affect vulnerability coverage or exit status",
            shorten=False,
        )
        _append_reconciliation_limitations(lines, reconciliation_limitations)
    if reconciliation_groups:
        _start_section(
            lines,
            f"RECONCILIATION DIFFERENCES ({len(reconciliation_groups)})",
        )
        _field(lines, "Comparison", "go version -m versus govulncheck", shorten=False)
        _field(
            lines,
            "Effect",
            "informational; does not affect coverage or exit status",
            shorten=False,
        )
        _append_reconciliation_groups(lines, reconciliation_groups)

    _append_report_context(lines, report)
    return "\n".join(lines).rstrip()


def render_grouped(report: ScanReport, group_by: str) -> str:
    if group_by in {"container", "package"}:
        return render_findings(report)
    if group_by == "binary":
        return render_binaries(report)
    if group_by != "vulnerability":
        raise ValueError(f"unsupported finding group: {group_by}")
    return _render_by_vulnerability(report)


def render_checks(report: ScanReport, checks: Sequence[str]) -> str:
    results = evaluate_checks(report, checks)
    title = "VULNERABILITY CHECK" if len(results) == 1 else "VULNERABILITY CHECKS"
    lines = [title, "=" * len(title)]
    if not results:
        _start_section(lines, "RESULT")
        lines.append("  No vulnerability identifiers requested.")
    for result in results:
        _append_check(lines, report, result)
    _append_check_context(lines, report)
    return "\n".join(lines).rstrip()


def render_check_result(report: ScanReport, result: CheckResult) -> str:
    title = "VULNERABILITY CHECK"
    lines = [title, "=" * len(title)]
    _append_check(lines, report, result)
    _append_check_context(lines, report)
    return "\n".join(lines).rstrip()


def _render_by_vulnerability(report: ScanReport) -> str:
    records = finding_records(report.finding_occurrences())
    lines = _report_title("PYGO-AUDIT FINDINGS BY VULNERABILITY")
    _start_section(lines, "RESULT")
    _field(lines, "Status", _result_label(report.result_state))
    _field(lines, "Coverage", _coverage_label(report))
    _field(lines, "Vulnerability scans", _scan_status_label(report))
    _append_diagnostic_counts(lines, report)

    _append_coverage_warning(lines, report)

    grouped = [
        (identifier, list(values))
        for identifier, values in groupby(
            sorted(records, key=lambda record: record.vulnerability),
            key=lambda record: record.vulnerability,
        )
    ]
    if not grouped:
        lines.append("")
        lines.append("  No vulnerability findings detected.")
    for identifier, values in grouped:
        _start_section(lines, "VULNERABILITY")
        _field(lines, "Identifier", identifier, shorten=False)
        _field(lines, "Affected packages", str(len({item.package for item in values})))
        _field(
            lines,
            "Affected binaries",
            str(len({path for item in values for path in item.binary_paths})),
        )
        for record in values:
            lines.append("")
            _field(lines, "Package", record.package)
            _field(lines, "Module", record.module)
            _field(lines, "Current version", record.current_version or "(unknown)")
            _field(lines, "Evidence", ", ".join(record.evidence))
            lines.append("  Binaries")
            _bullets(lines, record.binary_paths, indent="    ")
    _append_report_context(lines, report)
    return "\n".join(lines).rstrip()


def _append_check(
    lines: list[str],
    report: ScanReport,
    result: CheckResult,
) -> None:
    if lines and lines[-1]:
        lines.append("")
    lines.extend((result.identifier, "-" * LINE_WIDTH))
    _field(lines, "Result", _check_status_label(result.status), shorten=False)
    _field(lines, "Coverage", _coverage_label(report), shorten=False)

    records = finding_records(result.matches)
    if result.status == "detected":
        _field(lines, "Affected packages", str(len({item.package for item in records})))
        _field(
            lines,
            "Affected binaries",
            str(len({path for item in records for path in item.binary_paths})),
        )
        _append_check_packages(lines, records)
    elif result.status == "not_detected":
        lines.append("")
        lines.append(
            "  No matching finding was detected in this snapshot with complete scan coverage."
        )
    elif result.status == "no_go_binaries":
        lines.append("")
        lines.append("  No recognized Go binaries were available for evaluation.")
    else:
        lines.append("")
        lines.append(
            "  No matching finding was detected in this snapshot, but scan coverage is incomplete."
        )


def _append_check_packages(
    lines: list[str],
    records: Iterable[FindingRecord],
) -> None:
    packages = [
        (package, list(values))
        for package, values in groupby(
            sorted(
                records,
                key=lambda record: (
                    record.package,
                    record.module,
                    record.current_version,
                ),
            ),
            key=lambda record: record.package,
        )
    ]
    for package, package_records in packages:
        _start_section(lines, "AFFECTED PACKAGE", full_width=False)
        _field(lines, "Name", package)
        components = [
            (key, list(values))
            for key, values in groupby(
                package_records,
                key=lambda record: (record.module, record.current_version),
            )
        ]
        for (module, version), component_records in components:
            if len(components) > 1:
                lines.append("")
                lines.append("Component")
            _field(lines, "Module", module)
            _field(lines, "Current version", version or "(unknown)")
            evidence = sorted(
                {
                    value
                    for record in component_records
                    for value in record.evidence
                }
            )
            binary_paths = sorted(
                {
                    path
                    for record in component_records
                    for path in record.binary_paths
                }
            )
            _field(lines, "Evidence", ", ".join(evidence))
            lines.append("")
            lines.append(f"Affected binaries ({len(binary_paths)})")
            _bullets(lines, binary_paths)


def _append_check_context(lines: list[str], report: ScanReport) -> None:
    _start_section(lines, "SCAN CONTEXT", full_width=True)
    identity = report.image_identity
    if identity.reference:
        _field(lines, "Subject", identity.reference)
    else:
        _field(lines, "Subject", report.root)
    if identity.digest:
        _field(lines, "Image digest", identity.digest, shorten=False)
    if identity.platform:
        _field(lines, "Platform", identity.platform, shorten=False)
    _field(lines, "Snapshot SHA-256", snapshot_digest(report), shorten=False)
    if report.scan_completed_at:
        _field(lines, "Scan completed", report.scan_completed_at, shorten=False)
    producer = " ".join(
        value for value in (report.producer_name, report.producer_version) if value
    )
    if producer:
        _field(lines, "Scanner", producer)
    if report.go_tool_version:
        _field(lines, "Go toolchain", report.go_tool_version)
    govulncheck_version = _compact_govulncheck_version(report)
    if govulncheck_version:
        _field(lines, "govulncheck", govulncheck_version)
    databases = report.vulnerability_databases()
    for index, database in enumerate(databases, start=1):
        suffix = f" {index}" if len(databases) > 1 else ""
        _field(lines, f"Database{suffix}", database["url"])
        if database["last_modified"]:
            _field(
                lines,
                f"Database updated{suffix}",
                database["last_modified"],
                shorten=False,
            )


def _compact_govulncheck_version(report: ScanReport) -> str:
    lines = [
        line.strip()
        for line in report.govulncheck_tool_version.splitlines()
        if line.strip()
    ]
    for line in lines:
        label, separator, value = line.partition(":")
        if separator and label.lower() == "scanner":
            return value.strip()
    return lines[0] if lines else ""


def _append_package_groups(
    lines: list[str],
    records: Iterable[FindingRecord],
) -> None:
    records_by_package = [
        (package, list(values))
        for package, values in groupby(
            sorted(
                records,
                key=lambda record: (
                    record.package,
                    record.module,
                    record.current_version,
                    record.vulnerability,
                ),
            ),
            key=lambda record: record.package,
        )
    ]
    for package, package_records in records_by_package:
        _start_section(lines, "PACKAGE", full_width=False)
        _field(lines, "Name", package)

        components = [
            (key, list(values))
            for key, values in groupby(
                package_records,
                key=lambda record: (record.module, record.current_version),
            )
        ]
        for (module, version), component_records in components:
            if len(components) > 1:
                lines.append("")
                lines.append("Component")
            _field(lines, "Module", module)
            _field(lines, "Current version", version or "(unknown)")
            lines.append("")
            lines.append(f"Vulnerabilities ({len(component_records)})")
            for record in component_records:
                lines.append(f"  {record.vulnerability}")
                _nested_field(lines, "Evidence", ", ".join(record.evidence))
                lines.append(f"    Affected binaries ({len(record.binary_paths)})")
                _bullets(lines, record.binary_paths, indent="      ")


def _append_dependencies(lines: list[str], binary: BinaryReport) -> None:
    _start_section(
        lines,
        f"DECLARED DEPENDENCIES ({len(binary.dependencies)})",
        full_width=False,
    )
    if not binary.dependencies:
        lines.append("  None recorded in Go build information.")
        return

    for index, dependency in enumerate(binary.dependencies, start=1):
        lines.append("")
        _field(lines, f"Dependency {index}", dependency.path)
        _field(lines, "Declared version", dependency.version or "(unknown)")
        if dependency.sum:
            _field(lines, "Checksum", dependency.sum)
        if dependency.replace is not None:
            replacement = dependency.replace
            _field(lines, "Replacement path", replacement.path)
            _field(lines, "Replacement version", replacement.version or "(unknown)")
            if replacement.sum:
                _field(lines, "Replacement checksum", replacement.sum)


def _report_title(title: str) -> list[str]:
    return [title, "=" * min(len(title), LINE_WIDTH)]


def _append_report_context(lines: list[str], report: ScanReport) -> None:
    _start_section(lines, "SUBJECT")
    subject_type = "container image" if report.image_identity.is_present else "unpacked rootfs"
    _field(lines, "Type", subject_type)
    _field(lines, "Root", report.root)
    identity = report.image_identity
    if identity.reference:
        _field(lines, "Image reference", identity.reference)
    if identity.digest:
        _field(lines, "Image digest", identity.digest)
    if identity.platform:
        _field(lines, "Platform", identity.platform)
    if identity.extractor:
        _field(lines, "Extractor", identity.extractor)

    _start_section(lines, "PROVENANCE")
    producer = " ".join(
        value for value in (report.producer_name, report.producer_version) if value
    )
    if producer:
        _field(lines, "Scanner", producer)
    if report.go_tool_version:
        _field(lines, "Go toolchain", report.go_tool_version)
    if report.go_command:
        _field(lines, "Go command", report.go_command)
    _field(lines, "govulncheck status", report.govulncheck_status or "unknown")
    if report.govulncheck_tool_version:
        version_lines = [
            line.strip()
            for line in report.govulncheck_tool_version.splitlines()
            if line.strip()
        ]
        for index, version_line in enumerate(version_lines):
            label = "govulncheck version" if index == 0 else ""
            _field(lines, label, version_line)
    if report.govulncheck_command:
        _field(lines, "govulncheck command", report.govulncheck_command)
    if report.scan_started_at:
        _field(lines, "Scan started", report.scan_started_at, shorten=False)
    if report.scan_completed_at:
        _field(lines, "Scan completed", report.scan_completed_at, shorten=False)
    databases = report.vulnerability_databases()
    for index, database in enumerate(databases, start=1):
        suffix = f" {index}" if len(databases) > 1 else ""
        _field(lines, f"Database{suffix}", database["url"])
        if database["last_modified"]:
            _field(
                lines,
                f"Database updated{suffix}",
                database["last_modified"],
                shorten=False,
            )


def _append_coverage_warning(lines: list[str], report: ScanReport) -> None:
    if not report.incomplete_vulnerability_scans:
        return
    _start_section(lines, "COVERAGE WARNING")
    lines.append(
        "  Vulnerability scanning did not complete for "
        f"{report.incomplete_vulnerability_scans} of {len(report.binaries)} binaries."
    )
    lines.append("  Missing findings must not be interpreted as a clean result.")


def _diagnostic_issues(
    report: ScanReport,
) -> tuple[list[ScanIssue], list[ScanIssue]]:
    sort_key = lambda issue: (issue.stage, issue.path, issue.message)
    actionable = sorted(report.actionable_issues, key=sort_key)
    informational = sorted(
        (issue for issue in report.issues if issue.is_informational),
        key=sort_key,
    )
    return actionable, informational


def _append_diagnostic_counts(lines: list[str], report: ScanReport) -> None:
    actionable, informational = _diagnostic_issues(report)
    partial_binaries = sum(
        binary.reconciliation.status == "partial" for binary in report.binaries
    )
    limitations = _reconciliation_limitations(report)
    if actionable:
        _field(lines, "Operational issues", str(len(actionable)), shorten=False)
    if partial_binaries:
        _field(
            lines,
            "Reconciliation",
            f"PARTIAL ({partial_binaries} of {len(report.binaries)} binaries)",
            shorten=False,
        )
    if limitations:
        _field(
            lines,
            "Unverifiable",
            _count_phrase(len(limitations), "component"),
            shorten=False,
        )
    if informational:
        _field(
            lines,
            "Recon. differences",
            _count_phrase(
                len(_reconciliation_groups(informational)),
                "difference",
            ),
            shorten=False,
        )


def _append_operational_issue_groups(
    lines: list[str], issues: Iterable[ScanIssue]
) -> None:
    for stage, stage_issues in groupby(issues, key=lambda issue: issue.stage):
        _start_section(lines, f"STAGE: {stage.upper()}", full_width=False)
        for index, issue in enumerate(stage_issues):
            if index:
                lines.append("")
            _field(lines, "Path", issue.path)
            _wrapped_field(lines, "Detail", issue.message)


def _reconciliation_limitations(
    report: ScanReport,
) -> list[_ReconciliationLimitation]:
    grouped: dict[
        tuple[str, str, str, str, str],
        _ReconciliationLimitation,
    ] = {}

    def add_limitation(
        binary: BinaryReport,
        *,
        kind: str,
        declared: str,
        effective: str,
        observed: str,
        description: str,
        source: str,
    ) -> None:
        key = (kind, declared, effective, observed, description)
        limitation = grouped.get(key)
        if limitation is None:
            limitation = _ReconciliationLimitation(
                kind=kind,
                declared=declared,
                effective=effective,
                observed=observed,
                description=description,
            )
            grouped[key] = limitation
        limitation.sources.add(source)
        limitation.binary_paths.update(binary.paths)

    for binary in sorted(report.binaries, key=lambda item: min(item.paths)):
        reconciliation = binary.reconciliation
        if reconciliation.go_version_status == "unverifiable":
            add_limitation(
                binary,
                kind="go_toolchain",
                declared=reconciliation.go_version_m or "(not reported)",
                effective="",
                observed=reconciliation.govulncheck_go_version or "(not reported)",
                description=(
                    "The Go toolchain version could not be verified between "
                    "go version -m and govulncheck."
                ),
                source="Go toolchain",
            )

        for component in reconciliation.sbom_modules:
            if component.status == "unverifiable":
                _add_component_limitation(
                    binary,
                    component,
                    source="govulncheck SBOM",
                    add=add_limitation,
                )

        for vulnerability in binary.vulnerability_scan.vulnerabilities:
            for finding in vulnerability.findings:
                component = finding.reconciliation
                if component is not None and component.status == "unverifiable":
                    _add_component_limitation(
                        binary,
                        component,
                        source="vulnerability finding",
                        add=add_limitation,
                    )

    return sorted(
        grouped.values(),
        key=lambda item: (
            item.kind,
            item.effective,
            item.observed,
            item.declared,
            item.description,
        ),
    )


def _add_component_limitation(
    binary: BinaryReport,
    component: ModuleReconciliation,
    *,
    source: str,
    add: Callable[..., None],
) -> None:
    inventory = component.inventory_entry
    declared = ""
    effective = ""
    if inventory is not None:
        declared = _component_label(
            inventory.declared_path,
            inventory.declared_version,
        )
        effective = _component_label(
            inventory.effective_path,
            inventory.effective_version,
        )
    observed = _component_label(
        component.govulncheck_path,
        component.govulncheck_version,
    )
    add(
        binary,
        kind="component",
        declared=declared,
        effective=effective,
        observed=observed,
        description=component.detail or "The component version could not be verified.",
        source=source,
    )


def _component_label(path: str, version: str) -> str:
    if not path:
        return "(not reported)"
    return f"{path}@{version}" if version else path


def _append_reconciliation_limitations(
    lines: list[str], limitations: Iterable[_ReconciliationLimitation]
) -> None:
    for limitation in limitations:
        _start_section(lines, "COMPONENT", full_width=False)
        _field(lines, "Source", ", ".join(sorted(limitation.sources)))
        if limitation.kind == "go_toolchain":
            _wrapped_field(lines, "go version -m", limitation.declared)
            _wrapped_field(lines, "govulncheck", limitation.observed)
        else:
            if limitation.declared:
                _wrapped_field(lines, "Declared component", limitation.declared)
            if limitation.effective:
                _wrapped_field(lines, "Effective component", limitation.effective)
            if not limitation.effective or limitation.observed != limitation.effective:
                _wrapped_field(lines, "govulncheck component", limitation.observed)
        _wrapped_field(lines, "Description", limitation.description)
        binary_paths = sorted(limitation.binary_paths)
        _start_section(
            lines,
            f"AFFECTED BINARIES ({len(binary_paths)})",
            full_width=False,
        )
        _bullets(lines, binary_paths)


def _reconciliation_groups(
    issues: Iterable[ScanIssue],
) -> list[tuple[str, str, list[str]]]:
    grouped_paths: dict[tuple[str, str], set[str]] = {}
    for issue in issues:
        finding, description = _split_reconciliation_detail(issue.message)
        grouped_paths.setdefault((finding, description), set()).add(issue.path)
    return [
        (finding, description, sorted(paths))
        for (finding, description), paths in sorted(grouped_paths.items())
    ]


def _split_reconciliation_detail(message: str) -> tuple[str, str]:
    finding, separator, description = message.rpartition(": ")
    if not separator:
        return message, ""
    if finding.lower().startswith("finding "):
        finding = finding[len("finding ") :]
    return finding, description


def _append_reconciliation_groups(
    lines: list[str], groups: Iterable[tuple[str, str, list[str]]]
) -> None:
    for finding, description, binary_paths in groups:
        _start_section(lines, "DIFFERENCE", full_width=False)
        _wrapped_field(lines, "Finding", finding)
        if description:
            _wrapped_field(lines, "Description", description)
        _start_section(
            lines,
            f"AFFECTED BINARIES ({len(binary_paths)})",
            full_width=False,
        )
        _bullets(lines, binary_paths)


def _start_section(
    lines: list[str], title: str, *, full_width: bool = True
) -> None:
    if lines and lines[-1]:
        lines.append("")
    separator_width = LINE_WIDTH if full_width else min(len(title), LINE_WIDTH)
    lines.extend((title, "-" * separator_width))


def _field(
    lines: list[str],
    label: str,
    value: str,
    *,
    shorten: bool = True,
) -> None:
    label_text = f"{label}:" if label else ""
    prefix = f"{label_text:<{LABEL_WIDTH}}"
    available = max(8, LINE_WIDTH - len(prefix))
    displayed = tail_string(value, available) if shorten else str(value)
    lines.append(prefix + displayed)


def _wrapped_field(lines: list[str], label: str, value: str) -> None:
    label_text = f"{label}:" if label else ""
    prefix = f"{label_text:<{LABEL_WIDTH}}"
    available = max(8, LINE_WIDTH - len(prefix))
    wrapped = textwrap.wrap(
        _single_line(value),
        width=available,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    lines.append(prefix + wrapped[0])
    continuation = " " * len(prefix)
    lines.extend(continuation + segment for segment in wrapped[1:])


def _single_line(value: str) -> str:
    return "; ".join(
        line.strip() for line in str(value).splitlines() if line.strip()
    )


def _count_phrase(count: int, singular: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"


def _nested_field(lines: list[str], label: str, value: str) -> None:
    prefix = f"    {label}: "
    lines.append(prefix + tail_string(value, LINE_WIDTH - len(prefix)))


def _bullets(
    lines: list[str],
    values: Iterable[str],
    *,
    indent: str = "  ",
) -> None:
    prefix = indent + "- "
    available = max(8, LINE_WIDTH - len(prefix))
    for value in values:
        lines.append(prefix + tail_string(value, available))


def _coverage_label(report: ScanReport) -> str:
    if report.coverage_state == "no_go_binaries":
        return "NO GO BINARIES (0 recognized)"
    return (
        f"{report.coverage_state.upper()} "
        f"({report.complete_vulnerability_scans} of {len(report.binaries)} binaries)"
    )


def _scan_status_label(report: ScanReport) -> str:
    statuses = Counter(
        binary.vulnerability_scan.status or "unknown" for binary in report.binaries
    )
    if not statuses:
        return "none"
    return ", ".join(
        f"{status.upper()}={count}" for status, count in sorted(statuses.items())
    )


def _result_label(result: str) -> str:
    return {
        "vulnerable": "VULNERABILITIES DETECTED",
        "clean": "NO VULNERABILITIES DETECTED",
        "incomplete": "INDETERMINATE - INCOMPLETE COVERAGE",
        "no_go_binaries": "NO GO BINARIES",
        "operational_error": "OPERATIONAL ERROR",
    }.get(result, result.upper())


def _check_status_label(status: str) -> str:
    return {
        "detected": "DETECTED",
        "not_detected": "NOT DETECTED IN THIS SNAPSHOT",
        "no_go_binaries": "NO GO BINARIES",
        "indeterminate": "INDETERMINATE",
    }.get(status, status.upper())
