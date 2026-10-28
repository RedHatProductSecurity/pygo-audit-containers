"""Shared subject, provenance, coverage, and status sections for text reports."""

from __future__ import annotations

from pygo_audit.models import ImageIdentity, AuditReport
from pygo_audit.report_views import (
    reconciliation_diagnostics,
)
from pygo_audit.storage import json_digest
from pygo_audit.text_layout import TextLayout, Verbosity, count_phrase


def append_check_context(lines: TextLayout, report: AuditReport) -> None:
    lines.section("PROVENANCE")
    identity = report.metadata.image
    lines.field("Subject", identity.reference or report.metadata.root)
    append_image_identity_fields(lines, identity, reference_label=None)
    lines.field("Audit SHA-256", json_digest(report.to_dict()))
    lines.field("Scan completed", report.scan_completed_at or None)
    append_scanner_identity(lines, report)
    lines.field("govulncheck", compact_govulncheck_version(report) or None)
    append_databases(lines, report)


def append_scanner_identity(lines: TextLayout, report: AuditReport) -> None:
    producer = " ".join(
        value for value in (report.producer_name, report.producer_version) if value
    )
    lines.fields(
        ("Scanner", producer or None), ("Go toolchain", report.go_tool_version or None)
    )


def append_databases(lines: TextLayout, report: AuditReport) -> None:
    databases = report.vulnerability_databases()
    for index, database in enumerate(databases, start=1):
        suffix = f" {index}" if len(databases) > 1 else ""
        lines.field(f"Database{suffix}", database["url"])
        lines.field(f"Database updated{suffix}", database["last_modified"] or None)


def compact_govulncheck_version(report: AuditReport) -> str:
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


def append_report_context(
    lines: TextLayout,
    report: AuditReport,
) -> None:
    lines.section("SUBJECT")
    subject_type = (
        "container image" if report.metadata.image.is_present else "unpacked rootfs"
    )
    lines.field("Type", subject_type)
    lines.field("Root", report.metadata.root)
    append_image_identity_fields(lines, report.metadata.image)


def append_provenance_context(lines: TextLayout, report: AuditReport) -> None:
    lines.section("PROVENANCE")
    append_scanner_identity(lines, report)
    lines.field("Go command", report.go_command or None)
    lines.field("govulncheck status", report.govulncheck_status or "unknown")
    if report.govulncheck_tool_version:
        version_lines = [
            line.strip()
            for line in report.govulncheck_tool_version.splitlines()
            if line.strip()
        ]
        for index, version_line in enumerate(version_lines):
            label = "govulncheck version" if index == 0 else ""
            lines.field(label, version_line)
    lines.fields(
        ("govulncheck command", report.govulncheck_command or None),
        ("Scan started", report.scan_started_at or None),
        ("Scan completed", report.scan_completed_at or None),
    )
    append_databases(lines, report)


def finish_report(lines: TextLayout, report: AuditReport) -> str:
    """End every report view with provenance or the verbosity hint."""
    if lines.policy.shows(Verbosity.FORENSIC):
        append_provenance_context(lines, report)
    append_detail_footer(lines)
    return lines.render()


def append_detail_footer(lines: TextLayout) -> None:
    if lines.policy.shows(Verbosity.FORENSIC):
        return
    lines.append("")
    lines.append(
        "More information: use -v, -vv, or -vvv for increasing detail; add --wide "
        "to avoid truncating results."
    )


def append_image_identity_fields(
    lines: TextLayout,
    identity: ImageIdentity,
    *,
    reference_label: str | None = "Image reference",
) -> None:
    """Append the portable image sidecar fields to a report context."""
    if reference_label is not None and identity.reference:
        lines.field(reference_label, identity.reference)
    fields = [
        ("Image name", "name"),
        ("Component", "component"),
        ("CPE", "cpe"),
        ("Product version", "product_version"),
        ("Component version", "component_version"),
        ("Source Git URL", "source_git_url"),
        ("Product component", "product_component"),
        ("Image digest", "digest"),
        ("Digest (short)", "digest_short"),
        ("Platform", "platform"),
        ("Extractor", "extractor"),
    ]
    for label, attribute in fields:
        value = getattr(identity, attribute)
        if value:
            lines.field(label, value)


def append_coverage_warning(lines: TextLayout, report: AuditReport) -> None:
    if not report.incomplete_vulnerability_scans:
        return
    lines.section("COVERAGE WARNING")
    lines.append(
        f"  Vulnerability scanning did not complete for {report.incomplete_vulnerability_scans} of {len(report.binaries)} binaries."
    )
    lines.append("  Missing findings must not be interpreted as a clean result.")


def append_unaccounted_historical_summary(
    lines: TextLayout, report: AuditReport
) -> None:
    """Surface unexplained layer binaries before detailed report sections."""
    binary_count = len(report.unaccounted_historical_binaries)
    finding_count = len(report.unaccounted_historical_findings())
    if binary_count:
        lines.field("Unaccounted historical binaries", str(binary_count))
    if finding_count:
        lines.field("Unaccounted historical findings", str(finding_count))
    if not binary_count:
        return
    lines.section("UNACCOUNTED HISTORICAL CONTENT")
    lines.append(
        "  These binaries were observed in a layer but not in the final runtime"
    )
    lines.append("  filesystem, and no deletion or replacement evidence was found.")


def append_diagnostic_counts(
    lines: TextLayout, report: AuditReport, *, include_reconciliation: bool = True
) -> None:
    actionable = report.actionable_issues
    if actionable:
        lines.field("Operational issues", str(len(actionable)))
    if not include_reconciliation:
        return
    limited_binaries = sum(
        (binary.reconciliation.status == "limited" for binary in report.binaries)
    )
    limitations, differences = reconciliation_diagnostics(report)
    if limited_binaries:
        lines.field(
            "Reconciliation",
            f"LIMITED ({limited_binaries} of {len(report.binaries)} binaries)",
        )
    if limitations:
        lines.field("Unverifiable", count_phrase(len(limitations), "component"))
    if differences:
        lines.field(
            "Recon. differences",
            count_phrase(len(differences), "difference"),
        )


def coverage_label(report: AuditReport) -> str:
    if report.coverage_state == "no_go_binaries":
        return "NO GO BINARIES (0 recognized)"
    return f"{report.coverage_state.upper()} ({report.complete_vulnerability_scans} of {len(report.binaries)} binaries)"


def runtime_disposition_label(value: str) -> str:
    return {
        "runtime": "RUNTIME",
        "deleted": "DELETED FROM FINAL IMAGE",
        "replaced": "REPLACED IN FINAL IMAGE",
        "unaccounted": "UNACCOUNTED HISTORICAL",
        "unknown": "UNVERIFIED",
    }.get(value, value.upper())


def result_label(result: str) -> str:
    return {
        "vulnerable": "VULNERABILITIES DETECTED",
        "clean": "NO VULNERABILITIES DETECTED",
        "incomplete": "INDETERMINATE - INCOMPLETE COVERAGE",
        "no_go_binaries": "NO GO BINARIES",
        "operational_error": "OPERATIONAL ERROR",
    }.get(result, result.upper())


def check_status_label(status: str) -> str:
    return {
        "detected": "DETECTED",
        "not_detected": "NOT DETECTED IN THIS AUDIT",
        "no_go_binaries": "NO GO BINARIES",
        "indeterminate": "INDETERMINATE",
    }.get(status, status.upper())
