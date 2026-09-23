"""Human-readable and JSON report rendering."""

from __future__ import annotations

from collections import Counter
import json
from typing import Any, Iterable, Sequence

from pygo_audit.models import BinaryReport, FindingOccurrence, ScanReport


_FINDINGS_TABLE_HEADER = "PACKAGES | CURRENT VERSION | VULNERABILITY"
_FINDINGS_TABLE_DIVIDER = "---------|-----------------|--------------"


def render_json(
    report: ScanReport,
    *,
    group_by: str | None = None,
    checks: Sequence[str] = (),
) -> str:
    if group_by not in {None, "container", "binary", "package", "vulnerability"}:
        raise ValueError(f"unsupported finding group: {group_by}")
    document = report.to_dict()
    if group_by or checks:
        document["query"] = {
            "group_by": group_by,
            "result": report.result_state,
            "coverage": {
                "state": report.coverage_state,
                "complete": report.complete_vulnerability_scans,
                "incomplete": report.incomplete_vulnerability_scans,
            },
            "groups": _json_groups(report, group_by),
            "checks": _json_check_results(report, checks),
        }
    return json.dumps(document, indent=2, ensure_ascii=True)


def render_container(report: ScanReport) -> str:
    """Render vulnerabilities once per container instead of once per binary."""
    findings = _aggregate_findings(report.finding_occurrences())
    scan_statuses = Counter(
        binary.vulnerability_scan.status for binary in report.binaries
    )
    cgo_binaries = sum(binary.cgo_enabled for binary in report.binaries)

    lines = [
        f"Container findings for {report.root}",
        f"Go binaries: {len(report.binaries)}; CGO enabled: {cgo_binaries}",
        f"Vulnerability scans: {_format_scan_statuses(scan_statuses)}",
    ]

    lines.extend(_format_databases(report.binaries))

    lines.extend(
        (
            f"Unique vulnerabilities: {len(findings)}",
            "Evidence: compiled-binary findings; runtime reachability unknown.",
            "",
        )
    )

    if findings:
        lines.extend(_format_findings_table(findings))
    else:
        lines.append("No container-level vulnerability findings.")

    incomplete = sum(
        count for status, count in scan_statuses.items() if status != "complete"
    )
    if incomplete:
        lines.extend(("", f"Warning: {incomplete} vulnerability scan(s) incomplete."))
    if report.actionable_issues:
        lines.append(
            f"Issues: {len(report.actionable_issues)} "
            "(use --format json for details)."
        )
    lines.extend(_format_reconciliation_differences(report, leading_blank=True))

    return "\n".join(lines)


def render_summary(report: ScanReport) -> str:
    """Render complete, deduplicated package and vulnerability lists."""
    findings = _aggregate_findings(report.finding_occurrences())
    packages = sorted(
        {
            package
            for finding in findings
            for component in finding["components"]
            for package in component["packages"]
        }
    )
    vulnerabilities = sorted(
        {
            _format_vulnerability_identifier(
                str(finding["id"]), finding["aliases"]
            )
            for finding in findings
        }
    )

    lines = [f"PACKAGES ({len(packages)})"]
    lines.extend(packages or ["none"])
    lines.extend(("", f"VULNERABILITIES ({len(vulnerabilities)})"))
    lines.extend(vulnerabilities or ["none"])

    incomplete = sum(
        binary.vulnerability_scan.status != "complete"
        for binary in report.binaries
    )
    if incomplete:
        lines.extend(("", f"WARNING: {incomplete} vulnerability scan(s) incomplete."))
    if report.actionable_issues:
        lines.append(
            f"WARNING: {len(report.actionable_issues)} scan issue(s); "
            "use --format json for details."
        )
    lines.extend(_format_reconciliation_differences(report, leading_blank=True))
    return "\n".join(lines)


def render_text(report: ScanReport) -> str:
    """Render one compact vulnerability table for each discovered Go binary."""
    binaries = sorted(report.binaries, key=lambda binary: min(binary.paths))
    cgo_binaries = sum(binary.cgo_enabled for binary in binaries)
    lines = [
        f"Binary findings under {report.root}",
        f"Go binaries: {len(binaries)}; CGO enabled: {cgo_binaries}",
        "",
    ]

    if not binaries:
        lines.append("No Go binaries found.")

    for binary in binaries:
        findings = _aggregate_findings(binary.finding_occurrences())
        scan = binary.vulnerability_scan
        primary_path = min(binary.paths)
        lines.append(f"Binary findings for {primary_path}")
        if len(binary.paths) > 1:
            hardlinks = sorted(path for path in binary.paths if path != primary_path)
            lines.append(f"Hardlinks: {', '.join(hardlinks)}")
        lines.extend(
            (
                f"Go: {binary.go_version}",
                f"CGO enabled: {str(binary.cgo_enabled).lower()}",
                f"Vulnerability scan: {scan.status}",
            )
        )
        lines.extend(_format_databases([binary]))
        lines.extend(
            (
                f"Unique vulnerabilities: {len(findings)}",
                "Evidence: compiled-binary findings; runtime reachability unknown.",
                "",
            )
        )

        if findings:
            lines.extend(_format_findings_table(findings))
        else:
            lines.append("No vulnerability findings for this binary.")

        if scan.status != "complete":
            warning = "Warning: vulnerability scan incomplete."
            if scan.error:
                warning = f"Warning: vulnerability scan incomplete: {scan.error}"
            lines.extend(("", warning))
        lines.append("")

    if report.actionable_issues:
        lines.append(
            f"Issues: {len(report.actionable_issues)} "
            "(use --format json for details)."
        )
    lines.extend(_format_reconciliation_differences(report, leading_blank=True))

    return "\n".join(lines).rstrip()


def render_grouped(report: ScanReport, group_by: str) -> str:
    """Render evidence-rich findings grouped along one requested dimension."""
    if group_by not in {"container", "binary", "package", "vulnerability"}:
        raise ValueError(f"unsupported finding group: {group_by}")

    occurrences = report.finding_occurrences()
    cgo_binaries = sum(binary.cgo_enabled for binary in report.binaries)
    lines = [
        f"Audit findings for {report.root}",
        f"Result: {report.result_state}",
        f"Coverage: {_format_coverage(report)}",
        f"Go binaries: {len(report.binaries)}; CGO enabled: {cgo_binaries}",
    ]
    lines.extend(_format_databases(report.binaries))
    lines.append("")

    if not occurrences:
        lines.append("No vulnerability findings.")
    elif group_by == "container":
        lines.extend(
            _format_detailed_table(
                occurrences,
                ("binary", "package", "version", "vulnerability", "evidence"),
            )
        )
    elif group_by == "binary":
        for binary in sorted(report.binaries, key=lambda item: min(item.paths)):
            binary_occurrences = binary.finding_occurrences()
            if not binary_occurrences:
                continue
            primary_path = min(binary.paths)
            lines.append(f"Binary: {primary_path}")
            if len(binary.paths) > 1:
                lines.append(
                    "Hardlinks: "
                    + ", ".join(
                        sorted(path for path in binary.paths if path != primary_path)
                    )
                )
            lines.extend(
                _format_detailed_table(
                    binary_occurrences,
                    ("package", "version", "vulnerability", "evidence"),
                )
            )
            lines.append("")
    elif group_by == "package":
        packages = sorted(
            {occurrence.package or "(unknown package)" for occurrence in occurrences}
        )
        for package in packages:
            lines.append(f"Package: {package}")
            lines.extend(
                _format_detailed_table(
                    [
                        occurrence
                        for occurrence in occurrences
                        if (occurrence.package or "(unknown package)") == package
                    ],
                    ("binary", "version", "vulnerability", "evidence"),
                )
            )
            lines.append("")
    else:
        identifiers = sorted(
            {_preferred_identifier(occurrence) for occurrence in occurrences}
        )
        for identifier in identifiers:
            lines.append(f"Vulnerability: {identifier}")
            lines.extend(
                _format_detailed_table(
                    [
                        occurrence
                        for occurrence in occurrences
                        if _preferred_identifier(occurrence) == identifier
                    ],
                    ("binary", "package", "version", "evidence"),
                )
            )
            lines.append("")

    if report.actionable_issues:
        lines.extend(
            (
                "",
                f"Issues: {len(report.actionable_issues)} "
                "(use --format json for details).",
            )
        )
    lines.extend(_format_reconciliation_differences(report, leading_blank=True))
    return "\n".join(lines).rstrip()


def render_checks(report: ScanReport, checks: Sequence[str]) -> str:
    """Render an explicit outcome for every requested vulnerability identifier."""
    requested = list(dict.fromkeys(check.strip() for check in checks if check.strip()))
    lines = [
        "Targeted vulnerability checks",
        f"Coverage: {_format_coverage(report)}",
    ]

    for identifier in requested:
        matches = report.findings_for_identifier(identifier)
        if matches:
            lines.extend(("", f"{identifier}: DETECTED"))
            lines.extend(
                _format_detailed_table(
                    matches,
                    ("binary", "package", "version", "vulnerability", "evidence"),
                )
            )
        elif report.coverage_state == "complete":
            lines.extend(("", f"{identifier}: NO MATCHING FINDING DETECTED"))
        elif report.coverage_state == "no_go_binaries":
            lines.extend(("", f"{identifier}: NO GO BINARIES FOUND"))
        else:
            lines.extend(
                (
                    "",
                    f"{identifier}: INDETERMINATE; no matching finding detected "
                    "and vulnerability coverage is incomplete",
                )
            )

    return "\n".join(lines)


def _json_check_results(
    report: ScanReport,
    checks: Sequence[str],
) -> list[dict[str, Any]]:
    requested = list(dict.fromkeys(check.strip() for check in checks if check.strip()))
    results = []
    for identifier in requested:
        matches = report.findings_for_identifier(identifier)
        if matches:
            status = "detected"
        elif report.coverage_state == "complete":
            status = "not_detected"
        elif report.coverage_state == "no_go_binaries":
            status = "no_go_binaries"
        else:
            status = "indeterminate"
        results.append(
            {
                "identifier": identifier,
                "status": status,
                "coverage": report.coverage_state,
                "matches": [match.to_dict() for match in matches],
            }
        )
    return results


def _json_groups(
    report: ScanReport,
    group_by: str | None,
) -> list[dict[str, Any]]:
    if group_by is None:
        return []

    grouped: dict[str, list[FindingOccurrence]] = {}
    for occurrence in report.finding_occurrences():
        if group_by == "container":
            key = report.root
        elif group_by == "binary":
            key = min(occurrence.binary_paths)
        elif group_by == "package":
            key = occurrence.package or "(unknown package)"
        else:
            key = _preferred_identifier(occurrence)
        grouped.setdefault(key, []).append(occurrence)

    return [
        {
            "key": key,
            "findings": [occurrence.to_dict() for occurrence in grouped[key]],
        }
        for key in sorted(grouped)
    ]


def _format_detailed_table(
    occurrences: Iterable[FindingOccurrence],
    columns: tuple[str, ...],
) -> list[str]:
    labels = {
        "binary": "BINARY",
        "package": "PACKAGE",
        "version": "CURRENT VERSION",
        "vulnerability": "VULNERABILITY",
        "evidence": "EVIDENCE",
    }
    rows = _detailed_rows(occurrences)
    header = " | ".join(labels[column] for column in columns)
    divider = "|".join("-" * len(labels[column]) for column in columns)
    formatted = [
        " | ".join(str(row[column]) for column in columns)
        for row in rows
    ]
    return [header, divider, *formatted]


def _detailed_rows(
    occurrences: Iterable[FindingOccurrence],
) -> list[dict[str, str]]:
    aggregated: dict[tuple[str, str], dict[str, set[str]]] = {}
    for occurrence in occurrences:
        package = occurrence.package or "(unknown package)"
        version = occurrence.module or "(unknown module)"
        if occurrence.current_version:
            version = f"{version}@{occurrence.current_version}"
        identifier = _preferred_identifier(occurrence)
        row = aggregated.setdefault(
            (package, identifier),
            {"binary": set(), "version": set(), "evidence": set()},
        )
        row["binary"].update(occurrence.binary_paths)
        row["version"].add(version)
        row["evidence"].add(_format_evidence(occurrence))

    rows = [
        {
            "binary": ", ".join(sorted(values["binary"])),
            "package": package,
            "version": ", ".join(sorted(values["version"])),
            "vulnerability": identifier,
            "evidence": ", ".join(sorted(values["evidence"])),
        }
        for (package, identifier), values in aggregated.items()
    ]
    rows.sort(
        key=lambda row: (
            row["package"],
            row["version"],
            row["vulnerability"],
            row["binary"],
        )
    )
    return rows


def _format_evidence(occurrence: FindingOccurrence) -> str:
    return occurrence.evidence or "unknown"


def _preferred_identifier(occurrence: FindingOccurrence) -> str:
    return _format_vulnerability_identifier(
        occurrence.vulnerability_id,
        list(occurrence.aliases),
    )


def _aggregate_findings(
    occurrences: Iterable[FindingOccurrence],
) -> list[dict[str, Any]]:
    aggregated: dict[str, dict[str, Any]] = {}

    for occurrence in occurrences:
        finding = aggregated.setdefault(
            occurrence.vulnerability_id,
            {
                "id": occurrence.vulnerability_id,
                "aliases": set(),
                "components": {},
            },
        )
        finding["aliases"].update(occurrence.aliases)

        component_key = (
            occurrence.module or "(unknown module)",
            occurrence.current_version,
        )
        component = finding["components"].setdefault(
            component_key,
            {"packages": set()},
        )
        if occurrence.package:
            component["packages"].add(occurrence.package)

    normalized = []
    for finding in aggregated.values():
        components = []
        for (module, version), component in finding["components"].items():
            components.append(
                {
                    "module": module,
                    "version": version,
                    "packages": sorted(component["packages"]),
                }
            )
        components.sort(key=lambda item: (item["module"], item["version"]))
        normalized.append(
            {
                "id": finding["id"],
                "aliases": sorted(finding["aliases"]),
                "components": components,
            }
        )

    normalized.sort(key=lambda finding: finding["id"])
    return normalized


def _format_findings_table(findings: list[dict[str, Any]]) -> list[str]:
    rows = [
        row
        for finding in findings
        for row in _format_finding_rows(finding)
    ]
    return [_FINDINGS_TABLE_HEADER, _FINDINGS_TABLE_DIVIDER, *sorted(rows)]


def _format_finding_rows(finding: dict[str, Any]) -> list[str]:
    identifier = _format_vulnerability_identifier(
        str(finding["id"]), finding["aliases"]
    )

    package_components: dict[str, set[str]] = {}
    for component in finding["components"]:
        value = component["module"]
        if component["version"]:
            value = f"{value}@{component['version']}"
        packages = component["packages"] or ["(unknown package)"]
        for package in packages:
            package_components.setdefault(package, set()).add(value)

    if not package_components:
        package_components["(unknown package)"] = {"(unknown version)"}

    return [
        " | ".join(
            (
                package,
                _bounded_list(sorted(components), limit=3),
                identifier,
            )
        )
        for package, components in sorted(package_components.items())
    ]


def _format_databases(binaries: list[BinaryReport]) -> list[str]:
    databases = {
        (
            binary.vulnerability_scan.database,
            binary.vulnerability_scan.database_last_modified,
        )
        for binary in binaries
        if binary.vulnerability_scan.database
    }
    if len(databases) == 1:
        database, last_modified = next(iter(databases))
        if last_modified:
            database = f"{database} (updated {last_modified})"
        return [f"Database: {database}"]
    if len(databases) > 1:
        return [f"Databases: {len(databases)}"]
    return []


def _format_coverage(report: ScanReport) -> str:
    total = len(report.binaries)
    complete = report.complete_vulnerability_scans
    if report.coverage_state == "no_go_binaries":
        return "no_go_binaries (0 recognized Go binaries)"
    return f"{report.coverage_state} ({complete}/{total} binary scans complete)"


def _format_reconciliation_differences(
    report: ScanReport,
    *,
    leading_blank: bool = False,
) -> list[str]:
    differences = sorted(
        (
            issue
            for issue in report.issues
            if issue.stage == "reconciliation-difference"
        ),
        key=lambda issue: (issue.path, issue.message),
    )
    if not differences:
        return []

    lines = ["Reconciliation differences:"]
    lines.extend(f"{issue.path}: {issue.message}" for issue in differences)
    if leading_blank:
        lines.insert(0, "")
    return lines


def _bounded_list(values: list[str], *, limit: int) -> str:
    displayed = values[:limit]
    if len(values) > limit:
        displayed.append(f"+{len(values) - limit} more")
    return ", ".join(displayed)


def _format_scan_statuses(statuses: Counter[str]) -> str:
    if not statuses:
        return "none"
    preferred_order = ("complete", "failed", "not_run", "disabled")
    ordered = [status for status in preferred_order if status in statuses]
    ordered.extend(sorted(set(statuses) - set(preferred_order)))
    return ", ".join(f"{status}={statuses[status]}" for status in ordered)


def _format_vulnerability_identifier(identifier: str, aliases: list[str]) -> str:
    identifiers = list(dict.fromkeys((identifier, *aliases)))

    def priority(value: str) -> int:
        if value.startswith("CVE-"):
            return 0
        if value.startswith("GHSA-"):
            return 1
        if value.startswith("GO-"):
            return 2
        return 3

    ordered = sorted(
        enumerate(identifiers),
        key=lambda item: (priority(item[1]), item[0]),
    )
    return ordered[0][1]
