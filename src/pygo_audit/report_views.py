"""Shared derived views for JSON, text, grouping, and targeted checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from pygo_audit.models import FindingOccurrence, ScanReport


VALID_GROUPS = frozenset({"container", "binary", "package", "vulnerability"})


@dataclass(slots=True, frozen=True)
class FindingRecord:
    """A human-scale finding with duplicate symbol observations consolidated."""

    package: str
    module: str
    current_version: str
    vulnerability: str
    binary_paths: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class CheckResult:
    identifier: str
    status: str
    coverage: str
    matches: tuple[FindingOccurrence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "status": self.status,
            "coverage": self.coverage,
            "matches": [match.to_dict() for match in self.matches],
        }


def evaluate_checks(
    report: ScanReport,
    checks: Sequence[str],
) -> list[CheckResult]:
    results = []
    for identifier in requested_identifiers(checks):
        matches = tuple(report.findings_for_identifier(identifier))
        if matches:
            status = "detected"
        elif report.coverage_state == "complete":
            status = "not_detected"
        elif report.coverage_state == "no_go_binaries":
            status = "no_go_binaries"
        else:
            status = "indeterminate"
        results.append(
            CheckResult(
                identifier=identifier,
                status=status,
                coverage=report.coverage_state,
                matches=matches,
            )
        )
    return results


def requested_identifiers(checks: Sequence[str]) -> list[str]:
    requested: list[str] = []
    seen: set[str] = set()
    for check in checks:
        identifier = check.strip()
        key = identifier.upper()
        if not identifier or key in seen:
            continue
        seen.add(key)
        requested.append(identifier)
    return requested


def finding_records(
    occurrences: Iterable[FindingOccurrence],
) -> list[FindingRecord]:
    aggregated: dict[
        tuple[str, str, str, str],
        dict[str, set[str]],
    ] = {}
    for occurrence in occurrences:
        package = occurrence.package or "(unknown package)"
        module = occurrence.module or "(unknown module)"
        identifier = preferred_identifier(
            occurrence.vulnerability_id,
            occurrence.aliases,
        )
        key = (package, module, occurrence.current_version, identifier)
        values = aggregated.setdefault(
            key,
            {"binary_paths": set(), "evidence": set()},
        )
        values["binary_paths"].update(occurrence.binary_paths)
        values["evidence"].add(occurrence.evidence or "unknown")

    records = [
        FindingRecord(
            package=package,
            module=module,
            current_version=current_version,
            vulnerability=vulnerability,
            binary_paths=tuple(sorted(values["binary_paths"])),
            evidence=tuple(sorted(values["evidence"])),
        )
        for (
            package,
            module,
            current_version,
            vulnerability,
        ), values in aggregated.items()
    ]
    records.sort(
        key=lambda record: (
            record.package,
            record.module,
            record.current_version,
            record.vulnerability,
            record.binary_paths,
        )
    )
    return records


def group_occurrences(
    report: ScanReport,
    group_by: str,
) -> dict[str, list[FindingOccurrence]]:
    if group_by not in VALID_GROUPS:
        raise ValueError(f"unsupported finding group: {group_by}")

    grouped: dict[str, list[FindingOccurrence]] = {}
    for occurrence in report.finding_occurrences():
        if group_by == "container":
            key = report.root
        elif group_by == "binary":
            key = min(occurrence.binary_paths)
        elif group_by == "package":
            key = occurrence.package or "(unknown package)"
        else:
            key = preferred_identifier(
                occurrence.vulnerability_id,
                occurrence.aliases,
            )
        grouped.setdefault(key, []).append(occurrence)
    return {key: grouped[key] for key in sorted(grouped)}


def preferred_identifier(
    identifier: str,
    aliases: Iterable[str],
) -> str:
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
