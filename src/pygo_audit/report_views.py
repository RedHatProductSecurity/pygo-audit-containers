"""Shared derived views for JSON, text, grouping, and targeted checks."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from operator import attrgetter

from pygo_audit.models import (
    AuditReport,
    BinaryReport,
    CveEvidence,
    DependencyReconciliationRow,
    FindingOccurrence,
    FindingSummary,
    ModuleReconciliation,
    ReconciliationDiagnostic,
    Vulnerability,
)

CVE_RE = re.compile(r"^CVE-([0-9]{4})-([0-9]{4,})$", re.IGNORECASE)


def normalize_cve(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().upper()
    return value if CVE_RE.fullmatch(value) else None


def vulnerability_cves(vulnerability: Vulnerability) -> set[str]:
    return {
        cve
        for value in (vulnerability.id, *vulnerability.aliases)
        if (cve := normalize_cve(value)) is not None
    }


def index_cve_evidence(report: AuditReport) -> dict[str, CveEvidence]:
    """Index original observations once, retaining advisories without findings."""
    observations = defaultdict(list)
    for binary, vulnerability in iter_binary_vulnerabilities(report):
        for cve in vulnerability_cves(vulnerability):
            observations[cve].append((binary, vulnerability))
    return {
        cve: CveEvidence(cve, tuple(items))
        for cve, items in sorted(observations.items())
    }


def iter_binary_vulnerabilities(
    report: AuditReport,
) -> Iterator[tuple[BinaryReport, Vulnerability]]:
    """Yield original evidence, including advisories without finding records."""
    for binary in report.binaries:
        for vulnerability in binary.vulnerability_scan.vulnerabilities:
            yield binary, vulnerability


def binary_module_versions(
    binary: BinaryReport, *, effective: bool = False
) -> Iterator[tuple[str, str]]:
    """Pair recorded paths with versions; optionally apply build replacements."""
    for module in (binary.main_module, *binary.dependencies):
        replacement = module
        while replacement is not None and replacement.replace is not None:
            replacement = replacement.replace
        while module is not None:
            yield module.path, (replacement if effective else module).version
            module = module.replace
    for entry in binary.reconciliation.effective_module_inventory:
        yield (
            entry.declared_path,
            (entry.effective_version if effective else entry.declared_version),
        )
        yield entry.effective_path, entry.effective_version
    for observed in (binary.vulnerability_scan.sbom or {}).get("modules", []):
        yield observed["path"], observed["version"]
    for vulnerability in binary.vulnerability_scan.vulnerabilities:
        for finding in vulnerability.findings:
            yield finding.module, finding.found_version


def module_identifiers(report: AuditReport) -> Iterator[str]:
    """Keep each recorded module path/version pair, including replacements."""
    for binary in report.binaries:
        for path, version in binary_module_versions(binary):
            if path:
                yield component_label(path, version or "unknown")


def package_identifiers(report: AuditReport) -> Iterator[str]:
    """Version observed packages using evidence from their own binary."""
    for binary in report.binaries:
        versions = defaultdict(set)
        for path, version in binary_module_versions(binary, effective=True):
            if path:
                versions[path].add(version)

        packages = [
            (
                binary.main_package,
                "",
                binary.main_module.path if binary.main_module else "",
            ),
            *(
                (root, "", "")
                for root in (binary.vulnerability_scan.sbom or {}).get("roots", [])
            ),
            *(
                (finding.package, finding.found_version, finding.module)
                for vulnerability in binary.vulnerability_scan.vulnerabilities
                for finding in vulnerability.findings
            ),
        ]
        for package, version, module in packages:
            if not package:
                continue
            if not version:
                owner = module or max(
                    (
                        path
                        for path in versions
                        if package == path or package.startswith(path + "/")
                    ),
                    key=len,
                    default="",
                )
                candidates = versions.get(owner, set()) - {""}
                version = next(iter(candidates)) if len(candidates) == 1 else "unknown"
            yield component_label(package, version)


@dataclass(slots=True, frozen=True)
class CheckResult:
    identifier: str  # Requested advisory identifier, retaining user spelling.
    status: str  # Detected, not detected, no binaries, or indeterminate.
    matches: tuple[
        FindingOccurrence, ...
    ]  # Saved finding observations matching the requested identifier.


def evaluate_checks(
    report: AuditReport,
    checks: Sequence[str],
) -> list[CheckResult]:
    requested = requested_identifiers(checks)
    if not requested:
        return []
    coverage = report.coverage_state
    missing_status = {
        "complete": "not_detected",
        "no_go_binaries": "no_go_binaries",
    }.get(coverage, "indeterminate")
    matches = {identifier.upper(): [] for identifier in requested}
    for occurrence in report.finding_occurrences():
        for identifier in {
            value.upper() for value in occurrence.identifiers
        } & matches.keys():
            matches[identifier].append(occurrence)
    return [
        CheckResult(
            identifier,
            "detected" if matches[identifier.upper()] else missing_status,
            tuple(matches[identifier.upper()]),
        )
        for identifier in requested
    ]


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


def binary_occurrence_groups(
    occurrences: Iterable[FindingOccurrence],
) -> list[tuple[FindingOccurrence, ...]]:
    """Group vulnerability findings by the binary observation that produced them."""
    grouped: dict[tuple[object, ...], list[FindingOccurrence]] = {}
    for occurrence in occurrences:
        key = (
            occurrence.binary_paths,
            occurrence.binary_symlinks,
            occurrence.binary_sha256,
            occurrence.runtime_disposition,
            occurrence.layer_history,
        )
        grouped.setdefault(key, []).append(occurrence)
    return [
        tuple(values)
        for _, values in sorted(
            grouped.items(),
            key=lambda item: (
                min(item[0][0]),
                item[0][2],
                item[0][3] != "runtime",
            ),
        )
    ]


def group_items[Item, Key](
    items: Iterable[Item], key: Callable[[Item], Key]
) -> list[tuple[Key, list[Item]]]:
    """Group by an explicit identity, preserving observations within sorted groups."""
    grouped = defaultdict(list)
    for item in items:
        grouped[key(item)].append(item)
    return sorted(grouped.items())


def vulnerability_occurrences(
    report: AuditReport,
) -> dict[str, list[FindingOccurrence]]:
    """Index findings by the advisory identifier displayed in vulnerability reports."""
    return dict(
        group_items(
            report.finding_occurrences(),
            lambda item: preferred_identifier(item.vulnerability_id, item.aliases),
        )
    )


def preferred_identifier(
    identifier: str,
    aliases: Iterable[str],
) -> str:
    def priority(value: str) -> int:
        if value.startswith("CVE-"):
            return 0
        if value.startswith("GHSA-"):
            return 1
        if value.startswith("GO-"):
            return 2
        return 3

    return min((identifier, *aliases), key=priority)


def finding_summaries(report: AuditReport) -> list[FindingSummary]:
    """Collapse repeated symbol observations into review-sized groups."""
    return summarize_findings(report.finding_occurrences())


def summarize_findings(
    occurrences: Iterable[FindingOccurrence],
) -> list[FindingSummary]:
    """Collapse finding observations without requiring their parent report."""

    def key(item: FindingOccurrence) -> tuple[str, str, str, str, str]:
        return (
            preferred_identifier(item.vulnerability_id, item.aliases),
            item.package or "(unknown package)",
            item.module or "(unknown module)",
            item.current_version,
            item.fixed_version,
        )

    return [
        FindingSummary(
            *identity,
            aliases={alias for item in items for alias in item.identifiers}
            - {identity[0]},
            advisory_urls={item.advisory_url for item in items if item.advisory_url},
            evidence={item.evidence or "unknown" for item in items},
            reachability={item.reachability or "unspecified" for item in items},
            observation_count=len(items),
        )
        for identity, items in group_items(occurrences, key)
    ]


def dependency_reconciliation_rows(
    binary: BinaryReport,
) -> tuple[
    list[DependencyReconciliationRow],
    list[ModuleReconciliation],
]:
    rows_by_entry = {
        entry: DependencyReconciliationRow(entry)
        for entry in binary.reconciliation.effective_module_inventory
    }
    unmatched_observations: list[ModuleReconciliation] = []
    for result in binary.reconciliation.sbom_modules:
        if result.inventory_entry is None:
            unmatched_observations.append(result)
            continue
        row = rows_by_entry.setdefault(
            result.inventory_entry,
            DependencyReconciliationRow(result.inventory_entry),
        )
        row.observations.append(result)

    for vulnerability in binary.vulnerability_scan.vulnerabilities:
        identifier = preferred_identifier(vulnerability.id, vulnerability.aliases)
        for finding in vulnerability.findings:
            reconciliation = finding.reconciliation
            if reconciliation is None or reconciliation.inventory_entry is None:
                continue
            row = rows_by_entry.setdefault(
                reconciliation.inventory_entry,
                DependencyReconciliationRow(reconciliation.inventory_entry),
            )
            row.vulnerable_findings.append((identifier, finding))

    rows = sorted(
        rows_by_entry.values(),
        key=attrgetter(
            "entry.effective_path", "entry.effective_version", "entry.declared_path"
        ),
    )
    unmatched_observations.sort(
        key=attrgetter("govulncheck_path", "govulncheck_version", "status")
    )
    return rows, unmatched_observations


def dependency_row_status(row: DependencyReconciliationRow) -> str:
    if not row.observations:
        return "UNVERIFIABLE"
    observed = [result for result in row.observations if result.govulncheck_path]
    if not observed:
        return "MISSING FROM SBOM"
    statuses = {result.status for result in observed}
    if "mismatch" in statuses:
        return "VERSION MISMATCH"
    if "unverifiable" in statuses:
        return "UNVERIFIABLE"
    if "representation_difference" in statuses:
        return "MATCHED WITH DIFFERENCES"
    if "replacement" in statuses:
        return "MATCHED (REPLACEMENT)"
    if statuses <= {"exact", "stdlib"}:
        return "MATCHED"
    return ", ".join(sorted(status.upper() for status in statuses))


def reconciliation_diagnostics(
    report: AuditReport,
) -> tuple[list[ReconciliationDiagnostic], list[ReconciliationDiagnostic]]:
    """Group original outcomes, keeping limitations and differences distinct."""
    grouped = {}

    def add(key: tuple, diagnostic: ReconciliationDiagnostic, source: str) -> None:
        item = grouped.setdefault(key, diagnostic)
        item.sources.add(source)
        if all(existing is not binary for existing in item.binaries):
            item.binaries.append(binary)

    go_descriptions = {
        "unverifiable": (
            "The Go toolchain version could not be verified between "
            "go version -m and govulncheck."
        ),
        "mismatch": "The Go toolchain versions reported by go version -m and govulncheck differ.",
        "representation_difference": "The tools identify the same Go release using different version representations.",
    }
    for binary in sorted(report.binaries, key=lambda item: min(item.paths)):
        reconciliation = binary.reconciliation
        status = reconciliation.go_version_status
        if status in go_descriptions:
            add(
                (
                    "go_toolchain",
                    status,
                    reconciliation.go_version_m,
                    reconciliation.govulncheck_go_version,
                ),
                ReconciliationDiagnostic(
                    status,
                    "GO_VERSION_MISSING"
                    if status == "unverifiable"
                    else status.upper(),
                    "go_toolchain",
                    reconciliation.go_version_m or "(not reported)",
                    "",
                    reconciliation.govulncheck_go_version or "(not reported)",
                    go_descriptions[status],
                ),
                "Go toolchain",
            )
        observations = [
            ("govulncheck SBOM", item) for item in reconciliation.sbom_modules
        ]
        observations.extend(
            ("vulnerability finding", finding.reconciliation)
            for vulnerability in binary.vulnerability_scan.vulnerabilities
            for finding in vulnerability.findings
            if finding.reconciliation is not None
        )
        for source, component in observations:
            if component.status not in go_descriptions:
                continue
            inventory = component.inventory_entry
            reason = (
                component_limitation_reason(
                    component,
                    sbom_missing=source == "govulncheck SBOM"
                    and binary.vulnerability_scan.sbom is None,
                )
                if component.status == "unverifiable"
                else component.status.upper()
            )
            add(
                ("component", component, reason),
                ReconciliationDiagnostic(
                    component.status,
                    reason,
                    "component",
                    component_label(inventory.declared_path, inventory.declared_version)
                    if inventory
                    else "",
                    component_label(
                        inventory.effective_path, inventory.effective_version
                    )
                    if inventory
                    else "",
                    component_label(
                        component.govulncheck_path, component.govulncheck_version
                    ),
                    component.detail
                    or (
                        "The component version could not be verified."
                        if component.status == "unverifiable"
                        else "The observed component differs from the embedded build metadata."
                    ),
                ),
                source,
            )
    items = sorted(
        grouped.values(),
        key=attrgetter(
            "reason", "kind", "effective", "observed", "declared", "description"
        ),
    )
    return (
        [item for item in items if item.status == "unverifiable"],
        [item for item in items if item.status != "unverifiable"],
    )


def component_limitation_reason(
    component: ModuleReconciliation, *, sbom_missing: bool
) -> str:
    """Classify why a component comparison is unverifiable."""
    if (
        sbom_missing
        and not component.govulncheck_path
        and component.inventory_entry is None
    ):
        return "NO_SBOM"
    if not component.govulncheck_path:
        return "MODULE_PATH_MISSING"

    inventory = component.inventory_entry
    versions = [component.govulncheck_version]
    if inventory is not None:
        versions.extend((inventory.declared_version, inventory.effective_version))
    if any(version in {"devel", "(devel)"} for version in versions):
        return "DEVELOPMENT_VERSION"
    if inventory is None or not inventory.effective_version:
        return "DECLARED_VERSION_MISSING"
    if not component.govulncheck_version:
        return "OBSERVED_VERSION_MISSING"
    return "VERSION_UNVERIFIABLE"


def component_label(path: str, version: str) -> str:
    if not path:
        return "(not reported)"
    return f"{path}@{version}" if version else path
