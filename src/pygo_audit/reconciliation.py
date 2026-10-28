"""Reconcile Go build information with govulncheck's binary inventory."""

from __future__ import annotations

from dataclasses import replace
from operator import attrgetter
import re

from pygo_audit.models import (
    BinaryReconciliation,
    BinaryReport,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
)


_GO_VERSION = re.compile(
    r"(?P<prefix>go|v)(?P<release>\d+(?:\.\d+){1,2}(?:[a-z]+\d+)?)"
)
_UNVERIFIABLE_VERSIONS = {"", "(devel)", "devel"}


def reconcile_binary(binary: BinaryReport) -> None:
    """Attach complete reconciliation records for later reporting."""
    scan = binary.vulnerability_scan
    if scan.status != "complete":
        binary.reconciliation = BinaryReconciliation(status="not_run")
        return

    inventory = _effective_inventory(binary)
    go_version_status = _compare_go_versions(binary.go_version, scan.go_version)

    finding_results: list[ModuleReconciliation] = []
    for vulnerability in scan.vulnerabilities:
        reconciled_findings = []
        for finding in vulnerability.findings:
            result = _match_component(
                finding.module,
                finding.found_version,
                inventory,
            )
            finding_results.append(result)
            reconciled_findings.append(replace(finding, reconciliation=result))
        vulnerability.findings = reconciled_findings

    sbom_results = _reconcile_sbom(scan.sbom, inventory)
    binary.reconciliation = BinaryReconciliation(
        status=_overall_status(
            [
                go_version_status,
                *(item.status for item in (*finding_results, *sbom_results)),
            ]
        ),
        go_version_status=go_version_status,
        go_version_m=binary.go_version,
        govulncheck_go_version=scan.go_version,
        effective_module_inventory=inventory,
        sbom_modules=sbom_results,
    )


def _effective_inventory(binary: BinaryReport) -> list[ModuleInventoryEntry]:
    inventory = [_inventory_entry("stdlib", Module("stdlib", binary.go_version))]
    if binary.main_module is not None and binary.main_module.path:
        inventory.append(_inventory_entry("main", binary.main_module))
    inventory.extend(
        _inventory_entry("dependency", dependency)
        for dependency in binary.dependencies
        if dependency.path
    )
    inventory.sort(
        key=attrgetter("effective_path", "effective_version", "declared_path")
    )
    return inventory


def _inventory_entry(source: str, module: Module) -> ModuleInventoryEntry:
    effective = module.replace or module
    return ModuleInventoryEntry(
        source=source,
        declared_path=module.path,
        declared_version=module.version,
        effective_path=effective.path,
        effective_version=effective.version,
    )


def _compare_go_versions(go_version_m: str, govulncheck: str) -> str:
    if not go_version_m or not govulncheck:
        return "unverifiable"
    if go_version_m == govulncheck:
        return "exact"
    left = _GO_VERSION.search(go_version_m)
    right = _GO_VERSION.search(govulncheck)
    if left and right and left["release"] == right["release"]:
        if left["prefix"] != right["prefix"]:
            return "representation_difference"
        return "exact"
    return "mismatch"


def _match_component(
    path: str,
    version: str,
    inventory: list[ModuleInventoryEntry],
) -> ModuleReconciliation:
    candidates = [
        entry
        for entry in inventory
        if entry.effective_path == path
        or (entry.is_replacement and entry.declared_path == path)
    ]
    entry = None
    if not path:
        status, detail = "unverifiable", "govulncheck did not report a module path"
    elif not candidates:
        status, detail = (
            "mismatch",
            "module is absent from the effective go version -m inventory",
        )
    else:
        status, entry = next(
            (
                (status, entry)
                for entry in candidates
                if (status := _component_status(entry, version)) is not None
            ),
            ("mismatch", candidates[0]),
        )
        detail = _match_detail(status)
    return ModuleReconciliation(status, path, version, entry, detail)


def _component_status(entry: ModuleInventoryEntry, version: str) -> str | None:
    """Return a matching status, or None so another candidate can be tried."""
    if entry.source == "stdlib":
        status = _compare_go_versions(entry.effective_version, version)
        return "stdlib" if status == "exact" else status
    if (
        entry.is_replacement
        and version
        in {entry.declared_version, entry.effective_version} - _UNVERIFIABLE_VERSIONS
    ):
        return "replacement"
    if (
        version in _UNVERIFIABLE_VERSIONS
        or entry.effective_version in _UNVERIFIABLE_VERSIONS
    ):
        return "unverifiable"
    if not entry.is_replacement and version == entry.effective_version:
        return "exact"
    return None


def _reconcile_sbom(
    sbom: dict[str, object] | None,
    inventory: list[ModuleInventoryEntry],
) -> list[ModuleReconciliation]:
    if sbom is None:
        return [
            ModuleReconciliation(
                status="unverifiable",
                govulncheck_path="",
                govulncheck_version="",
                detail="govulncheck did not emit an SBOM",
            )
        ]

    # Scanner output is normalized before reconciliation; saved audits are validated.
    results = [
        _match_component(module["path"], module["version"], inventory)
        for module in sbom["modules"]
    ]
    matched_entries = {result.inventory_entry for result in results}
    results.extend(
        ModuleReconciliation(
            status="mismatch",
            govulncheck_path="",
            govulncheck_version="",
            inventory_entry=entry,
            detail="effective go version -m module is absent from the govulncheck SBOM",
        )
        for entry in inventory
        if entry not in matched_entries
    )

    results.sort(
        key=lambda result: (
            result.govulncheck_path
            or (
                result.inventory_entry.effective_path
                if result.inventory_entry is not None
                else ""
            ),
            result.govulncheck_version,
            result.status,
        )
    )
    return results


def _match_detail(status: str) -> str:
    if status == "mismatch":
        return "module path matches but the effective versions differ"
    if status == "replacement":
        return "matches the effective replacement recorded by go version -m"
    if status == "stdlib":
        return "matches the Go toolchain version recorded by go version -m"
    if status == "representation_difference":
        return "identifies the same Go release using a different version representation"
    if status == "unverifiable":
        return "module path matches but at least one version is not verifiable"
    return "matches the effective go version -m module and version"


def _overall_status(statuses: list[str]) -> str:
    if "mismatch" in statuses:
        return "mismatch"
    if "unverifiable" in statuses:
        return "limited"
    if "representation_difference" in statuses:
        return "matched_with_differences"
    return "matched"
