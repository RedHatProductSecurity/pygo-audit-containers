"""Reconcile Go build information with govulncheck's binary inventory."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
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


def reconcile_binary(binary: BinaryReport) -> list[str]:
    """Attach reconciliation evidence and return mismatches and differences."""
    scan = binary.vulnerability_scan
    if scan.status != "complete":
        binary.reconciliation = BinaryReconciliation(status="not_run")
        return []

    inventory = _effective_inventory(binary)
    mismatch_details: list[str] = []
    observed_statuses: list[str] = []

    go_version_status = _compare_go_versions(binary.go_version, scan.go_version)
    observed_statuses.append(go_version_status)
    if go_version_status == "mismatch":
        mismatch_details.append(
            "Go version differs: "
            f"go version -m reported {binary.go_version!r}, "
            f"govulncheck reported {scan.go_version!r}"
        )
    elif go_version_status == "representation_difference":
        mismatch_details.append(
            "Go version representation differs: "
            f"go version -m reported {binary.go_version!r}, "
            f"govulncheck reported {scan.go_version!r}; "
            "both identify the same Go release"
        )

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
            observed_statuses.append(result.status)
            if result.status == "mismatch":
                mismatch_details.append(
                    _mismatch_message("finding", result)
                )
            elif result.status == "representation_difference":
                mismatch_details.append(
                    _difference_message("finding", result)
                )
            reconciled_findings.append(replace(finding, reconciliation=result))
        vulnerability.findings = reconciled_findings

    sbom_results = _reconcile_sbom(scan.sbom, inventory)
    for result in sbom_results:
        observed_statuses.append(result.status)
        if result.status == "mismatch":
            mismatch_details.append(_mismatch_message("SBOM", result))
        elif result.status == "representation_difference":
            mismatch_details.append(_difference_message("SBOM", result))

    binary.reconciliation = BinaryReconciliation(
        status=_overall_status(observed_statuses),
        go_version_status=go_version_status,
        go_version_m=binary.go_version,
        govulncheck_go_version=scan.go_version,
        effective_module_inventory=inventory,
        sbom_modules=sbom_results,
        finding_statuses=dict(Counter(result.status for result in finding_results)),
        sbom_statuses=dict(Counter(result.status for result in sbom_results)),
    )
    return list(dict.fromkeys(mismatch_details))


def _effective_inventory(binary: BinaryReport) -> list[ModuleInventoryEntry]:
    inventory = [
        ModuleInventoryEntry(
            source="stdlib",
            declared_path="stdlib",
            declared_version=binary.go_version,
            effective_path="stdlib",
            effective_version=binary.go_version,
        )
    ]
    if binary.main_module is not None and binary.main_module.path:
        inventory.append(_inventory_entry("main", binary.main_module))
    inventory.extend(
        _inventory_entry("dependency", dependency)
        for dependency in binary.dependencies
        if dependency.path
    )
    inventory.sort(
        key=lambda entry: (
            entry.effective_path,
            entry.effective_version,
            entry.declared_path,
        )
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
    left = _base_go_version(go_version_m)
    right = _base_go_version(govulncheck)
    if left and left == right:
        if _go_version_prefix(go_version_m) != _go_version_prefix(govulncheck):
            return "representation_difference"
        return "exact"
    return "mismatch"


def _base_go_version(value: str) -> str:
    match = _GO_VERSION.search(value)
    return match.group("release") if match is not None else ""


def _go_version_prefix(value: str) -> str:
    match = _GO_VERSION.search(value)
    return match.group("prefix") if match is not None else ""


def _match_component(
    path: str,
    version: str,
    inventory: list[ModuleInventoryEntry],
) -> ModuleReconciliation:
    if not path:
        return ModuleReconciliation(
            status="unverifiable",
            govulncheck_path=path,
            govulncheck_version=version,
            detail="govulncheck did not report a module path",
        )

    candidates = [
        entry
        for entry in inventory
        if entry.effective_path == path
        or (entry.is_replacement and entry.declared_path == path)
    ]
    if not candidates:
        return ModuleReconciliation(
            status="mismatch",
            govulncheck_path=path,
            govulncheck_version=version,
            detail="module is absent from the effective go version -m inventory",
        )

    for entry in candidates:
        if entry.source == "stdlib":
            status = _compare_go_versions(entry.effective_version, version)
            if status == "exact":
                status = "stdlib"
        elif entry.is_replacement and version in {
            entry.declared_version,
            entry.effective_version,
        } - _UNVERIFIABLE_VERSIONS:
            status = "replacement"
        elif (
            not entry.is_replacement
            and version not in _UNVERIFIABLE_VERSIONS
            and entry.effective_version not in _UNVERIFIABLE_VERSIONS
            and version == entry.effective_version
        ):
            status = "exact"
        elif (
            version in _UNVERIFIABLE_VERSIONS
            or entry.effective_version in _UNVERIFIABLE_VERSIONS
        ):
            status = "unverifiable"
        else:
            continue

        return ModuleReconciliation(
            status=status,
            govulncheck_path=path,
            govulncheck_version=version,
            inventory_entry=entry,
            detail=_match_detail(status),
        )

    return ModuleReconciliation(
        status="mismatch",
        govulncheck_path=path,
        govulncheck_version=version,
        inventory_entry=candidates[0],
        detail="module path matches but the effective versions differ",
    )


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

    raw_modules = sbom.get("modules")
    modules = raw_modules if isinstance(raw_modules, list) else []
    results: list[ModuleReconciliation] = []
    matched_entries: set[ModuleInventoryEntry] = set()
    for module in modules:
        if not isinstance(module, dict):
            continue
        path = module.get("path")
        version = module.get("version")
        result = _match_component(
            path if isinstance(path, str) else "",
            version if isinstance(version, str) else "",
            inventory,
        )
        results.append(result)
        if result.inventory_entry is not None:
            matched_entries.add(result.inventory_entry)

    for entry in inventory:
        if entry not in matched_entries:
            results.append(
                ModuleReconciliation(
                    status="mismatch",
                    govulncheck_path="",
                    govulncheck_version="",
                    inventory_entry=entry,
                    detail="effective go version -m module is absent from the govulncheck SBOM",
                )
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
    if status == "replacement":
        return "matches the effective replacement recorded by go version -m"
    if status == "stdlib":
        return "matches the Go toolchain version recorded by go version -m"
    if status == "representation_difference":
        return (
            "identifies the same Go release using a different version "
            "representation"
        )
    if status == "unverifiable":
        return "module path matches but at least one version is not verifiable"
    return "matches the effective go version -m module and version"


def _mismatch_message(source: str, result: ModuleReconciliation) -> str:
    if result.govulncheck_path:
        observed = result.govulncheck_path
        if result.govulncheck_version:
            observed = f"{observed}@{result.govulncheck_version}"
        return f"{source} {observed}: {result.detail}"

    if result.inventory_entry is not None:
        expected = result.inventory_entry.effective_path
        if result.inventory_entry.effective_version:
            expected = f"{expected}@{result.inventory_entry.effective_version}"
        return f"{source} missing {expected}: {result.detail}"
    return f"{source}: {result.detail}"


def _difference_message(source: str, result: ModuleReconciliation) -> str:
    observed = result.govulncheck_path or "stdlib"
    if result.govulncheck_version:
        observed = f"{observed}@{result.govulncheck_version}"
    expected = ""
    if result.inventory_entry is not None:
        expected = result.inventory_entry.effective_path
        if result.inventory_entry.effective_version:
            expected = f"{expected}@{result.inventory_entry.effective_version}"
    comparison = f" versus {expected}" if expected else ""
    return f"{source} {observed}{comparison}: {result.detail}"


def _overall_status(statuses: list[str]) -> str:
    if "mismatch" in statuses:
        return "mismatch"
    if "unverifiable" in statuses:
        return "partial"
    if "representation_difference" in statuses:
        return "matched_with_differences"
    return "matched"
