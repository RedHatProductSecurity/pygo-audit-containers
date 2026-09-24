"""Data models for scan results and serialized reports."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class Module:
    path: str = ""
    version: str = ""
    sum: str = ""
    replace: Module | None = None

    @classmethod
    def from_go_json(cls, value: object) -> Module | None:
        if not isinstance(value, dict) or not value:
            return None

        return cls(
            path=_string(value.get("Path")),
            version=_string(value.get("Version")),
            sum=_string(value.get("Sum")),
            replace=cls.from_go_json(value.get("Replace")),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "version": self.version,
            "sum": self.sum,
        }
        if self.replace is not None:
            result["replace"] = self.replace.to_dict()
        return result

    def identity(self) -> tuple[object, ...]:
        replacement = self.replace.identity() if self.replace is not None else None
        return (self.path, self.version, self.sum, replacement)


@dataclass(slots=True, frozen=True)
class BuildSetting:
    key: str
    value: str

    @classmethod
    def from_go_json(cls, value: object) -> BuildSetting | None:
        if not isinstance(value, dict):
            return None
        key = value.get("Key")
        setting_value = value.get("Value")
        if not isinstance(key, str) or not isinstance(setting_value, str):
            return None
        return cls(key=key, value=setting_value)

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass(slots=True, frozen=True)
class ModuleInventoryEntry:
    source: str
    declared_path: str
    declared_version: str
    effective_path: str
    effective_version: str

    @property
    def is_replacement(self) -> bool:
        return (
            self.declared_path != self.effective_path
            or self.declared_version != self.effective_version
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "declared": {
                "path": self.declared_path,
                "version": self.declared_version,
            },
            "effective": {
                "path": self.effective_path,
                "version": self.effective_version,
            },
            "replacement": self.is_replacement,
        }


@dataclass(slots=True, frozen=True)
class ModuleReconciliation:
    status: str
    govulncheck_path: str
    govulncheck_version: str
    inventory_entry: ModuleInventoryEntry | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "govulncheck": {
                "path": self.govulncheck_path,
                "version": self.govulncheck_version,
            },
            "go_version_m": (
                self.inventory_entry.to_dict()
                if self.inventory_entry is not None
                else None
            ),
            "detail": self.detail,
        }


@dataclass(slots=True)
class BinaryReconciliation:
    status: str = "not_run"
    go_version_status: str = "not_checked"
    go_version_m: str = ""
    govulncheck_go_version: str = ""
    effective_module_inventory: list[ModuleInventoryEntry] = field(
        default_factory=list
    )
    sbom_modules: list[ModuleReconciliation] = field(default_factory=list)
    finding_statuses: dict[str, int] = field(default_factory=dict)
    sbom_statuses: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "go_version": {
                "status": self.go_version_status,
                "go_version_m": self.go_version_m,
                "govulncheck": self.govulncheck_go_version,
            },
            "effective_module_inventory": [
                entry.to_dict() for entry in self.effective_module_inventory
            ],
            "sbom_modules": [module.to_dict() for module in self.sbom_modules],
            "finding_statuses": dict(sorted(self.finding_statuses.items())),
            "sbom_statuses": dict(sorted(self.sbom_statuses.items())),
        }


@dataclass(slots=True, frozen=True)
class VulnerabilityFinding:
    module: str = ""
    found_version: str = ""
    fixed_version: str = ""
    package: str = ""
    symbol: str = ""
    evidence: str = "module"
    reachability: str = "unknown"
    reconciliation: ModuleReconciliation | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "found_version": self.found_version,
            "fixed_version": self.fixed_version,
            "package": self.package,
            "symbol": self.symbol,
            "evidence": self.evidence,
            "reachability": self.reachability,
            "reconciliation": (
                self.reconciliation.to_dict()
                if self.reconciliation is not None
                else None
            ),
        }


@dataclass(slots=True)
class Vulnerability:
    id: str
    aliases: list[str] = field(default_factory=list)
    details: str = ""
    published: str = ""
    modified: str = ""
    withdrawn: str = ""
    review_status: str = "REVIEWED"
    advisory_url: str = ""
    references: list[dict[str, str]] = field(default_factory=list)
    affected: list[dict[str, Any]] = field(default_factory=list)
    findings: list[VulnerabilityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "aliases": self.aliases,
            "details": self.details,
            "published": self.published,
            "modified": self.modified,
            "withdrawn": self.withdrawn,
            "review_status": self.review_status,
            "advisory_url": self.advisory_url,
            "references": self.references,
            "affected": self.affected,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class VulnerabilityScan:
    status: str = "not_run"
    protocol_version: str = ""
    scanner_name: str = ""
    scanner_version: str = ""
    database: str = ""
    database_last_modified: str = ""
    go_version: str = ""
    scan_mode: str = ""
    scan_level: str = ""
    sbom: dict[str, Any] | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "protocol_version": self.protocol_version,
            "scanner": {
                "name": self.scanner_name,
                "version": self.scanner_version,
            },
            "database": {
                "url": self.database,
                "last_modified": self.database_last_modified,
            },
            "go_version": self.go_version,
            "scan_mode": self.scan_mode,
            "scan_level": self.scan_level,
            "sbom": self.sbom,
            "vulnerabilities": [
                vulnerability.to_dict() for vulnerability in self.vulnerabilities
            ],
            "error": self.error,
        }


@dataclass(slots=True, frozen=True)
class FindingOccurrence:
    """One vulnerability finding tied to the binary paths that contain it."""

    vulnerability_id: str
    aliases: tuple[str, ...]
    advisory_url: str
    binary_paths: tuple[str, ...]
    binary_sha256: str
    module: str
    current_version: str
    fixed_version: str
    package: str
    symbol: str
    evidence: str
    reachability: str

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.vulnerability_id, *self.aliases)))

    def matches_identifier(self, identifier: str) -> bool:
        requested = identifier.strip().upper()
        return any(value.upper() == requested for value in self.identifiers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "aliases": list(self.aliases),
            "advisory_url": self.advisory_url,
            "binary_paths": list(self.binary_paths),
            "binary_sha256": self.binary_sha256,
            "module": self.module,
            "current_version": self.current_version,
            "fixed_version": self.fixed_version,
            "package": self.package,
            "symbol": self.symbol,
            "evidence": self.evidence,
            "reachability": self.reachability,
        }


@dataclass(slots=True)
class BinaryReport:
    paths: list[str]
    size: int
    go_version: str
    main_package: str
    main_module: Module | None
    dependencies: list[Module]
    build_settings: list[BuildSetting]
    sha256: str = ""
    vulnerability_scan: VulnerabilityScan = field(default_factory=VulnerabilityScan)
    reconciliation: BinaryReconciliation = field(default_factory=BinaryReconciliation)

    @classmethod
    def from_go_json(
        cls,
        value: object,
        *,
        container_path: str,
        size: int,
    ) -> BinaryReport:
        if not isinstance(value, dict):
            raise ValueError("Go returned a JSON value that is not an object")

        go_version = value.get("GoVersion")
        if not isinstance(go_version, str) or not go_version:
            raise ValueError("Go JSON output does not contain GoVersion")

        raw_dependencies = value.get("Deps", [])
        if not isinstance(raw_dependencies, list):
            raise ValueError("Go JSON output contains a non-list Deps field")
        dependencies = [
            module
            for raw_module in raw_dependencies
            if (module := Module.from_go_json(raw_module)) is not None
        ]

        raw_settings = value.get("Settings", [])
        if not isinstance(raw_settings, list):
            raise ValueError("Go JSON output contains a non-list Settings field")
        settings = [
            setting
            for raw_setting in raw_settings
            if (setting := BuildSetting.from_go_json(raw_setting)) is not None
        ]

        return cls(
            paths=[container_path],
            size=size,
            go_version=go_version,
            main_package=_string(value.get("Path")),
            main_module=Module.from_go_json(value.get("Main")),
            dependencies=dependencies,
            build_settings=settings,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": sorted(self.paths),
            "size": self.size,
            "sha256": self.sha256,
            "go_version": self.go_version,
            "cgo_enabled": self.cgo_enabled,
            "main_package": self.main_package,
            "main_module": (
                self.main_module.to_dict() if self.main_module is not None else None
            ),
            "dependencies": [module.to_dict() for module in self.dependencies],
            "build_settings": [setting.to_dict() for setting in self.build_settings],
            "vulnerability_scan": self.vulnerability_scan.to_dict(),
            "reconciliation": self.reconciliation.to_dict(),
        }

    def finding_occurrences(self) -> list[FindingOccurrence]:
        occurrences = [
            FindingOccurrence(
                vulnerability_id=vulnerability.id,
                aliases=tuple(dict.fromkeys(vulnerability.aliases)),
                advisory_url=vulnerability.advisory_url,
                binary_paths=tuple(sorted(self.paths)),
                binary_sha256=self.sha256,
                module=finding.module,
                current_version=finding.found_version,
                fixed_version=finding.fixed_version,
                package=finding.package,
                symbol=finding.symbol,
                evidence=finding.evidence,
                reachability=finding.reachability,
            )
            for vulnerability in self.vulnerability_scan.vulnerabilities
            for finding in vulnerability.findings
        ]
        occurrences.sort(key=_finding_occurrence_sort_key)
        return occurrences

    @property
    def cgo_enabled(self) -> bool:
        return any(
            setting.key == "CGO_ENABLED"
            and setting.value.strip().lower() in {"1", "true"}
            for setting in self.build_settings
        )


@dataclass(slots=True, frozen=True)
class ScanIssue:
    path: str
    stage: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "stage": self.stage, "message": self.message}

    @property
    def is_informational(self) -> bool:
        return self.stage == "reconciliation-difference"


@dataclass(slots=True)
class ScanStats:
    directories: int = 0
    entries: int = 0
    regular_files: int = 0
    unique_regular_files: int = 0
    elf_paths: int = 0
    unique_elf_files: int = 0
    go_binaries: int = 0
    go_binary_paths: int = 0
    symlinks_skipped: int = 0
    special_files_skipped: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "directories": self.directories,
            "entries": self.entries,
            "regular_files": self.regular_files,
            "unique_regular_files": self.unique_regular_files,
            "elf_paths": self.elf_paths,
            "unique_elf_files": self.unique_elf_files,
            "go_binaries": self.go_binaries,
            "go_binary_paths": self.go_binary_paths,
            "symlinks_skipped": self.symlinks_skipped,
            "special_files_skipped": self.special_files_skipped,
        }


@dataclass(slots=True, frozen=True)
class ImageIdentity:
    reference: str = ""
    digest: str = ""
    platform: str = ""
    extractor: str = ""

    @property
    def is_present(self) -> bool:
        return any((self.reference, self.digest, self.platform, self.extractor))

    def to_dict(self) -> dict[str, str]:
        return {
            "reference": self.reference,
            "digest": self.digest,
            "platform": self.platform,
            "extractor": self.extractor,
        }


@dataclass(slots=True)
class ScanReport:
    root: str
    go_command: str
    go_tool_version: str
    producer_name: str = ""
    producer_version: str = ""
    govulncheck_status: str = "disabled"
    govulncheck_command: str = ""
    govulncheck_tool_version: str = ""
    scan_started_at: str = ""
    scan_completed_at: str = ""
    image_identity: ImageIdentity = field(default_factory=ImageIdentity)
    binaries: list[BinaryReport] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def dependency_summary(self) -> list[dict[str, Any]]:
        usages: dict[tuple[object, ...], tuple[Module, set[str]]] = {}
        for binary in self.binaries:
            for module in binary.dependencies:
                key = module.identity()
                if key not in usages:
                    usages[key] = (module, set())
                usages[key][1].update(binary.paths)

        summary: list[dict[str, Any]] = []
        for module, paths in usages.values():
            item = module.to_dict()
            item["used_by"] = sorted(paths)
            summary.append(item)
        summary.sort(key=lambda item: (item["path"], item["version"], item["sum"]))
        return summary

    def finding_occurrences(self) -> list[FindingOccurrence]:
        occurrences = [
            occurrence
            for binary in self.binaries
            for occurrence in binary.finding_occurrences()
        ]
        occurrences.sort(key=_finding_occurrence_sort_key)
        return occurrences

    def findings_for_identifier(self, identifier: str) -> list[FindingOccurrence]:
        return [
            occurrence
            for occurrence in self.finding_occurrences()
            if occurrence.matches_identifier(identifier)
        ]

    def vulnerability_scan_counts(self) -> dict[str, int]:
        return dict(
            sorted(
                Counter(
                    binary.vulnerability_scan.status for binary in self.binaries
                ).items()
            )
        )

    def vulnerability_databases(self) -> list[dict[str, str]]:
        observations = {
            (
                binary.vulnerability_scan.database,
                binary.vulnerability_scan.database_last_modified,
            )
            for binary in self.binaries
            if binary.vulnerability_scan.database
        }
        return [
            {"url": url, "last_modified": last_modified}
            for url, last_modified in sorted(observations)
        ]

    @property
    def complete_vulnerability_scans(self) -> int:
        return sum(
            binary.vulnerability_scan.status == "complete"
            for binary in self.binaries
        )

    @property
    def incomplete_vulnerability_scans(self) -> int:
        return len(self.binaries) - self.complete_vulnerability_scans

    @property
    def coverage_state(self) -> str:
        if not self.binaries:
            return "no_go_binaries"
        if self.incomplete_vulnerability_scans:
            return "incomplete"
        return "complete"

    @property
    def actionable_issues(self) -> list[ScanIssue]:
        return [issue for issue in self.issues if not issue.is_informational]

    @property
    def result_state(self) -> str:
        if self.finding_occurrences():
            return "vulnerable"
        if not self.binaries:
            return "operational_error" if self.actionable_issues else "no_go_binaries"
        if self.incomplete_vulnerability_scans:
            return "incomplete"
        if self.actionable_issues:
            return "operational_error"
        return "clean"

    def to_dict(self) -> dict[str, Any]:
        binaries = sorted(self.binaries, key=lambda binary: min(binary.paths))
        issues = sorted(self.issues, key=lambda issue: (issue.path, issue.stage))
        return {
            "schema_version": 6,
            "root": self.root,
            "producer": {
                "name": self.producer_name,
                "version": self.producer_version,
            },
            "subject": {
                "type": (
                    "container_image"
                    if self.image_identity.is_present
                    else "unpacked_rootfs"
                ),
                "image": (
                    self.image_identity.to_dict()
                    if self.image_identity.is_present
                    else None
                ),
            },
            "scan": {
                "started_at": self.scan_started_at,
                "completed_at": self.scan_completed_at,
            },
            "toolchain": {
                "command": self.go_command,
                "version": self.go_tool_version,
            },
            "vulnerability_toolchain": {
                "status": self.govulncheck_status,
                "command": self.govulncheck_command,
                "version": self.govulncheck_tool_version,
            },
            "vulnerability_databases": self.vulnerability_databases(),
            "binaries": [binary.to_dict() for binary in binaries],
            "dependency_summary": self.dependency_summary(),
            "issues": [issue.to_dict() for issue in issues],
            "stats": self.stats.to_dict(),
        }


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _finding_occurrence_sort_key(
    occurrence: FindingOccurrence,
) -> tuple[object, ...]:
    return (
        occurrence.vulnerability_id,
        occurrence.binary_paths,
        occurrence.package,
        occurrence.module,
        occurrence.current_version,
        occurrence.symbol,
    )
