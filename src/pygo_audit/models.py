"""Data models for scan results and serialized reports."""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass, field, fields, is_dataclass, replace
from operator import attrgetter
from pathlib import Path
from typing import Any, ClassVar, Literal

# Ordered choices are shared by validation and report counters.
RUNTIME_DISPOSITIONS = ("runtime", "deleted", "replaced", "unaccounted", "unknown")
MODULE_STATUSES = (
    "exact",
    "replacement",
    "representation_difference",
    "mismatch",
    "unverifiable",
    "stdlib",
)


class JsonModel:
    """Check construction invariants and serialize declared evidence fields."""

    __slots__ = ()
    required_values: ClassVar[tuple[str, ...]] = ()
    optional_fields: ClassVar[tuple[str, ...]] = ()
    field_choices: ClassVar[dict[str, Collection[str]]] = {}

    def __post_init__(self) -> None:
        for name in self.required_values:
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        for name, choices in self.field_choices.items():
            value = getattr(self, name)
            if value not in choices:
                raise ValueError(f"{name} has unsupported value: {value!r}")

    def to_dict(self) -> dict[str, object]:
        if not is_dataclass(self):
            raise TypeError("JSON models must be dataclass instances")
        return {
            item.name: json_value(getattr(self, item.name))
            for item in fields(self)
            if item.name not in self.optional_fields
            or getattr(self, item.name) is not None
        }


def json_value(value: object) -> object:
    if isinstance(value, JsonModel):
        return value.to_dict()
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return {key: json_value(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


@dataclass(slots=True, frozen=True)
class Module(JsonModel):
    path: str = ""  # Module import path recorded by Go.
    version: str = ""  # Recorded module version; empty if unavailable.
    checksum: str = ""  # Go module checksum, distinct from the binary SHA-256.
    replace: Module | None = (
        None  # Replacement module, or None when no replacement was recorded.
    )

    @classmethod
    def from_go_json(cls, value: object) -> Module | None:
        if not isinstance(value, dict) or not value:
            return None

        return cls(
            path=(raw_text if isinstance(raw_text := value.get("Path"), str) else ""),
            version=(raw_text if isinstance(raw_text := value.get("Version"), str) else ""),
            checksum=(raw_text if isinstance(raw_text := value.get("Sum"), str) else ""),
            replace=cls.from_go_json(value.get("Replace")),
        )


@dataclass(slots=True, frozen=True)
class BuildSetting(JsonModel):
    required_values = ("key",)

    key: str  # Build option name, such as GOARCH or CGO_ENABLED.
    value: str  # Option value embedded in the binary.

    @classmethod
    def from_go_json(cls, value: object) -> BuildSetting | None:
        if not isinstance(value, dict):
            return None
        key = value.get("Key")
        setting_value = value.get("Value")
        if not isinstance(key, str) or not isinstance(setting_value, str):
            return None
        return cls(key=key, value=setting_value)


@dataclass(slots=True, frozen=True)
class ModuleInventoryEntry(JsonModel):
    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "source": {"stdlib", "main", "dependency"}
    }

    source: str  # Inventory origin: stdlib, main module, or dependency.
    declared_path: str  # Module path before applying a replacement.
    declared_version: str  # Version before applying a replacement.
    effective_path: str  # Module path after applying a replacement.
    effective_version: str  # Version after applying a replacement.

    @property
    def is_replacement(self) -> bool:
        return (
            self.declared_path != self.effective_path
            or self.declared_version != self.effective_version
        )


@dataclass(slots=True, frozen=True)
class ModuleReconciliation(JsonModel):
    field_choices: ClassVar[dict[str, Collection[str]]] = {"status": MODULE_STATUSES}

    status: str  # Outcome of comparing one observed module to build metadata.
    govulncheck_path: str  # Observed module path; empty for a missing observation.
    govulncheck_version: str  # Observed module version; empty if not reported.
    inventory_entry: ModuleInventoryEntry | None = (
        None  # Matched build inventory entry, if one was found.
    )
    detail: str = ""  # Explanation of the comparison outcome.


@dataclass(slots=True)
class BinaryReconciliation(JsonModel):
    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "status": (
            "matched",
            "matched_with_differences",
            "limited",
            "mismatch",
            "not_run",
        ),
        "go_version_status": (
            "exact",
            "representation_difference",
            "mismatch",
            "unverifiable",
            "not_checked",
        ),
    }

    status: str = (
        "not_run"  # Overall agreement between Go metadata and vulnerability evidence.
    )
    go_version_status: str = (
        "not_checked"  # Outcome of comparing the two reported Go versions.
    )
    go_version_m: str = ""  # Compiler version embedded in the binary.
    govulncheck_go_version: str = ""  # Compiler version reported by govulncheck.
    # Build inventory with replacements applied.
    effective_module_inventory: list[ModuleInventoryEntry] = field(default_factory=list)
    # Recorded comparisons for observed and missing SBOM modules.
    sbom_modules: list[ModuleReconciliation] = field(default_factory=list)

    @property
    def sbom_statuses(self) -> dict[str, int]:
        return dict(Counter(item.status for item in self.sbom_modules))


@dataclass(slots=True, frozen=True)
class VulnerabilityFinding(JsonModel):
    optional_fields = ("symbol",)
    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "evidence": {"module", "package", "symbol"},
        "reachability": {"unspecified"},
    }

    module: str = ""  # Affected module path reported by govulncheck.
    found_version: str = ""  # Observed vulnerable version; empty if not reported.
    fixed_version: str = ""  # Reported fix version; empty if not available.
    package: str = ""  # Affected package path; empty for module-only evidence.
    evidence: str = "module"  # Finest observed precision: module, package, or symbol.
    reachability: str = (
        "unspecified"  # Binary evidence does not establish runtime reachability.
    )
    reconciliation: ModuleReconciliation | None = (
        None  # Comparison with embedded build metadata, if performed.
    )
    symbol: str | None = None  # Observed receiver/function name; None when not recorded.


@dataclass(slots=True)
class Vulnerability(JsonModel):
    required_values = ("id",)

    id: str  # Primary advisory identifier, normally a GO identifier.
    aliases: list[str] = field(
        default_factory=list
    )  # Alternate identifiers, including CVE and GHSA IDs.
    details: str = ""  # Advisory description from the vulnerability database.
    published: str = ""  # Advisory publication timestamp, as reported.
    modified: str = ""  # Advisory modification timestamp, as reported.
    withdrawn: str = ""  # Withdrawal timestamp; empty for an active advisory.
    review_status: str = (
        "REVIEWED"  # Advisory review classification; defaults to REVIEWED.
    )
    advisory_url: str = ""  # Primary advisory link, if supplied.
    references: list[dict[str, str]] = field(
        default_factory=list
    )  # Related links with their recorded type and URL.
    # Normalized affected modules, version ranges, and packages.
    affected: list[dict[str, Any]] = field(default_factory=list)
    findings: list[VulnerabilityFinding] = field(
        default_factory=list
    )  # Observations for this binary; may be empty.


@dataclass(slots=True)
class VulnerabilityScan(JsonModel):
    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "status": {"not_run", "disabled", "failed", "complete"}
    }

    status: str = (
        "not_run"  # Execution outcome; complete does not mean vulnerability-free.
    )
    protocol_version: str = ""  # govulncheck JSON protocol version.
    scanner_name: str = ""  # Vulnerability scanner name from its config message.
    scanner_version: str = ""  # Vulnerability scanner version from its config message.
    database: str = ""  # Vulnerability database URL used for this check.
    database_last_modified: str = (
        ""  # Database freshness timestamp reported by the scanner.
    )
    go_version: str = ""  # Binary compiler version reported in config or SBOM.
    scan_mode: str = ""  # Mode reported by the scanner, normally binary.
    scan_level: str = ""  # Requested evidence precision reported by the scanner.
    sbom: dict[str, Any] | None = (
        None  # Normalized scanner inventory; None when no SBOM was emitted.
    )
    # Recorded advisories and their finding observations.
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str = ""  # Operational failure detail; empty when none was recorded.


@dataclass(slots=True, frozen=True)
class BinaryLayerObservation(JsonModel):
    """One historical observation of a binary in an image layer."""

    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "status": {"found", "replaced", "deleted"}
    }

    layer_index: int  # Zero-based position in the supplied layer sequence.
    status: str  # Found, replaced, or deleted at this layer.
    paths: tuple[str, ...]  # Container paths associated with this layer event.
    symlinks: tuple[str, ...] = ()  # Symlink aliases recorded in this layer.


@dataclass(slots=True, frozen=True)
class FindingOccurrence:
    """One vulnerability finding tied to the binary paths that contain it."""

    vulnerability_id: str  # Primary advisory identifier for this observation.
    aliases: tuple[str, ...]  # Alternate identifiers retained from the advisory.
    advisory_url: str  # Advisory link retained from the source evidence.
    binary_paths: tuple[str, ...]  # Container paths sharing the affected binary record.
    binary_symlinks: tuple[str, ...]  # Symlink aliases to the affected binary.
    binary_sha256: str  # Binary content digest; empty if hashing failed.
    runtime_disposition: str  # This scan's final runtime or historical classification.
    module: str  # Affected module path.
    current_version: str  # Observed module version, copied from found_version.
    fixed_version: str  # Reported fix version; empty if unavailable.
    package: str  # Affected package path; empty for module-only evidence.
    evidence: str  # Recorded module, package, or symbol precision.
    reachability: str  # Recorded reachability conclusion; normally unspecified.
    layer_history: tuple[
        BinaryLayerObservation, ...
    ] = ()  # Historical observations copied from the binary.
    symbol: str | None = None  # Observed symbol copied from the finding, if recorded.

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.vulnerability_id, *self.aliases)))


@dataclass(slots=True)
class BinaryReport(JsonModel):
    required_values = ("paths", "go_version")
    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "runtime_disposition": RUNTIME_DISPOSITIONS
    }

    paths: list[str]  # Observed container paths sharing this binary record.
    size: int  # Binary size in bytes at discovery.
    go_version: str  # Compiler version embedded in the binary.
    main_package: str  # Executable's main package path, if reported.
    main_module: Module | None  # Main module metadata, or None if absent.
    dependencies: list[Module]  # Embedded dependency records, including replacements.
    build_settings: list[
        BuildSetting
    ]  # Compiler and build options embedded in the binary.
    sha256: str = ""  # Lowercase content digest; empty if hashing failed.
    runtime_disposition: str = (
        "unknown"  # Context-specific classification rebuilt for each scan.
    )
    # Ordered historical evidence for this binary.
    layer_history: list[BinaryLayerObservation] = field(default_factory=list)
    # Current scan's vulnerability evidence and execution status.
    vulnerability_scan: VulnerabilityScan = field(default_factory=VulnerabilityScan)
    # Recorded comparison of build metadata and scanner evidence.
    reconciliation: BinaryReconciliation = field(default_factory=BinaryReconciliation)
    symlinks: list[str] = field(default_factory=list)  # Resolved container aliases.

    def __post_init__(self) -> None:
        JsonModel.__post_init__(self)
        if self.sha256 and (
            len(self.sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("sha256 must be 64 lowercase hexadecimal digits")

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
            main_package=(raw_text if isinstance(raw_text := value.get("Path"), str) else ""),
            main_module=Module.from_go_json(value.get("Main")),
            dependencies=dependencies,
            build_settings=settings,
        )

    def to_dict(self) -> dict[str, object]:
        result = JsonModel.to_dict(self)
        result["paths"] = sorted(self.paths)
        result["symlinks"] = sorted(self.symlinks)
        return result

    @property
    def finding_statuses(self) -> dict[str, int]:
        return dict(
            Counter(
                finding.reconciliation.status
                for vulnerability in self.vulnerability_scan.vulnerabilities
                for finding in vulnerability.findings
                if finding.reconciliation is not None
            )
        )

    def finding_occurrences(self) -> list[FindingOccurrence]:
        occurrences = [
            FindingOccurrence(
                vulnerability_id=vulnerability.id,
                aliases=tuple(dict.fromkeys(vulnerability.aliases)),
                advisory_url=vulnerability.advisory_url,
                binary_paths=tuple(sorted(self.paths)),
                binary_symlinks=tuple(sorted(self.symlinks)),
                binary_sha256=self.sha256,
                runtime_disposition=self.runtime_disposition,
                module=finding.module,
                current_version=finding.found_version,
                fixed_version=finding.fixed_version,
                package=finding.package,
                evidence=finding.evidence,
                reachability=finding.reachability,
                layer_history=tuple(self.layer_history),
                symbol=finding.symbol,
            )
            for vulnerability in self.vulnerability_scan.vulnerabilities
            for finding in vulnerability.findings
        ]
        occurrences.sort(key=finding_occurrence_sort_key)
        return occurrences

    @property
    def cgo_enabled(self) -> bool | None:
        values = {
            setting.value.strip().lower()
            for setting in self.build_settings
            if setting.key == "CGO_ENABLED"
        }
        if values and values <= {"1", "true"}:
            return True
        if values and values <= {"0", "false"}:
            return False
        return None


@dataclass(slots=True, frozen=True)
class ScanIssue(JsonModel):
    path: str  # Affected container path, possibly prefixed with a layer label.
    stage: str  # Processing stage that emitted the diagnostic.
    message: str  # Human-readable explanation of the observation or failure.

    @property
    def is_informational(self) -> bool:
        return self.stage == "reconciliation-difference"


@dataclass(slots=True)
class ScanStats(JsonModel):
    directories: int = 0  # Directories visited across the supplied subjects.
    entries: int = 0  # Directory entries examined, including skipped entries.
    regular_files: int = 0  # Regular-file paths seen, including hard-link aliases.
    unique_regular_files: int = 0  # Distinct device/inode pairs seen per subject.
    elf_paths: int = 0  # Paths recognized as ELF, including hard-link aliases.
    unique_elf_files: int = 0  # Distinct ELF device/inode pairs seen per subject.
    symlinks_skipped: int = 0  # Symbolic links excluded from binary discovery.
    special_files_skipped: int = (
        0  # Non-directory, non-regular, non-symlink entries skipped.
    )


@dataclass(slots=True, frozen=True)
class ProductIdentity(JsonModel):
    """A product context supplied by a user or metadata helper."""

    name: str = ""
    component: str = ""
    version: str = ""
    release: str = ""
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()  # Supplied provenance, not independently verified.


@dataclass(slots=True, frozen=True)
class ImageIdentity(JsonModel):
    reference: str = ""  # Supplied registry image reference, if known.
    digest: str = ""  # Full OCI algorithm:hex image digest.
    platform: str = ""  # Supplied OS/architecture identity.
    extractor: str = ""  # Tool or process that prepared the container filesystem.
    name: str = ""  # Supplied image name used for product matching.
    vendor_image_name: str = ""  # Image name supplied by the vendor's image label.
    image_build_release: str = ""  # Image build release supplied by the vendor's label.
    component: str = ""  # Supplied component identity, independent of its version.
    source_git_url: str = ""  # Source repository URL recorded in image metadata.
    product_version: str = ""  # Version of the enclosing product or release.
    component_version: str = ""  # Version of this image's component.
    product_component: str = ""  # Product-maintainer component label.
    cpes: tuple[str, ...] = ()  # Platform alternatives for this image only.
    purls: tuple[str, ...] = ()  # Explicit package identities for this image.
    sources: tuple[str, ...] = ()  # Supplied provenance for the final image.
    products: tuple[ProductIdentity, ...] = ()  # Separately supplied product contexts.
    csaf_product_ids: tuple[str, ...] = ()  # Exact, user-selected CSAF entries.

    @property
    def digest_short(self) -> str:
        return self.digest.split(":", 1)[-1][:12] if self.digest else ""

    @property
    def is_present(self) -> bool:
        return any(self.to_dict().values())


@dataclass(slots=True)
class ContainerMetadata(JsonModel):
    required_values = ("root",)

    root: str  # Host path of the scanned root filesystem.
    image: ImageIdentity = field(
        default_factory=ImageIdentity
    )  # Recorded image identity; empty fields mean unknown.


@dataclass(slots=True)
class AuditReport(JsonModel):
    """Saved evidence and provenance for one container, including its layers."""

    field_choices: ClassVar[dict[str, Collection[str]]] = {
        "govulncheck_status": {"disabled", "available", "unavailable"}
    }

    metadata: ContainerMetadata  # Container subject and recorded image identity.
    go_command: str  # Host Go executable used to inspect binaries.
    go_tool_version: str  # Version of the host Go inspection tool.
    # Go binary records composed from rootfs and optional layers.
    binaries: list[BinaryReport] = field(default_factory=list)
    issues: list[ScanIssue] = field(
        default_factory=list
    )  # Operational and informational scan diagnostics.
    stats: ScanStats = field(
        default_factory=ScanStats
    )  # Discovery and composition counters for this scan.
    producer_name: str = ""  # Audit producer name; required in saved evidence.
    producer_version: str = ""  # Audit producer version; required in saved evidence.
    govulncheck_status: str = (
        "disabled"  # Tool availability, distinct from per-binary scan outcomes.
    )
    govulncheck_command: str = ""  # Host vulnerability scanner command, if enabled.
    govulncheck_tool_version: str = (
        ""  # Version output collected from the host scanner.
    )
    scan_started_at: str = (
        ""  # UTC scan start timestamp; empty before provenance is set.
    )
    scan_completed_at: str = (
        ""  # UTC scan completion timestamp; empty while assembling.
    )
    run_id: str = ""  # Scan/batch lifetime identifier for vulnerability-cache reuse.
    schema_version: Literal[4] = (
        4  # Current audit contract includes vendor image identity labels.
    )

    @property
    def unaccounted_historical_binaries(self) -> list[BinaryReport]:
        """Return non-runtime binaries without deletion or replacement evidence."""
        return [
            binary
            for binary in self.binaries
            if binary.runtime_disposition == "unaccounted"
        ]

    def unaccounted_historical_findings(self) -> list[FindingOccurrence]:
        """Return findings attached to unaccounted historical binaries."""
        return [
            occurrence
            for binary in self.unaccounted_historical_binaries
            for occurrence in binary.finding_occurrences()
        ]

    def finding_occurrences(self) -> list[FindingOccurrence]:
        occurrences = [
            occurrence
            for binary in self.binaries
            for occurrence in binary.finding_occurrences()
        ]
        occurrences.sort(key=finding_occurrence_sort_key)
        return occurrences

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
            binary.vulnerability_scan.status == "complete" for binary in self.binaries
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

    def to_dict(self) -> dict[str, object]:
        return JsonModel.to_dict(replace(
            self,
            binaries=sorted(self.binaries, key=lambda binary: min(binary.paths)),
            issues=sorted(self.issues, key=attrgetter("path", "stage")),
        ))


@dataclass(slots=True, frozen=True)
class CveEvidence:
    """References to saved binary/advisory observations for one container CVE."""

    cve: str  # Normalized CVE identifier shared by these observations.
    observations: tuple[
        tuple[BinaryReport, Vulnerability], ...
    ] = ()  # Original records, including advisories with no findings.


@dataclass(slots=True, frozen=True)
class TargetOutcome:
    """Execution status and evidence location for one batch target."""

    name: str  # Target workspace name used in progress and summary output.
    status: Literal[
        "COMPLETE", "FAILED", "CANCELLED"
    ]  # Execution outcome, independent of vulnerability findings.
    audit_file: Path | None = (
        None  # Actual published evidence path, including strict failed scans.
    )
    detail: str = ""  # Failure or cancellation explanation, if present.

    def summary(self) -> str:
        return (
            f"{self.name}: {self.status}"
            + (f" — {self.audit_file}" if self.audit_file else "")
            + (f" — {self.detail}" if self.detail else "")
        )


@dataclass(slots=True)
class ReconciliationDiagnostic:
    """A saved reconciliation outcome grouped for display across binaries."""

    status: str  # Unverifiable, mismatch, or representation difference.

    reason: str  # Diagnostic cause code.
    kind: str  # Go-toolchain or component comparison.
    declared: str  # Display label for the original build declaration.
    effective: str  # Display label after applying a replacement.
    observed: str  # Display label for govulncheck's observation.
    description: str  # Explanation of the recorded comparison.
    sources: set[str] = field(
        default_factory=set
    )  # Evidence sources that share this diagnostic.
    binaries: list[BinaryReport] = field(
        default_factory=list
    )  # Original records, including historical binaries sharing a path.


@dataclass(slots=True)
class DependencyReconciliationRow:
    """A declared module with its observed inventory and vulnerable packages."""

    # Declared/effective module inventory entry being displayed.
    entry: ModuleInventoryEntry
    # SBOM comparisons associated with this inventory entry.
    observations: list[ModuleReconciliation] = field(default_factory=list)
    vulnerable_findings: list[tuple[str, VulnerabilityFinding]] = field(
        default_factory=list
    )  # Advisory identifier and finding pairs for this module.


@dataclass(slots=True)
class FindingSummary:
    """Display evidence grouped by advisory, package, module, and both versions."""

    identifier: str
    package: str
    module: str
    current_version: str
    fixed_version: str
    aliases: set[str]
    advisory_urls: set[str]
    evidence: set[str]
    reachability: set[str]
    observation_count: int


finding_occurrence_sort_key = attrgetter(
    "vulnerability_id", "binary_paths", "package", "module", "current_version"
)
