"""Immutable, content-addressed scan snapshot support."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from pygo_audit.models import (
    BinaryReconciliation,
    BinaryReport,
    BuildSetting,
    ImageIdentity,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
    ScanIssue,
    ScanReport,
    ScanStats,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)


CURRENT_SCHEMA_VERSION = 6
SUPPORTED_SCHEMA_VERSIONS = {3, 4, 5, CURRENT_SCHEMA_VERSION}
_CONTENT_ADDRESS_NAME = re.compile(r"[0-9a-fA-F]{64}")


class SnapshotError(ValueError):
    """Raised when a scan snapshot cannot be stored or reconstructed."""


def write_snapshot(report: ScanReport, snapshot_directory: Path) -> Path:
    """Write an immutable, content-addressed scan snapshot."""
    document = report.to_dict()
    digest = snapshot_digest(report)
    directory = Path(snapshot_directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SnapshotError(
            f"cannot create snapshot store {directory}: {_os_error(error)}"
        ) from error
    if not directory.is_dir():
        raise SnapshotError(f"snapshot store is not a directory: {directory}")

    destination = directory / f"{digest}.json"
    payload = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=directory,
            prefix=".pygo-audit-",
            suffix=".tmp",
            delete=False,
        ) as snapshot_file:
            temporary_path = Path(snapshot_file.name)
            snapshot_file.write(payload)
            snapshot_file.flush()
            os.fsync(snapshot_file.fileno())
        try:
            os.link(temporary_path, destination)
        except FileExistsError:
            existing = _read_json_document(destination)
            if _document_digest(existing) != digest:
                raise SnapshotError(
                    f"snapshot does not match its content address: {destination}"
                )
    except SnapshotError:
        raise
    except OSError as error:
        raise SnapshotError(
            f"cannot write snapshot {destination}: {_os_error(error)}"
        ) from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
    return destination


def snapshot_digest(report: ScanReport) -> str:
    """Return the semantic SHA-256 content address for a scan snapshot."""
    return _document_digest(report.to_dict())


def load_snapshot(snapshot_path: Path) -> ScanReport:
    """Load a supported snapshot from a JSON file or single-snapshot directory."""
    path = _resolve_snapshot_path(Path(snapshot_path))
    document = _read_json_document(path)
    _verify_content_address(path, document)
    try:
        return _parse_scan_report(document)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, SnapshotError):
            raise
        raise SnapshotError(f"invalid snapshot {path}: {error}") from error


def _resolve_snapshot_path(path: Path) -> Path:
    if path.is_dir():
        try:
            snapshots = sorted(
                candidate
                for candidate in path.iterdir()
                if candidate.is_file() and candidate.suffix == ".json"
            )
        except OSError as error:
            raise SnapshotError(
                f"cannot inspect snapshot store {path}: {_os_error(error)}"
            ) from error
        if not snapshots:
            raise SnapshotError(f"snapshot store contains no JSON snapshots: {path}")
        if len(snapshots) > 1:
            raise SnapshotError(
                f"snapshot store contains {len(snapshots)} snapshots; "
                "select one JSON file"
            )
        return snapshots[0]
    return path


def _read_json_document(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as snapshot_file:
            value = json.load(snapshot_file)
    except FileNotFoundError as error:
        raise SnapshotError(f"snapshot does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise SnapshotError(
            f"snapshot is not valid JSON at line {error.lineno}, "
            f"column {error.colno}: {path}"
        ) from error
    except OSError as error:
        raise SnapshotError(
            f"cannot read snapshot {path}: {_os_error(error)}"
        ) from error
    if not isinstance(value, dict):
        raise SnapshotError(f"snapshot is not a JSON object: {path}")
    return value


def _document_digest(document: dict[str, Any]) -> str:
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_content_address(path: Path, document: dict[str, Any]) -> None:
    if _CONTENT_ADDRESS_NAME.fullmatch(path.stem) is None:
        return
    expected = path.stem.lower()
    actual = _document_digest(document)
    if actual != expected:
        raise SnapshotError(
            f"snapshot does not match its content address: {path}; "
            f"expected {expected}, computed {actual}"
        )


def _parse_scan_report(value: dict[str, Any]) -> ScanReport:
    schema_version = value.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise SnapshotError(
            f"unsupported snapshot schema {schema_version!r}; "
            f"expected one of {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )

    producer = (
        _mapping(value.get("producer"), "producer")
        if schema_version >= 6
        else _optional_mapping(value.get("producer"), "producer")
    )
    subject = _optional_mapping(value.get("subject"), "subject")
    scan = _optional_mapping(value.get("scan"), "scan")
    toolchain = _mapping(value.get("toolchain"), "toolchain")
    vulnerability_toolchain = _mapping(
        value.get("vulnerability_toolchain"),
        "vulnerability_toolchain",
    )
    report = ScanReport(
        root=_required_string(value.get("root"), "root"),
        producer_name=(
            _required_string(producer.get("name"), "producer.name")
            if schema_version >= 6
            else _string(producer.get("name"))
        ),
        producer_version=(
            _required_string(producer.get("version"), "producer.version")
            if schema_version >= 6
            else _string(producer.get("version"))
        ),
        go_command=_string(toolchain.get("command")),
        go_tool_version=_string(toolchain.get("version")),
        govulncheck_status=_string(vulnerability_toolchain.get("status")),
        govulncheck_command=_string(vulnerability_toolchain.get("command")),
        govulncheck_tool_version=_string(vulnerability_toolchain.get("version")),
        scan_started_at=_string(scan.get("started_at")),
        scan_completed_at=_string(scan.get("completed_at")),
        image_identity=_parse_image_identity(subject.get("image")),
        binaries=[
            _parse_binary(item)
            for item in _mapping_list(value.get("binaries"), "binaries")
        ],
        issues=[
            ScanIssue(
                path=_string(item.get("path")),
                stage=_string(item.get("stage")),
                message=_string(item.get("message")),
            )
            for item in _mapping_list(value.get("issues"), "issues")
        ],
        stats=_parse_stats(_mapping(value.get("stats"), "stats")),
    )
    if schema_version >= 6:
        database_observations = [
            {
                "url": _required_string(item.get("url"), "database URL"),
                "last_modified": _string(item.get("last_modified")),
            }
            for item in _mapping_list(
                value.get("vulnerability_databases"),
                "vulnerability_databases",
            )
        ]
        if database_observations != report.vulnerability_databases():
            raise SnapshotError(
                "vulnerability_databases does not match per-binary observations"
            )
    report.binaries.sort(key=lambda binary: min(binary.paths))
    return report


def _parse_image_identity(value: object) -> ImageIdentity:
    if value is None:
        return ImageIdentity()
    image = _mapping(value, "subject image")
    return ImageIdentity(
        reference=_string(image.get("reference")),
        digest=_string(image.get("digest")),
        platform=_string(image.get("platform")),
        extractor=_string(image.get("extractor")),
    )


def _parse_binary(value: dict[str, Any]) -> BinaryReport:
    paths = _string_list(value.get("paths"), "binary paths")
    if not paths:
        raise SnapshotError("binary paths must not be empty")
    return BinaryReport(
        paths=paths,
        size=_integer(value.get("size"), "binary size"),
        sha256=_sha256(value.get("sha256")),
        go_version=_required_string(value.get("go_version"), "binary go_version"),
        main_package=_string(value.get("main_package")),
        main_module=_parse_optional_module(value.get("main_module")),
        dependencies=[
            _parse_module(item)
            for item in _mapping_list(value.get("dependencies"), "dependencies")
        ],
        build_settings=[
            BuildSetting(
                key=_required_string(item.get("key"), "build setting key"),
                value=_string(item.get("value")),
            )
            for item in _mapping_list(value.get("build_settings"), "build_settings")
        ],
        vulnerability_scan=_parse_vulnerability_scan(
            _mapping(value.get("vulnerability_scan"), "vulnerability_scan")
        ),
        reconciliation=_parse_binary_reconciliation(
            _mapping(value.get("reconciliation"), "reconciliation")
        ),
    )


def _parse_module(value: dict[str, Any]) -> Module:
    replacement = value.get("replace")
    return Module(
        path=_string(value.get("path")),
        version=_string(value.get("version")),
        sum=_string(value.get("sum")),
        replace=(
            _parse_module(_mapping(replacement, "module replacement"))
            if replacement is not None
            else None
        ),
    )


def _parse_optional_module(value: object) -> Module | None:
    if value is None:
        return None
    return _parse_module(_mapping(value, "main_module"))


def _parse_vulnerability_scan(value: dict[str, Any]) -> VulnerabilityScan:
    scanner = _mapping(value.get("scanner"), "vulnerability scanner")
    database = _mapping(value.get("database"), "vulnerability database")
    sbom = value.get("sbom")
    if sbom is not None and not isinstance(sbom, dict):
        raise SnapshotError("vulnerability SBOM must be an object or null")
    return VulnerabilityScan(
        status=_string(value.get("status")),
        protocol_version=_string(value.get("protocol_version")),
        scanner_name=_string(scanner.get("name")),
        scanner_version=_string(scanner.get("version")),
        database=_string(database.get("url")),
        database_last_modified=_string(database.get("last_modified")),
        go_version=_string(value.get("go_version")),
        scan_mode=_string(value.get("scan_mode")),
        scan_level=_string(value.get("scan_level")),
        sbom=sbom,
        vulnerabilities=[
            _parse_vulnerability(item)
            for item in _mapping_list(
                value.get("vulnerabilities"),
                "vulnerabilities",
            )
        ],
        error=_string(value.get("error")),
    )


def _parse_vulnerability(value: dict[str, Any]) -> Vulnerability:
    references = _mapping_list(value.get("references"), "vulnerability references")
    affected = _mapping_list(value.get("affected"), "vulnerability affected")
    return Vulnerability(
        id=_required_string(value.get("id"), "vulnerability id"),
        aliases=_string_list(value.get("aliases"), "vulnerability aliases"),
        details=_string(value.get("details")),
        published=_string(value.get("published")),
        modified=_string(value.get("modified")),
        withdrawn=_string(value.get("withdrawn")),
        review_status=_string(value.get("review_status")),
        advisory_url=_string(value.get("advisory_url")),
        references=[
            {str(key): _string(item_value) for key, item_value in item.items()}
            for item in references
        ],
        affected=affected,
        findings=[
            _parse_vulnerability_finding(item)
            for item in _mapping_list(value.get("findings"), "vulnerability findings")
        ],
    )


def _parse_vulnerability_finding(value: dict[str, Any]) -> VulnerabilityFinding:
    reconciliation = value.get("reconciliation")
    return VulnerabilityFinding(
        module=_string(value.get("module")),
        found_version=_string(value.get("found_version")),
        fixed_version=_string(value.get("fixed_version")),
        package=_string(value.get("package")),
        symbol=_string(value.get("symbol")),
        evidence=_string(value.get("evidence")) or "module",
        reachability=_string(value.get("reachability")) or "unknown",
        reconciliation=(
            _parse_module_reconciliation(
                _mapping(reconciliation, "finding reconciliation")
            )
            if reconciliation is not None
            else None
        ),
    )


def _parse_binary_reconciliation(value: dict[str, Any]) -> BinaryReconciliation:
    go_version = _mapping(value.get("go_version"), "reconciliation go_version")
    return BinaryReconciliation(
        status=_string(value.get("status")) or "not_run",
        go_version_status=_string(go_version.get("status")) or "not_checked",
        go_version_m=_string(go_version.get("go_version_m")),
        govulncheck_go_version=_string(go_version.get("govulncheck")),
        effective_module_inventory=[
            _parse_inventory_entry(item)
            for item in _mapping_list(
                value.get("effective_module_inventory"),
                "effective module inventory",
            )
        ],
        sbom_modules=[
            _parse_module_reconciliation(item)
            for item in _mapping_list(value.get("sbom_modules"), "SBOM modules")
        ],
        finding_statuses=_integer_mapping(
            value.get("finding_statuses"),
            "finding statuses",
        ),
        sbom_statuses=_integer_mapping(
            value.get("sbom_statuses"),
            "SBOM statuses",
        ),
    )


def _parse_module_reconciliation(value: dict[str, Any]) -> ModuleReconciliation:
    govulncheck = _mapping(value.get("govulncheck"), "govulncheck component")
    inventory = value.get("go_version_m")
    return ModuleReconciliation(
        status=_string(value.get("status")),
        govulncheck_path=_string(govulncheck.get("path")),
        govulncheck_version=_string(govulncheck.get("version")),
        inventory_entry=(
            _parse_inventory_entry(_mapping(inventory, "go version inventory entry"))
            if inventory is not None
            else None
        ),
        detail=_string(value.get("detail")),
    )


def _parse_inventory_entry(value: dict[str, Any]) -> ModuleInventoryEntry:
    declared = _mapping(value.get("declared"), "declared module")
    effective = _mapping(value.get("effective"), "effective module")
    return ModuleInventoryEntry(
        source=_string(value.get("source")),
        declared_path=_string(declared.get("path")),
        declared_version=_string(declared.get("version")),
        effective_path=_string(effective.get("path")),
        effective_version=_string(effective.get("version")),
    )


def _parse_stats(value: dict[str, Any]) -> ScanStats:
    return ScanStats(
        directories=_integer(value.get("directories"), "stats.directories"),
        entries=_integer(value.get("entries"), "stats.entries"),
        regular_files=_integer(value.get("regular_files"), "stats.regular_files"),
        unique_regular_files=_integer(
            value.get("unique_regular_files"),
            "stats.unique_regular_files",
        ),
        elf_paths=_integer(value.get("elf_paths"), "stats.elf_paths"),
        unique_elf_files=_integer(
            value.get("unique_elf_files"),
            "stats.unique_elf_files",
        ),
        go_binaries=_integer(value.get("go_binaries"), "stats.go_binaries"),
        go_binary_paths=_integer(
            value.get("go_binary_paths"),
            "stats.go_binary_paths",
        ),
        symlinks_skipped=_integer(
            value.get("symlinks_skipped"),
            "stats.symlinks_skipped",
        ),
        special_files_skipped=_integer(
            value.get("special_files_skipped"),
            "stats.special_files_skipped",
        ),
    )


def _mapping(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotError(f"{field_name} must be an object")
    return value


def _optional_mapping(value: object, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    return _mapping(value, field_name)


def _mapping_list(value: object, field_name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SnapshotError(f"{field_name} must be a list of objects")
    return value


def _string(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SnapshotError("expected a string")
    return value


def _required_string(value: object, field_name: str) -> str:
    result = _string(value)
    if not result:
        raise SnapshotError(f"{field_name} must not be empty")
    return result


def _sha256(value: object) -> str:
    result = _string(value)
    if result and (
        len(result) != 64
        or any(character not in "0123456789abcdef" for character in result)
    ):
        raise SnapshotError("binary sha256 must be 64 lowercase hexadecimal digits")
    return result


def _string_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SnapshotError(f"{field_name} must be a list of strings")
    return value


def _integer(value: object, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SnapshotError(f"{field_name} must be an integer")
    return value


def _integer_mapping(value: object, field_name: str) -> dict[str, int]:
    mapping = _mapping(value, field_name)
    result = {}
    for key, item in mapping.items():
        if not isinstance(key, str):
            raise SnapshotError(f"{field_name} keys must be strings")
        result[key] = _integer(item, f"{field_name}.{key}")
    return result


def _os_error(error: OSError) -> str:
    return error.strerror or str(error)
