"""Filesystem discovery and Go build-information extraction."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Final

from pygo_audit import __version__
from pygo_audit.models import BinaryReport, ScanIssue, ScanReport, VulnerabilityScan
from pygo_audit.reconciliation import reconcile_binary
from pygo_audit.vulnerabilities import GovulncheckOutputError, parse_govulncheck_json


ELF_MAGIC: Final = b"\x7fELF"


class ScanConfigurationError(RuntimeError):
    """Raised when a scan cannot start because its configuration is invalid."""


@dataclass(slots=True)
class _ElfFile:
    path: Path
    paths: list[str]
    device: int
    inode: int
    size: int


@dataclass(slots=True)
class _Discovery:
    elf_files: list[_ElfFile] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)


def scan_root(
    root: Path,
    *,
    go_command: str = "go",
    govulncheck_command: str | None = "govulncheck",
    timeout: float = 30.0,
    jobs: int = 4,
) -> ScanReport:
    if timeout <= 0:
        raise ScanConfigurationError("timeout must be greater than zero")
    if jobs <= 0:
        raise ScanConfigurationError("jobs must be greater than zero")

    root = Path(os.path.abspath(root))
    _validate_root(root)
    scan_started_at = _utc_timestamp()
    resolved_go, go_tool_version = _resolve_go_tool(go_command, timeout)
    if not os.path.isdir("/proc/self/fd"):
        raise ScanConfigurationError(
            "/proc/self/fd is required for safe file inspection"
        )

    report = ScanReport(
        root=os.fspath(root),
        go_command=resolved_go,
        go_tool_version=go_tool_version,
        producer_name="pygo-audit",
        producer_version=__version__,
        scan_started_at=scan_started_at,
    )
    resolved_govulncheck: str | None = None
    govulncheck_unavailable = ""
    if govulncheck_command is None:
        report.govulncheck_status = "disabled"
    else:
        report.govulncheck_command = govulncheck_command
        try:
            resolved_govulncheck, govulncheck_version = _resolve_govulncheck_tool(
                govulncheck_command, timeout
            )
        except ScanConfigurationError as error:
            report.govulncheck_status = "unavailable"
            govulncheck_unavailable = str(error)
            report.issues.append(ScanIssue("/", "govulncheck", str(error)))
        else:
            report.govulncheck_status = "available"
            report.govulncheck_command = resolved_govulncheck
            report.govulncheck_tool_version = govulncheck_version

    discovery = _discover_elf_files(root, report)
    report.issues.extend(discovery.issues)

    def inspect(elf_file: _ElfFile) -> tuple[BinaryReport | None, list[ScanIssue]]:
        return _inspect_elf_file(
            elf_file,
            go_command=resolved_go,
            govulncheck_command=resolved_govulncheck,
            govulncheck_disabled=govulncheck_command is None,
            govulncheck_unavailable=govulncheck_unavailable,
            timeout=timeout,
        )

    with ThreadPoolExecutor(
        max_workers=jobs,
        thread_name_prefix="pygo-audit",
    ) as executor:
        for binary, issues in executor.map(inspect, discovery.elf_files):
            if binary is not None:
                report.binaries.append(binary)
            report.issues.extend(issues)

    report.binaries.sort(key=lambda binary: binary.paths[0])
    report.stats.go_binaries = len(report.binaries)
    report.stats.go_binary_paths = sum(len(binary.paths) for binary in report.binaries)
    report.scan_completed_at = _utc_timestamp()
    return report


def _discover_elf_files(root: Path, report: ScanReport) -> _Discovery:
    discovery = _Discovery()
    seen_files: dict[tuple[int, int], _ElfFile | None] = {}
    directories = [root]

    while directories:
        directory = directories.pop()
        report.stats.directories += 1
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    report.stats.entries += 1
                    entry_path = Path(entry.path)
                    display_path = _container_path(root, entry_path)
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        discovery.issues.append(
                            ScanIssue(display_path, "stat", _format_os_error(error))
                        )
                        continue

                    mode = entry_stat.st_mode
                    if stat.S_ISLNK(mode):
                        report.stats.symlinks_skipped += 1
                        continue
                    if stat.S_ISDIR(mode):
                        directories.append(entry_path)
                        continue
                    if not stat.S_ISREG(mode):
                        report.stats.special_files_skipped += 1
                        continue

                    report.stats.regular_files += 1
                    inode_key = (entry_stat.st_dev, entry_stat.st_ino)
                    if inode_key in seen_files:
                        existing = seen_files[inode_key]
                        if existing is not None:
                            existing.paths.append(display_path)
                            report.stats.elf_paths += 1
                        continue

                    report.stats.unique_regular_files += 1
                    try:
                        descriptor = _open_regular_file(
                            entry_path,
                            expected_device=entry_stat.st_dev,
                            expected_inode=entry_stat.st_ino,
                        )
                    except OSError as error:
                        discovery.issues.append(
                            ScanIssue(display_path, "open", _format_os_error(error))
                        )
                        seen_files[inode_key] = None
                        continue

                    try:
                        try:
                            prefix = os.pread(descriptor, len(ELF_MAGIC), 0)
                        except OSError as error:
                            discovery.issues.append(
                                ScanIssue(display_path, "read", _format_os_error(error))
                            )
                            seen_files[inode_key] = None
                            continue
                    finally:
                        os.close(descriptor)

                    if prefix != ELF_MAGIC:
                        seen_files[inode_key] = None
                        continue

                    elf_file = _ElfFile(
                        path=entry_path,
                        paths=[display_path],
                        device=entry_stat.st_dev,
                        inode=entry_stat.st_ino,
                        size=entry_stat.st_size,
                    )
                    seen_files[inode_key] = elf_file
                    discovery.elf_files.append(elf_file)
                    report.stats.elf_paths += 1
                    report.stats.unique_elf_files += 1
        except OSError as error:
            discovery.issues.append(
                ScanIssue(
                    _container_path(root, directory),
                    "walk",
                    _format_os_error(error),
                )
            )

    for elf_file in discovery.elf_files:
        elf_file.paths.sort()
    discovery.elf_files.sort(key=lambda elf_file: elf_file.paths[0])
    return discovery


def _inspect_elf_file(
    elf_file: _ElfFile,
    *,
    go_command: str,
    govulncheck_command: str | None,
    govulncheck_disabled: bool,
    govulncheck_unavailable: str,
    timeout: float,
) -> tuple[BinaryReport | None, list[ScanIssue]]:
    display_path = elf_file.paths[0]
    try:
        descriptor = _open_regular_file(
            elf_file.path,
            expected_device=elf_file.device,
            expected_inode=elf_file.inode,
        )
    except OSError as error:
        return None, [ScanIssue(display_path, "open", _format_os_error(error))]

    descriptor_path = f"/proc/self/fd/{descriptor}"
    try:
        try:
            completed = subprocess.run(
                [go_command, "version", "-m", "-json", descriptor_path],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_go_environment(),
                pass_fds=(descriptor,),
            )
        except subprocess.TimeoutExpired:
            return None, [
                ScanIssue(
                    display_path,
                    "go-version",
                    f"timed out after {timeout:g} seconds",
                )
            ]
        except OSError as error:
            return None, [
                ScanIssue(display_path, "go-version", _format_os_error(error))
            ]

        if completed.returncode != 0:
            return None, []

        try:
            value = json.loads(completed.stdout)
            binary = BinaryReport.from_go_json(
                value,
                container_path=display_path,
                size=elf_file.size,
            )
            binary.paths = elf_file.paths.copy()
        except (json.JSONDecodeError, ValueError) as error:
            return None, [ScanIssue(display_path, "go-json", str(error))]

        issues: list[ScanIssue] = []
        try:
            binary.sha256 = _sha256_descriptor(descriptor)
        except OSError as error:
            issues.append(
                ScanIssue(display_path, "hash", _format_os_error(error))
            )

        if govulncheck_disabled:
            binary.vulnerability_scan = VulnerabilityScan(status="disabled")
            return binary, issues
        if govulncheck_command is None:
            binary.vulnerability_scan = VulnerabilityScan(
                status="not_run",
                error=govulncheck_unavailable,
            )
            return binary, issues

        vulnerability_scan, issue = _inspect_vulnerabilities(
            descriptor_path,
            descriptor=descriptor,
            display_path=display_path,
            govulncheck_command=govulncheck_command,
            timeout=timeout,
        )
        binary.vulnerability_scan = vulnerability_scan
        if issue is not None:
            issues.append(issue)
        reconciliation_issue = _reconciliation_issue(binary, display_path)
        if reconciliation_issue is not None:
            issues.append(reconciliation_issue)
        return binary, issues
    finally:
        os.close(descriptor)


def _inspect_vulnerabilities(
    descriptor_path: str,
    *,
    descriptor: int,
    display_path: str,
    govulncheck_command: str,
    timeout: float,
) -> tuple[VulnerabilityScan, ScanIssue | None]:
    try:
        completed = subprocess.run(
            [
                govulncheck_command,
                "-mode",
                "binary",
                "-format",
                "json",
                descriptor_path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_govulncheck_environment(),
            pass_fds=(descriptor,),
        )
    except subprocess.TimeoutExpired:
        message = f"timed out after {timeout:g} seconds"
        return (
            VulnerabilityScan(status="failed", error=message),
            ScanIssue(display_path, "govulncheck", message),
        )
    except OSError as error:
        message = _format_os_error(error)
        return (
            VulnerabilityScan(status="failed", error=message),
            ScanIssue(display_path, "govulncheck", message),
        )

    try:
        scan = parse_govulncheck_json(completed.stdout)
    except GovulncheckOutputError as error:
        detail = completed.stderr.strip() or str(error)
        scan = VulnerabilityScan(status="failed", error=detail)
        return scan, ScanIssue(display_path, "govulncheck", detail)

    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        scan.status = "failed"
        scan.error = detail
        return scan, ScanIssue(display_path, "govulncheck", detail)

    return scan, None


def _open_regular_file(
    path: Path,
    *,
    expected_device: int,
    expected_inode: int,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        current_stat = os.fstat(descriptor)
        if not stat.S_ISREG(current_stat.st_mode):
            raise OSError("file changed and is no longer regular")
        if (current_stat.st_dev, current_stat.st_ino) != (
            expected_device,
            expected_inode,
        ):
            raise OSError("file changed during scan")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_root(root: Path) -> None:
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ScanConfigurationError(
            f"cannot inspect root {root}: {_format_os_error(error)}"
        ) from error
    if stat.S_ISLNK(root_stat.st_mode):
        raise ScanConfigurationError(f"scan root must not be a symlink: {root}")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ScanConfigurationError(f"scan root is not a directory: {root}")


def _resolve_go_tool(command: str, timeout: float) -> tuple[str, str]:
    resolved = shutil.which(command)
    if resolved is None:
        raise ScanConfigurationError(f"Go command not found: {command}")
    try:
        completed = subprocess.run(
            [resolved, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_go_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanConfigurationError(f"cannot run {resolved}: {error}") from error
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise ScanConfigurationError(f"cannot use Go command {resolved}: {detail}")

    try:
        help_result = subprocess.run(
            [resolved, "help", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_go_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanConfigurationError(
            f"cannot inspect {resolved} capabilities: {error}"
        ) from error
    if help_result.returncode != 0 or "-json" not in help_result.stdout:
        raise ScanConfigurationError(
            f"Go command does not support 'version -m -json': {resolved}"
        )
    return resolved, version


def _resolve_govulncheck_tool(command: str, timeout: float) -> tuple[str, str]:
    resolved = shutil.which(command)
    if resolved is None:
        raise ScanConfigurationError(f"govulncheck command not found: {command}")
    try:
        completed = subprocess.run(
            [resolved, "-version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_govulncheck_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanConfigurationError(f"cannot run {resolved}: {error}") from error
    version = completed.stdout.strip()
    if not version:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise ScanConfigurationError(
            f"cannot use govulncheck command {resolved}: {detail}"
        )
    return resolved, version


def _go_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("GOFLAGS", None)
    environment["GOENV"] = "off"
    environment["GOTOOLCHAIN"] = "local"
    return environment


def _govulncheck_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("GOFLAGS", None)
    environment.pop("GOENV", None)
    environment.pop("GOTOOLCHAIN", None)
    return environment


def _container_path(root: Path, path: Path) -> str:
    if path == root:
        return "/"
    return f"/{path.relative_to(root).as_posix()}"


def _format_os_error(error: OSError) -> str:
    return error.strerror or str(error)


def _sha256_descriptor(descriptor: int, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(descriptor, chunk_size, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _summarize_reconciliation(messages: list[str], *, limit: int = 5) -> str:
    displayed = messages[:limit]
    if len(messages) > limit:
        displayed.append(f"and {len(messages) - limit} more difference(s)")
    return "; ".join(displayed)


def _reconciliation_issue(
    binary: BinaryReport,
    display_path: str,
) -> ScanIssue | None:
    messages = reconcile_binary(binary)
    if not messages:
        return None
    return ScanIssue(
        display_path,
        "reconciliation-difference",
        _summarize_reconciliation(messages),
    )
