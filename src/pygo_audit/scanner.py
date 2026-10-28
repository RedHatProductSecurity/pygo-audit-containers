"""Filesystem discovery and Go build-information extraction."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Final
from uuid import uuid4

from pygo_audit import __version__
from pygo_audit.binary_cache import BinaryResultCache
from pygo_audit.layer_scan import compose_reports
from pygo_audit.models import (
    BinaryReport,
    ContainerMetadata,
    ScanIssue,
    AuditReport,
    VulnerabilityScan,
)
from pygo_audit.reconciliation import reconcile_binary
from pygo_audit.result_cache import ResultCacheError
from pygo_audit.vulnerabilities import GovulncheckOutputError, parse_govulncheck_json


ELF_MAGIC: Final = b"\x7fELF"


class ScanConfigurationError(RuntimeError):
    """Raised when a scan cannot start because its configuration is invalid."""


@dataclass(slots=True)
class _ElfFile:
    path: Path  # Host path used to reopen this discovered ELF file.
    paths: list[str]  # Sorted container paths, including discovered hard-link aliases.
    symlinks: list[str]  # Resolved symlink aliases to this file.
    device: int  # Device number pinned for the later identity check.
    inode: int  # Inode number pinned for the later identity check.
    size: int  # File size in bytes recorded during discovery.


def scan_root(
    root: Path,
    layer_dirs: Sequence[Path] = (),
    *,
    layers_ordered: bool = True,
    go_command: str = "go",
    govulncheck_command: str | None = "govulncheck",
    timeout: float = 30.0,
    jobs: int = 4,
    binary_cache_dir: Path | None = None,
    run_id: str | None = None,
    work_dir: Path | None = None,
) -> AuditReport:
    """Scan rootfs and optional layers with one tool setup, worker pool, and cache.

    Explicit layer paths must exist. Only a known oldest-to-newest layer order
    supports inferring deletion and replacement history.
    """
    if timeout <= 0:
        raise ScanConfigurationError("timeout must be greater than zero")
    if jobs <= 0:
        raise ScanConfigurationError("jobs must be greater than zero")

    normalized_roots = [Path(os.path.abspath(path)) for path in (root, *layer_dirs)]
    if len({path.resolve() for path in normalized_roots}) != len(normalized_roots):
        raise ScanConfigurationError("rootfs and layer directories must be distinct")
    for root in normalized_roots:
        _validate_root(root)
    if binary_cache_dir is not None:
        binary_cache_dir = Path(os.path.abspath(binary_cache_dir))
        resolved_cache = binary_cache_dir.resolve()
        for root in normalized_roots:
            if resolved_cache.is_relative_to(root.resolve()):
                raise ScanConfigurationError(
                    "binary cache directory must not be inside a scan root"
                )
    run_id = run_id or uuid4().hex
    work_dir = work_dir or normalized_roots[0].parent / "work"
    if any(
        work_dir.resolve().is_relative_to(root.resolve()) for root in normalized_roots
    ):
        raise ScanConfigurationError("work directory must not be inside a scan root")
    if work_dir.is_symlink():
        raise ScanConfigurationError("work directory must not be a symlink")
    work_dir.mkdir(parents=True, exist_ok=True)
    environment = _go_environment(work_dir)
    scan_started_at = _utc_timestamp()
    resolved_go, go_tool_version = _resolve_go_tool(go_command, timeout, environment)
    if not os.path.isdir("/proc/self/fd"):
        raise ScanConfigurationError(
            "/proc/self/fd is required for safe file inspection"
        )

    reports = [
        AuditReport(
            metadata=ContainerMetadata(root=os.fspath(root)),
            go_command=resolved_go,
            go_tool_version=go_tool_version,
            producer_name="pygo-audit",
            producer_version=__version__,
            scan_started_at=scan_started_at,
            run_id=run_id,
        )
        for root in normalized_roots
    ]
    resolved_govulncheck: str | None = None
    govulncheck_tool_version = ""
    govulncheck_unavailable = ""
    if govulncheck_command is not None:
        for report in reports:
            report.govulncheck_command = govulncheck_command
        try:
            resolved_govulncheck, govulncheck_version = _resolve_govulncheck_tool(
                govulncheck_command, timeout, environment
            )
        except ScanConfigurationError as error:
            govulncheck_unavailable = str(error)
            for report in reports:
                report.govulncheck_status = "unavailable"
                report.issues.append(ScanIssue("/", "govulncheck", str(error)))
        else:
            for report in reports:
                report.govulncheck_status = "available"
                report.govulncheck_command = resolved_govulncheck
                report.govulncheck_tool_version = govulncheck_version
            govulncheck_tool_version = govulncheck_version

    cache_profile = {
        "go_command": resolved_go,
        "go_tool_version": go_tool_version,
        "govulncheck_command": resolved_govulncheck or "",
        "govulncheck_tool_version": govulncheck_tool_version,
        "vulnerability_mode": (
            "disabled"
            if govulncheck_command is None
            else "binary"
            if resolved_govulncheck is not None
            else "unavailable"
        ),
    }
    try:
        binary_cache = BinaryResultCache(binary_cache_dir, cache_profile, run_id=run_id)
    except ResultCacheError as error:
        raise ScanConfigurationError(str(error)) from error

    def inspect(
        item: tuple[int, _ElfFile],
    ) -> tuple[int, BinaryReport | None, list[ScanIssue]]:
        root_index, elf_file = item
        binary, issues = _inspect_elf_file(
            elf_file,
            go_command=resolved_go,
            govulncheck_command=resolved_govulncheck,
            govulncheck_disabled=govulncheck_command is None,
            govulncheck_unavailable=govulncheck_unavailable,
            timeout=timeout,
            binary_cache=binary_cache,
            runtime_disposition="unknown" if root_index else "runtime",
            environment=environment,
        )
        return root_index, binary, issues

    work = [
        (root_index, elf_file)
        for root_index, (report, root) in enumerate(zip(reports, normalized_roots))
        for elf_file in _discover_elf_files(root, report)
    ]

    with ThreadPoolExecutor(
        max_workers=jobs,
        thread_name_prefix="pygo-audit",
    ) as executor:
        for root_index, binary, issues in executor.map(inspect, work):
            if binary is not None:
                reports[root_index].binaries.append(binary)
            reports[root_index].issues.extend(issues)

    scan_completed_at = _utc_timestamp()
    for report in reports:
        report.binaries.sort(key=lambda binary: binary.paths[0])
        report.scan_completed_at = scan_completed_at
    return compose_reports(reports, normalized_roots[1:], layers_ordered=layers_ordered)


def _discover_elf_files(root: Path, report: AuditReport) -> list[_ElfFile]:
    elf_files: list[_ElfFile] = []
    seen_files: dict[tuple[int, int], _ElfFile | None] = {}
    symlinks: dict[str, str] = {}
    directory_paths = {"/"}
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
                        report.issues.append(
                            ScanIssue(display_path, "stat", _format_os_error(error))
                        )
                        continue

                    mode = entry_stat.st_mode
                    if stat.S_ISLNK(mode):
                        report.stats.symlinks_skipped += 1
                        try:
                            symlinks[display_path] = os.readlink(entry_path)
                        except OSError as error:
                            report.issues.append(
                                ScanIssue(
                                    display_path,
                                    "readlink",
                                    _format_os_error(error),
                                )
                            )
                        continue
                    if stat.S_ISDIR(mode):
                        directory_paths.add(display_path)
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
                        report.issues.append(
                            ScanIssue(display_path, "open", _format_os_error(error))
                        )
                        seen_files[inode_key] = None
                        continue

                    try:
                        prefix = os.pread(descriptor, len(ELF_MAGIC), 0)
                    except OSError as error:
                        report.issues.append(
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
                        symlinks=[],
                        device=entry_stat.st_dev,
                        inode=entry_stat.st_ino,
                        size=entry_stat.st_size,
                    )
                    seen_files[inode_key] = elf_file
                    elf_files.append(elf_file)
                    report.stats.elf_paths += 1
                    report.stats.unique_elf_files += 1
        except OSError as error:
            report.issues.append(
                ScanIssue(
                    _container_path(root, directory),
                    "walk",
                    _format_os_error(error),
                )
            )

    for elf_file in elf_files:
        elf_file.paths.sort()
    attach_symlink_aliases(elf_files, symlinks, directory_paths)
    elf_files.sort(key=lambda elf_file: elf_file.paths[0])
    return elf_files


def attach_symlink_aliases(
    elf_files: Sequence[_ElfFile],
    symlinks: Mapping[str, str],
    directories: set[str],
) -> None:
    """Associate safe in-root file and directory aliases with ELF records."""
    files_by_path = {
        path: elf_file for elf_file in elf_files for path in elf_file.paths
    }
    for link_path in sorted(symlinks):
        target = resolve_symlink_path(link_path, symlinks)
        if target is None:
            continue
        if target in files_by_path:
            files_by_path[target].symlinks.append(link_path)
            continue
        if target not in directories:
            continue
        prefix = target.rstrip("/") + "/"
        for path, elf_file in files_by_path.items():
            if path.startswith(prefix):
                elf_file.symlinks.append(link_path.rstrip("/") + path[len(target) :])
    for elf_file in elf_files:
        elf_file.symlinks = sorted(set(elf_file.symlinks))


def resolve_symlink_path(path: str, symlinks: Mapping[str, str]) -> str | None:
    """Resolve recorded container links lexically without opening their targets."""
    pending = [part for part in path.split("/") if part]
    resolved: list[str] = []
    visited: set[str] = set()
    while pending:
        part = pending.pop(0)
        candidate = "/" + "/".join((*resolved, part))
        target = symlinks.get(candidate)
        if target is None:
            resolved.append(part)
            continue
        if candidate in visited:
            return None
        visited.add(candidate)
        target_parts = symlink_target_parts(candidate, target)
        if target_parts is None:
            return None
        pending = [*target_parts, *pending]
        resolved = []
    return "/" + "/".join(resolved)


def symlink_target_parts(path: str, target: str) -> list[str] | None:
    parts = [] if target.startswith("/") else path.strip("/").split("/")[:-1]
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return parts


def _inspect_elf_file(
    elf_file: _ElfFile,
    *,
    go_command: str,
    govulncheck_command: str | None,
    govulncheck_disabled: bool,
    govulncheck_unavailable: str,
    timeout: float,
    binary_cache: BinaryResultCache,
    runtime_disposition: str,
    environment: dict[str, str],
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
        issues: list[ScanIssue] = []
        sha256 = ""
        try:
            sha256 = _sha256_descriptor(descriptor)
        except OSError as error:
            issues.append(ScanIssue(display_path, "hash", _format_os_error(error)))

        def inspect() -> tuple[BinaryReport | None, list[ScanIssue]]:
            binary = (
                binary_cache.load(
                    sha256,
                    paths=elf_file.paths,
                    symlinks=elf_file.symlinks,
                    size=elf_file.size,
                    runtime_disposition=runtime_disposition,
                )
                if sha256
                else None
            )
            if binary is None:
                try:
                    completed = subprocess.run(
                        [go_command, "version", "-m", "-json", descriptor_path],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        env=environment,
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
                    binary = BinaryReport.from_go_json(
                        json.loads(completed.stdout),
                        container_path=display_path,
                        size=elf_file.size,
                    )
                except (json.JSONDecodeError, ValueError) as error:
                    return None, [ScanIssue(display_path, "go-json", str(error))]
                binary.paths = elf_file.paths.copy()
                binary.symlinks = elf_file.symlinks.copy()
                binary.runtime_disposition = runtime_disposition
                binary.sha256 = sha256
                # Preserve build facts even if vulnerability analysis fails.
                binary_cache.store(binary.sha256, binary)
            if govulncheck_disabled:
                binary.vulnerability_scan = VulnerabilityScan(status="disabled")
            elif govulncheck_command is None:
                binary.vulnerability_scan = VulnerabilityScan(
                    status="not_run", error=govulncheck_unavailable
                )
            elif binary.vulnerability_scan.status != "complete":
                binary.vulnerability_scan, issue = _inspect_vulnerabilities(
                    descriptor_path,
                    descriptor=descriptor,
                    display_path=display_path,
                    govulncheck_command=govulncheck_command,
                    timeout=timeout,
                    environment=environment,
                )
                if issue is not None:
                    issues.append(issue)
            reconcile_binary(binary)
            binary_cache.store(binary.sha256, binary)
            return binary, issues

        if not sha256:
            return inspect()
        with binary_cache.key_lock(sha256, wait_seconds=timeout * 2):
            return inspect()

    finally:
        os.close(descriptor)


def _inspect_vulnerabilities(
    descriptor_path: str,
    *,
    descriptor: int,
    display_path: str,
    govulncheck_command: str,
    timeout: float,
    environment: dict[str, str],
) -> tuple[VulnerabilityScan, ScanIssue | None]:
    scan = VulnerabilityScan(status="failed")
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
            env=environment,
            pass_fds=(descriptor,),
        )
        scan = parse_govulncheck_json(completed.stdout)
        # Nonzero exits can include partial findings, which must be retained.
        if completed.returncode != 0:
            scan.status = "failed"
            scan.error = (
                completed.stderr.strip() or f"exit status {completed.returncode}"
            )
    except subprocess.TimeoutExpired:
        scan.error = f"timed out after {timeout:g} seconds"
    except OSError as error:
        scan.error = _format_os_error(error)
    except GovulncheckOutputError as error:
        scan.error = completed.stderr.strip() or str(error)
    issue = (
        ScanIssue(display_path, "govulncheck", scan.error)
        if scan.status == "failed"
        else None
    )
    return scan, issue


def _open_regular_file(
    path: Path,
    *,
    expected_device: int,
    expected_inode: int,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
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


def _probe_tool(
    command: str, arguments: list[str], timeout: float, environment: dict[str, str]
) -> tuple[str, subprocess.CompletedProcess[str]]:
    """Share tool discovery and execution; callers validate the response."""
    resolved = shutil.which(command)
    if resolved is None:
        raise ScanConfigurationError(f"command not found: {command}")
    try:
        completed = subprocess.run(
            [resolved, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ScanConfigurationError(f"cannot run {resolved}: {error}") from error
    return resolved, completed


def _resolve_go_tool(
    command: str, timeout: float, environment: dict[str, str]
) -> tuple[str, str]:
    resolved, completed = _probe_tool(command, ["version"], timeout, environment)
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise ScanConfigurationError(f"cannot use Go command {resolved}: {detail}")

    _, help_result = _probe_tool(resolved, ["help", "version"], timeout, environment)
    if help_result.returncode != 0 or "-json" not in help_result.stdout:
        raise ScanConfigurationError(
            f"Go command does not support 'version -m -json': {resolved}"
        )
    return resolved, version


def _resolve_govulncheck_tool(
    command: str, timeout: float, environment: dict[str, str]
) -> tuple[str, str]:
    resolved, completed = _probe_tool(command, ["-version"], timeout, environment)
    # Some releases print version metadata then complain about missing targets.
    # This metadata probe is separate from the checked binary scan invocation.
    version = completed.stdout.strip()
    if not version:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise ScanConfigurationError(
            f"cannot use govulncheck command {resolved}: {detail}"
        )
    return resolved, version


def _go_environment(work_dir: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("GOFLAGS", None)
    environment["GOENV"] = "off"
    environment["GOTOOLCHAIN"] = "local"
    # Explicit caller environment settings win; implicit tool defaults stay local.
    for variable, child in {
        "GOCACHE": "go-build",
        "GOMODCACHE": "go-modules",
        "GOPATH": "go",
        "XDG_CACHE_HOME": "tool-cache",
        "XDG_CONFIG_HOME": "tool-config",
        "TMPDIR": "tmp",
    }.items():
        path = work_dir.absolute() / child
        if not environment.get(variable):
            path.mkdir(parents=True, exist_ok=True)
            environment[variable] = str(path)
    return environment


def _container_path(root: Path, path: Path) -> str:
    if path == root:
        return "/"
    return f"/{path.relative_to(root).as_posix()}"


def _format_os_error(error: OSError) -> str:
    return error.strerror or str(error)


def _sha256_descriptor(
    descriptor: int,
    *,
    chunk_size: int = 1024 * 1024,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(descriptor, chunk_size, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
