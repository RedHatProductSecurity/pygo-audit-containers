"""Filesystem discovery and Go build-information extraction."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Final

from pygo_audit.models import BinaryReport, ScanIssue, ScanReport


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
    timeout: float = 30.0,
    jobs: int = 4,
) -> ScanReport:
    if timeout <= 0:
        raise ScanConfigurationError("timeout must be greater than zero")
    if jobs <= 0:
        raise ScanConfigurationError("jobs must be greater than zero")

    root = Path(os.path.abspath(root))
    _validate_root(root)
    resolved_go, go_tool_version = _resolve_go_tool(go_command, timeout)
    if not os.path.isdir("/proc/self/fd"):
        raise ScanConfigurationError("/proc/self/fd is required for safe file inspection")

    report = ScanReport(
        root=os.fspath(root),
        go_command=resolved_go,
        go_tool_version=go_tool_version,
    )
    discovery = _discover_elf_files(root, report)
    report.issues.extend(discovery.issues)

    def inspect(elf_file: _ElfFile) -> tuple[BinaryReport | None, ScanIssue | None]:
        return _inspect_elf_file(
            elf_file,
            go_command=resolved_go,
            timeout=timeout,
        )

    with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="pygo-audit") as executor:
        for binary, issue in executor.map(inspect, discovery.elf_files):
            if binary is not None:
                report.binaries.append(binary)
            if issue is not None:
                report.issues.append(issue)

    report.binaries.sort(key=lambda binary: binary.paths[0])
    report.stats.go_binaries = len(report.binaries)
    report.stats.go_binary_paths = sum(len(binary.paths) for binary in report.binaries)
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
                ScanIssue(_container_path(root, directory), "walk", _format_os_error(error))
            )

    for elf_file in discovery.elf_files:
        elf_file.paths.sort()
    discovery.elf_files.sort(key=lambda elf_file: elf_file.paths[0])
    return discovery


def _inspect_elf_file(
    elf_file: _ElfFile,
    *,
    go_command: str,
    timeout: float,
) -> tuple[BinaryReport | None, ScanIssue | None]:
    display_path = elf_file.paths[0]
    try:
        descriptor = _open_regular_file(
            elf_file.path,
            expected_device=elf_file.device,
            expected_inode=elf_file.inode,
        )
    except OSError as error:
        return None, ScanIssue(display_path, "open", _format_os_error(error))

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
            return None, ScanIssue(
                display_path,
                "go-version",
                f"timed out after {timeout:g} seconds",
            )
        except OSError as error:
            return None, ScanIssue(display_path, "go-version", _format_os_error(error))

        if completed.returncode != 0:
            return None, None

        try:
            value = json.loads(completed.stdout)
            binary = BinaryReport.from_go_json(
                value,
                container_path=display_path,
                size=elf_file.size,
            )
            binary.paths = elf_file.paths.copy()
            return binary, None
        except (json.JSONDecodeError, ValueError) as error:
            return None, ScanIssue(display_path, "go-json", str(error))
    finally:
        os.close(descriptor)


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
        raise ScanConfigurationError(f"cannot inspect {resolved} capabilities: {error}") from error
    if help_result.returncode != 0 or "-json" not in help_result.stdout:
        raise ScanConfigurationError(
            f"Go command does not support 'version -m -json': {resolved}"
        )
    return resolved, version


def _go_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("GOFLAGS", None)
    environment["GOENV"] = "off"
    environment["GOTOOLCHAIN"] = "local"
    return environment


def _container_path(root: Path, path: Path) -> str:
    if path == root:
        return "/"
    return f"/{path.relative_to(root).as_posix()}"


def _format_os_error(error: OSError) -> str:
    return error.strerror or str(error)
