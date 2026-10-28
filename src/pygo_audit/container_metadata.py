"""Facts discovered by inspecting an extracted container filesystem."""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil
import stat
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, BinaryIO, Iterator

from pygo_audit.storage import atomic_write_json


CONTAINER_METADATA_NAME = ".pygo-audit-container.json"
_RPMDB_DIRECTORIES = (
    Path("usr/share/rpm"),
    Path("usr/lib/sysimage/rpm"),
    Path("var/lib/rpm"),
)
_RPMDB_NAMES = ("rpmdb.sqlite", "Packages")
_RPM_QUERY_FORMAT = (
    "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
)
_OS_RELEASE_LIMIT = 64 * 1024


@dataclass(frozen=True, slots=True)
class RpmPackage:
    """The stable package coordinates needed for product matching."""

    name: str  # Installed RPM package name.
    epoch: str  # RPM version epoch as returned by the query.
    version: str  # Upstream package version.
    release: str  # RPM packaging release identifier.
    architecture: str  # RPM architecture, such as x86_64 or noarch.
    source_rpm: str  # Source RPM filename reported by the database.

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ContainerFacts:
    """Evidence read from the image filesystem, independent of registry data."""

    os_release: dict[str, str]  # Parsed operating-system identity keys and values.
    rpmdb_paths: tuple[str, ...]  # Discovered database paths relative to rootfs.
    rpm_packages: tuple[
        RpmPackage, ...
    ]  # Package coordinates from the selected RPM database.
    rpm_error: str = ""  # Query limitation or failure; empty if none was recorded.

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "os-release": dict(self.os_release),
            "rpmdb": {
                "paths": list(self.rpmdb_paths),
                "package-count": len(self.rpm_packages),
                "packages": [package.to_dict() for package in self.rpm_packages],
            },
        }
        if self.rpm_error:
            result["rpmdb"]["error"] = self.rpm_error
        return result


@contextmanager
def _open_subject_file(rootfs: Path, path: Path) -> Iterator[BinaryIO]:
    """Allow contained links, then pin every component without following links."""
    root = rootfs.resolve(strict=True)
    try:
        relative = path.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise OSError(f"metadata path escapes the extracted root: {path}") from error
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(root, directory_flags)
        stack.callback(os.close, directory)
        for part in relative.parts[:-1]:
            directory = os.open(part, directory_flags, dir_fd=directory)
            stack.callback(os.close, directory)
        descriptor = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        stream = stack.enter_context(os.fdopen(descriptor, "rb"))
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError(f"metadata is not a regular file: {path}")
        yield stream


def read_os_release(rootfs: Path) -> dict[str, str]:
    """Read the standard OS identity file without executing anything in rootfs."""
    for path in (rootfs / "usr/lib/os-release", rootfs / "etc/os-release"):
        try:
            with _open_subject_file(rootfs, path) as stream:
                raw = stream.read(_OS_RELEASE_LIMIT + 1)
            if len(raw) > _OS_RELEASE_LIMIT:
                continue
            content = raw.decode("utf-8")
        except OSError, UnicodeDecodeError:
            continue
        values: dict[str, str] = {}
        for line in content.splitlines():
            key, separator, raw_value = line.partition("=")
            if not separator or not _valid_key(key):
                continue
            values[key] = _unquote(raw_value)
        return values
    return {}


def discover_rpmdb(rootfs: Path) -> tuple[Path, ...]:
    """Find supported RPM database locations without following arbitrary paths."""
    paths: list[Path] = []
    for directory in _RPMDB_DIRECTORIES:
        for name in _RPMDB_NAMES:
            candidate = rootfs / directory / name
            try:
                if candidate.is_symlink():
                    continue
                with _open_subject_file(rootfs, candidate):
                    paths.append(candidate)
            except OSError:
                continue
    return tuple(paths)


def collect_container_facts(
    rootfs: Path,
    *,
    rpm_command: str = "rpm",
    rpm_timeout: float = 30.0,
) -> ContainerFacts:
    """Collect safe, read-only product evidence from an extracted rootfs."""
    if rpm_timeout <= 0:
        raise ValueError("RPM query timeout must be greater than zero")
    root = Path(rootfs).resolve()
    rpmdb_paths = discover_rpmdb(root)
    packages: tuple[RpmPackage, ...] = ()
    rpm_error = ""
    if rpmdb_paths:
        executable = shutil.which(rpm_command)
        if executable is None:
            rpm_error = f"RPM command not found: {rpm_command}"
        else:
            packages, rpm_error = _query_rpmdb(
                executable, rpmdb_paths[0], rootfs=root, timeout=rpm_timeout
            )
    return ContainerFacts(
        os_release=read_os_release(root),
        rpmdb_paths=tuple(_relative_path(root, path) for path in rpmdb_paths),
        rpm_packages=packages,
        rpm_error=rpm_error,
    )


def write_container_facts(audit_root: Path, facts: ContainerFacts) -> Path:
    """Persist filesystem facts outside the extracted subject tree."""
    destination = Path(audit_root) / CONTAINER_METADATA_NAME
    atomic_write_json(destination, facts.to_dict(), overwrite=True, sort_keys=True)
    return destination


def _query_rpmdb(
    executable: str,
    database: Path,
    *,
    rootfs: Path,
    timeout: float,
) -> tuple[tuple[RpmPackage, ...], str]:
    try:
        # RPM may write locks/journals during queries; keep them out of the subject.
        with TemporaryDirectory(prefix="rpm-query-", dir=rootfs.parent) as temporary:
            working = Path(temporary)
            for path in database.parent.iterdir():
                if path.is_symlink() or not path.is_file():
                    continue
                with _open_subject_file(rootfs, path) as source:
                    destination = working / path.name
                    with destination.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    destination.chmod(0o600)
            if not (working / database.name).is_file():
                raise OSError(f"RPM database is no longer a regular file: {database}")
            completed = subprocess.run(
                [
                    executable,
                    "--dbpath",
                    str(working),
                    "-qa",
                    "--qf",
                    _RPM_QUERY_FORMAT,
                ],
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                text=True,
                timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return (), f"RPM query timed out after {timeout:g} seconds"
    except OSError as error:
        return (), f"cannot read RPM database: {error}"
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "rpm query failed"
        return (), detail

    packages: list[RpmPackage] = []
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or not fields[0]:
            continue
        packages.append(RpmPackage(*fields))
    packages.sort(
        key=lambda package: (package.name, package.architecture, package.version)
    )
    return tuple(packages), ""


def _relative_path(rootfs: Path, path: Path) -> str:
    return path.relative_to(rootfs).as_posix()


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _valid_key(value: str) -> bool:
    return (
        bool(value)
        and (value[0].isalpha() or value[0] == "_")
        and all(character.isalnum() or character == "_" for character in value)
    )
