"""Shared file publication, private checksums, and semantic JSON hashing."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Iterator, TextIO


class ChecksumError(ValueError):
    """A private result file has a missing or invalid checksum footer."""


class FileLockError(ValueError):
    """A publisher or cache computation could not acquire its file lock."""


def json_digest(document: object) -> str:
    """Hash JSON content independently of indentation and dictionary key order."""
    canonical = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@contextmanager
def atomic_text_writer(
    destination: Path,
    *,
    overwrite: bool = False,
    newline: str | None = None,
    checksum: bool = False,
) -> Iterator[TextIO]:
    """Publish a complete 0600 UTF-8 file; its parent must already exist.

    Create-only publication raises FileExistsError if another writer wins.
    Callers own directory validation and decide whether replacement is allowed.
    Optional checksum footers are for private files, never exported formats.
    """
    stream = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="" if checksum else newline,
        dir=destination.parent,
        prefix=f"{destination.name}-",
        suffix=".tmp",
        delete=False,
    )
    temporary = Path(stream.name)
    try:
        with stream:
            yield stream
            stream.flush()
            if checksum:
                # Hash the exact payload bytes, excluding the LF-delimited footer.
                with temporary.open("rb") as payload:
                    digest = hashlib.file_digest(payload, "sha256").hexdigest()
                stream.seek(0, os.SEEK_END)
                stream.write(f"\n{digest}\n")
                stream.flush()
            os.fsync(stream.fileno())
        # A hard link publishes without replacing even a dangling symlink.
        if overwrite:
            os.replace(temporary, destination)
        else:
            os.link(temporary, destination)
    finally:
        # Warn about cleanup without changing the write/publication outcome.
        try:
            temporary.unlink(missing_ok=True)
        except OSError as error:
            print(
                f"pygo-audit: warning: cannot remove temporary file {temporary}: {error}",
                file=sys.stderr,
            )


def atomic_write_text(
    destination: Path,
    content: str,
    *,
    overwrite: bool = False,
    checksum: bool = False,
) -> None:
    """Publish text without exposing a partial destination file."""
    with atomic_text_writer(
        destination, overwrite=overwrite, checksum=checksum
    ) as stream:
        stream.write(content)


def atomic_write_json(
    destination: Path,
    document: object,
    *,
    overwrite: bool = False,
    sort_keys: bool = False,
    checksum: bool = False,
) -> None:
    """Publish readable JSON; opt into a checksum footer only for private files."""
    with atomic_text_writer(
        destination, overwrite=overwrite, checksum=checksum
    ) as stream:
        json.dump(document, stream, indent=2, ensure_ascii=True, sort_keys=sort_keys)
        stream.write("\n")


def atomic_read_text(path: Path, *, checksum: bool = False) -> str:
    """Read one UTF-8 file version and verify an optional private-file footer.

    Paired atomic writers may replace the path without changing the opened file.
    Concurrent in-place writes are outside this contract.
    """
    content = path.read_bytes()
    if checksum:
        payload, separator, digest = content[:-1].rpartition(b"\n")
        if (
            not content.endswith(b"\n")
            or not separator
            or digest != hashlib.sha256(payload).hexdigest().encode("ascii")
        ):
            raise ChecksumError(f"missing or invalid checksum footer: {path}")
        content = payload
    return content.decode("utf-8")


def atomic_read_json(path: Path, *, checksum: bool = False) -> Any:
    """Decode JSON through the shared text reader and checksum verification."""
    return json.loads(atomic_read_text(path, checksum=checksum))


def ensure_private_directory(directory: Path) -> None:
    """Create or restrict a directory to 0700, rejecting a symlink boundary."""
    if directory.is_symlink():
        raise OSError(f"directory must not be a symlink: {directory}")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)


@contextmanager
def file_lock(path: Path, *, wait_seconds: float = 0) -> Iterator[None]:
    """Acquire a kernel lock, failing immediately or after a bounded wait.

    Keep the lock file: unlinking it could let waiters lock different inodes.
    Closing the descriptor releases ownership, including on process termination.
    """
    validate_lock_wait(wait_seconds)
    if path.is_symlink():
        raise FileLockError(f"lock must not be a symlink: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        raise FileLockError(f"cannot open lock {path}: {error}") from error
    with os.fdopen(descriptor, "w") as stream:
        acquire_lock(stream.fileno(), path, wait_seconds)
        yield


@contextmanager
def directory_lock(directory: Path, *, wait_seconds: float = 0) -> Iterator[None]:
    """Lock an existing directory inode without creating a lock artifact."""
    validate_lock_wait(wait_seconds)
    if directory.is_symlink() or not directory.is_dir():
        raise FileLockError(
            f"lock directory must be an existing directory, not a symlink: {directory}"
        )
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise FileLockError(
            f"cannot open lock directory {directory}: {error}"
        ) from error
    try:
        acquire_lock(descriptor, directory, wait_seconds)
        yield
    finally:
        os.close(descriptor)


def validate_lock_wait(wait_seconds: float) -> None:
    if not math.isfinite(wait_seconds) or wait_seconds < 0:
        raise ValueError("lock wait must be finite and nonnegative")


def acquire_lock(descriptor: int, target: Path, wait_seconds: float) -> None:
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as error:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FileLockError(f"output is already in use: {target}") from error
            time.sleep(min(0.05, remaining))
        except OSError as error:
            raise FileLockError(f"cannot acquire lock {target}: {error}") from error
