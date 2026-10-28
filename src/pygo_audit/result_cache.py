"""Private result storage shared by binary scans and CSAF comparisons."""

from __future__ import annotations

from contextlib import contextmanager
import copy
from pathlib import Path
import threading
from typing import Any, Iterator
from uuid import uuid4

from pygo_audit.storage import (
    atomic_read_json,
    atomic_write_json,
    ensure_private_directory,
    file_lock,
    FileLockError,
)


class ResultCacheError(RuntimeError):
    """A private result cache could not be initialized or written."""


class ResultCache:
    """Store checked JSON results in memory and optionally a shared directory.

    Callers derive content keys from the inputs and profile for each result.
    """

    def __init__(self, directory: Path | None, *, run_id: str | None = None):
        self.run_id = run_id or uuid4().hex
        self.directory = Path(directory) if directory is not None else None
        self.memory: dict[str, dict[str, Any]] = {}
        self.memory_lock = threading.Lock()
        self.key_locks: dict[str, threading.Lock] = {}
        self.key_locks_guard = threading.Lock()
        if self.directory is not None:
            try:
                ensure_private_directory(self.directory)
                for name in ("objects", "locks"):
                    ensure_private_directory(self.directory / name)
            except OSError as error:
                raise ResultCacheError(
                    f"cannot create result cache {self.directory}: {error}"
                ) from error

    def load(self, key: str) -> dict[str, Any] | None:
        with self.memory_lock:
            document = self.memory.get(key)
        if document is None:
            if self.directory is None:
                return None
            path = self.object_path(key)
            if path.is_symlink():
                return None
            try:
                document = atomic_read_json(path, checksum=True)
            except OSError, ValueError:
                return None
        if not isinstance(document, dict):
            return None
        with self.memory_lock:
            self.memory[key] = document
        return copy.deepcopy(document)

    def store(self, key: str, document: dict[str, Any]) -> None:
        with self.memory_lock:
            self.memory[key] = copy.deepcopy(document)
        if self.directory is None:
            return
        path = self.object_path(key)
        try:
            # Replace corrupt entries after successful computation.
            atomic_write_json(path, document, overwrite=True, checksum=True)
        except OSError as error:
            raise ResultCacheError(
                f"cannot write result cache {path}: {error}"
            ) from error

    def object_path(self, key: str) -> Path:
        assert self.directory is not None
        return self.directory / "objects" / f"{key}.json"

    @contextmanager
    def key_lock(self, key: str, *, wait_seconds: float = 30) -> Iterator[None]:
        """Serialize first-time work; lock failures stop the computation."""
        with self.key_locks_guard:
            local_lock = self.key_locks.setdefault(key, threading.Lock())
        with local_lock:
            if self.directory is None:
                yield
                return
            path = self.directory / "locks" / f"{key}.lock"
            try:
                with file_lock(path, wait_seconds=wait_seconds):
                    yield
            except FileLockError as error:
                raise ResultCacheError(
                    f"cannot lock result cache {path}: {error}"
                ) from error
