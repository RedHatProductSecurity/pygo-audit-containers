"""Safely persist portable reports derived from one scan snapshot."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile
from typing import Sequence

from pygo_audit.models import ScanReport
from pygo_audit.report import (
    render_binaries,
    render_check_result,
    render_diagnostics,
    render_findings,
    render_json,
    render_overview,
)
from pygo_audit.report_views import evaluate_checks


class ArtifactError(ValueError):
    """Raised when an artifact bundle cannot be written safely."""


def validate_artifact_directory(output_directory: Path) -> None:
    """Reject output locations that cannot safely contain an artifact bundle."""
    directory = Path(output_directory)
    if directory.is_symlink():
        raise ArtifactError(f"artifact output must not be a symlink: {directory}")
    if directory.exists() and not directory.is_dir():
        raise ArtifactError(f"artifact output is not a directory: {directory}")


def write_artifacts(
    report: ScanReport,
    output_directory: Path,
    *,
    checks: Sequence[str] = (),
) -> list[Path]:
    """Write or reuse a complete bundle without overwriting differing content."""
    payloads = {
        Path("audit.json"): _terminated(render_json(report)),
        Path("overview.txt"): _terminated(render_overview(report)),
        Path("findings.txt"): _terminated(render_findings(report)),
        Path("binaries.txt"): _terminated(render_binaries(report)),
        Path("diagnostics.txt"): _terminated(render_diagnostics(report)),
    }
    payloads.update(_check_payloads(report, checks))
    return _write_payloads(Path(output_directory), payloads)


def write_check_artifacts(
    report: ScanReport,
    output_directory: Path,
    checks: Sequence[str],
) -> list[Path]:
    """Write or reuse only the requested targeted-check reports."""
    return _write_payloads(
        Path(output_directory),
        _check_payloads(report, checks),
    )


def _check_payloads(
    report: ScanReport,
    checks: Sequence[str],
) -> dict[Path, str]:
    payloads: dict[Path, str] = {}
    for result in evaluate_checks(report, checks):
        relative_path = Path("checks") / _check_filename(result.identifier)
        payload = _terminated(render_check_result(report, result))
        existing = payloads.get(relative_path)
        if existing is not None and existing != payload:
            raise ArtifactError(
                f"multiple checks map to conflicting artifact {relative_path}"
            )
        payloads[relative_path] = payload
    return payloads


def _write_payloads(
    directory: Path,
    payloads: dict[Path, str],
) -> list[Path]:
    validate_artifact_directory(directory)
    destinations = [(directory / relative, payload) for relative, payload in payloads.items()]

    for destination, payload in destinations:
        if destination.parent != directory:
            parent = destination.parent
            if parent.is_symlink():
                raise ArtifactError(f"artifact directory must not be a symlink: {parent}")
            if parent.exists() and not parent.is_dir():
                raise ArtifactError(f"artifact parent is not a directory: {parent}")
        if destination.is_symlink():
            raise ArtifactError(f"artifact output must not be a symlink: {destination}")
        if destination.exists():
            if not destination.is_file():
                raise ArtifactError(f"artifact output is not a file: {destination}")
            try:
                existing = destination.read_text(encoding="utf-8")
            except OSError as error:
                raise ArtifactError(
                    f"cannot read existing artifact {destination}: {_os_error(error)}"
                ) from error
            if existing != payload:
                raise ArtifactError(
                    f"artifact output contains different content: {destination}"
                )

    try:
        directory.mkdir(parents=True, exist_ok=True)
        for destination, _ in destinations:
            destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ArtifactError(
            f"cannot create artifact directory {directory}: {_os_error(error)}"
        ) from error

    created_paths: list[Path] = []
    temporary_paths: list[Path] = []
    try:
        for destination, payload in destinations:
            if destination.exists():
                continue
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}-",
                suffix=".tmp",
                delete=False,
            ) as artifact:
                temporary_path = Path(artifact.name)
                temporary_paths.append(temporary_path)
                artifact.write(payload)
                artifact.flush()
                os.fsync(artifact.fileno())
            try:
                os.link(temporary_path, destination)
            except FileExistsError as error:
                raise ArtifactError(
                    f"artifact output appeared while writing: {destination}"
                ) from error
            created_paths.append(destination)
    except ArtifactError:
        _remove_created(created_paths)
        raise
    except OSError as error:
        _remove_created(created_paths)
        raise ArtifactError(
            f"cannot write artifact bundle in {directory}: {_os_error(error)}"
        ) from error
    finally:
        for temporary_path in temporary_paths:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
    return [destination for destination, _ in destinations]


def _check_filename(identifier: str) -> str:
    normalized = identifier.strip().upper()
    safe = re.sub(r"[^A-Z0-9._-]+", "-", normalized).strip(".-")
    if not safe:
        safe = "query"
    if safe != normalized or safe in {".", ".."}:
        suffix = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe}-{suffix}"
    return f"{safe}.txt"


def _terminated(value: str) -> str:
    return value.rstrip("\n") + "\n"


def _remove_created(paths: list[Path]) -> None:
    for path in reversed(paths):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _os_error(error: OSError) -> str:
    return error.strerror or str(error)
