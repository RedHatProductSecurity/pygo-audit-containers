"""Safely persist portable reports derived from one audit."""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Iterable, Mapping, Sequence

from pygo_audit.audit import AuditError, load_audit
from pygo_audit.models import AuditReport
from pygo_audit.report import (
    REPORT_VIEWS,
    render_check_results,
    render_json,
)
from pygo_audit.report_views import evaluate_checks
from pygo_audit.storage import atomic_write_text, directory_lock
from pygo_audit.text_layout import FULL_POLICY


class ArtifactError(ValueError):
    """Raised when audit artifacts cannot be written safely."""


AUDIT_NAME = REPORT_VIEWS["json"].filename
TEXT_REPORT_NAMES = tuple(
    view.filename for name, view in REPORT_VIEWS.items() if name != "json"
)


def history_filename(report: AuditReport) -> str:
    identifier = re.sub(r"[^A-Za-z0-9_-]", "", report.run_id)
    date = re.sub(r"[^0-9TZ]", "", report.scan_completed_at)
    if not identifier or not date:
        raise ArtifactError("archiving an audit requires run_id and scan_completed_at")
    return f"audit-{identifier}-{date}.json"


def prepare_output(directory: Path, reports_directory: Path | None = None) -> None:
    """Validate destinations and prove writability before inspecting binaries."""
    reports_directory = reports_directory or directory
    validate_artifact_directory(directory)
    validate_artifact_directory(reports_directory)
    directory.mkdir(parents=True, exist_ok=True)
    reports_directory.mkdir(parents=True, exist_ok=True)
    report_paths = [reports_directory / name for name in TEXT_REPORT_NAMES]
    for path in [directory / AUDIT_NAME, *report_paths]:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ArtifactError(f"report output must be a regular file: {path}")
    with TemporaryDirectory(prefix="write-check-", dir=directory):
        pass


def publish_audit(
    report: AuditReport,
    directory: Path,
    history: Path,
    work: Path,
    reports_directory: Path | None = None,
) -> None:
    """Stage every view, preserve the previous JSON, then publish JSON last.

    The caller holds the workspace lock. Each file replacement is atomic; the
    canonical JSON is the publication marker. Ordinary failures restore old views.
    """
    reports_directory = reports_directory or directory
    prepare_output(directory, reports_directory)
    with TemporaryDirectory(prefix="publish-", dir=work) as temporary:
        staging = Path(temporary)
        audit_file = staging / AUDIT_NAME
        atomic_write_text(audit_file, terminated(render_json(report)))
        write_report_artifacts(load_audit(audit_file), staging)
        destinations = [
            *((reports_directory / name, staging / name) for name in TEXT_REPORT_NAMES),
            (directory / AUDIT_NAME, staging / AUDIT_NAME),
        ]
        current = directory / AUDIT_NAME
        old = current.read_text(encoding="utf-8") if current.exists() else None
        if old is not None:
            history.mkdir(parents=True, exist_ok=True)
            try:
                destination_name = history_filename(load_audit(current))
            except AuditError, ArtifactError:
                destination_name = (
                    "audit-invalid-"
                    f"{hashlib.sha256(old.encode('utf-8')).hexdigest()[:16]}.json"
                )
            destination = history / destination_name
            if destination.is_symlink():
                raise ArtifactError(f"history must not be a symlink: {destination}")
            if destination.exists():
                if destination.read_text(encoding="utf-8") != old:
                    raise ArtifactError(
                        f"history contains different content: {destination}"
                    )
            else:
                atomic_write_text(destination, old)
        replace_payloads(
            {
                destination: source.read_text(encoding="utf-8")
                for destination, source in destinations
            }
        )


def validate_artifact_directory(output_directory: Path) -> None:
    """Reject output locations that cannot safely contain audit artifacts."""
    directory = Path(output_directory)
    if directory.is_symlink():
        raise ArtifactError(f"artifact output must not be a symlink: {directory}")
    if directory.exists() and not directory.is_dir():
        raise ArtifactError(f"artifact output is not a directory: {directory}")


def write_report_artifacts(
    report: AuditReport,
    output_directory: Path,
) -> list[Path]:
    """Write derived text views without duplicating the canonical audit JSON."""
    payloads = {
        Path(view.filename): terminated(view.render(report, FULL_POLICY))
        for name, view in REPORT_VIEWS.items()
        if name != "json"
    }
    return write_payloads(Path(output_directory), payloads)


def write_check_artifacts(
    report: AuditReport,
    output_directory: Path,
    checks: Sequence[str],
) -> list[Path]:
    """Write or reuse only the requested targeted-check reports."""
    return write_payloads(
        Path(output_directory),
        check_payloads(report, checks),
    )


def write_comparison_artifacts(
    directory: Path,
    name: str,
    document: object,
    text: str,
    *,
    inputs: Iterable[Path],
    csv_text: str | None = None,
) -> tuple[Path, Path]:
    """Publish comparison views under one lock, with canonical JSON last."""
    payloads = comparison_payloads(directory, name, document, text, csv_text=csv_text)
    write_artifact_group(payloads, inputs=inputs)
    return directory / f"{name}.json", directory / f"{name}.txt"


def comparison_payloads(
    directory: Path,
    name: str,
    document: object,
    text: str,
    *,
    csv_text: str | None = None,
) -> dict[Path, str]:
    """Stage every view before publication, placing canonical JSON last."""
    json_path, text_path = directory / f"{name}.json", directory / f"{name}.txt"
    payloads = {text_path: terminated(text)}
    if csv_text is not None:
        payloads[directory / f"{name}.csv"] = terminated(csv_text)
    payloads[json_path] = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
    return payloads


def write_artifact_group(
    payloads: Mapping[Path, str], *, inputs: Iterable[Path]
) -> None:
    """Lock destinations in order and roll back all ordinary write failures."""
    if len({path.resolve() for path in payloads}) != len(payloads):
        raise ArtifactError("artifact outputs must have distinct resolved paths")
    input_paths = {path.resolve() for path in inputs}
    for path in payloads:
        if path.is_symlink() or path.resolve() in input_paths:
            raise ArtifactError(
                f"artifact output must differ from its inputs and not be a symlink: {path}"
            )
    directories = sorted({path.parent.resolve() for path in payloads})
    for path in payloads:
        validate_artifact_directory(path.parent)
    with ExitStack() as locks:
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            locks.enter_context(directory_lock(directory))
        replace_payloads(payloads)


def check_payloads(
    report: AuditReport,
    checks: Sequence[str],
) -> dict[Path, str]:
    payloads: dict[Path, str] = {}
    for result in evaluate_checks(report, checks):
        relative_path = Path("checks") / check_filename(result.identifier)
        payload = terminated(render_check_results(report, [result], FULL_POLICY))
        existing = payloads.get(relative_path)
        if existing is not None and existing != payload:
            raise ArtifactError(
                f"multiple checks map to conflicting artifact {relative_path}"
            )
        payloads[relative_path] = payload
    return payloads


def write_payloads(directory: Path, payloads: dict[Path, str]) -> list[Path]:
    validate_artifact_directory(directory)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        return replace_payloads(
            {directory / name: value for name, value in payloads.items()}
        )
    except OSError as error:
        raise ArtifactError(
            f"cannot write artifacts in {directory}: {error}"
        ) from error


def replace_payloads(payloads: Mapping[Path, str]) -> list[Path]:
    """Replace ordered files atomically, restoring prior contents on failure."""
    previous = {}
    for path in payloads:
        validate_artifact_directory(path.parent)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ArtifactError(
                f"artifact output must be a regular file, not a symlink: {path}"
            )
        previous[path] = path.read_text(encoding="utf-8") if path.exists() else None
    for path in payloads:
        path.parent.mkdir(parents=True, exist_ok=True)
    published = []
    try:
        for path, content in payloads.items():
            atomic_write_text(path, content, overwrite=True)
            published.append(path)
    except OSError:
        for path in reversed(published):
            original = previous[path]
            if original is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write_text(path, original, overwrite=True)
        raise
    return list(payloads)


def check_filename(identifier: str) -> str:
    normalized = identifier.strip().upper()
    safe = re.sub(r"[^A-Z0-9._-]+", "-", normalized).strip(".-")
    if not safe:
        safe = "query"
    if safe != normalized or safe in {".", ".."}:
        suffix = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe}-{suffix}"
    return f"{safe}.txt"


def terminated(value: str) -> str:
    return value.rstrip("\n") + "\n" if value else ""
