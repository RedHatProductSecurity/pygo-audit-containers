"""Validate scan subjects and publish one container's audit evidence."""

import argparse
from contextlib import nullcontext
from pathlib import Path
import sys

from pygo_audit import scanner
from pygo_audit.artifacts import prepare_output, publish_audit
from pygo_audit.audit import load_audit
from pygo_audit.layer_scan import discover_layer_directories
from pygo_audit.models import AuditReport
from pygo_audit.storage import directory_lock, ensure_private_directory


def container_output_directory(output_root: Path, audit_root: Path) -> Path:
    """Return the shared per-container destination used by batch report commands."""
    return output_root / audit_root.name


def outside_subjects(paths: list[Path], subjects: list[Path]) -> None:
    for path in paths:
        for subject in subjects:
            if path.resolve().is_relative_to(subject.resolve()):
                raise ValueError(
                    f"generated path must not be inside a scan root: {path}"
                )


def scan_subjects(settings: argparse.Namespace) -> list[Path]:
    layers = []
    if settings.layers:
        layers = settings.layer_dir
        if not layers and (
            settings.layers_dir.exists()
            or settings.layers_dir.is_symlink()
            or settings.layers_dir != settings.audit_root / "layers"
        ):
            layers = discover_layer_directories(
                settings.layers_dir, sort=settings.layer_sort
            )
    subjects = [settings.rootfs, *layers]
    for path in [settings.audit_root, *subjects]:
        if path.is_symlink() or not path.is_dir():
            raise ValueError(
                f"audit root and subjects must be existing directories, not symlinks: {path}"
            )
    outside_subjects(
        [
            settings.output_dir,
            *(
                [settings.bundle_output_dir]
                if getattr(settings, "bundle_output_dir", None)
                else []
            ),
            settings.history_dir,
            settings.cache_dir,
            settings.work_dir,
        ],
        subjects,
    )
    return subjects


def scan_workspace(
    settings: argparse.Namespace, *, run_id: str
) -> tuple[AuditReport, Path]:
    subjects = scan_subjects(settings)
    reports_directory = settings.output_dir / "reports"
    bundle_directory = getattr(settings, "bundle_output_dir", None)
    prepare_output(
        settings.output_dir,
        reports_directory,
        bundle_directory=bundle_directory,
    )
    for directory in (settings.history_dir, settings.cache_dir, settings.work_dir):
        ensure_private_directory(directory)
    with directory_lock(settings.output_dir):
        report = scanner.scan_root(
            subjects[0],
            subjects[1:],
            layers_ordered=bool(settings.layer_dir),
            go_command=settings.go,
            govulncheck_command=settings.govulncheck if settings.vulncheck else None,
            timeout=settings.timeout,
            jobs=settings.jobs,
            binary_cache_dir=settings.cache_dir,
            work_dir=settings.work_dir,
            run_id=run_id,
        )
        report.metadata.image = settings.image
        report.run_id = run_id
        if settings.strict and report.actionable_issues:
            destination = (
                settings.work_dir / f"failed-{settings.audit_root.name}-{run_id}"
            )
            label = "Incomplete scan saved"
        else:
            destination = settings.output_dir
            label = "Audit"
        with (
            directory_lock(bundle_directory)
            if bundle_directory is not None
            and bundle_directory.resolve() != settings.output_dir.resolve()
            else nullcontext()
        ):
            publish_audit(
                report,
                destination,
                settings.history_dir,
                settings.work_dir,
                destination / "reports",
                bundle_directory=bundle_directory,
            )
        print(f"{label}: {destination / 'audit.json'}", file=sys.stderr)
        audit_file = destination / "audit.json"
        return load_audit(audit_file), audit_file
