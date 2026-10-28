"""Compose runtime and image-layer scans into one container report."""

from __future__ import annotations

from collections import defaultdict
import copy
from dataclasses import fields, replace
from operator import attrgetter
from pathlib import Path
import re
from typing import Sequence

from pygo_audit.models import (
    BinaryLayerObservation,
    BinaryReport,
    ScanIssue,
    AuditReport,
    VulnerabilityScan,
)
from pygo_audit.reconciliation import reconcile_binary


LAYER_SORT_CHOICES = ("lexicographic", "numeric")


def discover_layer_directories(
    parent: Path, *, sort: str = "lexicographic"
) -> list[Path]:
    """Discover immediate layer directories without assuming image chronology."""
    if sort not in LAYER_SORT_CHOICES:
        raise ValueError(f"unknown layer sort: {sort}")
    try:
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError(
                f"layer parent must be a directory, not a symlink: {parent}"
            )
        entries = list(parent.iterdir())
        if any(path.is_symlink() for path in entries):
            raise ValueError(f"layer entries must not be symlinks: {parent}")
        layers = sorted(
            (path for path in entries if path.is_dir()), key=lambda path: path.name
        )
    except OSError as error:
        raise ValueError(f"cannot discover layers in {parent}: {error}") from error
    if not layers:
        raise ValueError(f"no layer directories found in {parent}")
    if sort == "numeric":
        # Compare digit groups as integers; stable ties retain lexicographic order.
        layers.sort(
            key=lambda path: [
                (1, int(part)) if part.isdecimal() else (0, part)
                for part in re.split(r"(\d+)", path.name)
            ]
        )
    return layers


def compose_reports(
    reports: Sequence[AuditReport],
    layer_dirs: Sequence[Path],
    *,
    layers_ordered: bool = True,
) -> AuditReport:
    """Merge rootfs and layer reports while preserving layer provenance."""
    if len(reports) != len(layer_dirs) + 1:
        raise ValueError("one scan report is required for the rootfs and each layer")

    runtime_report = reports[0]
    if not layer_dirs:
        return runtime_report
    merged = {
        _binary_key(binary): copy.deepcopy(binary) for binary in runtime_report.binaries
    }
    root_keys = set(merged)

    path_history: dict[str, list[tuple[int, str]]] = defaultdict(list)
    layer_events: dict[str, list[BinaryLayerObservation]] = defaultdict(list)
    for layer_index, (report, layer_dir) in enumerate(zip(reports[1:], layer_dirs)):
        for binary in report.binaries:
            key = _binary_key(binary)
            _merge_binary(merged, key, binary)
            paths = tuple(sorted(binary.paths))
            layer_events[key].append(
                BinaryLayerObservation(
                    layer_index,
                    "found",
                    paths,
                    tuple(sorted(binary.symlinks)),
                )
            )
            for path in paths:
                path_history[path].append((layer_index, key))

        # A display sort cannot establish which image layer changed a path later.
        if not layers_ordered:
            continue
        whiteouts = _whiteout_targets(Path(layer_dir))
        for key, events in layer_events.items():
            for event in list(events):
                if event.layer_index > layer_index:
                    continue
                for path in event.paths:
                    status = _later_path_status(
                        path,
                        key,
                        event.layer_index,
                        layer_index,
                        path_history,
                        whiteouts,
                    )
                    if status is None:
                        continue
                    status_layer, status_name = status
                    events.append(
                        BinaryLayerObservation(
                            status_layer,
                            status_name,
                            (path,),
                        )
                    )

    for key, binary in merged.items():
        binary.layer_history = _unique_layer_events(layer_events.get(key, ()))
        if key in root_keys:
            binary.runtime_disposition = "runtime"
        else:
            binary.runtime_disposition = _historical_disposition(binary.layer_history)

    for layer_index, report in enumerate(reports[1:]):
        prefix = f"layer-{layer_index:03d}"
        runtime_report.issues.extend(
            ScanIssue(
                path=f"{prefix}:{issue.path}",
                stage=issue.stage,
                message=issue.message,
            )
            for issue in report.issues
        )
        _add_stats(runtime_report, report)

    runtime_report.binaries = sorted(
        merged.values(),
        key=lambda binary: min(binary.paths),
    )
    return runtime_report


def _binary_key(binary: BinaryReport) -> str:
    """Use content identity, falling back to the first path for incomplete data."""
    return binary.sha256 or f"path:{min(binary.paths)}"


def _merge_binary(
    merged: dict[str, BinaryReport],
    key: str,
    incoming: BinaryReport,
) -> None:
    current = merged.get(key)
    if current is None:
        merged[key] = copy.deepcopy(incoming)
        return
    current.paths = sorted(set(current.paths) | set(incoming.paths))
    current.symlinks = sorted(set(current.symlinks) | set(incoming.symlinks))
    if current.vulnerability_scan == incoming.vulnerability_scan:
        return
    current.vulnerability_scan = _merge_vulnerability_scans(
        current.vulnerability_scan,
        incoming.vulnerability_scan,
    )
    reconcile_binary(current)


def _historical_disposition(
    history: Sequence[BinaryLayerObservation],
) -> str:
    statuses = {event.status for event in history}
    if "replaced" in statuses:
        return "replaced"
    if "deleted" in statuses:
        return "deleted"
    return "unaccounted"


def _merge_vulnerability_scans(
    left: VulnerabilityScan,
    right: VulnerabilityScan,
) -> VulnerabilityScan:
    """Union findings from equivalent binary observations without duplicates."""
    # Keep successful tool/database/SBOM provenance when another attempt failed.
    if left.status != "complete" and right.status == "complete":
        left, right = right, left
    result = copy.deepcopy(left)
    by_id = {
        vulnerability.id: vulnerability for vulnerability in result.vulnerabilities
    }
    for incoming in right.vulnerabilities:
        current = by_id.get(incoming.id)
        if current is None:
            current = copy.deepcopy(incoming)
            result.vulnerabilities.append(current)
            by_id[incoming.id] = current
            continue
        current.aliases = sorted(set(current.aliases) | set(incoming.aliases))
        # Reconciliation is derived after the union, not part of observation identity.
        current.findings = list(
            dict.fromkeys(
                replace(finding, reconciliation=None)
                for finding in (*current.findings, *incoming.findings)
            )
        )
    result.vulnerabilities.sort(key=lambda vulnerability: vulnerability.id)
    return result


def _whiteout_targets(layer_dir: Path) -> list[tuple[str, str]]:
    """Return whiteout targets as (kind, path) pairs from one layer directory."""
    targets: list[tuple[str, str]] = []
    for candidate in layer_dir.rglob("*"):
        name = candidate.name
        relative_parent = candidate.parent.relative_to(layer_dir)
        parent = "/" + "/".join(relative_parent.parts)
        parent = parent.rstrip("/")
        if name == ".wh..wh..opq":
            targets.append(("opaque", parent or "/"))
        elif name.startswith(".wh."):
            targets.append(("delete", f"{parent}/{name[4:]}"))
    return targets


def _later_path_status(
    path: str,
    key: str,
    layer_index: int,
    current_layer_index: int,
    path_history: dict[str, list[tuple[int, str]]],
    whiteouts: list[tuple[str, str]],
) -> tuple[int, str] | None:
    later = [
        (index, other_key)
        for index, other_key in path_history.get(path, ())
        if index > layer_index
    ]
    if later:
        index, other_key = min(later)
        if other_key != key:
            return index, "replaced"
    if any(
        (kind == "delete" and target == path)
        or (
            kind == "opaque"
            and (path == target or path.startswith(target.rstrip("/") + "/"))
        )
        for kind, target in whiteouts
    ):
        return current_layer_index, "deleted"
    return None


def _unique_layer_events(
    events: Sequence[BinaryLayerObservation],
) -> list[BinaryLayerObservation]:
    return sorted(set(events), key=attrgetter("layer_index", "status", "paths"))


def _add_stats(destination: AuditReport, source: AuditReport) -> None:
    """Add discovery totals from another scanned filesystem."""
    destination_stats = destination.stats
    source_stats = source.stats
    for item in fields(destination_stats):
        setattr(
            destination_stats,
            item.name,
            getattr(destination_stats, item.name) + getattr(source_stats, item.name),
        )
