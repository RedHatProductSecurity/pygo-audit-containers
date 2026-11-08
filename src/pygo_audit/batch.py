"""Scan prepared child audit workspaces with a shared cache and run lifetime."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pygo_audit.artifacts import validate_artifact_directory
from pygo_audit.scanner import ScanConfigurationError
from pygo_audit.models import TargetOutcome
from pygo_audit.storage import atomic_text_writer, atomic_write_text, directory_lock
from pygo_audit.workspace import scan_subjects, scan_workspace, outside_subjects


def write_progress(root: Path, results: Mapping[str, TargetOutcome]) -> None:
    with atomic_text_writer(
        root / "progress.tsv", overwrite=True, newline=""
    ) as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(("name", "status", "audit_file", "detail"))
        writer.writerows(
            (
                results[name].name,
                results[name].status,
                results[name].audit_file or "",
                results[name].detail,
            )
            for name in sorted(results)
        )


def run(options: argparse.Namespace, settings: list[argparse.Namespace]) -> int:
    root = options.audit_root
    reports_directory = root / "reports"
    subjects = [subject for item in settings for subject in scan_subjects(item)]
    outputs = [item.output_dir.resolve() for item in settings]
    if len(set(outputs)) != len(outputs):
        raise ValueError("each target must have a distinct report output directory")
    outside_subjects(
        [
            root,
            options.cache_dir,
            options.work_dir,
            *(
                path
                for item in settings
                for path in (
                    item.output_dir,
                    item.history_dir,
                    item.cache_dir,
                    item.work_dir,
                )
            ),
        ],
        subjects,
    )
    run_id = uuid4().hex
    results: dict[str, TargetOutcome] = {}

    with directory_lock(root):
        with ThreadPoolExecutor(max_workers=options.workers) as pool:
            pending = {
                pool.submit(scan_workspace, item, run_id=run_id): item
                for item in settings
            }
            for future in as_completed(pending):
                item = pending[future]
                name = item.audit_root.name
                try:
                    if future.cancelled():
                        outcome = TargetOutcome(name, "CANCELLED", detail="not started")
                    else:
                        report, audit_file = future.result()
                        status: Literal["FAILED", "COMPLETE"] = (
                            "FAILED"
                            if item.strict and report.actionable_issues
                            else "COMPLETE"
                        )
                        outcome = TargetOutcome(
                            name,
                            status,
                            audit_file,
                            "actionable scan issues" if status == "FAILED" else "",
                        )
                except (OSError, ValueError, ScanConfigurationError) as error:
                    outcome = TargetOutcome(
                        name, "FAILED", detail=" ".join(str(error).split())
                    )
                results[name] = outcome
                print(outcome.summary(), flush=True)
                if outcome.status == "FAILED" and options.fail_fast:
                    for queued in pending:
                        queued.cancel()
                write_progress(root, results)
        lines = [results[name].summary() for name in sorted(results)]
        validate_artifact_directory(reports_directory)
        reports_directory.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            reports_directory / "container-summary.txt",
            "\n".join(lines) + "\n",
            overwrite=True,
        )
    return int(any(outcome.status != "COMPLETE" for outcome in results.values()))
