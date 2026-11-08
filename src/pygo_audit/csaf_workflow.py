"""Orchestrate the same image comparison for one workspace or a batch."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, replace
import multiprocessing
from pathlib import Path
from typing import Any

from pygo_audit import csaf, image_csaf
from pygo_audit.artifacts import (
    comparison_payloads,
    validate_artifact_directory,
    write_artifact_group,
)
from pygo_audit.audit import load_audit
from pygo_audit.identity import resolve_image_identity
from pygo_audit.report_views import normalize_cve
from pygo_audit.storage import json_digest
from pygo_audit.text_layout import FULL_POLICY, RenderPolicy, SUMMARY_POLICY
from pygo_audit.workspace import outside_subjects


@dataclass(frozen=True, slots=True)
class WorkspaceCheck:
    root: Path
    output_dir: Path
    audit: image_csaf.ImageAudit
    inputs: tuple[Path, ...]
    files: tuple[Path, ...]
    missing: image_csaf.MissingDocuments
    identity_override: str
    identity_key: str
    protected_inputs: frozenset[Path]


@dataclass(frozen=True, slots=True)
class CompletedCheck:
    workspace: WorkspaceCheck
    data: dict[str, Any]  # Canonical comparison JSON from image_csaf.build_comparison.


def load_workspaces(settings: list[argparse.Namespace]) -> list[WorkspaceCheck]:
    outputs = [options.output_dir.resolve() for options in settings]
    if len(set(outputs)) != len(outputs):
        raise csaf.CsafCheckError(
            "each container comparison needs a distinct output directory"
        )
    subjects = [
        path
        for options in settings
        for path in (options.rootfs, options.layers_dir, *options.layer_dir)
    ]
    outside_subjects([options.output_dir for options in settings], subjects)
    collections: dict[
        tuple[Path, ...], tuple[list[Path], image_csaf.MissingDocuments]
    ] = {}
    targets = []
    for options in settings:
        validate_artifact_directory(options.output_dir)
        report = load_audit(options.audit_file)
        identity = report.metadata.image
        if options.image_metadata is not None:
            identity = resolve_image_identity(
                options.rootfs, metadata_path=options.image_metadata
            )
        if options.csaf_product_id is not None:
            identity = replace(
                identity,
                csaf_product_ids=(options.csaf_product_id,)
                if options.csaf_product_id
                else (),
            )
        inputs = tuple(options.csaf)
        if inputs not in collections:
            collections[inputs] = image_csaf.comparison_inputs(list(inputs))
        files, missing = collections[inputs]
        source = image_csaf.prepare_image(options.audit_file, report, identity)
        override = str(options.image_metadata or "")
        if options.csaf_product_id is not None:
            override += " --csaf-product-id=" + options.csaf_product_id
        protected = {
            source.path,
            *files,
            *(
                Path(record["source"])
                for records in missing.values()
                for record in records
            ),
        }
        if options.image_metadata is not None:
            protected.add(options.image_metadata)
        targets.append(
            WorkspaceCheck(
                options.audit_root,
                options.output_dir,
                source,
                inputs,
                tuple(files),
                missing,
                override,
                json_digest(source.inputs),
                frozenset(protected),
            )
        )
    protected_inputs = frozenset(
        path for target in targets for path in target.protected_inputs
    )
    return [replace(target, protected_inputs=protected_inputs) for target in targets]


def inspect_source(
    path: Path,
    contexts: dict[str, dict[str, Any]],
    selections: dict[str, frozenset[str]] | None,
) -> tuple[Path, dict[str, dict[str, Any]]]:
    """Read/index a document once and reuse matching for identical lookup inputs."""
    document = csaf.load_document(path)
    if selections is not None:
        cves = {
            cve
            for number, record in enumerate(document.get("vulnerabilities", []), 1)
            if isinstance(record, dict)
            if (
                cve := normalize_cve(
                    image_csaf.vulnerability_identifier(record, number)
                )
            )
        }
        contexts = {
            key: value for key, value in contexts.items() if selections[key] & cves
        }
    if not contexts:
        return path, {}
    index = csaf.index_document(document)
    return path, {
        key: image_csaf.inspect_document(path, path.name, inputs, index)
        for key, inputs in contexts.items()
    }


def compare_workspaces(
    targets: list[WorkspaceCheck], *, jobs: int, recorded_only: bool
) -> list[CompletedCheck]:
    """Share document work; build every local conclusion from its own saved audit."""
    if jobs < 1:
        raise ValueError("CSAF jobs must be positive")
    contexts: dict[Path, dict[str, dict[str, Any]]] = {}
    selections: dict[Path, dict[str, set[str]]] = {}
    for target in targets:
        for path in target.files:
            contexts.setdefault(path, {})[target.identity_key] = target.audit.inputs
            selections.setdefault(path, {}).setdefault(
                target.identity_key, set()
            ).update(target.audit.evidence)
    paths = sorted(contexts)
    documents: dict[Path, dict[str, dict[str, Any]]] = {}
    if paths:
        workers = min(jobs, len(paths))
        executor = (
            ThreadPoolExecutor(max_workers=1)
            if workers == 1
            else ProcessPoolExecutor(
                max_workers=workers, mp_context=multiprocessing.get_context("spawn")
            )
        )
        with executor as pool:
            for path, matches in pool.map(
                inspect_source,
                paths,
                (contexts[path] for path in paths),
                (
                    {key: frozenset(cves) for key, cves in selections[path].items()}
                    if recorded_only
                    else None
                    for path in paths
                ),
                buffersize=workers,
            ):
                documents[path] = matches
    completed = []
    for target in targets:
        names = csaf.relative_document_names(
            {str(path): path for path in target.files}, target.inputs
        )
        selected = []
        for path in target.files:
            if target.identity_key not in documents[path]:
                continue
            document = deepcopy(documents[path][target.identity_key])
            document["source_display"] = names[str(path)]
            if recorded_only:
                document["vulnerabilities"] = [
                    record
                    for record in document["vulnerabilities"]
                    if normalize_cve(record["id"]) in target.audit.evidence
                ]
                if not document["vulnerabilities"]:
                    continue
            selected.append(document)
        missing = {
            cve: deepcopy(records)
            for cve, records in target.missing.items()
            if not recorded_only or cve in target.audit.evidence
        }
        result = image_csaf.build_comparison(target.audit, selected, missing)
        result["identity_override"] = target.identity_override
        completed.append(CompletedCheck(target, result))
    return completed


def publish_checks(
    checks: list[CompletedCheck], additional: Mapping[Path, str] | None = None
) -> None:
    payloads: dict[Path, str] = {}
    for check in checks:
        payloads.update(
            comparison_payloads(
                check.workspace.output_dir,
                "comparison",
                check.data,
                image_csaf.render_text(check.data, FULL_POLICY),
            )
        )
    for path, content in (additional or {}).items():
        if path in payloads:
            raise csaf.CsafCheckError(f"multiple reports use the same output: {path}")
        payloads[path] = content
    write_artifact_group(
        payloads,
        inputs={path for check in checks for path in check.workspace.protected_inputs},
    )


def run(
    settings: list[argparse.Namespace],
    policy: RenderPolicy = SUMMARY_POLICY,
    *,
    jobs: int = 1,
    recorded_only: bool = False,
) -> int:
    targets = load_workspaces(settings)
    if not any(
        target.files or target.missing or target.audit.evidence for target in targets
    ):
        raise csaf.CsafCheckError("no CSAF JSON files supplied")
    completed = compare_workspaces(targets, jobs=jobs, recorded_only=recorded_only)
    publish_checks(completed)
    for check in completed:
        print(image_csaf.render_text(check.data, policy), end="")
        print(
            f"Comparison: {check.workspace.output_dir / 'comparison.txt'}\nJSON: {check.workspace.output_dir / 'comparison.json'}"
        )
    return 0
