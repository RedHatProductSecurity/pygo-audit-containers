"""Aggregate saved container audits into readable text and structured JSON."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
import multiprocessing
from pathlib import Path
from typing import Any, Iterable

from pygo_audit import comparison, csaf
from pygo_audit import models
from pygo_audit.artifacts import write_comparison_artifacts
from pygo_audit.audit import load_audit
from pygo_audit.report_views import index_cve_evidence
from pygo_audit.result_cache import ResultCache
from pygo_audit.workspace import outside_subjects
from pygo_audit.storage import json_digest
from pygo_audit.text_layout import TextLayout

CSAF_ASSESSMENTS = (
    "exact_image_digest",
    "component_release_architecture",
    "component_release",
    "component",
    "cpe",
    "cpe_compatible",
    "cpe_version_family",
    "cpe_parent",
    "cpe_parent_compatible",
    "cpe_parent_version_family",
    "no_matching_product",
    "document_has_no_matching_cve_record",
)
PRODUCT_STATUSES = {
    "status": ("known_affected", "known_not_affected", "fixed", "under_investigation"),
    "flag": (
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
    ),
    "remediation": ("vendor_fix", "workaround", "none_available"),
}
RECONCILIATION_COUNTERS = {
    "pygo_binary_reconciliation": (
        "binary",
        models.BinaryReconciliation.field_choices["status"],
    ),
    "pygo_go_version": (
        "go",
        tuple(
            status
            for status in models.BinaryReconciliation.field_choices["go_version_status"]
            if status != "not_checked"
        ),
    ),
    "pygo_finding_reconciliation": ("finding", models.MODULE_STATUSES),
    "pygo_sbom_reconciliation": ("sbom", models.MODULE_STATUSES),
}
VEX_COUNTERS = {
    "pygo_cve_vex": (
        "comparison",
        (
            "agreement",
            "resolved_difference",
            "code_presence_conflict",
            "mismatch",
            "unverified",
            "conflicting_vex",
        ),
    ),
    "pygo_cve_vex_resolution": (
        "resolution",
        ("fixed", "code_not_present", "code_not_reachable", "code_not_controllable"),
    ),
}


def counter_fields(
    prefix: str,
    counts: Counter[str],
    statuses: Iterable[str],
    *,
    key_prefix: str = "",
    suffix: str = "",
) -> dict[str, int]:
    """Emit stable counter fields, including zeroes for unobserved statuses."""
    return {
        f"{prefix}_{status}{suffix}": counts[f"{key_prefix}{status}"]
        for status in statuses
    }


@dataclass(slots=True)
class TargetAudit:
    index: int  # One-based position in the batch output.
    directory: Path  # Host directory holding this container's audit.
    report: models.AuditReport  # Strictly reconstructed saved audit evidence.
    evidence: dict[str, models.CveEvidence] = field(
        init=False
    )  # Original observations indexed once for every output view.
    assessments: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )  # CSAF identity assessments indexed by CVE.
    audit_file: Path | None = None  # Preserve explicitly selected evidence paths.

    def __post_init__(self) -> None:
        self.evidence = index_cve_evidence(self.report)


def string(value: object) -> str:
    return value if isinstance(value, str) else ""


def short_hash(value: str) -> str:
    if not value:
        return ""
    digest = value.split(":", 1)[-1]
    return digest[:12] + "..." if len(digest) > 12 else digest


def image_metadata(target: TargetAudit) -> dict[str, str]:
    image = target.report.metadata.image
    return {
        "image_reference": image.reference,
        "image_digest": image.digest,
        "image_digest_short": short_hash(image.digest),
        "platform": image.platform,
        "image_name": image.name,
        "component": image.component,
        "source_git_url": image.source_git_url,
        "product_version": image.product_version,
        "component_version": image.component_version,
        "product_component": image.product_component,
        "cpe": image.cpe,
    }


def load_target(directory: Path, audit_path: Path, index: int = 1) -> TargetAudit:
    return TargetAudit(index, directory, load_audit(audit_path), audit_file=audit_path)


def assess_cve_worker(
    cve: str,
    document_path: Path | None,
    identities: dict[int, models.ImageIdentity],
) -> tuple[str, dict[int, dict[str, Any]]]:
    """Index one local document and match it to every relevant container."""
    fetch = csaf.read_document(cve, document_path)
    comparison = csaf.CsafComparison(cve, fetch, ResultCache(None))
    assessments = {
        target_index: comparison.assess(
            identity,
            include_details=False,
        )
        for target_index, identity in identities.items()
    }
    return cve, assessments


def enrich_with_csaf(
    targets: list[TargetAudit], args: argparse.Namespace
) -> dict[str, Path]:
    """Share each indexed local document across the relevant targets."""
    locations = csaf.document_locations(args.csaf)
    target_by_cve: dict[str, list[TargetAudit]] = {}
    for target in targets:
        for cve in target.evidence:
            target_by_cve.setdefault(cve, []).append(target)

    cves = sorted(target_by_cve)
    executor = (
        ThreadPoolExecutor(max_workers=1)
        if args.jobs == 1
        else ProcessPoolExecutor(
            max_workers=args.jobs, mp_context=multiprocessing.get_context("spawn")
        )
    )
    with executor as pool:
        results = pool.map(
            assess_cve_worker,
            cves,
            (locations.get(cve) for cve in cves),
            (
                {
                    target.index: target.report.metadata.image
                    for target in target_by_cve[cve]
                }
                for cve in cves
            ),
            buffersize=args.jobs,
        )
        for cve, assessments in results:
            for target in target_by_cve[cve]:
                target.assessments[cve] = assessments[target.index]
    return locations


def _binary_counters(target: TargetAudit) -> dict[str, Counter[str]]:
    counters = {key: Counter() for key in ("binary", "go", "finding", "sbom")}
    for binary in target.report.binaries:
        reconciliation = binary.reconciliation
        counters["binary"][reconciliation.status] += 1
        counters["go"][reconciliation.go_version_status] += 1
        counters["finding"].update(binary.finding_statuses)
        counters["sbom"].update(reconciliation.sbom_statuses)
    return counters


def _csaf_counters(target: TargetAudit) -> dict[str, Counter[str]]:
    assessments = Counter()
    product_statuses = Counter()
    for assessment in target.assessments.values():
        assessments[string(assessment.get("assessment"))] += 1
        if string(assessment.get("assessment")).startswith("cpe"):
            # Platform candidate statuses do not establish a container status.
            continue
        for status in assessment.get("statuses", []):
            if isinstance(status, str):
                product_statuses[status] += 1
    return {"assessment": assessments, "product": product_statuses}


def _cve_comparison_counters(
    evaluations: dict[str, dict[str, Any]],
) -> dict[str, Counter[str]]:
    return {
        "comparison": Counter(item["comparison"] for item in evaluations.values()),
        "resolution": Counter(
            value for item in evaluations.values() for value in item["resolutions"]
        ),
    }


def finding_counts(target: TargetAudit) -> tuple[int, int]:
    """Count indexed CVE observations, retaining advisories without findings."""
    counts = Counter()
    for evidence in target.evidence.values():
        for binary, vulnerability in evidence.observations:
            counts[binary.runtime_disposition] += max(len(vulnerability.findings), 1)
    return counts.total(), counts["unaccounted"]


def summary_row(
    target: TargetAudit, evaluations: dict[str, dict[str, Any]] | None = None
) -> dict[str, object]:
    binaries = target.report.binaries
    binary_sha256 = {binary.sha256 for binary in binaries if binary.sha256}
    disposition_counts = Counter(binary.runtime_disposition for binary in binaries)
    binary_counts = _binary_counters(target)
    csaf_counts = _csaf_counters(target)
    if evaluations is None:
        evaluations = {
            cve: comparison.evaluation_dict(
                comparison.evaluate(evidence, target.assessments.get(cve))
            )
            for cve, evidence in target.evidence.items()
        }
    cve_counts = _cve_comparison_counters(evaluations)
    finding_count, historical_finding_count = finding_counts(target)
    row: dict[str, object] = {
        "target_index": f"{target.index:03d}",
        "container_name": target.directory.name,
        "audit_directory": str(target.directory),
        "audit_complete": "true",
        **image_metadata(target),
        "binary_count": len(binaries),
        "unaccounted_historical_binary_count": disposition_counts["unaccounted"],
        "unaccounted_historical_finding_count": historical_finding_count,
        "unique_binary_sha256_count": len(binary_sha256),
        "unique_cve_count": len(target.evidence),
        "finding_row_count": finding_count,
        "csaf_cve_count": len(target.assessments),
        "csaf_documents_found": sum(
            assessment.get("assessment") != "document_missing"
            for assessment in target.assessments.values()
        ),
        "csaf_documents_missing": csaf_counts["assessment"].get("document_missing", 0),
        "csaf_cpe_candidate_count": sum(
            a.get("cpe_candidate_count", 0) for a in target.assessments.values()
        ),
        "csaf_cpe_known_affected": sum(
            bool(a.get("cpe_known_affected")) for a in target.assessments.values()
        ),
    }
    row.update(
        counter_fields(
            "runtime_disposition",
            disposition_counts,
            models.RUNTIME_DISPOSITIONS,
            suffix="_count",
        )
    )
    row.update(counter_fields("csaf", csaf_counts["assessment"], CSAF_ASSESSMENTS))
    product_counts = csaf_counts["product"]
    for category, statuses in PRODUCT_STATUSES.items():
        prefix = "csaf" if category == "status" else f"csaf_{category}"
        row.update(
            counter_fields(prefix, product_counts, statuses, key_prefix=f"{category}:")
        )
    for groups, counters in (
        (RECONCILIATION_COUNTERS, binary_counts),
        (VEX_COUNTERS, cve_counts),
    ):
        for prefix, (name, statuses) in groups.items():
            row.update(counter_fields(prefix, counters[name], statuses))
    for category in ("status", "remediation"):
        known = {f"{category}:{status}" for status in PRODUCT_STATUSES[category]}
        row[f"csaf_{category}_other"] = sum(
            count
            for key, count in product_counts.items()
            if key.startswith(f"{category}:") and key not in known
        )
    return row


def build_result(targets: list[TargetAudit]) -> dict[str, Any]:
    """Keep current evidence and comparison counts together for every container."""
    containers = []
    for target in targets:
        document = csaf.build_result(
            target.audit_file or target.directory / "audit.json",
            target.report.metadata.image,
            target.evidence,
            target.assessments,
        )
        containers.append(
            {
                **document,
                "container_name": target.directory.name,
                "audit_sha256": json_digest(target.report.to_dict()),
                "scan_coverage": target.report.coverage_state,
                "audit_summary": summary_row(target, document["comparisons"]),
            }
        )
    metrics = comparison.summarize(
        item["comparison"]
        for container in containers
        for item in container["comparisons"].values()
    )
    return {
        "counting_unit": "container_cve",
        "summary": {"container_count": len(containers), "metrics": metrics},
        "containers": containers,
    }


def render_text(result: dict[str, Any]) -> str:
    lines = TextLayout.titled("CSAF BATCH COMPARISON")
    comparison.append_summary(lines, result["summary"]["metrics"])
    lines.field("Containers", result["summary"]["container_count"])
    containers = sorted(
        result["containers"],
        key=lambda item: (
            -item["summary"]["metrics"]["unresolved_conflicts"],
            -item["summary"]["metrics"]["unknown_cves"],
            item["container_name"],
        ),
    )
    lines.section("CONTAINER SUMMARY")
    for container in containers:
        metrics = container["summary"]["metrics"]
        lines.field(
            container["container_name"],
            f"coverage {comparison.format_ratio(metrics['coverage'])}; "
            f"corroboration {comparison.format_ratio(metrics['corroboration'])}; "
            f"conflicts {metrics['unresolved_conflicts']}; "
            f"scan coverage {container['scan_coverage']}",
        )
    for container in containers:
        lines.section(f"CONTAINER: {container['container_name']}")
        lines.append(csaf.render_text(container).rstrip())
    return lines.render() + "\n"


def aggregate(
    targets: list[TargetAudit], output_directory: Path, args: argparse.Namespace
) -> tuple[Path, Path]:
    """Write batch headlines and detailed per-container comparisons."""
    locations = enrich_with_csaf(targets, args) if args.csaf else {}
    result = build_result(targets)
    text = render_text(result)
    inputs = {
        target.audit_file or target.directory / "audit.json" for target in targets
    }
    inputs.update(locations.values())
    return write_comparison_artifacts(
        output_directory, "aggregate", result, text, inputs=inputs
    )


def run(settings: argparse.Namespace, children: list[argparse.Namespace]) -> int:
    output_directory = settings.output_dir
    outside_subjects(
        [output_directory],
        [path for child in children for path in (child.rootfs, child.layers_dir)],
    )
    if output_directory.is_symlink():
        raise ValueError("output directory must not be a symlink")
    output_directory.mkdir(parents=True, exist_ok=True)
    targets = [
        load_target(child.audit_root, child.audit_file, index)
        for index, child in enumerate(children, 1)
    ]
    json_path, text_path = aggregate(targets, output_directory, settings)
    print(f"Summary and details: {text_path}")
    print(f"Structured results: {json_path}")
    return 0
