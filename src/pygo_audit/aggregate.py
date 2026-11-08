"""Aggregate the canonical image comparisons into text, JSON, and triage CSV."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import io
from typing import Any

from pygo_audit import comparison, csaf_workflow, image_csaf, report
from pygo_audit.artifacts import comparison_payloads
from pygo_audit.audit import load_audit
from pygo_audit.report_sections import append_detail_footer
from pygo_audit.report_views import normalize_cve
from pygo_audit.text_layout import (
    FULL_POLICY,
    RenderPolicy,
    SUMMARY_POLICY,
    TextLayout,
    Verbosity,
)
from pygo_audit.workspace import outside_subjects


TRIAGE_COLUMNS = (
    "CONTAINER",
    "CVE",
    "CVSS SCORE",
    "PYGO ASSESSMENT",
    "VENDOR ASSESSMENT",
    "AGREEMENT",
    "EVIDENCE",
    "BINARIES",
    "CSAF URL",
    "CONTAINER URL",
)
AGGREGATE_VIEWS = ("cves", "modules", "packages")


@dataclass(frozen=True, slots=True)
class TriageCase:
    container: str
    cve: str
    cvss_scores: tuple[float, ...]
    local_scan: str
    vendor_assessment: str
    agreement: str
    evidence: tuple[str, ...]
    binary_count: int
    canonical_urls: tuple[str, ...]
    container_url: str

    def review_key(self) -> tuple[float, str, int, str]:
        return (
            -max(self.cvss_scores, default=-1.0),
            self.container.casefold(),
            comparison.review_key(self.agreement)[0],
            self.cve,
        )

    def cells(self) -> tuple[object, ...]:
        return (
            self.container,
            self.cve,
            "; ".join(f"{score:.1f}" for score in self.cvss_scores),
            image_csaf.LOCAL_SCAN_LABELS[self.local_scan],
            self.vendor_assessment,
            comparison.AGREEMENT_LABELS[self.agreement],
            self.evidence,
            self.binary_count,
            self.canonical_urls,
            self.container_url,
        )


def audit_summary(source: image_csaf.ImageAudit) -> dict[str, Any]:
    """Retain inventory and reconciliation counts without another CSAF assessment."""
    binaries = source.report.binaries
    reconciliation: dict[str, Counter[str]] = {
        name: Counter()
        for name in ("binaries", "go_versions", "findings", "sbom_modules")
    }
    for binary in binaries:
        reconciliation["binaries"][binary.reconciliation.status] += 1
        reconciliation["go_versions"][binary.reconciliation.go_version_status] += 1
        reconciliation["findings"].update(binary.finding_statuses)
        reconciliation["sbom_modules"].update(binary.reconciliation.sbom_statuses)
    observations: Counter[str] = Counter()
    for evidence in source.evidence.values():
        for binary, vulnerability in evidence.observations:
            observations[binary.runtime_disposition] += max(
                len(vulnerability.findings), 1
            )
    return {
        "inventory": {
            "binaries": len(binaries),
            "unique_binary_sha256": len(
                {binary.sha256 for binary in binaries if binary.sha256}
            ),
            "runtime_dispositions": dict(
                sorted(
                    Counter(binary.runtime_disposition for binary in binaries).items()
                )
            ),
            "cve_observations": observations.total(),
        },
        "reconciliation": {
            name: dict(sorted(counts.items()))
            for name, counts in reconciliation.items()
        },
    }


def build_result(checks: list[csaf_workflow.CompletedCheck]) -> dict[str, Any]:
    containers = [
        {
            **check.data,
            "container_name": check.workspace.root.name,
            "container_url": check.workspace.audit.image.reference,
            "detail_report": str(check.workspace.output_dir / "comparison.txt"),
            "audit_summary": audit_summary(check.workspace.audit),
        }
        for check in checks
    ]
    conclusions = [
        value
        for container in containers
        for cve, value in container["conclusions"].items()
        if normalize_cve(cve)
    ]
    return {
        "counting_unit": "container_cve",
        "summary": {
            "container_count": len(containers),
            "unique_cves": len(
                {
                    cve
                    for container in containers
                    for cve in container["conclusions"]
                    if normalize_cve(cve)
                }
            ),
            "metrics": comparison.summarize(conclusions),
        },
        "containers": containers,
    }


def triage_cases(result: dict[str, Any]) -> list[TriageCase]:
    """Project the shared conclusions without evaluating identity or agreement again."""
    cases = []
    for container in result["containers"]:
        for cve, observations in image_csaf.vulnerability_groups(container):
            if not normalize_cve(cve):
                continue
            conclusion = container["conclusions"][cve]
            artifacts = container["local_findings"][cve]
            cases.append(
                TriageCase(
                    container=container["container_name"],
                    cve=cve,
                    cvss_scores=tuple(
                        sorted(
                            {
                                score
                                for number, document, record in observations
                                for score in record["cvss_scores"]
                            }
                        )
                    ),
                    local_scan=conclusion["local_scan"]["status"],
                    vendor_assessment=conclusion["vendor_assessment"],
                    agreement=conclusion["agreement"]["comparison"],
                    evidence=tuple(conclusion["evidence"]),
                    binary_count=len(artifacts),
                    canonical_urls=tuple(
                        sorted(
                            {
                                url
                                for number, document, record in observations
                                for url in document["canonical_urls"]
                            }
                        )
                    ),
                    container_url=container["container_url"],
                )
            )
    return sorted(cases, key=TriageCase.review_key)


def csv_cell(value: object) -> str:
    text = (
        "; ".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)
    )
    return (
        "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else text
    )


def render_csv(result: dict[str, Any]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(TRIAGE_COLUMNS)
    writer.writerows(
        tuple(csv_cell(value) for value in case.cells())
        for case in triage_cases(result)
    )
    return stream.getvalue()


def render_identifier_view(children: list[argparse.Namespace], view: str) -> str:
    if view not in AGGREGATE_VIEWS:
        raise ValueError(f"unsupported aggregate view: {view}")
    renderer = report.REPORT_VIEWS[view].render
    identifiers = {
        identifier
        for child in children
        for identifier in renderer(
            load_audit(child.audit_file), SUMMARY_POLICY
        ).splitlines()
        if identifier
    }
    return "\n".join(sorted(identifiers))


def container_review_key(container: dict[str, Any]) -> tuple[int, str]:
    counts = container["summary"]["metrics"]["agreement_counts"]
    priority = next(
        (
            index
            for index, kind in enumerate(comparison.AGREEMENT_ORDER)
            if counts.get(kind)
        ),
        len(comparison.AGREEMENT_ORDER),
    )
    return priority, container["container_name"]


def render_text(result: dict[str, Any], policy: RenderPolicy = SUMMARY_POLICY) -> str:
    lines = TextLayout.titled("CSAF BATCH COMPARISON", policy=policy)
    summary = result["summary"]
    metrics = summary["metrics"]
    lines.fields(
        ("Containers", summary["container_count"]),
        ("Unique CVEs", summary["unique_cves"]),
        ("Container/CVE comparisons", metrics["comparisons"]),
        ("Discrepancies", metrics["discrepancies"]),
    )
    with lines.subsection("[AGREEMENT]") as agreement:
        agreement.columns(
            [
                ("AGREEMENT", "CONTAINER/CVE PAIRS"),
                *(
                    (
                        comparison.AGREEMENT_LABELS[kind],
                        metrics["agreement_counts"][kind],
                    )
                    for kind in comparison.AGREEMENT_ORDER
                    if kind in metrics["agreement_counts"]
                ),
            ]
        )
    containers = sorted(result["containers"], key=container_review_key)
    with lines.subsection("[CONTAINERS]") as inventory:
        inventory.columns(
            [
                ("CONTAINER", "SCAN COVERAGE", "CVEs", "DISCREPANCIES"),
                *(
                    (
                        container["container_name"],
                        container["summary"]["scan_coverage"]["state"],
                        container["summary"]["metrics"]["comparisons"],
                        container["summary"]["metrics"]["discrepancies"],
                    )
                    for container in inventory.limited("containers", containers)
                ),
            ]
        )
    with lines.subsection("[CVE TRIAGE]") as triage:
        with triage.preview("comparisons", triage_cases(result)) as cases:
            triage.columns([TRIAGE_COLUMNS[:6], *(case.cells()[:6] for case in cases)])
    if policy.shows(Verbosity.EXPANDED):
        for container in lines.limited("container details", containers):
            with lines.subsection(
                f"CONTAINER: {container['container_name']}"
            ) as detail:
                image_csaf.append_check(detail, container)
    if policy.shows(Verbosity.FORENSIC):
        with lines.subsection("[PROVENANCE]") as provenance:
            for container in containers:
                with provenance.subsection(
                    f"CONTAINER: {container['container_name']}"
                ) as context:
                    image_csaf.append_provenance(context, container)
    append_detail_footer(lines)
    return lines.render() + "\n"


def run(
    settings: argparse.Namespace,
    children: list[argparse.Namespace],
    policy: RenderPolicy = SUMMARY_POLICY,
    view: str | None = None,
) -> int:
    if view is not None:
        output = render_identifier_view(children, view)
        if output:
            print(output)
        return 0
    outside_subjects(
        [settings.output_dir],
        [
            path
            for child in children
            for path in (child.rootfs, child.layers_dir, *child.layer_dir)
        ],
    )
    targets = csaf_workflow.load_workspaces(children)
    checks = csaf_workflow.compare_workspaces(
        targets, jobs=settings.jobs, recorded_only=True
    )
    result = build_result(checks)
    payloads = comparison_payloads(
        settings.output_dir,
        "aggregate",
        result,
        render_text(result, FULL_POLICY),
        csv_text=render_csv(result),
    )
    csaf_workflow.publish_checks(checks, payloads)
    print(render_text(result, policy), end="")
    print(
        f"Summary and details: {settings.output_dir / 'aggregate.txt'}\nStructured results: {settings.output_dir / 'aggregate.json'}\nTriage CSV: {settings.output_dir / 'aggregate.csv'}"
    )
    return 0
