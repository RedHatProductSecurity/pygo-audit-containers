"""Aggregate canonical image comparisons into summary, triage, and JSON reports."""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Iterable
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
TRIAGE_FILENAME = "pygo-audit-triage.csv"
CVSS_SEVERITIES = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "None (0.0)",
    "Unscored",
)


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


def cve_groups(cases: Iterable[TriageCase]) -> dict[str, list[TriageCase]]:
    groups: dict[str, list[TriageCase]] = {}
    for case in cases:
        groups.setdefault(case.cve, []).append(case)
    return groups


def highest_cvss(cases: Iterable[TriageCase]) -> float | None:
    return max((score for case in cases for score in case.cvss_scores), default=None)


def cvss_severity(score: float | None) -> str:
    if score is None:
        return "Unscored"
    if score == 0:
        return "None (0.0)"
    return next(
        severity
        for threshold, severity in (
            (9, "Critical"),
            (7, "High"),
            (4, "Medium"),
            (0, "Low"),
        )
        if score >= threshold
    )


def severity_counts(cases: Iterable[TriageCase]) -> Counter[str]:
    return Counter(
        cvss_severity(highest_cvss(group)) for group in cve_groups(cases).values()
    )


def discrepancy_rate(discrepancies: int, comparisons: int) -> str:
    if not comparisons:
        return f"{discrepancies} / 0 (N/A)"
    rate = discrepancies / comparisons * 100
    return f"{discrepancies} / {comparisons} ({rate:.1f}%)"


def append_severity_counts(lines: TextLayout, cases: Iterable[TriageCase]) -> None:
    counts = severity_counts(cases)
    lines.columns(
        [
            ("CVSS SEVERITY", "UNIQUE CVEs"),
            *((severity, counts[severity]) for severity in CVSS_SEVERITIES),
        ]
    )


def append_agreement_definitions(lines: TextLayout) -> None:
    with lines.subsection("AGREEMENT DEFINITIONS") as definitions:
        definitions.bullets(
            (
                "Yes — exact product match; vendor conclusion supports the local finding.",
                "Qualified yes — supports the finding with a tentative match, version inference, or vendor qualification.",
                "No — exact product match; vendor conclusion verifiably contradicts the local finding.",
                "Qualified no — possible disagreement, but no verified contradiction.",
                "Mixed — accepted product candidates reach conflicting conclusions.",
                "Undetermined — insufficient product-match or vendor-status evidence to decide.",
            ),
            wrap=True,
        )


def append_batch_provenance(
    lines: TextLayout, containers: Iterable[dict[str, Any]]
) -> None:
    with lines.subsection("[PROVENANCE]") as provenance:
        for container in containers:
            with provenance.subsection(
                f"CONTAINER: {container['container_name']}"
            ) as context:
                image_csaf.append_provenance(context, container)


def append_aggregate_summary(
    lines: TextLayout, result: dict[str, Any], cases: list[TriageCase]
) -> None:
    summary = result["summary"]
    metrics = summary["metrics"]
    lines.fields(
        ("Containers", summary["container_count"]),
        ("Unique CVEs", summary["unique_cves"]),
        ("Vulnerability findings (container/CVE)", metrics["comparisons"]),
        (
            "Locally affected findings",
            metrics["local_scan_counts"].get("affected", 0),
        ),
        (
            "Discrepancy rate",
            discrepancy_rate(metrics["discrepancies"], metrics["comparisons"]),
        ),
    )
    with lines.subsection("CVSS SEVERITY (UNIQUE CVEs)") as scores:
        append_severity_counts(scores, cases)
    with lines.subsection("AGREEMENT RESULTS") as agreements:
        agreements.columns(
            [
                ("AGREEMENT", "CONTAINER/CVE FINDINGS"),
                *(
                    (
                        comparison.AGREEMENT_LABELS[kind],
                        metrics["agreement_counts"].get(kind, 0),
                    )
                    for kind in comparison.AGREEMENT_ORDER
                ),
            ]
        )
    containers = sorted(result["containers"], key=lambda item: item["container_name"])
    with lines.subsection("DISCREPANCIES BY CONTAINER") as discrepancies:
        discrepancies.columns(
            [
                ("CONTAINER", "DISCREPANCIES / COMPARISONS", "RATE"),
                *(
                    (
                        container["container_name"],
                        f"{container['summary']['metrics']['discrepancies']} / "
                        f"{container['summary']['metrics']['comparisons']}",
                        discrepancy_rate(
                            container["summary"]["metrics"]["discrepancies"],
                            container["summary"]["metrics"]["comparisons"],
                        ),
                    )
                    for container in containers
                ),
            ]
        )
    append_agreement_definitions(lines)
    with lines.subsection("CVSS SCORING") as scoring:
        scoring.bullets(
            (
                "Each CVE is counted once at its highest reported score across containers.",
                "Critical 9.0–10.0; High 7.0–8.9; Medium 4.0–6.9; Low 0.1–3.9; None 0.0; Unscored has no reported score.",
            ),
            wrap=True,
        )
    with lines.subsection("DISCREPANCY RATE") as rate:
        rate.append(
            "Discrepancies count No, Qualified no, and Mixed results; the denominator "
            "is recorded container/CVE comparisons."
        )


def render_aggregate_report(result: dict[str, Any]) -> str:
    return render_text(result, FULL_POLICY, include_details=False)


def cve_review_key(item: tuple[str, list[TriageCase]]) -> tuple[float, str]:
    score = highest_cvss(item[1])
    return -(score if score is not None else -1), item[0]


def render_text(
    result: dict[str, Any],
    policy: RenderPolicy = SUMMARY_POLICY,
    *,
    include_details: bool = True,
) -> str:
    lines = TextLayout.titled("CSAF BATCH AGGREGATE", policy=policy)
    cases = triage_cases(result)
    append_aggregate_summary(lines, result, cases)
    if include_details and policy.shows(Verbosity.EXPANDED):
        containers = sorted(result["containers"], key=container_review_key)
        for container in lines.limited("container details", containers):
            with lines.subsection(
                f"CONTAINER: {container['container_name']}"
            ) as detail:
                image_csaf.append_check(detail, container)
    if policy.shows(Verbosity.FORENSIC):
        append_batch_provenance(lines, result["containers"])
    append_detail_footer(lines)
    return lines.render() + "\n"


def render_cve_aggregates(result: dict[str, Any]) -> str:
    lines = TextLayout.titled("CVE AGGREGATES", policy=FULL_POLICY)
    lines.append(
        "Only recorded container/CVE comparisons are listed. An absent row does not mean Not Affected."
    )
    cases = triage_cases(result)
    container_index = {
        (container["container_name"], cve): container["conclusions"][cve]
        for container in result["containers"]
        for cve in container["conclusions"]
        if normalize_cve(cve)
    }
    groups = cve_groups(cases)
    for cve, group in sorted(groups.items(), key=cve_review_key):
        score = highest_cvss(group)
        lines.section(f"{cve} — {score:.1f}" if score is not None else cve)
        lines.field("CVSS severity", cvss_severity(score))
        lines.columns(
            [
                (
                    "CONTAINER",
                    "CVSS SCORE",
                    "PYGO ASSESSMENT",
                    "CSAF ID MATCH",
                    "VENDOR ASSESSMENT",
                    "AGREEMENT",
                ),
                *(
                    (
                        case.container,
                        "; ".join(f"{score:.1f}" for score in case.cvss_scores)
                        or "Unscored",
                        image_csaf.LOCAL_SCAN_LABELS[case.local_scan],
                        image_csaf.MATCH_LABELS[
                            container_index[case.container, cve]["match"]
                        ],
                        case.vendor_assessment,
                        comparison.AGREEMENT_LABELS[case.agreement],
                    )
                    for case in sorted(group, key=lambda value: value.container)
                ),
            ]
        )
    append_batch_provenance(lines, result["containers"])
    return lines.render() + "\n"


def candidate_product_ids(conclusion: dict[str, Any]) -> tuple[str, ...]:
    candidates = conclusion.get("candidates", [])
    strongest = image_csaf.strongest_match(
        [candidate["match"] for candidate in candidates]
    )
    matches = {
        f"{image_csaf.MATCH_LABELS[candidate['match']]}: {product_id}"
        for candidate in candidates
        if candidate["match"] == strongest
        for product_id in candidate.get("product_ids", [])
    }
    return tuple(sorted(matches))


def render_container_aggregates(result: dict[str, Any]) -> str:
    lines = TextLayout.titled("CONTAINER AGGREGATES", policy=FULL_POLICY)
    cases = triage_cases(result)
    for container in sorted(
        result["containers"], key=lambda item: item["container_name"]
    ):
        name = container["container_name"]
        container_cases = [case for case in cases if case.container == name]
        metrics = container["summary"]["metrics"]
        hashes = {
            artifact["sha256"]
            for artifacts in container["local_findings"].values()
            for artifact in artifacts
        }
        lines.section(name)
        lines.field("Container image", container["container_url"])
        lines.fields(
            ("CVEs", len(container_cases)),
            (
                "Discrepancies",
                discrepancy_rate(metrics["discrepancies"], metrics["comparisons"]),
            ),
            ("Unique vulnerable binaries", len(hashes)),
            (
                "Binary/CVE evidence links",
                sum(case.binary_count for case in container_cases),
            ),
        )
        with lines.subsection("CVSS SEVERITY") as scores:
            append_severity_counts(scores, container_cases)
        match_counts = Counter(
            conclusion["match"]
            for cve, conclusion in container["conclusions"].items()
            if normalize_cve(cve)
        )
        with lines.subsection("CSAF PRODUCT MATCHES") as matches:
            matches.columns(
                [
                    ("CSAF ID MATCH", "CVEs"),
                    *(
                        (image_csaf.MATCH_LABELS[kind], match_counts[kind])
                        for kind in (
                            "exact",
                            "fuzzy",
                            "ambiguous",
                            "no_match",
                            "no_document",
                        )
                    ),
                ]
            )
            matches.columns(
                [
                    ("CVE", "CSAF ID MATCH", "CSAF PRODUCT ID CANDIDATES"),
                    *(
                        (
                            case.cve,
                            image_csaf.MATCH_LABELS[
                                container["conclusions"][case.cve]["match"]
                            ],
                            candidate_product_ids(container["conclusions"][case.cve])
                            or "(none)",
                        )
                        for case in container_cases
                    ),
                ]
            )
    append_batch_provenance(lines, result["containers"])
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
        render_aggregate_report(result),
    )
    json_path = settings.output_dir / "aggregate.json"
    json_payload = payloads.pop(json_path)
    payloads.update(
        {
            settings.output_dir / "cve-aggregates.txt": render_cve_aggregates(result),
            settings.output_dir
            / "container-aggregates.txt": render_container_aggregates(result),
            settings.output_dir / TRIAGE_FILENAME: render_csv(result),
        }
    )
    payloads[json_path] = json_payload
    csaf_workflow.publish_checks(
        checks, payloads, container_reports_dir=settings.output_dir
    )
    print(render_text(result, policy), end="")
    print(
        f"Aggregate statistics: {settings.output_dir / 'aggregate.txt'}\n"
        f"CVE results: {settings.output_dir / 'cve-aggregates.txt'}\n"
        f"Container results: {settings.output_dir / 'container-aggregates.txt'}\n"
        f"Structured results: {json_path}\n"
        f"Triage CSV: {settings.output_dir / TRIAGE_FILENAME}\n"
        f"Container comparisons: {settings.output_dir}/<container>/comparison.txt"
    )
    return 0
