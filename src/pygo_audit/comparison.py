"""Shared VEX interpretation and comparison metrics for text and JSON reports."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
import math
from pathlib import Path
from typing import Any, Iterable

from pygo_audit import models
from pygo_audit.storage import atomic_read_json, json_digest
from pygo_audit.text_layout import TextLayout

CODE_NOT_PRESENT_FLAGS = frozenset(
    {"component_not_present", "vulnerable_code_not_present"}
)
COMPARISON_ORDER = (
    "code_presence_conflict",
    "mismatch",
    "conflicting_vex",
    "unverified",
    "resolved_difference",
    "agreement",
)
SEVERITY_RANK = {
    "critical": 4,
    "important": 3,
    "high": 3,
    "moderate": 2,
    "medium": 2,
    "low": 1,
}


@dataclass(frozen=True, slots=True)
class VulnerabilityPriority:
    """Verified CSAF ranking evidence for one vulnerability."""

    identifier: str
    cvss_score: float | None
    severity: str
    score_source: str

    @property
    def sort_key(self) -> tuple[float, int, str]:
        score = self.cvss_score if self.cvss_score is not None else -1.0
        return (-score, -SEVERITY_RANK.get(self.severity.lower(), 0), self.identifier)


def load_verified_priorities(
    path: Path, report: models.AuditReport
) -> dict[str, VulnerabilityPriority]:
    """Load ranking evidence only when it names the selected audit content."""
    if path.is_symlink():
        raise ValueError(f"comparison input must not be a symlink: {path}")
    document = atomic_read_json(path)
    if not isinstance(document, dict):
        raise ValueError(f"comparison must be a JSON object: {path}")
    expected = json_digest(report.to_dict())
    if document.get("audit_sha256") != expected:
        raise ValueError(f"comparison audit SHA-256 does not match {path}")
    assessments = document.get("assessments")
    if not isinstance(assessments, list):
        raise ValueError(f"comparison assessments must be a list: {path}")
    priorities = {}
    for assessment in assessments:
        if not isinstance(assessment, dict) or not isinstance(
            assessment.get("cve"), str
        ):
            raise ValueError(f"comparison contains an invalid assessment: {path}")
        identifier = assessment["cve"].upper()
        severity = assessment.get("severity", "")
        if not isinstance(severity, str):
            raise ValueError(f"comparison contains an invalid severity: {path}")
        cvss = assessment.get("cvss")
        score, source = None, ""
        if cvss is not None:
            if not isinstance(cvss, dict):
                raise ValueError(f"comparison contains invalid CVSS evidence: {path}")
            raw_score, source = cvss.get("base_score"), cvss.get("source", "")
            if (
                isinstance(raw_score, bool)
                or not isinstance(raw_score, (int, float))
                or not math.isfinite(raw_score)
                or not 0 <= raw_score <= 10
                or not isinstance(source, str)
            ):
                raise ValueError(f"comparison contains invalid CVSS evidence: {path}")
            score = float(raw_score)
        priorities[identifier] = VulnerabilityPriority(
            identifier, score, severity, source
        )
    return priorities


@dataclass(frozen=True, slots=True)
class VexDetails:
    """Normalized VEX conclusions and explanations for one CVE."""

    statuses: frozenset[str]  # Product status labels with the status prefix removed.
    flags: frozenset[str]  # VEX justification labels with the flag prefix removed.
    resolutions: frozenset[str]  # VEX explanations for the difference.
    comparison: str  # Agreement or disagreement with the local CVE finding.


def vex_details(assessment: dict[str, Any] | None) -> VexDetails:
    """Classify the VEX conclusion without discarding its raw statuses."""
    if assessment is None:
        return VexDetails(frozenset(), frozenset(), frozenset(), "unverified")
    assessment_name = assessment.get("assessment") or "unavailable"
    statuses: set[str] = set()
    flags: set[str] = set()
    for raw_status in assessment.get("statuses", []):
        if not isinstance(raw_status, str):
            continue
        status = raw_status.removeprefix("status:")
        if status.startswith("flag:"):
            flags.add(status.removeprefix("flag:"))
        elif raw_status.startswith("status:"):
            statuses.add(status)
    if assessment_name.startswith("cpe") or assessment.get("match_level") == "platform":
        return VexDetails(
            frozenset(statuses),
            frozenset(flags),
            frozenset(),
            "unverified",
        )
    resolutions: set[str] = set()
    if "fixed" in statuses:
        resolutions.add("fixed")
    if flags & CODE_NOT_PRESENT_FLAGS:
        resolutions.add("code_not_present")
    if "vulnerable_code_not_in_execute_path" in flags:
        resolutions.add("code_not_reachable")
    if "vulnerable_code_cannot_be_controlled_by_adversary" in flags:
        resolutions.add("code_not_controllable")

    if assessment_name in {
        "document_missing",
        "no_matching_product",
        "document_has_no_matching_cve_record",
        "unavailable",
    }:
        comparison = "unverified"
    elif "under_investigation" in statuses:
        comparison = "unverified"
    elif "known_affected" in statuses and statuses & {"known_not_affected", "fixed"}:
        comparison = "conflicting_vex"
    elif resolutions:
        comparison = "resolved_difference"
    elif "known_affected" in statuses:
        comparison = "agreement"
    elif "known_not_affected" in statuses:
        comparison = "mismatch"
    else:
        comparison = "unverified"
    return VexDetails(
        frozenset(statuses),
        frozenset(flags),
        frozenset(resolutions),
        comparison,
    )


def cve_comparison(details: VexDetails, evidence: models.CveEvidence) -> str:
    """Promote symbol/code-presence conflicts above ordinary VEX resolution."""
    if details.comparison in {"unverified", "conflicting_vex"}:
        return details.comparison
    if "symbol" in evidence.evidence_types and details.flags & CODE_NOT_PRESENT_FLAGS:
        return "code_presence_conflict"
    return details.comparison


def evaluate(
    evidence: models.CveEvidence, assessment: dict[str, Any] | None
) -> VexDetails:
    details = vex_details(assessment)
    return replace(details, comparison=cve_comparison(details, evidence))


def evaluation_dict(evaluation: VexDetails) -> dict[str, Any]:
    return {
        "comparison": evaluation.comparison,
        "usable_vex": evaluation.comparison not in {"unverified", "conflicting_vex"},
        "statuses": sorted(evaluation.statuses),
        "flags": sorted(evaluation.flags),
        "resolutions": sorted(evaluation.resolutions),
    }


def ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percent": 100 * numerator / denominator if denominator else None,
    }


def summarize(comparisons: Iterable[str]) -> dict[str, Any]:
    counts = Counter(comparisons)
    observed = counts.total()
    unknown = counts["unverified"] + counts["conflicting_vex"]
    comparable = observed - unknown
    return {
        "observed_cves": observed,
        "comparable_cves": comparable,
        "corroborated_cves": counts["agreement"],
        "explained_differences": counts["resolved_difference"],
        "unresolved_conflicts": counts["mismatch"] + counts["code_presence_conflict"],
        "unknown_cves": unknown,
        "comparison_counts": dict(sorted(counts.items())),
        "coverage": ratio(comparable, observed),
        "corroboration": ratio(counts["agreement"], comparable),
    }


def review_key(comparison: str, cve: str = "") -> tuple[int, str]:
    return COMPARISON_ORDER.index(comparison), cve


def format_ratio(value: dict[str, Any]) -> str:
    percent = value["percent"]
    label = "N/A" if percent is None else f"{percent:.1f}".removesuffix(".0") + "%"
    return f"{label} ({value['numerator']}/{value['denominator']})"


def append_summary(lines: TextLayout, metrics: dict[str, Any]) -> None:
    lines.extend(
        (
            "",
            f"{'VEX COVERAGE':<46}AFFECTED-STATUS CORROBORATION",
            f"{format_ratio(metrics['coverage']):<46}{format_ratio(metrics['corroboration'])}",
        )
    )
    lines.section("COMPARISON BREAKDOWN")
    lines.fields(
        ("Binary-observed CVEs", metrics["observed_cves"]),
        ("Also marked affected", metrics["corroborated_cves"]),
        ("Explained differences", metrics["explained_differences"]),
        ("Unresolved conflicts", metrics["unresolved_conflicts"]),
        ("Missing/uncertain VEX", metrics["unknown_cves"]),
    )
