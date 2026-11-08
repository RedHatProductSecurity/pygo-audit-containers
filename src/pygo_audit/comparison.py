"""Shared VEX interpretation and comparison metrics for text and JSON reports."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from pygo_audit import models

CODE_NOT_PRESENT_FLAGS = frozenset(
    {"component_not_present", "vulnerable_code_not_present"}
)
AGREEMENT_ORDER = (
    "no",
    "qualified_no",
    "mixed",
    "undetermined",
    "qualified_yes",
    "yes",
)
DISAGREEMENTS = frozenset({"no", "qualified_no", "mixed"})


@dataclass(frozen=True, slots=True)
class VersionEvidence(models.JsonModel):
    value: str
    subject: Literal["product", "component"]
    source: str


@dataclass(frozen=True, slots=True)
class ProductContext:
    vendor: str = ""
    product: str = ""
    component: str = ""
    architecture: str = ""
    versions: tuple[VersionEvidence, ...] = ()
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VersionDeclaration:
    version: VersionEvidence
    statements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolicyContext:
    publisher_namespace: str
    candidate_product_id: str
    local: ProductContext
    candidate: ProductContext
    declarations: tuple[VersionDeclaration, ...] = ()


@dataclass(frozen=True, slots=True)
class VersionAssessment(models.JsonModel):
    status: str
    subject: str
    observed: VersionEvidence
    boundary: VersionEvidence
    normalized_observed: str
    normalized_boundary: str
    reason: str
    inferred: bool = True
    policy: str = ""
    statements: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VexDetails:
    """Normalized VEX conclusions and explanations for one CVE."""

    statuses: frozenset[str]  # Product status labels with the status prefix removed.
    flags: frozenset[str]  # VEX justification labels with the flag prefix removed.
    resolutions: frozenset[str]  # VEX explanations for the difference.


def vex_details(statements: Iterable[str]) -> VexDetails:
    """Separate raw statuses and justifications without classifying local findings."""
    statuses: set[str] = set()
    flags: set[str] = set()
    for raw_status in statements:
        status = raw_status.removeprefix("status:")
        if status.startswith("flag:"):
            flags.add(status.removeprefix("flag:"))
        elif raw_status.startswith("status:"):
            statuses.add(status)
    resolutions: set[str] = set()
    if "fixed" in statuses:
        resolutions.add("fixed")
    if flags & CODE_NOT_PRESENT_FLAGS:
        resolutions.add("code_not_present")
    if "vulnerable_code_not_in_execute_path" in flags:
        resolutions.add("code_not_reachable")
    if "vulnerable_code_cannot_be_controlled_by_adversary" in flags:
        resolutions.add("code_not_controllable")

    return VexDetails(
        frozenset(statuses),
        frozenset(flags),
        frozenset(resolutions),
    )


def status_categories(statuses: Iterable[str]) -> set[str]:
    """Treat boundary labels as the same outcome, preserving raw labels elsewhere."""
    return {
        "known_affected"
        if status in {"first_affected", "last_affected"}
        else "fixed"
        if status in {"first_fixed", "recommended"}
        else status
        for status in statuses
    }


AGREEMENT_LABELS = {
    "yes": "Yes",
    "qualified_yes": "Qualified yes",
    "qualified_no": "Qualified no",
    "mixed": "Mixed",
    "undetermined": "Undetermined",
    "no": "No",
}


def statement_outcomes(
    evidence: set[str], present_evidence: set[str], statements: list[str]
) -> list[tuple[str, str]]:
    """Compare each status using only the justifications attached to its product."""
    details = vex_details(statements)
    outcomes = []
    for status in sorted(status_categories(details.statuses)):
        if status == "known_affected":
            outcome = (
                "supports",
                "vendor reports affected, consistent with the local finding",
            )
        elif status == "fixed":
            outcome = (
                "disagrees",
                "vendor reports fixed; retained symbols or version metadata do not disprove a fix or backport",
            )
        elif status != "known_not_affected":
            outcome = (
                "unknown",
                "vendor investigation is ongoing"
                if status == "under_investigation"
                else "vendor status requires review",
            )
        elif "component_not_present" in details.flags and present_evidence & {
            "package",
            "symbol",
        }:
            outcome = (
                "contradicts",
                "vendor reports the component absent, but package/symbol evidence places it in a runtime binary",
            )
        elif details.flags & CODE_NOT_PRESENT_FLAGS:
            outcome = (
                "disagrees",
                "vendor reports component/vulnerable code absent; the local evidence does not verify the vulnerable implementation",
            )
        elif (
            evidence & {"module", "package", "symbol"}
            and "code_not_reachable" in details.resolutions
        ):
            outcome = (
                "qualified",
                "code is present, but the vendor declares it outside the execution path; local evidence does not establish reachability",
            )
        elif (
            evidence & {"module", "package", "symbol"}
            and "code_not_controllable" in details.resolutions
        ):
            outcome = (
                "qualified",
                "code is present, but the vendor declares it uncontrollable by an adversary; local evidence does not establish exploitability",
            )
        elif "inline_mitigations_already_exist" in details.flags:
            outcome = (
                "qualified",
                "vulnerable evidence is present, but the vendor declares built-in mitigations; the local scan does not test their effectiveness",
            )
        else:
            outcome = (
                "disagrees",
                "vendor reports not affected; a verifiable contradiction has not been established",
            )
        outcomes.append(outcome)
    return outcomes or [
        ("unknown", "vendor status not stated for the selected product")
    ]


def finding_agreement(
    evidence: list[str],
    match: str,
    statements: list[list[str]],
    *,
    present_evidence: Iterable[str] = (),
    inferred: bool = False,
    candidate_agreements: Iterable[str] = (),
) -> dict[str, Any]:
    """Compare scoped statements; only conflicting candidate results yield Mixed."""
    details = vex_details(value for group in statements for value in group)
    observed, present = set(evidence), set(present_evidence)
    outcomes = [
        outcome
        for group in statements
        for outcome in statement_outcomes(observed, present, group)
    ]
    kinds = {outcome[0] for outcome in outcomes}
    reasons = sorted({outcome[1] for outcome in outcomes})
    state = "undetermined"
    if match not in {"exact", "fuzzy", "ambiguous"}:
        reasons = ["no applicable vendor conclusion"]
    elif not evidence:
        reasons = ["no local finding recorded; absence is not established"]
    elif kinds & {"supports", "qualified"} and kinds & {"contradicts", "disagrees"}:
        agreements = set(candidate_agreements)
        if agreements & {"yes", "qualified_yes"} and agreements & {
            "no",
            "qualified_no",
        }:
            state = "mixed"
        reasons.insert(
            0,
            "accepted candidates reach conflicting conclusions"
            if state == "mixed"
            else "conflicting vendor statements prevent a candidate conclusion",
        )
    elif not outcomes or "unknown" in kinds:
        reasons = reasons or ["no applicable vendor status is available"]
    elif kinds <= {"supports", "qualified"}:
        state = "yes" if match == "exact" and kinds == {"supports"} else "qualified_yes"
    elif match == "exact" and "contradicts" in kinds:
        state = "no"
    elif kinds <= {"contradicts", "disagrees"}:
        state = "qualified_no"
    if match in {"fuzzy", "ambiguous"}:
        reasons.insert(0, "product identity remains tentative")
    if inferred:
        state = {"yes": "qualified_yes", "no": "qualified_no"}.get(state, state)
        reasons.insert(0, "vendor assessment uses a version heuristic")
    return {
        "comparison": state,
        "text": AGREEMENT_LABELS[state] + " — " + "; ".join(reasons),
        "statuses": sorted(details.statuses),
        "flags": sorted(details.flags),
        "reasons": reasons,
    }


def summarize(conclusions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Count normalized CVE conclusions; batch totals count container/CVE pairs."""
    values = list(conclusions)
    agreements = Counter(item["agreement"]["comparison"] for item in values)
    return {
        "comparisons": len(values),
        "discrepancies": sum(agreements[kind] for kind in DISAGREEMENTS),
        "agreement_counts": dict(sorted(agreements.items())),
        "local_scan_counts": dict(
            sorted(Counter(item["local_scan"]["status"] for item in values).items())
        ),
        "match_counts": dict(sorted(Counter(item["match"] for item in values).items())),
        "vendor_assessment_counts": dict(
            sorted(Counter(item["vendor_assessment"] for item in values).items())
        ),
    }


def review_key(agreement: str, cve: str = "") -> tuple[int, str]:
    return AGREEMENT_ORDER.index(agreement), cve
