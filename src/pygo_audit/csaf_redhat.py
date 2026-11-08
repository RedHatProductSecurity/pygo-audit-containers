"""Red Hat OpenShift matching and version inferences, separate from CSAF facts."""

from collections.abc import Sequence
import re

from pygo_audit.comparison import PolicyContext, VersionAssessment, status_categories

Version = tuple[int, int, int]


def normalize_version(value: str) -> Version | None:
    """Use numeric releases, preserving suffixes in the caller's raw evidence."""
    match = re.fullmatch(
        r"[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][A-Za-z0-9][A-Za-z0-9.+_-]*)?",
        value.strip(),
    )
    if match is None:
        return None
    return int(match[1]), int(match[2] or 0), int(match[3] or 0)


def supports(context: PolicyContext) -> bool:
    return (
        context.local.vendor == context.candidate.vendor == "redhat"
        and context.local.product == context.candidate.product == "openshift"
    )


def version_relation(local: Sequence[str], remote: Sequence[str]) -> str | None:
    """Interpret the version attribute only after the caller checks CPE scope."""
    if local[1:3] != remote[1:3] or tuple(local[1:3]) != ("redhat", "openshift"):
        return None
    left, right = normalize_version(local[3]), normalize_version(remote[3])
    if left is None or right is None:
        return None
    if left == right:
        return "normalized_version"
    if left[:2] == right[:2]:
        return "release_line"
    if re.fullmatch(r"[vV]?\d+", remote[3]) and left[0] == right[0]:
        return "version_family"
    return None


def infer_assessment(
    context: PolicyContext, statements: Sequence[str]
) -> tuple[VersionAssessment, ...]:
    """Apply a declared boundary only to versions of the same subject/release."""
    statuses = {
        item.removeprefix("status:")
        for item in statements
        if item.startswith("status:")
    }
    boundaries = statuses & {
        "fixed",
        "first_fixed",
        "recommended",
        "first_affected",
        "last_affected",
    }
    if (
        not supports(context)
        or not boundaries
        or statuses & {"known_affected", "known_not_affected", "under_investigation"}
    ):
        return ()
    results = []
    for boundary in context.candidate.versions:
        # A CPE on an enclosing platform is scope, not a component fix boundary.
        if not boundary.source.startswith(("purl:", "product_version:")):
            continue
        fixed = normalize_version(boundary.value)
        if fixed is None:
            continue
        observed_versions = [
            item for item in context.local.versions if item.subject == boundary.subject
        ]
        normalized = {normalize_version(item.value) for item in observed_versions}
        if len(normalized) != 1 or None in normalized:
            continue
        observed = observed_versions[0]
        current = normalize_version(observed.value)
        if current is None:
            continue
        declarations = [
            (item, version)
            for item in context.declarations
            if item.version.subject == boundary.subject
            and item.version.source.startswith(("purl:", "product_version:"))
            and (version := normalize_version(item.version.value)) is not None
            and version[:2] == current[:2]
        ]
        explicit = [item for item, version in declarations if version == current]
        reached_fixes = [
            (item, version)
            for item, version in declarations
            if version <= current
            and {
                value.removeprefix("status:")
                for value in item.statements
                if value.startswith("status:")
            }
            <= {"fixed", "first_fixed", "recommended"}
            and any(value.startswith("status:") for value in item.statements)
        ]
        effective: tuple[str, ...] = ()
        status, reason = (
            "undetermined",
            "Versions are in different release lines; no status inferred",
        )
        if current[:2] == fixed[:2]:
            outcomes = set()
            for label in boundaries:
                if label == "first_affected":
                    outcomes.add(
                        "known_not_affected"
                        if current < fixed
                        else "known_affected"
                        if current == fixed
                        else "undetermined"
                    )
                elif label == "last_affected":
                    outcomes.add("fixed" if current > fixed else "known_affected")
                else:
                    outcomes.add("known_affected" if current < fixed else "fixed")
            status = outcomes.pop() if len(outcomes) == 1 else "undetermined"
            reason = (
                "Before declared affected boundary"
                if status == "known_not_affected"
                else "Before fix or within declared affected boundary"
                if status == "known_affected"
                else "At or after the applicable fix boundary"
                if status == "fixed"
                else "Declared boundaries do not establish a consistent status"
            )
            if explicit:
                effective = tuple(
                    sorted({value for item in explicit for value in item.statements})
                )
                declared = status_categories(
                    value.removeprefix("status:")
                    for value in effective
                    if value.startswith("status:")
                )
                status = next(iter(declared)) if len(declared) == 1 else "undetermined"
                boundary = explicit[0].version
                fixed = current
                reason = "Explicit statement for the observed version takes precedence over boundary inference"
            elif reached_fixes and boundaries <= {
                "fixed",
                "first_fixed",
                "recommended",
            }:
                earlier, fixed = min(reached_fixes, key=lambda item: item[1])
                boundary = earlier.version
                status, reason = (
                    "fixed",
                    "An earlier declared fix already covers the observed version in this release line",
                )
        results.append(
            VersionAssessment(
                status,
                boundary.subject,
                observed,
                boundary,
                ".".join(map(str, current)),
                ".".join(map(str, fixed)),
                reason,
                inferred=current != fixed
                or any(
                    evidence.value.lstrip("vV") != ".".join(map(str, normalized))
                    for evidence, normalized in ((observed, current), (boundary, fixed))
                ),
                policy="redhat.openshift",
                statements=effective,
            )
        )
    return tuple(results)
