"""Compare serialized container audits with explicitly supplied CSAF documents."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field, replace
from functools import lru_cache
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable

from pygo_audit import audit, comparison, models
from pygo_audit.artifacts import write_comparison_artifacts
from pygo_audit.report_views import index_cve_evidence, normalize_cve
from pygo_audit.result_cache import ResultCache
from pygo_audit.storage import atomic_read_json, json_digest
from pygo_audit.workspace import outside_subjects
from pygo_audit.text_layout import TextLayout

ARCHITECTURE_ALIASES = {
    "x86_64": "amd64",
    "aarch64": "arm64",
}
CPE_MATCH_LEVELS = {
    "exact": ("cpe", 50),
    "compatible": ("cpe_compatible", 45),
    "version_family": ("cpe_version_family", 40),
}


class CsafCheckError(ValueError):
    """Raised when an audit document or CSAF response is unusable."""


@dataclass(frozen=True)
class ProductReference:
    """A CSAF status or remediation reference to one product."""

    product_id: str  # CSAF product identifier referenced by a conclusion.
    kind: str  # Prefixed status, flag, or remediation category.
    detail: str = ""  # Remediation explanation, when supplied.
    url: str = ""  # Remediation link, when supplied.


@dataclass(frozen=True)
class ProductInfo:
    """Indexed CSAF product metadata used during identity matching."""

    name: str = ""  # Display name from the CSAF product tree.
    cpe: str = ""  # CPE explicitly attached to this product, if any.
    cpe_sources: tuple[
        CpeSource, ...
    ] = ()  # Own or inherited CPEs with their relationship provenance.


@dataclass(frozen=True)
class CpeSource:
    """A product's own CPE or a parent CPE reached through CSAF relationships."""

    product_id: str  # Product that explicitly supplies the CPE.
    cpe: str  # CPE used to constrain the comparison.
    path: tuple[
        str, ...
    ]  # Product IDs traversed from the candidate to this CPE source.
    categories: tuple[str, ...] = ()  # Relationship categories along that traversal.


@dataclass(frozen=True)
class CpeEvidence(models.JsonModel):
    image_cpe: str  # CPE recorded for the audited container.
    source: CpeSource  # Advisory product CPE and its relationship provenance.
    relation: str  # Exact, compatible, or heuristic version-family relation.

    def to_dict(self) -> dict[str, object]:
        return {
            "image_cpe": self.image_cpe,
            "product_cpe": self.source.cpe,
            "source_product_id": self.source.product_id,
            "relationship_path": list(self.source.path),
            "relationship_categories": list(self.source.categories),
            "relation": self.relation,
        }


@dataclass(frozen=True)
class ProductMatch(models.JsonModel):
    """A CSAF product reference matched to the local image identity."""

    scope: str  # Identity or platform basis for this candidate match.
    score: int  # Match precedence; larger values take priority.
    product_id: str  # Matched product's CSAF identifier.
    product_name: str  # Matched product's display name.
    statuses: tuple[
        str, ...
    ]  # Prefixed conclusions associated with the matched product.
    detail: str = ""  # Selected remediation explanation, if supplied.
    url: str = ""  # Selected remediation link, if supplied.
    cpe_evidence: CpeEvidence | None = (
        None  # CPE provenance for platform matches; None for identity matches.
    )


@dataclass(frozen=True)
class DocumentResult:
    """One supplied CSAF document or an explicitly missing comparison."""

    cve: str  # CVE being compared with this advisory document.
    url: str  # Advisory source URI; empty when the document is unavailable.
    document: dict[str, Any] | None = (
        None  # Parsed CSAF input, or None when no document was supplied.
    )
    error: str = ""  # Explanation of missing comparison coverage.


@dataclass(frozen=True)
class CvssScore:
    """One product-scoped CVSS v3 score from a CSAF vulnerability record."""

    base_score: float
    base_severity: str
    vector: str
    products: tuple[str, ...]


@dataclass(frozen=True)
class CsafDocumentIndex:
    """Reusable CSAF metadata, products, and vulnerability records."""

    title: str  # Advisory title from document metadata.
    severity: str  # Advisory aggregate severity label.
    release_date: str  # Current advisory release timestamp.
    records: tuple[dict[str, Any], ...]  # Vulnerability records selected for this CVE.
    products: dict[str, ProductInfo]  # Product metadata indexed by CSAF product ID.
    reference_matches: tuple[
        ProductMatch, ...
    ]  # Product conclusions before matching an image identity.
    cvss_scores: tuple[CvssScore, ...]  # Product-scoped scores retained for ranking.
    cpe_candidates: dict[str, tuple[ProductMatch, ...]] = field(
        default_factory=dict, compare=False, repr=False
    )  # In-memory candidate matches reused by image CPE.


def _string(value: object) -> str: return value if isinstance(value, str) else ""


@lru_cache(maxsize=65536)
def normalize_component(value: str) -> str:
    """Reduce image and CSAF product names to their final component name."""
    normalized = value.strip().lower().split("@", 1)[0]
    if ":" in normalized and "://" not in normalized:
        normalized = normalized.rsplit(":", 1)[-1]
    component = normalized.rstrip("/").rsplit("/", 1)[-1]
    component = re.sub(r"_(?:amd64|arm64|ppc64le|s390x|riscv64|386)$", "", component)
    return component


def product_matches_component(product_id: str, identity: models.ImageIdentity) -> bool:
    component = normalize_component(identity.name or identity.component)
    return bool(component and normalize_component(product_id) == component)


def release_matches(product_id: str, identity: models.ImageIdentity) -> bool:
    # Component version is a matching heuristic when no product release is supplied.
    release = re.search(
        r"(\d+\.\d+)", identity.product_version or identity.component_version
    )
    if release is None:
        return False
    normalized = product_id.lower().replace("_", ".").replace("-", ".")
    return (
        re.search(rf"(?<!\d){re.escape(release.group(1))}(?!\d)", normalized)
        is not None
    )


def architecture_matches(product_id: str, identity: models.ImageIdentity) -> bool:
    architecture = identity.platform.rsplit("/", 1)[-1].lower()
    if not architecture:
        return False
    architecture = ARCHITECTURE_ALIASES.get(architecture, architecture)
    normalized = product_id.lower()
    return (
        re.search(
            rf"(?:^|[_/.-]){re.escape(architecture)}(?:$|[_/.-])",
            normalized,
        )
        is not None
    )


def _cpe_fields(value: str) -> list[str] | None:
    """Split formatted CPE fields without splitting escaped colons."""
    fields = [""]
    escaped = False
    for char in value:
        if escaped:
            fields[-1] += "\\" + char
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("")
        else:
            fields[-1] += char
    return None if escaped else fields


@lru_cache(maxsize=4096)
def parse_cpe(value: str) -> tuple[str, ...] | None:
    """Unbind the supported URI/2.3 forms, preserving literal escapes and ANY/NA.

    This is a conservative comparison helper, not a full CPE validator or
    applicability-language engine. Unsupported encodings fail closed.
    """
    if value.startswith("cpe:/"):
        fields = value[5:].split(":")
        if not 3 <= len(fields) <= 7:
            return None
        fields += [""] * (7 - len(fields))
        extras = [""] * 4
        if fields[5].startswith("~"):
            packed = fields[5].split("~")
            if len(packed) != 6:
                return None
            fields[5], *extras = packed[1:]
        fields += extras
        decoded = []
        for field_value in fields:
            if re.search(r"%(?![0-9a-fA-F]{2})|[^a-zA-Z0-9._%~-]", field_value):
                return None

            def decode(match: re.Match[str]) -> str:
                char = chr(int(match[0][1:], 16))
                if char == "\x01":
                    return "?"
                if char == "\x02":
                    return "*"
                return char if char.isalnum() or char in "._" else "\\" + char

            decoded.append(re.sub(r"%[0-9a-fA-F]{2}", decode, field_value) or "*")
        fields = decoded
    elif value.startswith("cpe:2.3:"):
        fields = _cpe_fields(value[8:])
        if fields is None or len(fields) != 11 or any(not f for f in fields):
            return None
    else:
        return None
    for field_value in fields:
        if any(ord(c) < 32 or ord(c) > 126 for c in field_value):
            return None
        if re.fullmatch(r"(?:\\[^a-zA-Z0-9]|[a-zA-Z0-9._?*\-])+", field_value) is None:
            return None
    fields = [f.lower() for f in fields]
    if fields[0] not in {"a", "o", "h"} or any(f in {"*", "-"} for f in fields[1:3]):
        return None
    return tuple(fields)


def _cpe_pattern(value: str) -> tuple[str, bool]:
    tokens = re.findall(r"\\.|[^\\]", value)
    return (
        "".join(
            re.escape(t[1:])
            if t.startswith("\\")
            else ".*"
            if t == "*"
            else "."
            if t == "?"
            else re.escape(t)
            for t in tokens
        ),
        any(t in {"*", "?"} for t in tokens),
    )


@lru_cache(maxsize=16384)
def cpe_relation(image_cpe: str, product_cpe: str) -> str | None:
    """Compare attributes; numeric release-family matches are explicitly heuristic.

    A literal version '4' is not a CPE wildcard. We separately record a
    version_family candidate for 4 -> 4.20, never an exact/standard CPE match.
    """
    image = parse_cpe(image_cpe)
    product = parse_cpe(product_cpe)
    if image is None or product is None:
        return None
    # Require concrete, equal platform identity; broad vendor/product wildcards
    # must not associate unrelated products with the scanned image.
    for local, remote in zip(image[:3], product[:3]):
        local_pattern, local_wildcard = _cpe_pattern(local)
        remote_pattern, remote_wildcard = _cpe_pattern(remote)
        if local_wildcard or remote_wildcard or local_pattern != remote_pattern:
            return None
    relation = "exact"
    for position, (local, remote) in enumerate(zip(image, product)):
        if local == remote:
            continue
        if relation == "exact":
            relation = "compatible"
        if "*" in {local, remote}:
            continue
        if "-" in {local, remote}:
            return None
        local_pattern, local_wildcard = _cpe_pattern(local)
        remote_pattern, remote_wildcard = _cpe_pattern(remote)
        local_literal = re.sub(r"\\(.)", r"\1", local)
        if not local_wildcard and re.fullmatch(remote_pattern, local_literal):
            continue
        if (
            not local_wildcard
            and not remote_wildcard
            and local_pattern == remote_pattern
        ):
            continue
        if (
            position == 3
            and re.fullmatch(r"\d+(?:\.\d+)*", remote)
            and re.fullmatch(r"\d+(?:\.\d+)*", local)
            and local.startswith(remote + ".")
        ):
            relation = "version_family"
            continue
        return None
    return relation


def product_scope(
    product_id: str, identity: models.ImageIdentity, cpe: str = ""
) -> tuple[str, int] | None:
    """Return the strongest identity match for one CSAF product reference."""
    lower = product_id.lower()
    digest = identity.digest.partition(":")[2].lower()
    if digest and digest in lower:
        return "exact_image_digest", 100

    if product_matches_component(product_id, identity):
        if release_matches(product_id, identity):
            if architecture_matches(product_id, identity):
                return "component_release_architecture", 80
            return "component_release", 70
        return "component", 60
    relation = cpe_relation(identity.cpe, cpe)
    if relation:
        return CPE_MATCH_LEVELS[relation]
    return None


def _walk_dicts(value: object) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def product_index(document: dict[str, Any]) -> dict[str, ProductInfo]:
    """Index CPEs and directed parent links for combination-product IDs.

    Do not attach a platform to a standalone component globally: a component
    can participate in combinations with several unrelated platforms.
    """
    products: dict[str, ProductInfo] = {}
    for value in _walk_dicts(document.get("product_tree", {})):
        product_id = _string(value.get("product_id"))
        name = _string(value.get("name"))
        helper = value.get("product_identification_helper", {})
        cpe = _string(helper.get("cpe")) if isinstance(helper, dict) else ""
        full_product_name = value.get("full_product_name")
        if isinstance(full_product_name, dict):
            product_id = _string(full_product_name.get("product_id")) or product_id
            name = _string(full_product_name.get("name")) or name
        if product_id:
            existing = products.get(product_id, ProductInfo())
            products[product_id] = ProductInfo(
                name=name or existing.name,
                cpe=cpe or existing.cpe,
            )
    parents: dict[str, set[tuple[str, str]]] = {}
    tree = document.get("product_tree", {})
    relationships = tree.get("relationships", []) if isinstance(tree, dict) else []
    for relationship in relationships if isinstance(relationships, list) else []:
        if not isinstance(relationship, dict):
            continue
        category = _string(relationship.get("category"))
        if category not in {
            "default_component_of",
            "optional_component_of",
            "external_component_of",
            "installed_on",
        }:
            # installed_with is a peer relationship, not parent inheritance.
            continue
        full_name = relationship.get("full_product_name", {})
        if not isinstance(full_name, dict):
            continue
        combined = _string(full_name.get("product_id"))
        component = _string(relationship.get("product_reference"))
        parent = _string(relationship.get("relates_to_product_reference"))
        if combined in products and component in products and parent in products:
            parents.setdefault(combined, set()).add((parent, category))

    def sources(product_id: str) -> tuple[CpeSource, ...]:
        pending = [(product_id, (product_id,), ())]
        seen: set[str] = set()
        found = []
        while pending:
            current, path, categories = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            product = products[current]
            if product.cpe:
                found.append(CpeSource(current, product.cpe, path, categories))
                # An explicit CPE constrains this product. Do not bypass a
                # conflicting version by continuing to a broader ancestor.
                continue
            for parent, category in sorted(parents.get(current, ()), reverse=True):
                pending.append((parent, (*path, parent), (*categories, category)))
        return tuple(sorted(found, key=lambda source: (source.product_id, source.path)))

    return {
        pid: replace(product, cpe_sources=sources(pid))
        for pid, product in products.items()
    }


def index_document(cve: str, document: dict[str, Any]) -> CsafDocumentIndex:
    """Index one CSAF document once for reuse across many identities."""
    metadata = document.get("document", {})
    tracking = metadata.get("tracking", {}) if isinstance(metadata, dict) else {}
    if not isinstance(tracking, dict):
        tracking = {}
    severity = (
        metadata.get("aggregate_severity", {}) if isinstance(metadata, dict) else {}
    )
    records = tuple(
        value
        for value in document.get("vulnerabilities", [])
        if isinstance(value, dict)
        and (
            normalize_cve(value.get("cve")) == cve
            or _string(tracking.get("id")).upper() == cve
        )
    )
    products = product_index(document)
    references: dict[str, list[ProductReference]] = {}
    for record in records:
        for reference in product_references(record):
            references.setdefault(reference.product_id, []).append(reference)
    reference_matches = tuple(
        ProductMatch(
            "",
            0,
            product_id,
            products.get(product_id, ProductInfo()).name,
            tuple(sorted({reference.kind for reference in refs})),
            next((reference.detail for reference in refs if reference.detail), ""),
            next((reference.url for reference in refs if reference.url), ""),
        )
        for product_id, refs in sorted(references.items())
    )
    return CsafDocumentIndex(
        title=_string(metadata.get("title")) if isinstance(metadata, dict) else "",
        severity=_string(severity.get("text")) if isinstance(severity, dict) else "",
        release_date=_string(tracking.get("current_release_date")),
        records=records,
        products=products,
        reference_matches=reference_matches,
        cvss_scores=index_cvss_scores(records),
    )


def index_cvss_scores(records: Iterable[dict[str, Any]]) -> tuple[CvssScore, ...]:
    """Retain valid CVSS v3 scores without interpreting their vectors."""
    scores = set()
    for record in records:
        for raw_score in record.get("scores", []):
            if not isinstance(raw_score, dict):
                continue
            cvss = raw_score.get("cvss_v3")
            products = raw_score.get("products", [])
            if not isinstance(cvss, dict) or not isinstance(products, list):
                continue
            base_score = cvss.get("baseScore")
            if (
                isinstance(base_score, bool)
                or not isinstance(base_score, (int, float))
                or not math.isfinite(base_score)
                or not 0 <= base_score <= 10
            ):
                continue
            scores.add(
                CvssScore(
                    float(base_score),
                    _string(cvss.get("baseSeverity")),
                    _string(cvss.get("vectorString")),
                    tuple(sorted(item for item in products if isinstance(item, str))),
                )
            )
    return tuple(
        sorted(
            scores,
            key=lambda item: (
                -item.base_score,
                item.base_severity,
                item.vector,
                item.products,
            ),
        )
    )


def select_cvss_score(
    scores: Iterable[CvssScore], matched_products: set[str]
) -> dict[str, Any] | None:
    """Prefer a matched-product score, otherwise use the document maximum."""
    available = list(scores)
    matched = [
        score for score in available if matched_products.intersection(score.products)
    ]
    candidates = matched or available
    if not candidates:
        return None
    selected = min(
        candidates,
        key=lambda item: (-item.base_score, item.base_severity, item.vector),
    )
    return {
        "base_score": selected.base_score,
        "base_severity": selected.base_severity,
        "vector": selected.vector,
        "source": "matched_product" if matched else "highest_available",
        "matched_products": sorted(matched_products.intersection(selected.products)),
    }


def product_references(vulnerability: dict[str, Any]) -> Iterable[ProductReference]:
    for flag in vulnerability.get("flags", []):
        if not isinstance(flag, dict):
            continue
        product_ids = flag.get("product_ids", [])
        if not isinstance(product_ids, list):
            continue
        for product_id in product_ids:
            if isinstance(product_id, str):
                yield ProductReference(product_id, f"flag:{_string(flag.get('label'))}")

    statuses = vulnerability.get("product_status", {})
    if isinstance(statuses, dict):
        for status, product_ids in statuses.items():
            if not isinstance(product_ids, list):
                continue
            for product_id in product_ids:
                if isinstance(product_id, str):
                    yield ProductReference(product_id, f"status:{status}")

    for remediation in vulnerability.get("remediations", []):
        if not isinstance(remediation, dict):
            continue
        kind = f"remediation:{_string(remediation.get('category'))}"
        detail = _string(remediation.get("details"))
        url = _string(remediation.get("url"))
        product_ids = remediation.get("product_ids", [])
        if not isinstance(product_ids, list):
            continue
        for product_id in product_ids:
            if isinstance(product_id, str):
                yield ProductReference(product_id, kind, detail, url)


def indexed_cpe_candidates(
    index: CsafDocumentIndex, image_cpe: str
) -> tuple[ProductMatch, ...]:
    """Share immutable CPE evidence among images with the same recorded CPE."""
    if image_cpe in index.cpe_candidates:
        return index.cpe_candidates[image_cpe]
    candidates: list[ProductMatch] = []
    for match in index.reference_matches:
        product = index.products.get(match.product_id, ProductInfo())
        for source in product.cpe_sources:
            relation = cpe_relation(image_cpe, source.cpe)
            if relation is None:
                continue
            scope, score = CPE_MATCH_LEVELS[relation]
            if len(source.path) > 1:
                scope = "cpe_parent" + scope.removeprefix("cpe")
                score -= 15
            candidates.append(
                replace(
                    match,
                    scope=scope,
                    score=score,
                    cpe_evidence=CpeEvidence(image_cpe, source, relation),
                )
            )
    result = tuple(
        sorted(candidates, key=lambda match: (-match.score, match.product_id))
    )
    index.cpe_candidates[image_cpe] = result
    return result


def assess_indexed_document(
    cve: str,
    fetch: DocumentResult,
    identity: models.ImageIdentity,
    index: CsafDocumentIndex | None,
    *,
    include_details: bool = True,
) -> dict[str, Any]:
    """Match one CSAF document to the local image and preserve its evidence."""
    result: dict[str, Any] = {
        "cve": cve,
        "url": fetch.url,
    }
    if fetch.document is None:
        result["assessment"] = "document_missing"
        result["error"] = fetch.error
        return result

    if index is None:
        index = index_document(cve, fetch.document)
    result["title"] = index.title
    result["severity"] = index.severity
    result["release_date"] = index.release_date

    cpe_matches = indexed_cpe_candidates(index, identity.cpe)
    matches = list(cpe_matches)
    for match in index.reference_matches:
        scope = product_scope(match.product_id, identity)
        if scope is not None:
            scope_name, score = scope
            matches.append(replace(match, scope=scope_name, score=score))

    # Batch summaries need counts/statuses, not thousands of repeated serialized
    # paths per image. Detailed JSON/text reports retain all the evidence.
    result["cpe_candidate_count"] = len(cpe_matches)
    if include_details:
        result["cpe_matches"] = [match.to_dict() for match in cpe_matches]
    result["cpe_statuses"] = sorted(
        {status for match in cpe_matches for status in match.statuses}
    )
    result["cpe_known_affected"] = any(
        "status:known_affected" in match.statuses for match in cpe_matches
    )
    result["match_level"] = "none"
    result["best_candidate_count"] = 0
    selected: list[ProductMatch] = []

    if not index.records:
        result["assessment"] = "document_has_no_matching_cve_record"
    elif not matches:
        result["assessment"] = "no_matching_product"
    else:
        strongest = max(match.score for match in matches)
        selected = sorted(
            (match for match in matches if match.score == strongest),
            key=lambda match: match.product_id,
        )
        result["assessment"] = selected[0].scope
        result["match_level"] = (
            "platform"
            if selected[0].cpe_evidence
            else "image_digest"
            if selected[0].scope == "exact_image_digest"
            else "component"
        )
        result["best_candidate_count"] = len(selected)
        if include_details:
            result["matches"] = [match.to_dict() for match in selected]
        result["statuses"] = sorted(
            {status for match in selected for status in match.statuses}
        )
    cvss = select_cvss_score(
        index.cvss_scores, {match.product_id for match in selected}
    )
    if cvss is not None:
        result["cvss"] = cvss
    return result


def assess_document(
    cve: str,
    fetch: DocumentResult,
    identity: models.ImageIdentity,
) -> dict[str, Any]:
    """Index and match one CSAF document for one container identity."""
    return assess_indexed_document(cve, fetch, identity, None)


class CsafComparison:
    """Reuse one document index and cache assessments across image identities."""

    def __init__(self, cve: str, fetch: DocumentResult, cache: ResultCache):
        self.cve = cve
        self.fetch = fetch
        self.cache = cache
        self.document_hash = json_digest(fetch.document)
        self.index: CsafDocumentIndex | None = None

    def assess(
        self, identity: models.ImageIdentity, *, include_details: bool = True
    ) -> dict[str, Any]:
        if self.fetch.document is None:
            return assess_indexed_document(self.cve, self.fetch, identity, None)
        key = json_digest(
            {
                "run_id": self.cache.run_id,
                "cve": self.cve,
                "document_sha256": self.document_hash,
                "image": identity.to_dict(),
                "include_details": include_details,
            }
        )
        with self.cache.key_lock(key):
            cached = self.cache.load(key)
            if cached is not None:
                # Source paths belong to this invocation, not the cached result.
                return {**cached, "url": self.fetch.url}
            if self.index is None:
                self.index = index_document(self.cve, self.fetch.document)
            result = assess_indexed_document(
                self.cve,
                self.fetch,
                identity,
                self.index,
                include_details=include_details,
            )
            assessment = {
                name: value for name, value in result.items() if name != "url"
            }
            self.cache.store(key, assessment)
            return result


def render_text(result: dict[str, Any]) -> str:
    """Render a complete analyst-readable CSAF comparison."""
    identity = result["image"]
    summary = result["summary"]
    lines = TextLayout.titled("CSAF VEX COMPARISON")
    comparison.append_summary(lines, summary["metrics"])
    lines.section("SUBJECT AND COVERAGE")
    lines.fields(
        ("Audit", result["audit"]),
        ("Image", identity.get("reference") or "(unknown)"),
        ("Component", identity.get("name") or identity.get("component") or "(unknown)"),
        ("Product version", identity.get("product_version") or "(unknown)"),
        ("Platform", identity.get("platform") or "(unknown)"),
        ("Image CPE", identity.get("cpe") or "(unknown)"),
        ("CSAF documents found", summary["documents_found"]),
        ("Missing documents", summary["documents_missing"]),
        ("Binary scan coverage", result.get("scan_coverage", "unknown")),
    )
    lines.section("DETAILED COMPARISONS", rule_width=None)
    for assessment in result["assessments"]:
        cve = assessment["cve"]
        local = result["local_findings"][cve]
        evaluation = result["comparisons"][cve]
        lines.extend(
            (
                f"{cve}  {evaluation['comparison']}",
                f"  Product match:       {assessment['assessment']}",
                f"  Usable VEX:          {'yes' if evaluation['usable_vex'] else 'no'}",
                f"  Local binaries:      {', '.join(local['binary_paths']) or '(unknown)'}",
                f"  Runtime disposition:  {', '.join(local['runtime_dispositions']) or '(unknown)'}",
            )
        )
        if evaluation["resolutions"]:
            lines.append(
                f"  VEX explanations:    {', '.join(evaluation['resolutions'])}"
            )
        for finding in local["findings"]:
            lines.append(
                f"  Binary finding:      {finding['module']} {finding['found_version']} "
                f"(evidence: {finding['evidence']})"
            )
            if finding["fixed_version"]:
                lines.append(f"    Fixed version:     {finding['fixed_version']}")
        if assessment.get("title"):
            lines.append(f"  CSAF title:           {assessment['title']}")
        if assessment.get("severity"):
            lines.append(f"  CSAF severity:        {assessment['severity']}")
        if assessment.get("cvss"):
            cvss = assessment["cvss"]
            source = cvss["source"].replace("_", " ")
            lines.append(
                f"  CSAF CVSS:            {cvss['base_score']:.1f} "
                f"{cvss['base_severity']} ({source})"
            )
        if assessment.get("statuses"):
            lines.append(f"  CSAF statuses:        {', '.join(assessment['statuses'])}")
        if assessment.get("match_level"):
            lines.append(f"  Best match level:     {assessment['match_level']}")
            lines.append(
                f"  Best candidate count: {assessment.get('best_candidate_count', len(assessment.get('matches', [])))}"
            )
        if assessment.get("match_level") == "platform":
            lines.append("  Container identity:   not established by the CPE match")
        if assessment.get("cpe_matches"):
            lines.append(
                "  CPE-related affected: "
                + (
                    "yes"
                    if assessment.get("cpe_known_affected")
                    else "no known_affected entry"
                )
            )
        for match in assessment.get("matches", []):
            if match.get("cpe_evidence"):
                # The complete evidence is printed once in the candidate list.
                continue
            lines.append(f"  Matched product:      {match['product_id']}")
            if match["product_name"]:
                lines.append(f"  Product name:         {match['product_name']}")
            if match["detail"]:
                lines.append(f"  Remediation details:   {match['detail']}")
            if match["url"]:
                lines.append(f"  Remediation URL:       {match['url']}")
        for match in assessment.get("cpe_matches", []):
            evidence = match["cpe_evidence"]
            lines.extend(
                (
                    f"  CPE candidate:        {match['product_id']}",
                    f"    Candidate statuses: {', '.join(match['statuses'])}",
                    f"    Match scope:        {match['scope']}",
                    f"    CPE comparison:     {evidence['relation']}",
                    f"    Product CPE:        {evidence['product_cpe']}",
                    f"    CPE source product: {evidence['source_product_id']}",
                    f"    Relationship path:  {' -> '.join(evidence['relationship_path'])}",
                )
            )
            if evidence["relationship_categories"]:
                lines.append(
                    f"    Relationship types: {' -> '.join(evidence['relationship_categories'])}"
                )
            if match["detail"]:
                lines.append(f"    Remediation details: {match['detail']}")
            if match["url"]:
                lines.append(f"    Remediation URL:     {match['url']}")
        if assessment.get("error"):
            lines.append(f"  Error:                {assessment['error']}")
        lines.append(f"  CSAF source:           {assessment['url']}")
        lines.append("")
    return lines.render() + "\n"


def build_result(
    audit_path: Path,
    identity: models.ImageIdentity,
    local: dict[str, models.CveEvidence],
    assessments: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    evaluations = {
        cve: comparison.evaluate(evidence, assessments.get(cve))
        for cve, evidence in local.items()
    }
    ordered_cves = sorted(
        local, key=lambda cve: comparison.review_key(evaluations[cve].comparison, cve)
    )
    ordered_assessments = [
        {
            "cve": cve,
            "assessment": "document_missing",
            "url": "",
            **assessments.get(cve, {}),
        }
        for cve in ordered_cves
    ]
    summary_counts = Counter(
        assessment["assessment"] for assessment in ordered_assessments
    )
    return {
        "audit": str(audit_path),
        "image": identity.to_dict(),
        "local_findings": {cve: item.to_dict() for cve, item in local.items()},
        "assessments": ordered_assessments,
        "comparisons": {
            cve: comparison.evaluation_dict(evaluations[cve]) for cve in ordered_cves
        },
        "assessment_basis": "container_identity",
        "local_evidence_basis": "observed_binaries_and_findings",
        "summary": {
            "metrics": comparison.summarize(
                item.comparison for item in evaluations.values()
            ),
            "cves_checked": len(local),
            "documents_found": len(ordered_assessments)
            - summary_counts["document_missing"],
            "documents_missing": summary_counts["document_missing"],
            "assessment_counts": dict(sorted(summary_counts.items())),
            "cves_with_cpe_candidates": sum(
                bool(a.get("cpe_candidate_count", len(a.get("cpe_matches", []))))
                for a in ordered_assessments
            ),
            "cves_with_cpe_known_affected": sum(
                bool(a.get("cpe_known_affected")) for a in ordered_assessments
            ),
        },
    }


def load_csaf(path: Path) -> dict[str, Any]:
    """Read a local CSAF document without contacting its publisher."""
    try:
        document = atomic_read_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CsafCheckError(f"cannot read CSAF document {path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(
        document.get("vulnerabilities"), list
    ):
        raise CsafCheckError(
            f"CSAF document must contain a vulnerabilities array: {path}"
        )
    return document


def document_locations(paths: Iterable[Path]) -> dict[str, Path]:
    """Index document CVEs; conflicting revisions must be chosen explicitly."""
    files: set[Path] = set()
    for path in paths:
        if path.is_dir():
            files.update(
                candidate.resolve()
                for candidate in path.glob("*.json")
                if candidate.is_file()
            )
        elif path.is_file():
            files.add(path.resolve())
        else:
            raise CsafCheckError(f"CSAF input does not exist: {path}")
    if not files:
        raise CsafCheckError("no CSAF JSON files supplied")
    locations: dict[str, Path] = {}
    for path in sorted(files):
        document = load_csaf(path)
        cves = {
            cve
            for entry in document["vulnerabilities"]
            if isinstance(entry, dict)
            if (cve := normalize_cve(entry.get("cve")))
        }
        if not cves:
            raise CsafCheckError(f"CSAF document contains no CVE records: {path}")
        for cve in sorted(cves):
            if cve in locations:
                raise CsafCheckError(
                    f"multiple CSAF documents contain {cve}: {locations[cve]}, {path}"
                )
            locations[cve] = path
    return locations


def read_document(cve: str, path: Path | None) -> DocumentResult:
    """Make missing comparison coverage visible alongside available evidence."""
    if path is None:
        return DocumentResult(cve, "", error="not present in supplied CSAF documents")
    return DocumentResult(cve, path.as_uri(), load_csaf(path))


def compare_audit(
    audit_json: Path,
    locations: dict[str, Path],
    cache: ResultCache | None = None,
) -> dict[str, Any]:
    """Compare saved evidence; a clean audit produces an empty result."""
    report = audit.load_audit(audit_json)
    identity, local = report.metadata.image, index_cve_evidence(report)
    cache = cache or ResultCache(None)
    assessments = {
        cve: CsafComparison(cve, read_document(cve, locations.get(cve)), cache).assess(
            identity
        )
        for cve in local
    }
    return {
        **build_result(audit_json, identity, local, assessments),
        "audit_sha256": json_digest(report.to_dict()),
        "scan_coverage": report.coverage_state,
    }


def run(targets: list[argparse.Namespace]) -> int:
    """Compare the audit files and advisory locations resolved by the CLI."""
    cache = ResultCache(None)
    missing = False
    outputs = [options.output_dir.resolve() for options in targets]
    if len(set(outputs)) != len(outputs):
        raise CsafCheckError(
            "each container comparison needs a distinct output directory"
        )
    all_subjects = [
        path for options in targets for path in (options.rootfs, options.layers_dir)
    ]
    outside_subjects([options.output_dir for options in targets], all_subjects)
    for options in targets:
        source = options.audit_file
        locations = document_locations(options.csaf) if options.csaf else {}
        result = compare_audit(source, locations, cache)
        json_path, _ = write_comparison_artifacts(
            options.output_dir,
            "comparison",
            result,
            render_text(result),
            inputs=[source, *locations.values()],
        )
        print(f"Comparison: {json_path}")
        missing |= bool(result["summary"]["documents_missing"])
    return int(missing)
