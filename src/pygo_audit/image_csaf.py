"""Match a container to CSAF components and their product contexts."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
from urllib.parse import parse_qs, unquote

from pygo_audit import audit, comparison, csaf, csaf_redhat, models
from pygo_audit.report_sections import (
    CGO_LABELS,
    append_detail_footer,
    runtime_availability_label,
    runtime_disposition_label,
)
from pygo_audit.report_views import group_items, index_cve_evidence, normalize_cve
from pygo_audit.storage import atomic_read_json, json_digest
from pygo_audit.text_layout import RenderPolicy, SUMMARY_POLICY, TextLayout, Verbosity
from pygo_audit.text_report import append_layer_observations, rootfs_location

MATCH_STRENGTH = ("exact", "fuzzy", "ambiguous")


type MissingDocuments = dict[str, list[dict[str, Any]]]
type DocumentObservation = tuple[int, dict[str, Any], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ImageAudit:
    path: Path
    report: models.AuditReport
    image: models.ImageIdentity
    inputs: dict[str, Any]
    evidence: dict[str, models.CveEvidence]


def strongest_match(kinds: Sequence[str]) -> str:
    return next((kind for kind in MATCH_STRENGTH if kind in kinds), "no_match")


def comparison_inputs(paths: list[Path]) -> tuple[list[Path], MissingDocuments]:
    """Read documents and cached absence records without fetching or using stale peers."""
    files: set[Path] = set()
    missing: MissingDocuments = {}
    for path in paths:
        if path.is_dir():
            files.update(
                item.resolve()
                for pattern in ("*.json", "*.missing")
                for item in path.glob(pattern)
                if item.is_file()
            )
        elif path.is_file():
            files.add(path.resolve())
        elif path.suffix == ".json" and (cve := normalize_cve(path.stem)):
            marker = path.with_suffix(".missing")
            if marker.is_file():
                files.add(marker.resolve())
            else:
                missing.setdefault(cve, []).append(
                    {"source": str(path.resolve()), "reason": "file not found"}
                )
        elif not path.exists() and not path.suffix:
            continue
        else:
            raise csaf.CsafCheckError(f"CSAF input does not exist: {path}")
    files.update(
        path.with_suffix(".missing")
        for path in list(files)
        if path.suffix == ".json" and path.with_suffix(".missing").is_file()
    )
    for marker in sorted(path for path in files if path.suffix == ".missing"):
        try:
            record = atomic_read_json(marker)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise csaf.CsafCheckError(
                f"cannot read CSAF missing marker {marker}: {error}"
            ) from error
        cve = normalize_cve(marker.stem)
        if (
            not cve
            or not isinstance(record, dict)
            or record.get("status") != 404
            or not all(
                isinstance(record.get(key), str) and record[key]
                for key in ("url", "checked_at")
            )
        ):
            raise csaf.CsafCheckError(f"invalid CSAF missing marker: {marker}")
        missing.setdefault(cve, []).append(
            {
                "source": str(marker),
                **{key: record[key] for key in ("url", "status", "checked_at")},
            }
        )
        files.discard(marker)
        files.discard(marker.with_suffix(".json"))
    return sorted(files), missing


def product_inputs(
    name: str,
    cpes: tuple[str, ...],
    purls: tuple[str, ...],
    name_field: str,
    *,
    image: bool = False,
    versions: tuple[comparison.VersionEvidence, ...] = (),
) -> dict[str, Any]:
    basename = (
        name.strip().rsplit("/", 1)[-1].partition("@")[0].partition(":")[0].lower()
    )
    return {
        "name": name,
        "cpes": list(cpes),
        "purls": list(purls),
        "image": image,
        "versions": [item.to_dict() for item in versions if item.value],
        "derived_purls": [{"value": f"pkg:oci/{basename}", "from": name_field}]
        if basename and not purls
        else [],
    }


def match_inputs(identity: models.ImageIdentity) -> dict[str, Any]:
    """Preserve supplied identifiers separately from generated lookup candidates."""
    architecture = identity.platform.split("/")[1] if "/" in identity.platform else ""
    name_field = "vendor_image_name" if identity.vendor_image_name else "name"
    return {
        "digest": identity.digest.lower()
        if csaf.IMAGE_DIGEST.fullmatch(identity.digest)
        else "",
        "architecture": csaf.ARCHITECTURE_ALIASES.get(architecture, architecture),
        "product_ids": list(identity.csaf_product_ids),
        "contexts": [
            product_inputs(
                getattr(identity, name_field),
                identity.cpes,
                identity.purls,
                f"image.{name_field}",
                image=True,
                versions=(
                    comparison.VersionEvidence(
                        identity.product_version, "product", "image.product_version"
                    ),
                    comparison.VersionEvidence(
                        identity.component_version,
                        "component",
                        "image.component_version",
                    ),
                ),
            ),
            *[
                product_inputs(
                    product.name,
                    product.cpes,
                    product.purls,
                    f"products[{i}].name",
                    versions=(
                        comparison.VersionEvidence(
                            product.version, "component", f"products[{i}].version"
                        ),
                    ),
                )
                for i, product in enumerate(identity.products)
            ],
        ],
    }


def parse_oci_purl(value: str) -> dict[str, str] | None:
    """Parse OCI identity fields before decoding, keeping qualifiers separate."""
    if (
        not value.startswith("pkg:oci/")
        or "#" in value
        or re.search(r"%(?![0-9a-fA-F]{2})", value)
    ):
        return None
    package, _, query = value.removeprefix("pkg:oci/").partition("?")
    name, _, version = package.partition("@")
    try:
        name, version = (
            unquote(name, errors="strict").lower(),
            unquote(version, errors="strict").lower(),
        )
        qualifiers = parse_qs(query, keep_blank_values=True, errors="strict")
    except UnicodeError:
        return None
    if not all(
        re.fullmatch(r"[a-z0-9][a-z0-9._-]*", part) for part in name.split("/")
    ) or any(len(values) != 1 for values in qualifiers.values()):
        return None
    arch = qualifiers.get("arch", [""])[0].lower()
    return {
        "name": name.rsplit("/", 1)[-1],
        "namespace": name.rpartition("/")[0],
        "version": version,
        "architecture": csaf.ARCHITECTURE_ALIASES.get(arch, arch),
        "tag": qualifiers.get("tag", [""])[0],
    }


def cpe_supported(
    image_cpe: str, evidence: dict[str, str], *, tentative: bool = False
) -> bool:
    """Require enough local identity to satisfy the stated product constraints."""
    local, remote = csaf.parse_cpe(image_cpe), csaf.parse_cpe(evidence["product_cpe"])
    if (
        not local
        or not remote
        or any(a == "*" and b != "*" for a, b in zip(local, remote))
    ):
        return False
    relation = evidence["relation"]
    return relation in {"exact", "compatible"} or (
        tentative
        and relation in {"version_family", "normalized_version", "release_line"}
    )


def select_policy(
    context: comparison.PolicyContext,
) -> (
    Callable[
        [comparison.PolicyContext, Sequence[str]],
        tuple[comparison.VersionAssessment, ...],
    ]
    | None
):
    """Vendor/product selection is independent of local vulnerability findings."""
    return csaf_redhat.infer_assessment if csaf_redhat.supports(context) else None


def policy_context(
    candidate: dict[str, Any],
    entry: dict[str, Any],
    inputs: dict[str, Any],
    index: csaf.CsafDocumentIndex,
    publisher: str,
) -> comparison.PolicyContext:
    cpes = tuple(item["product_cpe"] for item in entry["cpes"])
    if not cpes:
        cpes = tuple(
            item["product_cpe"]
            for related in candidate["entries"]
            for item in related["cpes"]
        )
    remote = next((parsed for value in cpes if (parsed := csaf.parse_cpe(value))), ())
    local_cpes = tuple(
        value
        for value in inputs["cpes"]
        if (parsed := csaf.parse_cpe(value)) and parsed[1:3] == remote[1:3]
    )
    local = csaf.parse_cpe(local_cpes[0]) if local_cpes else None
    local_versions = [
        audit.parse_model(value, comparison.VersionEvidence, "match input version")
        for value in inputs["versions"]
    ]
    local_versions.extend(
        comparison.VersionEvidence(parsed[3], "product", f"cpe:{value}")
        for value in local_cpes
        if (parsed := csaf.parse_cpe(value)) and parsed[3] not in {"*", "-"}
    )
    package = candidate["package"]
    remote_versions = list(
        index.products[entry["product_id"]].versions
        or index.products[candidate["product_id"]].versions
    )
    if package["version"]:
        remote_versions.append(
            comparison.VersionEvidence(
                package["version"], "component", f"purl:{candidate['product_id']}"
            )
        )
    for value in inputs["purls"]:
        supplied = parse_oci_purl(value)
        if supplied and supplied["name"] == package["name"] and supplied["version"]:
            local_versions.append(
                comparison.VersionEvidence(
                    supplied["version"], "component", f"purl:{value}"
                )
            )
    return comparison.PolicyContext(
        publisher,
        entry["product_id"],
        comparison.ProductContext(
            local[1] if local else "",
            local[2] if local else "",
            package["name"],
            inputs["architecture"],
            tuple(local_versions),
            local_cpes,
            tuple(inputs["purls"]),
        ),
        comparison.ProductContext(
            remote[1] if remote else "",
            remote[2] if remote else "",
            package["name"],
            package["architecture"],
            tuple(remote_versions),
            cpes,
            (candidate["purl"],),
        ),
    )


def match_context(
    document: dict[str, Any], index: csaf.CsafDocumentIndex, inputs: dict[str, Any]
) -> list[dict[str, Any]]:
    purls = [*inputs["purls"], *(item["value"] for item in inputs["derived_purls"])]
    wanted = [package for purl in purls if (package := parse_oci_purl(purl))]
    names = {package["name"] for package in wanted}
    candidates: list[dict[str, Any]] = []
    for product_id, product in index.products.items():
        package = parse_oci_purl(product.purl)
        if package is None:
            continue
        exact_digest = bool(inputs["digest"] and package["version"] == inputs["digest"])
        exact_name = package["name"] in names
        similar_name = any(
            name in package["name"] or package["name"] in name for name in names
        )
        if not (exact_digest or exact_name or similar_name):
            continue
        checks = {
            "component": csaf.identity_field(exact_name, bool(wanted)),
            "digest": csaf.identity_field(
                exact_digest,
                bool(
                    inputs["digest"] and csaf.IMAGE_DIGEST.fullmatch(package["version"])
                ),
            ),
            "architecture": csaf.identity_field(
                bool(
                    inputs["architecture"]
                    and package["architecture"] == inputs["architecture"]
                ),
                bool(inputs["architecture"] and package["architecture"]),
            ),
        }
        candidates.append(
            {
                "product_id": product_id,
                "purl": product.purl,
                "package": package,
                "checks": checks,
            }
        )
    csaf.attach_oci_platforms(
        candidates, document, index, next(iter(inputs["cpes"]), "")
    )
    for candidate in candidates:
        product = index.products[candidate["product_id"]]
        direct = {
            "product_id": candidate["product_id"],
            "relationship_path": [candidate["product_id"]],
            "relationship_categories": [],
            "cpes": [
                {
                    "product_cpe": product.cpe,
                    "source_product_id": candidate["product_id"],
                    "relation": "no_match",
                }
            ]
            if product.cpe
            else [],
        }
        entries = [direct, *candidate.pop("related_platforms")]
        for entry in entries:
            for evidence in entry["cpes"]:
                comparisons = [
                    (
                        relation,
                        cpe_supported(cpe, {**evidence, "relation": relation}),
                        cpe_supported(
                            cpe, {**evidence, "relation": relation}, tentative=True
                        ),
                        cpe,
                    )
                    for cpe in inputs["cpes"]
                    for relation in [
                        csaf.cpe_relation(cpe, evidence["product_cpe"]) or "no_match"
                    ]
                ]
                (
                    evidence["relation"],
                    evidence["supported"],
                    evidence["tentative_supported"],
                    evidence["image_cpe"],
                ) = max(
                    comparisons,
                    key=lambda item: (
                        item[1],
                        item[2],
                        item[0] == "exact",
                        item[0] != "no_match",
                    ),
                    default=("no_match", False, False, ""),
                )
        by_id = {entry["product_id"]: entry for entry in entries}
        package, checks = candidate["package"], candidate["checks"]
        exact_digest = checks["digest"]["result"] == "match"
        # Architecture variants are equivalent for this comparison. Keep the
        # recorded difference for detailed evidence rather than rejecting them.
        supplied_purl = any(
            {**local, "architecture": package["architecture"]} == package
            and (local["version"] or local["tag"])
            and not (
                inputs["digest"]
                and csaf.IMAGE_DIGEST.fullmatch(local["version"])
                and local["version"] != inputs["digest"]
            )
            for local in wanted
        )
        for entry in entries:
            entry.pop("statuses", None)
            # Every enclosing product constraint must hold, including intermediate
            # combinations. An outer matching platform cannot erase a conflict.
            cpes = [
                cpe for pid in entry["relationship_path"] for cpe in by_id[pid]["cpes"]
            ]
            scoped = all(
                pid == candidate["product_id"] or by_id[pid]["cpes"]
                for pid in entry["relationship_path"]
            )
            scope_ok = scoped and all(cpe["supported"] for cpe in cpes)
            scope_tentative = (
                scoped and cpes and all(cpe["tentative_supported"] for cpe in cpes)
            )
            entry["release_group"] = (
                "Same release"
                if cpes
                and (
                    scope_ok
                    or (
                        scope_tentative
                        and all(cpe["relation"] != "version_family" for cpe in cpes)
                    )
                )
                else "Broader product family"
                if scope_tentative
                else "Other releases or products"
            )
            entry["basis"] = (
                "image_digest"
                if exact_digest and scope_ok
                else "supplied_purl"
                if supplied_purl and scope_ok
                else "component_cpe"
                if checks["component"]["result"] == "match" and scope_tentative
                else ""
            )
            entry["match_kind"] = (
                "exact"
                if entry["basis"] in {"image_digest", "supplied_purl"}
                else "fuzzy"
                if entry["basis"]
                else "ambiguous"
            )
        candidate["entries"] = entries
        candidate["matched"] = any(entry["basis"] for entry in entries)
        candidate["reason"] = (
            "matched"
            if candidate["matched"]
            else "product scope not established"
            if checks["component"]["result"] == "match" or exact_digest
            else "similar name only"
        )
        candidate["mismatches"] = candidate_mismatches(candidate, inputs)
    return candidates


def match_candidates(
    document: dict[str, Any], index: csaf.CsafDocumentIndex, inputs: dict[str, Any]
) -> list[dict[str, Any]]:
    if inputs["product_ids"]:
        return [
            {
                "product_id": pid,
                "purl": index.products[pid].purl,
                "context": "user selection",
                "image": True,
                "package": {"namespace": ""},
                "checks": {},
                "matched": True,
                "reason": "explicit CSAF product_id",
                "mismatches": [],
                "entries": [
                    {
                        "product_id": pid,
                        "relationship_path": [pid],
                        "relationship_categories": [],
                        "cpes": [],
                        "basis": "explicit_product_id",
                        "match_kind": "exact",
                    }
                ],
            }
            for pid in dict.fromkeys(inputs["product_ids"])
            if pid in index.products
        ]
    candidates = []
    for context in inputs["contexts"]:
        for candidate in match_context(
            document,
            index,
            {
                **context,
                "architecture": inputs["architecture"],
                "digest": inputs["digest"] if context["image"] else "",
            },
        ):
            candidate["context"] = context["name"]
            candidate["image"] = context["image"]
            candidates.append(candidate)
    if any(
        entry["match_kind"] == "exact"
        for candidate in candidates
        for entry in candidate["entries"]
    ):
        candidates = [
            {**candidate, "entries": entries}
            for candidate in candidates
            if (
                entries := [
                    entry
                    for entry in candidate["entries"]
                    if entry["match_kind"] == "exact"
                ]
            )
        ]
    return sorted(
        candidates,
        key=lambda item: (
            not item["matched"],
            item["checks"]["digest"]["result"] != "match",
            item["checks"]["component"]["result"] != "match",
            item["product_id"],
        ),
    )


def assess_record(
    candidates: list[dict[str, Any]], record: dict[str, Any]
) -> dict[str, Any]:
    """Separate confirmed identities from tentative product-context comparisons."""
    choices = [
        (entry["match_kind"], candidate, entry)
        for candidate in candidates
        for entry in candidate["entries"]
        if entry["match_kind"]
    ]
    level = strongest_match([kind for kind, _, _ in choices])
    choices = [item for item in choices if item[0] == level]
    selected = sorted({entry["product_id"] for _, _, entry in choices})
    qualifications = set()
    for kind, candidate, entry in choices:
        if kind == "ambiguous":
            qualifications.add("component/product scope is unresolved")
        elif kind == "fuzzy":
            if candidate["checks"]["digest"]["result"] == "match":
                qualifications.add("image digest matches")
            else:
                qualifications.update(
                    ("product name/context match", "exact build unverified")
                )
            if any(
                cpe["relation"] == "version_family"
                for item in candidate["entries"]
                if item["product_id"] in entry["relationship_path"]
                for cpe in item["cpes"]
            ):
                qualifications.add("broader CPE version family")
        elif entry["basis"] == "explicit_product_id":
            qualifications.add("explicit CSAF product_id selection")
        elif entry["basis"] == "image_digest":
            qualifications.add("image digest matches")
        else:
            qualifications.add("supplied versioned PURL matches")
    references: dict[tuple[str, str], dict[str, Any]] = {}
    identities = []
    for (context, identifier), matches in group_items(
        choices,
        lambda item: (
            item[1]["context"],
            json_digest(
                {
                    key: value
                    for key, value in item[1]["package"].items()
                    if key != "architecture"
                }
            )
            if item[1]["purl"] and item[1]["checks"]
            else item[1]["product_id"],
        ),
    ):
        identities.append({"context": context, "identifier": identifier})
        ids = {entry["product_id"] for _, _, entry in matches}
        scoped = [
            reference
            for reference in record["references"]
            if reference["product_id"] in ids and reference["context"] == context
        ]
        for reference in scoped or [
            {
                "product_id": matches[0][1]["product_id"],
                "context": context,
                "statements": [],
                "effective_statements": [],
                "version_assessments": [],
            }
        ]:
            references[context, reference["product_id"]] = reference
    reference_statuses = sorted(
        {
            value.removeprefix("status:")
            for reference in record["references"]
            for value in reference["statements"]
            if value.startswith("status:")
        }
    )
    return {
        "kind": level,
        "product_ids": selected,
        "references": list(references.values()),
        "identities": identities,
        "qualifications": sorted(qualifications),
        "candidate_statuses": reference_statuses,
    }


def assessed_references(
    candidates: list[dict[str, Any]],
    record: dict[str, Any],
    inputs: dict[str, Any],
    index: csaf.CsafDocumentIndex,
    publisher: str,
) -> list[dict[str, Any]]:
    statements_by_id = csaf.product_statuses((record,))
    prepared = []
    for candidate in candidates:
        local = next(
            (
                item
                for item in inputs["contexts"]
                if item["name"] == candidate["context"]
            ),
            inputs["contexts"][0],
        )
        for entry in candidate["entries"]:
            statements = statements_by_id.get(entry["product_id"], ())
            if not statements:
                continue
            context = None
            if not inputs["product_ids"]:
                context = policy_context(
                    candidate,
                    entry,
                    {**local, "architecture": inputs["architecture"]},
                    index,
                    publisher,
                )
            prepared.append((candidate, entry, statements, context))
    declarations: dict[
        tuple[comparison.ProductContext, str, str, tuple[str, ...]],
        list[comparison.VersionDeclaration],
    ] = {}
    for _, entry, statements, context in prepared:
        if context is not None and entry["match_kind"] in {"exact", "fuzzy"}:
            key = (
                context.local,
                context.candidate.vendor,
                context.candidate.product,
                tuple(sorted(context.candidate.cpes)),
            )
            declarations.setdefault(key, []).extend(
                comparison.VersionDeclaration(version, tuple(statements))
                for version in context.candidate.versions
            )
    result = []
    for candidate, entry, statements, context in prepared:
        assessments: tuple[comparison.VersionAssessment, ...] = ()
        if context is not None:
            key = (
                context.local,
                context.candidate.vendor,
                context.candidate.product,
                tuple(sorted(context.candidate.cpes)),
            )
            context = replace(context, declarations=tuple(declarations.get(key, ())))
            policy = select_policy(context)
            if policy is not None:
                assessments = policy(context, statements)
        effective = list(statements)
        if assessments:
            outcomes = {item.status for item in assessments}
            effective = [
                item for item in statements if not item.startswith(("status:", "flag:"))
            ]
            effective.append(
                "status:"
                + (next(iter(outcomes)) if len(outcomes) == 1 else "undetermined")
            )
            effective.extend(
                sorted(
                    {
                        statement
                        for item in assessments
                        for statement in item.statements
                        if statement.startswith("flag:")
                    }
                )
            )
        result.append(
            {
                "product_id": entry["product_id"],
                "context": candidate["context"],
                "statements": list(statements),
                "effective_statements": effective,
                "version_assessments": [item.to_dict() for item in assessments],
            }
        )
    return result


def vulnerability_identifier(record: dict[str, Any], number: int) -> str:
    return (
        normalize_cve(record.get("cve"))
        or (raw if isinstance(raw := record.get("id"), str) else "")
        or f"record {number}"
    )


def cvss_score_values(record: dict[str, Any]) -> list[float]:
    scores = record.get("scores")
    if not isinstance(scores, list):
        return []
    return sorted(
        {
            float(details["baseScore"])
            for entry in scores
            if isinstance(entry, dict)
            for kind, details in entry.items()
            if kind.startswith("cvss_v") and isinstance(details, dict)
            if isinstance(details.get("baseScore"), (int, float))
            and not isinstance(details["baseScore"], bool)
        }
    )


def inspect_document(
    path: Path, display: str, inputs: dict[str, Any], index: csaf.CsafDocumentIndex
) -> dict[str, Any]:
    document = index.document
    candidates = match_candidates(document, index, inputs)
    matched_ids = {
        entry["product_id"]
        for candidate in candidates
        for entry in candidate["entries"]
        if entry["basis"]
    }
    presence = (
        "matched" if matched_ids else "ambiguous" if candidates else "not_identified"
    )
    vulnerabilities = []
    for number, record in enumerate(document.get("vulnerabilities", []), 1):
        if not isinstance(record, dict):
            continue
        references = assessed_references(
            candidates, record, inputs, index, index.publisher_namespace
        )
        matches = [
            reference
            for reference in references
            if reference["product_id"] in matched_ids
        ]
        statuses = sorted(
            {
                statement.removeprefix("status:")
                for match in matches
                for statement in match["statements"]
                if statement.startswith("status:")
            }
        )
        categories = comparison.status_categories(statuses)
        vulnerabilities.append(
            {
                "id": vulnerability_identifier(record, number),
                "record": number,
                "cvss_scores": cvss_score_values(record),
                "match": "ambiguous" if len(categories) > 1 else presence,
                "statuses": statuses,
                "matches": matches,
                "references": references,
            }
        )
    for record in vulnerabilities:
        record["assessment"] = assess_record(candidates, record)
    return {
        "source": path.as_uri(),
        "source_display": display,
        "title": index.title,
        "canonical_urls": list(index.canonical_urls),
        "presence": presence,
        "candidates": candidates,
        "missing_product_ids": [
            pid for pid in inputs["product_ids"] if pid not in index.products
        ],
        "vulnerabilities": vulnerabilities,
    }


def local_artifacts(
    index: dict[str, models.CveEvidence], cves: set[str]
) -> dict[str, list[dict[str, Any]]]:
    """Merge duplicate binary observations while preserving location and layer scope."""
    result = {}
    for cve in sorted(cves):
        grouped: dict[str, dict[str, Any]] = {}
        evidence = index.get(cve, models.CveEvidence(cve))
        for binary, vulnerability in evidence.observations:
            if re.fullmatch(r"[0-9a-fA-F]{64}", binary.sha256) is None:
                raise csaf.CsafCheckError(
                    f"Binary SHA256 missing or invalid for {binary.paths}; rescan before comparing artifacts"
                )
            observation = {
                "paths": sorted(set(binary.paths)),
                "runtime_disposition": binary.runtime_disposition,
                "cgo_enabled": binary.cgo_enabled,
                "symlinks": sorted(set(binary.symlinks)),
                "layer_history": [event.to_dict() for event in binary.layer_history],
            }
            artifact = grouped.setdefault(
                binary.sha256.lower(),
                {
                    "sha256": binary.sha256.lower(),
                    "observations": [],
                    "advisories": [],
                    "findings": [],
                },
            )
            if observation not in artifact["observations"]:
                artifact["observations"].append(observation)
            if vulnerability.id not in artifact["advisories"]:
                artifact["advisories"].append(vulnerability.id)
            for finding in vulnerability.findings:
                detail = {
                    key: getattr(finding, key)
                    for key in (
                        "module",
                        "found_version",
                        "fixed_version",
                        "package",
                        "evidence",
                        "reachability",
                        "symbol",
                    )
                }
                if detail not in artifact["findings"]:
                    artifact["findings"].append(detail)
        for artifact in grouped.values():
            observations = artifact["observations"]
            observations.sort(key=json_digest)
            for field in ("paths", "symlinks"):
                artifact[field] = sorted(
                    {
                        value
                        for observation in observations
                        for value in observation[field]
                    }
                )
            dispositions = {item["runtime_disposition"] for item in observations}
            artifact["runtime_disposition"] = next(
                value
                for value in (
                    "runtime",
                    "unknown",
                    "unaccounted",
                    "replaced",
                    "deleted",
                )
                if value in dispositions
            )
            settings = {item["cgo_enabled"] for item in observations}
            artifact["cgo_enabled"] = (
                next(iter(settings)) if len(settings) == 1 else None
            )
            events = {
                json_digest(event): event
                for item in observations
                for event in item["layer_history"]
            }
            artifact["layer_history"] = sorted(
                events.values(),
                key=lambda event: (event["layer_index"], json_digest(event)),
            )

            artifact["advisories"].sort()
            artifact["findings"].sort(
                key=lambda item: (
                    item["module"],
                    item["found_version"],
                    item["package"],
                    item["symbol"] or "",
                    item["fixed_version"],
                    item["evidence"],
                )
            )
        result[cve] = sorted(
            grouped.values(),
            key=lambda item: (
                PurePosixPath(item["paths"][0]).name,
                item["paths"],
                item["sha256"],
                item["runtime_disposition"],
                json_digest(item),
            ),
        )
    return result


def vulnerability_groups(
    result: dict[str, Any],
) -> list[tuple[str, list[DocumentObservation]]]:
    groups: dict[str, list[DocumentObservation]] = {
        cve: [] for cve in result["local_findings"]
    }
    for number, document in enumerate(result["documents"], 1):
        records = document["vulnerabilities"]
        if not records:
            record: dict[str, Any] = {
                "id": "no CVE records",
                "record": 0,
                "references": [],
            }
            record["assessment"] = assess_record(document["candidates"], record)
            record["assessment"]["qualifications"].append("document has no CVE record")
            records = [record]
        for record in records:
            identifier = (
                normalize_cve(record["id"]) or f"Document {number}: {record['id']}"
            )
            groups.setdefault(identifier, []).append((number, document, record))
    return sorted(groups.items())


def preferred_observations(
    observations: list[DocumentObservation],
) -> list[DocumentObservation]:
    """An exact product match takes precedence across all records for this CVE."""
    level = strongest_match(
        [record["assessment"]["kind"] for _, _, record in observations]
    )
    return [item for item in observations if item[2]["assessment"]["kind"] == level]


def artifact_evidence(artifacts: list[dict[str, Any]]) -> list[str]:
    kinds = sorted(
        {item["evidence"] for artifact in artifacts for item in artifact["findings"]}
    )
    return kinds or (["advisory only"] if artifacts else [])


def vendor_assessment(references: list[dict[str, Any]]) -> str:
    statuses = comparison.status_categories(
        value.removeprefix("status:")
        for item in references
        for value in item["effective_statements"]
        if value.startswith("status:")
    )
    if not statuses or statuses & {"undetermined", "under_investigation"}:
        return "Undetermined"
    if "known_affected" in statuses:
        return (
            "Conflicting statements"
            if statuses & {"fixed", "known_not_affected"}
            else "Affected"
        )
    return (
        "Fixed"
        if statuses == {"fixed"}
        else "Not affected"
        if statuses <= {"fixed", "known_not_affected"}
        else "Undetermined"
    )


def reference_agreement(
    evidence: Sequence[str],
    present_evidence: Sequence[str],
    kind: str,
    references: Sequence[dict[str, Any]],
    outcomes: Sequence[str] = (),
) -> dict[str, Any]:
    return comparison.finding_agreement(
        [item for item in evidence if item != "advisory only"],
        kind,
        [item["effective_statements"] for item in references],
        present_evidence=present_evidence,
        inferred=any(
            value["inferred"]
            for item in references
            for value in item["version_assessments"]
        ),
        candidate_agreements=outcomes,
    )


def summarize_cve(
    identifier: str,
    observations: list[DocumentObservation],
    artifacts: list[dict[str, Any]],
    missing: list[dict[str, Any]] | None,
    coverage: dict[str, Any],
) -> dict[str, Any]:
    selected = preferred_observations(observations)
    assessments = [record["assessment"] for _, _, record in selected]
    identities = {
        (item["context"], item["identifier"])
        for assessment in assessments
        for item in assessment["identities"]
    }
    match = (
        "no_document"
        if not observations
        else "no_match"
        if not selected
        else "ambiguous"
        if len(identities) > 1
        else assessments[0]["kind"]
    )
    statuses = sorted(
        {
            status
            for _, _, record in observations
            for status in record["assessment"]["candidate_statuses"]
        }
    )
    evidence = artifact_evidence(artifacts)
    current_evidence = artifact_evidence(
        [item for item in artifacts if item["runtime_disposition"] == "runtime"]
    )
    qualifiers = sorted(
        {value for item in assessments for value in item["qualifications"]}
    )
    if not observations and missing:
        qualifiers.append(
            "cached HTTP 404"
            if any(item.get("status") == 404 for item in missing)
            else "requested file is absent"
        )
    missing_ids = sorted(
        {
            pid
            for _, document, _ in observations
            for pid in document["missing_product_ids"]
        }
    )
    if missing_ids:
        qualifiers.extend(
            f"selected product ID not found: {pid}" for pid in missing_ids
        )

    candidates = []
    for number, document, record in observations:
        for index, candidate in enumerate(document["candidates"], 1):
            assessment = assess_record([candidate], record)
            candidates.append(
                {
                    "document": number,
                    "record": record["record"],
                    "candidate": index,
                    "match": assessment["kind"],
                    "product_ids": assessment["product_ids"],
                    "qualifications": assessment["qualifications"],
                    "mismatches": [
                        *candidate["mismatches"],
                        *[
                            {
                                "field": value["subject"] + "_version",
                                "text": (
                                    f"{value['subject'].capitalize()} version differs: local {value['observed']['value']}; "
                                    f"CSAF {value['boundary']['value']}"
                                ),
                            }
                            for reference in assessment["references"]
                            for value in reference["version_assessments"]
                            if value["normalized_observed"]
                            != value["normalized_boundary"]
                        ],
                    ],
                    "vendor_assessment": vendor_assessment(assessment["references"]),
                    "version_assessments": [
                        value
                        for item in assessment["references"]
                        for value in item["version_assessments"]
                    ],
                    "agreement": reference_agreement(
                        evidence,
                        current_evidence,
                        assessment["kind"],
                        assessment["references"],
                    ),
                }
            )
    selected_candidates = [
        candidate
        for candidate in candidates
        if assessments and candidate["match"] == assessments[0]["kind"]
    ]
    references = [reference for item in assessments for reference in item["references"]]
    return {
        "local_scan": local_scan_result(identifier, artifacts, coverage),
        "evidence": evidence,
        "match": match,
        "match_count": len(identities),
        "qualifications": qualifiers,
        "mismatches": [
            mismatch
            for candidate in selected_candidates
            for mismatch in candidate["mismatches"]
        ],
        "vendor_assessment": vendor_assessment(references),
        "agreement": reference_agreement(
            evidence,
            current_evidence,
            match,
            references,
            [item["agreement"]["comparison"] for item in selected_candidates],
        ),
        "candidates": candidates,
        "candidate_statuses": statuses,
    }


def local_scan_result(
    identifier: str, artifacts: list[dict[str, Any]], coverage: dict[str, Any]
) -> dict[str, Any]:
    observed = [artifact for artifact in artifacts if artifact["findings"]]
    historical_only = bool(observed) and all(
        item["runtime_disposition"] in {"deleted", "replaced"} for item in observed
    )
    if not normalize_cve(identifier):
        status = "undetermined"
        reason = "No CVE is specified for comparison with the local scan."
    elif observed:
        status = "affected"
        reason = (
            "The local scan recorded vulnerable module, package, or symbol evidence."
        )
        if historical_only:
            reason += (
                " All findings are in binaries deleted or replaced in the final image."
            )
    elif coverage["state"] == "incomplete" or coverage["operational_issues"]:
        status = "undetermined"
        reason = "No vulnerable code was recorded, but incomplete scanning or operational issues prevent a negative conclusion."
    else:
        status = "not_affected"
        reason = (
            "The scan found no Go binaries."
            if coverage["state"] == "no_go_binaries"
            else "The completed local scan recorded no vulnerable code for this CVE."
        )
    return {"status": status, "historical_only": historical_only, "reason": reason}


def prepare_image(
    audit_path: Path,
    report: models.AuditReport,
    image: models.ImageIdentity | None = None,
) -> ImageAudit:
    image = image if image is not None else report.metadata.image
    return ImageAudit(
        audit_path, report, image, match_inputs(image), index_cve_evidence(report)
    )


def check_image(
    audit_path: Path,
    report: models.AuditReport,
    files: list[Path],
    inputs: list[Path],
    *,
    image: models.ImageIdentity | None = None,
    missing_documents: MissingDocuments | None = None,
) -> dict[str, Any]:
    source = prepare_image(audit_path, report, image)
    names = csaf.relative_document_names({str(path): path for path in files}, inputs)
    documents = [
        inspect_document(
            path,
            names[str(path)],
            source.inputs,
            csaf.index_document(csaf.load_document(path)),
        )
        for path in files
    ]
    return build_comparison(source, documents, missing_documents or {})


def build_comparison(
    source: ImageAudit,
    documents: list[dict[str, Any]],
    missing_documents: MissingDocuments,
) -> dict[str, Any]:
    """Join matched documents to one audit, independently of loading or concurrency."""
    report = source.report
    summary = {
        "documents_checked": len(documents),
        "scan_coverage": {
            "state": report.coverage_state,
            "binaries": len(report.binaries),
            "completed": report.complete_vulnerability_scans,
            "operational_issues": len(report.actionable_issues),
        },
        **dict(sorted(Counter(item["presence"] for item in documents).items())),
    }
    exact_cves = {
        cve
        for document in documents
        for record in document["vulnerabilities"]
        if record["assessment"]["kind"] == "exact"
        and (cve := normalize_cve(record["id"]))
    }
    retained = []
    for document in documents:
        records = [
            record
            for record in document["vulnerabilities"]
            if normalize_cve(record["id"]) not in exact_cves
            or record["assessment"]["kind"] == "exact"
        ]
        if records or not document["vulnerabilities"]:
            retained.append({**document, "vulnerabilities": records})
    documents = retained
    local = source.evidence
    cves = (
        set(local)
        | set(missing_documents)
        | {
            cve
            for document in documents
            for record in document["vulnerabilities"]
            if (cve := normalize_cve(record["id"]))
        }
    )
    result: dict[str, Any] = {
        "audit": str(source.path),
        "audit_sha256": json_digest(report.to_dict()),
        "image": source.image.to_dict(),
        "match_inputs": source.inputs,
        "documents": documents,
        "missing_documents": missing_documents,
        "local_findings": local_artifacts(local, cves),
        "summary": summary,
    }
    conclusions = {}
    for identifier, observations in vulnerability_groups(result):
        artifacts = result["local_findings"].get(identifier, [])
        for artifact in artifacts:
            artifact["reachability"] = artifact_reachability(artifact, observations)
        conclusions[identifier] = summarize_cve(
            identifier,
            observations,
            artifacts,
            missing_documents.get(identifier),
            summary["scan_coverage"],
        )
    result["conclusions"] = conclusions
    summary["metrics"] = comparison.summarize(
        value for cve, value in conclusions.items() if normalize_cve(cve)
    )
    return result


def artifact_reachability(
    artifact: dict[str, Any], observations: list[DocumentObservation]
) -> str:
    """Assess execution in the final image without equating presence with reachability."""
    runtime = artifact["runtime_disposition"]
    if runtime in {"deleted", "replaced"}:
        return "NO"
    if runtime != "runtime":
        return "UNDETERMINED"
    observations = preferred_observations(observations)
    if not observations:
        return "UNDETERMINED"
    for _, document, record in observations:
        assessment = record["assessment"]
        if assessment["kind"] != "exact":
            return "UNDETERMINED"
        image_ids = {
            entry["product_id"]
            for candidate in document["candidates"]
            if candidate["image"]
            for entry in candidate["entries"]
            if entry["match_kind"] == "exact"
        }
        references = assessment["references"]
        if not references or any(
            reference["product_id"] not in image_ids for reference in references
        ):
            return "UNDETERMINED"
        for reference in references:
            statements = reference["statements"]
            statuses = comparison.status_categories(
                value.removeprefix("status:")
                for value in statements
                if value.startswith("status:")
            )
            if (
                statuses != {"known_not_affected"}
                or "flag:vulnerable_code_not_in_execute_path" not in statements
            ):
                return "UNDETERMINED"
    return "NO"


def append_module_findings(lines: TextLayout, artifacts: list[dict[str, Any]]) -> None:
    detailed = lines.policy.shows(Verbosity.DETAILED)
    columns = [("MODULE", "module", "not recorded")]
    if detailed:
        columns.append(("PACKAGE", "package", "not recorded"))
    columns.extend(
        [
            ("FOUND VERSION", "found_version", "unknown"),
            ("FIXED MODULE VERSION", "fixed_version", "not reported"),
        ]
    )
    grouped: dict[tuple[str, ...], set[str]] = {}
    for artifact in artifacts:
        for finding in artifact["findings"]:
            package = finding["package"]
            if finding["module"] and package:
                package = (
                    "."
                    if package == finding["module"]
                    else package.removeprefix(finding["module"] + "/")
                )
            row = tuple(
                (package if key == "package" else finding[key]) or empty
                for _, key, empty in columns
            )
            grouped.setdefault(row, set()).add(CGO_LABELS[artifact["cgo_enabled"]])
    if not grouped:
        return
    heading = "MODULE / PACKAGE FINDINGS" if detailed else "MODULES"
    headers = tuple(title for title, _, _ in columns) + (
        ("BINARY CGO",) if detailed else ()
    )
    rows = [
        row + ((tuple(sorted(settings)),) if detailed else ())
        for row, settings in sorted(grouped.items())
    ]
    with lines.subsection(heading) as modules:
        with modules.preview("module findings", rows) as visible:
            modules.columns([headers, *visible])


def artifact_locations(artifact: dict[str, Any]) -> list[str]:
    locations: set[str] = set()
    for observation in artifact["observations"]:
        observed = (
            [rootfs_location(path) for path in observation["paths"]]
            if observation["runtime_disposition"] == "runtime"
            else {
                f"layer-{event['layer_index']:03d}/{rootfs_location(path)}"
                for event in observation["layer_history"]
                if event["status"] == "found"
                for path in event["paths"]
            }
        )
        locations.update(
            observed or [f"scope unknown: {path}" for path in observation["paths"]]
        )
    return sorted(locations)


def append_local_artifacts(lines: TextLayout, artifacts: list[dict[str, Any]]) -> None:
    names = Counter(PurePosixPath(item["paths"][0]).name for item in artifacts)
    with lines.subsection("[LOCAL FINDINGS]") as lines:
        if not artifacts:
            lines.append("No local finding recorded in this audit.")
            return
        if not lines.policy.shows(Verbosity.FORENSIC):
            columns = (
                ("BINARY", Verbosity.SUMMARY),
                ("RUNTIME", Verbosity.SUMMARY),
                ("EVIDENCE", Verbosity.SUMMARY),
                ("REACHABILITY", Verbosity.EXPANDED),
                ("LOCATION", Verbosity.EXPANDED),
                ("CGO", Verbosity.DETAILED),
            )
            selected = [
                index
                for index, column in enumerate(columns)
                if lines.policy.shows(column[1])
            ]
            rows = []
            for artifact in artifacts:
                name = PurePosixPath(artifact["paths"][0]).name
                row = (
                    name
                    + (
                        f" ({lines.policy.hash(artifact['sha256'])})"
                        if names[name] > 1
                        else ""
                    ),
                    runtime_availability_label(artifact["runtime_disposition"]),
                    tuple(artifact_evidence([artifact])),
                    artifact["reachability"],
                    tuple(artifact_locations(artifact)),
                    CGO_LABELS[artifact["cgo_enabled"]],
                )
                rows.append(tuple(row[index] for index in selected))
            with lines.preview("binaries", sorted(rows)) as visible:
                lines.columns(
                    [tuple(columns[index][0] for index in selected), *visible]
                )
            if lines.policy.shows(Verbosity.EXPANDED):
                append_module_findings(lines, artifacts)
            return
        with lines.preview("artifacts", artifacts) as visible:
            for artifact in visible:
                name = PurePosixPath(artifact["paths"][0]).name
                with lines.subsection(f"BINARY: {name}") as binary:
                    binary.fields(
                        (
                            "Runtime disposition",
                            runtime_disposition_label(artifact["runtime_disposition"]),
                        ),
                        ("CGO", CGO_LABELS[artifact["cgo_enabled"]]),
                        ("Reachability", artifact["reachability"]),
                        ("SHA-256", binary.policy.hash(artifact["sha256"])),
                        ("Layer observations", len(artifact["layer_history"])),
                    )
                    binary.list_field("Symlinks", artifact["symlinks"], empty="none")
                    binary.list_field("Location", artifact_locations(artifact))
                    binary.list_field("Evidence", artifact_evidence([artifact]))
                    binary.list_field("Advisories", artifact["advisories"])
                    append_module_findings(binary, [artifact])
                    symbols = sorted(
                        {
                            f"{item['package']}.{item['symbol']}"
                            if item["package"]
                            else item["symbol"]
                            for item in artifact["findings"]
                            if item["symbol"]
                        }
                    )
                    if symbols:
                        with binary.subsection("SYMBOLS") as symbol_lines:
                            symbol_lines.preview_bullets("symbols", symbols)
                    if artifact["layer_history"]:
                        append_layer_observations(
                            binary,
                            [
                                models.BinaryLayerObservation(**event)
                                for event in artifact["layer_history"]
                            ],
                            multiline=True,
                        )


def entry_cpe_labels(entries: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            f"{cpe['product_cpe']} ({cpe['relation']})"
            for entry in entries
            for cpe in entry["cpes"]
        }
    )


def candidate_short_names(candidates: list[dict[str, Any]]) -> list[str]:
    packages = [parse_oci_purl(item["purl"]) or {} for item in candidates]
    names = [
        package.get("name") or item["product_id"]
        for package, item in zip(packages, candidates)
    ]
    repeated = Counter(names)
    for index, package in enumerate(packages):
        if repeated[names[index]] < 2:
            continue
        version = package.get("version") or package.get("tag", "")
        if version.startswith("sha256:") and len(version) > 19:
            version = version[:19] + "…"
        qualifiers = [version] if version else []
        if qualifiers:
            names[index] += " (" + ", ".join(qualifiers) + ")"
    for field in ("context", "product_id"):
        repeated = Counter(names)
        names = [
            f"{name} — {candidate[field]}" if repeated[name] > 1 else name
            for name, candidate in zip(names, candidates)
        ]
    return names


RELEASE_GROUPS = (
    "Selected product",
    "Same release",
    "Broader product family",
    "Other releases or products",
)


def candidate_release_group(candidate: dict[str, Any]) -> str:
    groups = {
        entry.get("release_group", "Selected product") for entry in candidate["entries"]
    }
    return next(group for group in RELEASE_GROUPS if group in groups)


def cpe_mismatches(evidence: dict[str, Any]) -> list[str]:
    local, remote = (
        csaf.parse_cpe(evidence["image_cpe"]),
        csaf.parse_cpe(evidence["product_cpe"]),
    )
    if not local or not remote:
        return []
    attributes = (
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "software edition",
        "target software",
        "target hardware",
        "other",
    )
    differences = []
    for attribute, observed, candidate in zip(attributes, local, remote):
        if observed == candidate or candidate == "*":
            continue
        if observed == "*":
            differences.append(
                f"CPE {attribute} is not supplied locally; CSAF requires {candidate}"
            )
        elif evidence["relation"] not in {"exact", "compatible", "normalized_version"}:
            qualification = (
                " (broader release scope)"
                if attribute == "version" and evidence["relation"] == "version_family"
                else ""
            )
            differences.append(
                f"CPE {attribute} differs: local {observed}; CSAF {candidate}{qualification}"
            )
    return differences


def candidate_mismatches(
    candidate: dict[str, Any], inputs: dict[str, Any]
) -> list[dict[str, str]]:
    """Record identity differences once; verbosity only controls their visibility."""
    checks = candidate["checks"]
    differences = []
    if checks["component"]["result"] == "mismatch":
        differences.append(
            (
                "component",
                f"Component name differs: local {inputs['name']}; CSAF {candidate['package']['name']}",
            )
        )
    if checks["digest"]["result"] == "mismatch":
        differences.append(("digest", "Build digest differs from the image"))
    level = strongest_match([entry["match_kind"] for entry in candidate["entries"]])
    differences.extend(
        ("cpe", difference)
        for entry in candidate["entries"]
        if entry["match_kind"] == level
        for evidence in entry["cpes"]
        for difference in cpe_mismatches(evidence)
    )
    if checks["architecture"]["result"] == "mismatch":
        differences.append(
            (
                "architecture",
                (
                    f"Architecture differs: image {inputs['architecture']}; candidate {candidate['package']['architecture']}; treated as equivalent"
                ),
            )
        )
    return [{"field": field, "text": text} for field, text in sorted(set(differences))]


def mismatch_descriptions(
    values: list[dict[str, str]], policy: RenderPolicy
) -> list[str]:
    return sorted(
        {
            value["text"]
            for value in values
            if value["field"] != "architecture" or policy.shows(Verbosity.DETAILED)
        }
    )


def append_csaf_evidence(
    lines: TextLayout,
    observations: list[DocumentObservation],
    candidates: list[dict[str, Any]],
    inputs: dict[str, Any],
) -> None:
    """List identified products by lookup context, retaining CVE-specific evidence."""
    if not observations:
        return
    documents = {number: document for number, document, _ in observations}
    groups: dict[str, list[dict[str, Any]]] = {}
    for assessment in candidates:
        candidate = documents[assessment["document"]]["candidates"][
            assessment["candidate"] - 1
        ]
        context = (
            inputs["contexts"][0]["name"]
            if inputs["product_ids"]
            else candidate["context"]
        )
        groups.setdefault(context, []).append(assessment)
    with lines.subsection("[IDENTIFIED PRODUCTS]") as products:
        if not groups:
            append_candidate_context(products, observations, [])
            return
        for context, assessments in groups.items():
            with products.subsection(context or "unknown") as section:
                if not lines.policy.shows(Verbosity.EXPANDED):
                    section.preview_bullets(
                        "products",
                        sorted(
                            {
                                documents[item["document"]]["candidates"][
                                    item["candidate"] - 1
                                ]["product_id"]
                                for item in assessments
                            }
                        ),
                    )
                    continue
                selected = {(item["document"], item["record"]) for item in assessments}
                append_candidate_context(
                    section,
                    [
                        observation
                        for observation in observations
                        if not selected
                        or (observation[0], observation[2]["record"]) in selected
                    ],
                    assessments,
                )


def append_candidate_context(
    lines: TextLayout,
    observations: list[DocumentObservation],
    candidates: list[dict[str, Any]],
) -> None:
    """Show each candidate's own matching evidence and comparison conclusion."""
    detailed = lines.policy.shows(Verbosity.DETAILED)
    for number, document, record in lines.limited("CSAF records", observations):
        if len(observations) > 1:
            lines.section(f"Document {number}, record {record['record']}", rule_width=0)
        if document["missing_product_ids"]:
            lines.list_field("Product IDs not found", document["missing_product_ids"])
        references = {
            item["product_id"]: item["statements"] for item in record["references"]
        }
        assessments = sorted(
            (
                item
                for item in candidates
                if item["document"] == number and item["record"] == record["record"]
            ),
            key=lambda item: (
                RELEASE_GROUPS.index(
                    candidate_release_group(
                        document["candidates"][item["candidate"] - 1]
                    )
                ),
                MATCH_STRENGTH.index(item["match"]),
                item["candidate"],
            ),
        )
        if not assessments:
            lines.append("No candidate product identified.")
        names = dict(
            zip(
                (item["candidate"] for item in assessments),
                candidate_short_names(
                    [
                        document["candidates"][item["candidate"] - 1]
                        for item in assessments
                    ]
                ),
            )
        )
        for assessment in lines.limited("candidates", assessments):
            index = assessment["candidate"] - 1
            candidate = document["candidates"][index]
            agreement = assessment["agreement"]
            with lines.subsection(names[assessment["candidate"]]) as item:
                item.fields(
                    (
                        "PURL",
                        (candidate["purl"] or "not provided") if detailed else None,
                    ),
                    ("CSAF product ID", candidate["product_id"]),
                    ("CSAF ID Match", MATCH_LABELS[assessment["match"]]),
                )
                item.list_field(
                    "Mismatches",
                    mismatch_descriptions(assessment["mismatches"], item.policy),
                    empty="none established",
                )
                item.field("Vendor assessment", assessment["vendor_assessment"])
                item.field(
                    "Agreement",
                    comparison.AGREEMENT_LABELS[agreement["comparison"]],
                )
                if not detailed:
                    if assessment["product_ids"] and assessment["product_ids"] != [
                        candidate["product_id"]
                    ]:
                        item.list_field(
                            "Matched product IDs", assessment["product_ids"]
                        )
                    continue
                item.list_field("Agreement explanation", agreement["reasons"])
                for version in assessment["version_assessments"]:
                    item.fields(
                        ("Version policy", version["policy"]),
                        ("Version subject", version["subject"]),
                        (
                            "Observed version",
                            f"{version['observed']['value']} → {version['normalized_observed']}",
                        ),
                        (
                            "Vendor boundary",
                            f"{version['boundary']['value']} → {version['normalized_boundary']}",
                        ),
                        ("Version assessment", version["reason"]),
                    )

                if candidate["package"]["namespace"]:
                    item.field(
                        "PURL form",
                        "Publisher-supplied OCI namespace retained",
                    )
                if candidate["checks"]:
                    item.list_field(
                        "Checks",
                        [
                            f"{key}: {value['result']}"
                            for key, value in candidate["checks"].items()
                            if key != "architecture"
                        ],
                    )
                for product_id, related in group_items(
                    candidate["entries"], lambda entry: entry["product_id"]
                ):
                    with item.subsection(f"PRODUCT: {product_id}") as product:
                        kinds = {entry["match_kind"] for entry in related}
                        match = strongest_match(list(kinds))
                        product.field("CSAF ID Match", MATCH_LABELS[match])
                        cpes = entry_cpe_labels(related)
                        if cpes:
                            product.list_field("Product CPE", cpes)
                        relationships = sorted(
                            {
                                category
                                for entry in related
                                for category in entry["relationship_categories"]
                            }
                        )
                        if relationships:
                            product.list_field("Relationship", relationships)
                        product.list_field(
                            "Vendor statement",
                            references.get(product_id, []),
                            empty="not stated",
                        )


def append_match_inputs(lines: TextLayout, inputs: dict[str, Any]) -> None:
    with lines.subsection("[LOCAL LOOKUP CANDIDATES]") as lines:
        if lines.policy.shows(Verbosity.EXPANDED):
            lines.fields(
                ("Image digest", lines.policy.hash(inputs["digest"]) or "unknown"),
                ("Architecture", inputs["architecture"] or "unknown"),
            )
        if inputs["product_ids"]:
            lines.field("Match method", "explicit CSAF product_id selection")
            lines.bullets(inputs["product_ids"])
        else:
            for heading, field, column in (
                ("CPEs", "cpes", "CPE"),
                ("PURLs", "purls", "PURL"),
            ):
                rows: list[tuple[str, str, str]] = []
                for context in inputs["contexts"]:
                    identifiers = [(value, "Provided") for value in context[field]]
                    if field == "purls":
                        identifiers.extend(
                            (
                                item["value"],
                                "From image name"
                                if context["image"]
                                else "From product name",
                            )
                            for item in context["derived_purls"]
                        )
                    rows.extend(
                        (context["name"] or "unknown", value, origin)
                        for value, origin in identifiers
                    )
                with lines.subsection(heading) as table:
                    if rows:
                        table.columns([("PRODUCT", column, "ORIGIN"), *rows])
                    else:
                        table.append("None provided.")


MATCH_LABELS = {
    "no_document": "Document not provided",
    "no_match": "No match found",
    "ambiguous": "Ambiguous",
    "fuzzy": "Fuzzy",
    "exact": "Exact",
}

LOCAL_SCAN_LABELS = {
    "affected": "Affected",
    "not_affected": "Not Affected",
    "undetermined": "Undetermined",
}


def append_check(lines: TextLayout, result: dict[str, Any]) -> None:
    """Compose the shared image body at the layout's selected verbosity."""
    policy = lines.policy
    image = result["image"]
    lines.section(
        f"SUBJECT: {image.get('name') or image.get('vendor_image_name') or 'unknown'}",
        rule_width=0,
    )
    append_match_inputs(lines, result["match_inputs"])
    for identifier, observations in lines.limited(
        "CVE groups", vulnerability_groups(result)
    ):
        urls = (
            sorted(
                {
                    url
                    for _, document, _ in observations
                    for url in document["canonical_urls"]
                }
            )
            if normalize_cve(identifier)
            else []
        )
        lines.banner(
            "\n".join(f"{identifier}: {url}" for url in urls) if urls else identifier
        )
        conclusion = result["conclusions"][identifier]
        artifacts = result["local_findings"].get(identifier, [])
        local = conclusion["local_scan"]
        local_label = LOCAL_SCAN_LABELS[local["status"]]
        match = MATCH_LABELS[conclusion["match"]]
        detailed = policy.shows(Verbosity.DETAILED)
        if "explicit CSAF product_id selection" in conclusion["qualifications"]:
            match += " (user-selected product ID)"
        lines.field("Local scan", local_label)
        if local["historical_only"]:
            lines.field("Runtime available", "No")
        if conclusion["match"] == "no_document":
            lines.append(
                "CSAF file not provided. Check whether one is available from your CSAF provider."
            )
        lines.fields(
            ("CSAF ID Match", match),
            ("Vendor assessment", conclusion["vendor_assessment"]),
            (
                "Agreement",
                comparison.AGREEMENT_LABELS[conclusion["agreement"]["comparison"]],
            ),
        )
        if detailed:
            lines.list_field(
                "Mismatches",
                mismatch_descriptions(conclusion["mismatches"], policy),
                empty="none established",
            )
            lines.list_field(
                "Agreement explanation", conclusion["agreement"]["reasons"]
            )
            lines.field("Local scan explanation", local["reason"], wrap=True)
        if normalize_cve(identifier):
            append_local_artifacts(lines, artifacts)
        append_csaf_evidence(
            lines,
            observations,
            conclusion["candidates"],
            result["match_inputs"],
        )


def append_provenance(lines: TextLayout, result: dict[str, Any]) -> None:
    image = result["image"]
    lines.fields(
        ("Audit", result["audit"]),
        ("Audit SHA256", lines.policy.hash(result["audit_sha256"])),
    )
    if result.get("identity_override"):
        lines.field("Identity override", result["identity_override"])
    for product in [image, *image["products"]]:
        if product["sources"]:
            lines.field("Product", product["name"] or product["component"])
            lines.bullets(product["sources"])
    for number, document in enumerate(result["documents"], 1):
        lines.field(f"Document {number}", document["source"])
        if document["canonical_urls"]:
            lines.list_field("Canonical URLs", document["canonical_urls"])
    for cve, records in sorted(result["missing_documents"].items()):
        for record in records:
            lines.field(f"Missing {cve}", record["source"])
            for key in ("url", "status", "checked_at", "reason"):
                if key in record:
                    lines.field("  " + key.replace("_", " ").capitalize(), record[key])


def render_text(result: dict[str, Any], policy: RenderPolicy = SUMMARY_POLICY) -> str:
    lines = TextLayout.titled("CSAF IMAGE CHECK", policy=policy)
    append_check(lines, result)
    if policy.shows(Verbosity.FORENSIC):
        with lines.subsection("[PROVENANCE]") as provenance:
            append_provenance(provenance, result)
    append_detail_footer(lines)
    return lines.render() + "\n"
