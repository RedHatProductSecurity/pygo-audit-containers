"""Read CSAF documents and index product identity and relationship evidence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from functools import lru_cache
import json
from operator import attrgetter
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from pygo_audit import comparison, csaf_redhat
from pygo_audit.storage import atomic_read_json

ARCHITECTURE_ALIASES = {
    "x86_64": "amd64",
    "aarch64": "arm64",
}
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.IGNORECASE)


class CsafCheckError(ValueError):
    """Raised when an audit document or CSAF response is unusable."""


@dataclass(frozen=True)
class ProductInfo:
    """Indexed CSAF product metadata used during identity matching."""

    name: str = ""  # Display name from the CSAF product tree.
    cpe: str = ""  # CPE explicitly attached to this product, if any.
    purl: str = ""  # Package identity, when supplied by the publisher.
    versions: tuple[comparison.VersionEvidence, ...] = ()
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
class CsafDocumentIndex:
    """One document's identity evidence, shared across container comparisons."""

    title: str  # Advisory title from document metadata.
    canonical_urls: tuple[str, ...]  # HTTPS self references to this CSAF document.
    products: dict[str, ProductInfo]  # Product metadata indexed by CSAF product ID.
    publisher_namespace: str
    document: dict[str, Any]  # External JSON retained at the CSAF parsing boundary.


def cpe_fields(value: str) -> list[str] | None:
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


def decode_cpe_character(match: re.Match[str]) -> str:
    char = chr(int(match[0][1:], 16))
    if char == "\x01":
        return "?"
    if char == "\x02":
        return "*"
    return char if char.isalnum() or char in "._" else "\\" + char


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

            decoded.append(
                re.sub(r"%[0-9a-fA-F]{2}", decode_cpe_character, field_value) or "*"
            )
        fields = decoded
    elif value.startswith("cpe:2.3:"):
        parsed_fields = cpe_fields(value[8:])
        if (
            parsed_fields is None
            or len(parsed_fields) != 11
            or any(not f for f in parsed_fields)
        ):
            return None
        fields = parsed_fields
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


def cpe_pattern(value: str) -> tuple[str, bool]:
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
    """Compare attributes, keeping vendor version heuristics distinguishable.

    A literal version '4' is not a CPE wildcard. We separately record a
    version_family candidate for OpenShift 4 -> 4.20. Normalized numeric equality
    and same-release relationships are also heuristic, never exact CPE matches.
    """
    image = parse_cpe(image_cpe)
    product = parse_cpe(product_cpe)
    if image is None or product is None:
        return None
    # Require concrete, equal platform identity; broad vendor/product wildcards
    # must not associate unrelated products with the scanned image.
    for local, remote in zip(image[:3], product[:3]):
        local_pattern, local_wildcard = cpe_pattern(local)
        remote_pattern, remote_wildcard = cpe_pattern(remote)
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
        local_pattern, local_wildcard = cpe_pattern(local)
        remote_pattern, remote_wildcard = cpe_pattern(remote)
        local_literal = re.sub(r"\\(.)", r"\1", local)
        if not local_wildcard and re.fullmatch(remote_pattern, local_literal):
            continue
        if (
            not local_wildcard
            and not remote_wildcard
            and local_pattern == remote_pattern
        ):
            continue
        if position == 3 and (
            version_relation := csaf_redhat.version_relation(image, product)
        ):
            relation = version_relation
            continue
        return None
    return relation


def walk_dicts(value: object) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def parent_relationships(
    document: dict[str, Any], products: dict[str, ProductInfo]
) -> Iterable[tuple[str, str, str, str]]:
    """Yield valid combined/component/parent/category links, excluding peers."""
    tree = document.get("product_tree", {})
    relations = tree.get("relationships", []) if isinstance(tree, dict) else []
    for relation in relations if isinstance(relations, list) else []:
        if not isinstance(relation, dict):
            continue
        category = raw if isinstance(raw := relation.get("category"), str) else ""
        full = relation.get("full_product_name")
        if category not in {
            "default_component_of",
            "optional_component_of",
            "external_component_of",
            "installed_on",
        } or not isinstance(full, dict):
            continue
        combined = raw if isinstance(raw := full.get("product_id"), str) else ""
        component = (
            raw if isinstance(raw := relation.get("product_reference"), str) else ""
        )
        parent = (
            raw
            if isinstance(raw := relation.get("relates_to_product_reference"), str)
            else ""
        )
        if all(value in products for value in (combined, component, parent)):
            yield combined, component, parent, category


def cpe_sources(
    product_id: str,
    products: dict[str, ProductInfo],
    parents: dict[str, set[tuple[str, str]]],
) -> tuple[CpeSource, ...]:
    pending: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
        (product_id, (product_id,), ())
    ]
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
            # An explicit CPE constrains this product; keep conflicting scope.
            continue
        for parent, category in sorted(parents.get(current, ()), reverse=True):
            pending.append((parent, (*path, parent), (*categories, category)))
    return tuple(sorted(found, key=attrgetter("product_id", "path")))


def product_index(document: dict[str, Any]) -> dict[str, ProductInfo]:
    """Index CPEs and directed parent links for combination-product IDs.

    Do not attach a platform to a standalone component globally: a component
    can participate in combinations with several unrelated platforms.
    """
    products: dict[str, ProductInfo] = {}
    for value in walk_dicts(document.get("product_tree", {})):
        product_id = raw if isinstance(raw := value.get("product_id"), str) else ""
        name = raw if isinstance(raw := value.get("name"), str) else ""
        helper = value.get("product_identification_helper", {})
        cpe = (
            (raw if isinstance(raw := helper.get("cpe"), str) else "")
            if isinstance(helper, dict)
            else ""
        )
        purl = (
            (raw if isinstance(raw := helper.get("purl"), str) else "")
            if isinstance(helper, dict)
            else ""
        )
        full_product_name = value.get("full_product_name")
        if isinstance(full_product_name, dict):
            product_id = (
                raw
                if isinstance(raw := full_product_name.get("product_id"), str)
                else ""
            ) or product_id
            name = (
                raw if isinstance(raw := full_product_name.get("name"), str) else ""
            ) or name
        if product_id:
            existing = products.get(product_id, ProductInfo())
            products[product_id] = ProductInfo(
                name=name or existing.name,
                cpe=cpe or existing.cpe,
                purl=purl or existing.purl,
            )
    parents: dict[str, set[tuple[str, str]]] = {}
    for combined, component, parent, category in parent_relationships(
        document, products
    ):
        parents.setdefault(combined, set()).add((parent, category))

    pending_versions: list[tuple[object, str]] = [
        (document.get("product_tree", {}), "")
    ]
    while pending_versions:
        node, version = pending_versions.pop()
        if isinstance(node, list):
            pending_versions.extend((child, version) for child in node)
        elif isinstance(node, dict):
            if node.get("category") == "product_version":
                version = raw if isinstance(raw := node.get("name"), str) else ""
            pid = raw if isinstance(raw := node.get("product_id"), str) else ""
            if version and pid in products:
                product = products[pid]
                products[pid] = replace(
                    product,
                    versions=(
                        comparison.VersionEvidence(
                            version,
                            "component" if product.purl else "product",
                            f"product_version:{pid}",
                        ),
                    ),
                )
            pending_versions.extend((child, version) for child in node.values())

    return {
        pid: replace(product, cpe_sources=cpe_sources(pid, products, parents))
        for pid, product in products.items()
    }


def canonical_urls(references: object, tracking_id: str) -> tuple[str, ...]:
    """Collect declared canonical URLs using CSAF sections 5.1 and 6.2.11."""
    if not tracking_id or not isinstance(references, list):
        return ()
    filename = re.sub(r"[^a-z0-9+-]+", "_", tracking_id.lower()) + ".json"
    urls = set()
    for reference in references:
        if not isinstance(reference, dict) or reference.get("category") != "self":
            continue
        url = raw if isinstance(raw := reference.get("url"), str) else ""
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if (
            url.startswith("https://")
            and url.endswith("/" + filename)
            and parts.netloc
            and parts.path.rsplit("/", 1)[-1] == filename
            and not parts.query
            and not parts.fragment
        ):
            urls.add(url)
    return tuple(sorted(urls))


def index_document(document: dict[str, Any]) -> CsafDocumentIndex:
    """Index identity once; vulnerability statements remain scoped to their records."""
    metadata = document.get("document", {})
    tracking = metadata.get("tracking", {}) if isinstance(metadata, dict) else {}
    if not isinstance(tracking, dict):
        tracking = {}
    publisher = metadata.get("publisher", {}) if isinstance(metadata, dict) else {}
    return CsafDocumentIndex(
        title=(raw if isinstance(raw := metadata.get("title"), str) else "")
        if isinstance(metadata, dict)
        else "",
        canonical_urls=canonical_urls(
            metadata.get("references") if isinstance(metadata, dict) else None,
            (raw if isinstance(raw := tracking.get("id"), str) else ""),
        ),
        products=product_index(document),
        publisher_namespace=(
            raw if isinstance(raw := publisher.get("namespace"), str) else ""
        )
        if isinstance(publisher, dict)
        else "",
        document=document,
    )


def product_statuses(records: Iterable[dict[str, Any]]) -> dict[str, tuple[str, ...]]:
    """Collect conclusions by product within the caller's selected record scope."""
    references = defaultdict(set)
    for record in records:
        statuses = record.get("product_status", {})
        groups = (
            [(f"status:{status}", ids) for status, ids in statuses.items()]
            if isinstance(statuses, dict)
            else []
        )
        for section, kind, label in (
            ("flags", "flag", "label"),
            ("remediations", "remediation", "category"),
        ):
            groups.extend(
                (
                    f"{kind}:{(raw if isinstance(raw := entry.get(label), str) else '')}",
                    entry.get("product_ids", []),
                )
                for entry in record.get(section, [])
                if isinstance(entry, dict)
            )
        for kind, product_ids in groups:
            if isinstance(product_ids, list):
                for product_id in product_ids:
                    if isinstance(product_id, str):
                        references[product_id].add(kind)
    return {
        product_id: tuple(sorted(statuses))
        for product_id, statuses in sorted(references.items())
    }


def attach_oci_platforms(
    candidates: list[dict[str, Any]],
    document: dict[str, Any],
    index: CsafDocumentIndex,
    image_cpe: str,
) -> None:
    """Attach only platform relationships explicitly linked to each OCI product."""
    edges: dict[str, list[tuple[str, str, str]]] = {}
    for combined, component, parent, category in parent_relationships(
        document, index.products
    ):
        edges.setdefault(component, []).append((combined, parent, category))

    valid_image_cpe = parse_cpe(image_cpe) is not None
    for candidate in candidates:
        root = candidate["product_id"]
        pending: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
            (root, (root,), ())
        ]
        related = []
        while pending:
            current, path, categories = pending.pop()
            for combined, parent, category in sorted(edges.get(current, [])):
                if combined in path:
                    continue
                next_path = (*path, combined)
                next_categories = (*categories, category)
                source_product = index.products[parent]
                combined_product = index.products[combined]
                cpes = []
                sources = (
                    combined_product.cpe_sources
                    if combined_product.cpe
                    else source_product.cpe_sources
                )
                for source in sources:
                    can_compare = valid_image_cpe and parse_cpe(source.cpe) is not None
                    relation = (
                        cpe_relation(image_cpe, source.cpe) if can_compare else None
                    )
                    cpes.append(
                        {
                            "product_cpe": source.cpe,
                            "source_product_id": source.product_id,
                            "relation": relation
                            or ("no_match" if can_compare else "unknown"),
                        }
                    )
                related.append(
                    {
                        "product_id": combined,
                        "platform_product_id": parent,
                        "relationship_categories": list(next_categories),
                        "relationship_path": list(next_path),
                        "cpes": cpes,
                    }
                )
                pending.append((combined, next_path, next_categories))
        candidate["related_platforms"] = related


def identity_field(
    matched: bool, differs: bool, candidate: str | None = None, expected: str = ""
) -> dict[str, str]:
    """Keep match, mismatch, and unavailable evidence distinct for every hint."""
    result = {"result": "match" if matched else "mismatch" if differs else "unknown"}
    if candidate is not None:
        result.update(candidate=candidate, expected=expected)
    return result


def load_document(path: Path) -> dict[str, Any]:
    """Read a local CSAF document without contacting its publisher."""
    try:
        document = atomic_read_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CsafCheckError(f"cannot read CSAF document {path}: {error}") from error
    if not isinstance(document, dict):
        raise CsafCheckError(f"CSAF document must be an object: {path}")
    if not isinstance(document.get("vulnerabilities", []), list):
        raise CsafCheckError(f"CSAF vulnerabilities must be an array: {path}")
    if "product_tree" in document and not isinstance(document["product_tree"], dict):
        raise CsafCheckError(f"CSAF product tree must be an object: {path}")
    return document


def relative_document_names(
    locations: dict[str, Path], inputs: Iterable[Path]
) -> dict[str, str]:
    """Include the collection directory in a concise document path."""
    roots = [path.resolve() for path in inputs if path.is_dir()]
    names = {}
    for cve, path in locations.items():
        parents = [root for root in roots if path.is_relative_to(root)]
        root = (
            max(parents, key=lambda item: len(item.parts)) if parents else path.parent
        )
        names[cve] = (str(Path(root.name) / path.relative_to(root)), root)
    collisions: dict[str, set[Path]] = {}
    for name, root in names.values():
        collisions.setdefault(name, set()).add(root)
    return {
        cve: f"{name} — {root}" if len(collisions[name]) > 1 else name
        for cve, (name, root) in names.items()
    }
