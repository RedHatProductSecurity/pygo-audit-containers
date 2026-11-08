"""Read and write explicit image identity supplied by users or helper scripts."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re

from pygo_audit.audit import parse_model, parse_value, unique_object, validate_fields
from pygo_audit.models import ImageIdentity, JsonModel, ProductIdentity
from pygo_audit.storage import atomic_read_text, atomic_write_json


DEFAULT_METADATA_NAME = ".pygo-audit-image.json"
_DIGEST = re.compile(r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,}$")
IDENTITY_OPTIONS = {
    "image-ref": "reference",
    "image-digest": "digest",
    "platform": "platform",
    "extractor": "extractor",
    "image-name": "name",
    "vendor-image-name": "vendor_image_name",
    "image-build-release": "image_build_release",
    "image-component": "component",
    "source-git-url": "source_git_url",
    "product-version": "product_version",
    "component-version": "component_version",
    "product-component": "product_component",
    "cpe": "cpes",
    "purl": "purls",
    "csaf-product-id": "csaf_product_ids",
}
LIST_OVERRIDES = {"cpes", "purls", "csaf_product_ids"}


class ImageIdentityError(ValueError):
    """Raised when supplied image identity metadata is invalid."""


def resolve_image_identity(
    root: Path, *, metadata_path: Path | None = None, **overrides: str | None
) -> ImageIdentity:
    unknown = overrides.keys() - IDENTITY_OPTIONS.values()
    if unknown:
        raise TypeError(
            f"unknown image identity overrides: {', '.join(sorted(unknown))}"
        )
    path = metadata_path or Path(root).parent / DEFAULT_METADATA_NAME
    identity = (
        read_identity(path) if metadata_path or path.exists() else ImageIdentity()
    )
    values = {
        key: ((value,) if value else ()) if key in LIST_OVERRIDES else value
        for key, value in overrides.items()
        if value is not None
    }
    identity = replace(identity, **values)
    if identity.digest and _DIGEST.fullmatch(identity.digest) is None:
        raise ImageIdentityError("image digest must use the OCI algorithm:hex form")
    if identity.platform and (
        "/" not in identity.platform
        or any(character.isspace() for character in identity.platform)
    ):
        raise ImageIdentityError("image platform must use the OS/architecture form")
    return identity


def metadata_model[T: JsonModel](value: object, model: type[T], path: str) -> T:
    defaults = model().to_dict()
    values = validate_fields(value, path, set(), set(defaults))
    return parse_model({**defaults, **values}, model, path)


def read_identity(path: Path) -> ImageIdentity:
    try:
        value = json.loads(atomic_read_text(path), object_pairs_hook=unique_object)
        value = validate_fields(value, "identity", set(), {"image", "products", "csaf"})
        image_fields = set(ImageIdentity().to_dict()) - {"products", "csaf_product_ids"}
        image = validate_fields(value.get("image", {}), "image", set(), image_fields)
        products = value.get("products", [])
        if not isinstance(products, list):
            raise ValueError("products must be a list")
        products = [
            metadata_model(item, ProductIdentity, f"products[{i}]").to_dict()
            for i, item in enumerate(products)
        ]
        csaf = validate_fields(value.get("csaf", {}), "csaf", set(), {"product_ids"})
        pins = parse_value(csaf.get("product_ids", []), list[str], "csaf.product_ids")
        identity = metadata_model(
            {**image, "products": products, "csaf_product_ids": pins},
            ImageIdentity,
            "image",
        )
        for item in (identity, *identity.products):
            for field in ("cpes", "purls"):
                if any(not value.strip() for value in getattr(item, field)):
                    raise ValueError(f"{field} entries must not be empty")
        if any(not pin.strip() for pin in pins):
            raise ValueError("csaf.product_ids entries must not be empty")
        return identity
    except FileNotFoundError as error:
        raise ImageIdentityError(f"image metadata does not exist: {path}") from error
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise ImageIdentityError(f"invalid image metadata {path}: {error}") from error


def write_identity(path: Path, identity: ImageIdentity) -> None:
    values = identity.to_dict()
    products, pins = values.pop("products"), values.pop("csaf_product_ids")
    document = {
        "image": {
            key: value
            for key, value in values.items()
            if value or key in {"cpes", "purls"}
        },
        "products": [
            {
                key: value
                for key, value in item.items()
                if value or key in {"cpes", "purls"}
            }
            for item in products
        ],
        "csaf": {"product_ids": pins},
    }
    atomic_write_json(path, document, overwrite=True)
