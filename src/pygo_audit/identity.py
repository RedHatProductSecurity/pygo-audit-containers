"""Explicit image identity metadata for extracted root filesystems."""

from __future__ import annotations

import json
from pathlib import Path
import re

from pygo_audit.models import ImageIdentity
from pygo_audit.storage import atomic_read_json


DEFAULT_METADATA_NAME = ".pygo-audit-image.json"
_DIGEST = re.compile(r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,}$")

SIDECAR_FIELDS = {
    "image-ref": "reference",
    "image-digest": "digest",
    "platform": "platform",
    "extractor": "extractor",
    "image-name": "name",
    "image-component": "component",
    "source-git-url": "source_git_url",
    "product-version": "product_version",
    "component-version": "component_version",
    "product-component": "product_component",
    "cpe": "cpe",
}


class ImageIdentityError(ValueError):
    """Raised when explicitly supplied image identity metadata is invalid."""


def resolve_image_identity(
    root: Path,
    *,
    metadata_path: Path | None = None,
    reference: str | None = None,
    digest: str | None = None,
    platform: str | None = None,
    extractor: str | None = None,
    name: str | None = None,
    component: str | None = None,
    source_git_url: str | None = None,
    product_version: str | None = None,
    component_version: str | None = None,
    product_component: str | None = None,
    cpe: str | None = None,
) -> ImageIdentity:
    """Load optional sidecar metadata and apply explicit CLI overrides."""
    path = metadata_path
    if path is None:
        default_path = Path(root).parent / DEFAULT_METADATA_NAME
        if default_path.exists():
            path = default_path

    values: dict[str, str] = {}
    if path is not None:
        values.update(_read_metadata(Path(path)))

    overrides = {
        "reference": reference,
        "digest": digest,
        "platform": platform,
        "extractor": extractor,
        "name": name,
        "component": component,
        "source_git_url": source_git_url,
        "product_version": product_version,
        "component_version": component_version,
        "product_component": product_component,
        "cpe": cpe,
    }
    values.update({key: value for key, value in overrides.items() if value is not None})
    identity = ImageIdentity(**values)
    _validate_identity(identity)
    return identity


def _read_metadata(path: Path) -> dict[str, str]:
    try:
        value = atomic_read_json(path)
    except FileNotFoundError as error:
        raise ImageIdentityError(f"image metadata does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise ImageIdentityError(
            f"image metadata is not valid JSON at line {error.lineno}, "
            f"column {error.colno}: {path}"
        ) from error
    except OSError as error:
        raise ImageIdentityError(
            f"cannot read image metadata {path}: {error.strerror or error}"
        ) from error
    if not isinstance(value, dict):
        raise ImageIdentityError(f"image metadata must be a JSON object: {path}")

    unknown_keys = sorted(set(value) - set(SIDECAR_FIELDS))
    if unknown_keys:
        formatted = ", ".join(repr(key) for key in unknown_keys)
        raise ImageIdentityError(
            "image metadata contains unknown fields; use scan option names: "
            f"{formatted}"
        )

    result: dict[str, str] = {}
    for sidecar_key, item in value.items():
        identity_key = SIDECAR_FIELDS[sidecar_key]
        if not isinstance(item, str):
            raise ImageIdentityError(
                f"image metadata field {sidecar_key!r} must be a string"
            )
        result[identity_key] = item
    return result


def _validate_identity(identity: ImageIdentity) -> None:
    if identity.digest and _DIGEST.fullmatch(identity.digest) is None:
        raise ImageIdentityError("image digest must use the OCI algorithm:hex form")
    if identity.platform and (
        "/" not in identity.platform
        or any(character.isspace() for character in identity.platform)
    ):
        raise ImageIdentityError("image platform must use the OS/architecture form")
