"""Explicit image identity metadata for extracted root filesystems."""

from __future__ import annotations

import json
from pathlib import Path
import re

from pygo_audit.models import ImageIdentity


DEFAULT_METADATA_NAME = ".pygo-audit-image.json"
_DIGEST = re.compile(r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,}$")


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
) -> ImageIdentity:
    """Load optional sidecar metadata and apply explicit CLI overrides."""
    path = metadata_path
    if path is None:
        default_path = Path(root) / DEFAULT_METADATA_NAME
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
    }
    values.update(
        {key: value for key, value in overrides.items() if value is not None}
    )
    identity = ImageIdentity(
        reference=values.get("reference", ""),
        digest=values.get("digest", ""),
        platform=values.get("platform", ""),
        extractor=values.get("extractor", ""),
    )
    _validate_identity(identity)
    return identity


def _read_metadata(path: Path) -> dict[str, str]:
    try:
        with path.open(encoding="utf-8") as metadata_file:
            value = json.load(metadata_file)
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

    result = {}
    for key in ("reference", "digest", "platform", "extractor"):
        item = value.get(key, "")
        if not isinstance(item, str):
            raise ImageIdentityError(f"image metadata field {key!r} must be a string")
        result[key] = item
    return result


def _validate_identity(identity: ImageIdentity) -> None:
    if identity.digest and _DIGEST.fullmatch(identity.digest) is None:
        raise ImageIdentityError(
            "image digest must use the OCI algorithm:hex form"
        )
    if identity.platform and (
        "/" not in identity.platform
        or any(character.isspace() for character in identity.platform)
    ):
        raise ImageIdentityError(
            "image platform must use the OS/architecture form"
        )
