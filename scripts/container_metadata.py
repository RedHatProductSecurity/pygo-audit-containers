"""Image identity fallbacks and product labels from extracted filesystems."""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
from typing import BinaryIO, Iterator

from pygo_audit.models import ImageIdentity, ProductIdentity


_OS_RELEASE_LIMIT = 64 * 1024


@contextmanager
def _open_subject_file(rootfs: Path, path: Path) -> Iterator[BinaryIO]:
    """Allow contained links, then pin every component without following links."""
    root = rootfs.resolve(strict=True)
    try:
        relative = path.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise OSError(f"metadata path escapes the extracted root: {path}") from error
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(root, directory_flags)
        stack.callback(os.close, directory)
        for part in relative.parts[:-1]:
            directory = os.open(part, directory_flags, dir_fd=directory)
            stack.callback(os.close, directory)
        descriptor = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        stream = stack.enter_context(os.fdopen(descriptor, "rb"))
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError(f"metadata is not a regular file: {path}")
        yield stream


def read_os_release(rootfs: Path) -> dict[str, str]:
    """Read only the OS-release fields used as image identity fallbacks."""
    for path in (rootfs / "usr/lib/os-release", rootfs / "etc/os-release"):
        try:
            with _open_subject_file(rootfs, path) as stream:
                raw = stream.read(_OS_RELEASE_LIMIT + 1)
            if len(raw) > _OS_RELEASE_LIMIT:
                continue
            content = raw.decode("utf-8")
        except OSError, UnicodeDecodeError:
            continue
        values: dict[str, str] = {}
        for line in content.splitlines():
            key, separator, raw_value = line.partition("=")
            if not separator or key not in {"VERSION_ID", "OPENSHIFT_VERSION", "CPE_NAME"}:
                continue
            values[key] = _unquote(raw_value)
        return values
    return {}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def collect_product_identities(
    identity: ImageIdentity, rootfs: Path, layers: list[Path]
) -> ImageIdentity:
    """Keep product coordinates together and merge duplicate label-file origins."""
    products = list(identity.products)
    for subject in (rootfs, *layers):
        for relative in (
            "root/buildinfo/labels.json",
            "usr/share/buildinfo/labels.json",
        ):
            try:
                with _open_subject_file(subject, subject / relative) as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    continue
                labels = json.loads(raw)
            except OSError, ValueError:
                continue
            if not isinstance(labels, dict):
                continue
            labels = {
                key: value for key, value in labels.items() if isinstance(value, str)
            }
            if not labels.get("cpe"):
                continue
            source = str(subject / relative)
            if (subject / relative).is_relative_to(rootfs.parent):
                source = str((subject / relative).relative_to(rootfs.parent))
            products.append(
                ProductIdentity(
                    name=labels.get("name", ""),
                    component=labels.get("com.redhat.component", ""),
                    version=labels.get("version", ""),
                    release=labels.get("release", ""),
                    cpes=(labels["cpe"],),
                    sources=(source,),
                )
            )
    final_product = ProductIdentity(
        name=identity.vendor_image_name,
        component=identity.component,
        version=identity.product_version,
        release=identity.image_build_release,
        cpes=identity.cpes,
        purls=identity.purls,
    )
    image_sources = list(identity.sources)
    grouped: dict[ProductIdentity, tuple[str, ...]] = {}
    for product in products:
        key = replace(product, sources=())
        if key == final_product:
            image_sources.extend(product.sources)
            continue
        grouped[key] = tuple(dict.fromkeys((*grouped.get(key, ()), *product.sources)))
    return replace(
        identity,
        sources=tuple(dict.fromkeys(image_sources)),
        products=tuple(
            replace(item, sources=sources) for item, sources in grouped.items()
        ),
    )
