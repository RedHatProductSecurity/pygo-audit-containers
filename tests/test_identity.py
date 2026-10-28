from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.identity import ImageIdentityError, resolve_image_identity


class ImageIdentityTests(unittest.TestCase):
    def test_image_contents_cannot_supply_default_audit_metadata(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            audit_root = Path(temporary_directory)
            root = audit_root / "rootfs"
            root.mkdir()
            subject_sidecar = root / ".pygo-audit-image.json"
            subject_sidecar.write_text('{"image-name": "image-owned"}', encoding="utf-8")
            self.assertFalse(resolve_image_identity(root).is_present)

            (audit_root / ".pygo-audit-image.json").write_text(
                '{"image-name": "trusted-workspace"}', encoding="utf-8"
            )
            self.assertEqual(resolve_image_identity(root).name, "trusted-workspace")
            self.assertEqual(resolve_image_identity(root, metadata_path=subject_sidecar).name, "image-owned")

    def test_loads_default_sidecar_and_applies_explicit_overrides(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            (root.parent / ".pygo-audit-image.json").write_text(
                json.dumps(
                    {
                        "image-ref": "registry.example.test/team/app:v1",
                        "image-digest": "sha256:" + "a" * 64,
                        "platform": "linux/amd64",
                        "extractor": "oc image extract",
                        "image-name": "openshift/example",
                        "image-component": "example-container",
                        "source-git-url": "https://github.com/example/project",
                        "product-version": "v4.20.0",
                        "component-version": "v1.2.3-4-gabcdef0",
                        "product-component": "Example",
                        "cpe": "cpe:/a:redhat:openshift:4.20::el9",
                    }
                ),
                encoding="utf-8",
            )

            identity = resolve_image_identity(
                root,
                platform="linux/arm64",
            )

        self.assertEqual(identity.reference, "registry.example.test/team/app:v1")
        self.assertEqual(identity.digest, "sha256:" + "a" * 64)
        self.assertEqual(identity.digest_short, "aaaaaaaaaaaa")
        self.assertEqual(identity.platform, "linux/arm64")
        self.assertEqual(identity.extractor, "oc image extract")
        self.assertEqual(identity.name, "openshift/example")
        self.assertEqual(identity.component, "example-container")
        self.assertEqual(
            identity.source_git_url,
            "https://github.com/example/project",
        )
        self.assertEqual(identity.product_version, "v4.20.0")
        self.assertEqual(identity.component_version, "v1.2.3-4-gabcdef0")
        self.assertEqual(identity.product_component, "Example")
        self.assertEqual(identity.cpe, "cpe:/a:redhat:openshift:4.20::el9")

    def test_returns_empty_identity_without_sidecar_or_flags(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            identity = resolve_image_identity(Path(temporary_directory))

        self.assertFalse(identity.is_present)

    def test_rejects_invalid_digest_and_platform(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            with self.assertRaisesRegex(ImageIdentityError, "algorithm:hex"):
                resolve_image_identity(root, digest="not-a-digest")
            with self.assertRaisesRegex(ImageIdentityError, "OS/architecture"):
                resolve_image_identity(root, platform="amd64")

    def test_rejects_nested_or_unknown_sidecar_fields(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            (root.parent / ".pygo-audit-image.json").write_text(
                json.dumps({"image": {"image-ref": "example/image"}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ImageIdentityError, "unknown fields"):
                resolve_image_identity(root)


if __name__ == "__main__":
    unittest.main()
