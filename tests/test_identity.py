from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.identity import (
    ImageIdentityError, resolve_image_identity, read_identity, write_identity,
)


class ImageIdentityTests(unittest.TestCase):
    def test_image_contents_cannot_supply_default_audit_metadata(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            audit_root = Path(temporary_directory)
            root = audit_root / "rootfs"
            root.mkdir()
            subject_sidecar = root / ".pygo-audit-image.json"
            subject_sidecar.write_text('{"image": {"name": "image-owned"}}', encoding="utf-8")
            self.assertFalse(resolve_image_identity(root).is_present)

            (audit_root / ".pygo-audit-image.json").write_text(
                '{"image": {"name": "trusted-workspace"}}', encoding="utf-8"
            )
            self.assertEqual(resolve_image_identity(root).name, "trusted-workspace")
            self.assertEqual(resolve_image_identity(root, metadata_path=subject_sidecar).name, "image-owned")

    def test_loads_default_sidecar_and_applies_explicit_overrides(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            (root.parent / ".pygo-audit-image.json").write_text(
                json.dumps(
                    {"image": {
                        "reference": "registry.example.test/team/app:v1",
                        "digest": "sha256:" + "a" * 64,
                        "platform": "linux/amd64",
                        "extractor": "oc image extract",
                        "name": "openshift/example",
                        "vendor_image_name": "openshift/vendor-example",
                        "image_build_release": "build-42",
                        "component": "example-container",
                        "source_git_url": "https://github.com/example/project",
                        "product_version": "v4.20.0",
                        "component_version": "v1.2.3-4-gabcdef0",
                        "product_component": "Example",
                        "cpes": ["cpe:/a:redhat:openshift:4.20::el9"],
                    }}
                ),
                encoding="utf-8",
            )

            identity = resolve_image_identity(
                root,
                platform="linux/arm64",
                image_build_release="build-43",
            )

        self.assertEqual(identity.reference, "registry.example.test/team/app:v1")
        self.assertEqual(identity.digest, "sha256:" + "a" * 64)
        self.assertEqual(identity.digest_short, "aaaaaaaaaaaa")
        self.assertEqual(identity.platform, "linux/arm64")
        self.assertEqual(identity.extractor, "oc image extract")
        self.assertEqual(identity.name, "openshift/example")
        self.assertEqual(identity.vendor_image_name, "openshift/vendor-example")
        self.assertEqual(identity.image_build_release, "build-43")
        self.assertEqual(identity.component, "example-container")
        self.assertEqual(
            identity.source_git_url,
            "https://github.com/example/project",
        )
        self.assertEqual(identity.product_version, "v4.20.0")
        self.assertEqual(identity.component_version, "v1.2.3-4-gabcdef0")
        self.assertEqual(identity.product_component, "Example")
        self.assertEqual(identity.cpes, ("cpe:/a:redhat:openshift:4.20::el9",))

    def test_returns_empty_identity_without_sidecar_or_flags(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            identity = resolve_image_identity(Path(temporary_directory))

        self.assertFalse(identity.is_present)

    def test_omitted_overrides_preserve_metadata_and_empty_strings_clear_it(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "rootfs"
            (root.parent / ".pygo-audit-image.json").write_text(
                '{"image": {"name": "saved"}}'
            )
            self.assertEqual(resolve_image_identity(root, name=None).name, "saved")
            self.assertEqual(resolve_image_identity(root, name="").name, "")
            for value in (None, ""):
                with (
                    self.subTest(value=value),
                    self.assertRaisesRegex(TypeError, "image_name"),
                ):
                    resolve_image_identity(root, image_name=value)

    def test_rejects_invalid_digest_and_platform(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            with self.assertRaisesRegex(ImageIdentityError, "algorithm:hex"):
                resolve_image_identity(root, digest="not-a-digest")
            with self.assertRaisesRegex(ImageIdentityError, "OS/architecture"):
                resolve_image_identity(root, platform="amd64")

    def test_rejects_unknown_sidecar_fields(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "rootfs"
            root.mkdir()
            (root.parent / ".pygo-audit-image.json").write_text(
                json.dumps({"image": {"typo": "example/image"}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ImageIdentityError, "unknown"):
                resolve_image_identity(root)

    def test_json_lists_round_trip_and_list_overrides(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".pygo-audit-image.json"
            path.write_text(json.dumps({
                "image": {"name": "demo", "cpes": ["cpe:/a:example:one:1", "cpe:/a:example:two:2"],
                          "purls": ["pkg:oci/demo"], "sources": ["registry metadata"]},
                "products": [{"name": "base", "version": "9.6", "cpes": ["cpe:/a:example:base:9.6"],
                              "sources": ["layers/layer-000/root/buildinfo/labels.json"]}],
                "csaf": {"product_ids": ["known-product", "another-product"]},
            }))
            identity = read_identity(path)
            self.assertEqual(len(identity.cpes), 2)
            self.assertEqual(identity.products[0].version, "9.6")
            self.assertEqual(identity.csaf_product_ids, ("known-product", "another-product"))
            write_identity(path, identity)
            self.assertEqual(read_identity(path), identity)
            self.assertIn('\n  "image": {\n', path.read_text())
            changed = resolve_image_identity(root / "rootfs", cpes="cpe:/a:example:override:1", csaf_product_ids="")
            self.assertEqual(changed.cpes, ("cpe:/a:example:override:1",))
            self.assertEqual(changed.csaf_product_ids, ())
            self.assertEqual(changed.products, identity.products)

    def test_rejects_duplicate_keys_and_wrong_types(self):
        for content in (
            '{"image": {"name": "one", "name": "two"}}',
            '{"image": {"cpes": "scalar"}}',
            '{"products": [{"version": 9.6}]}',
            '{"products": [{"cpes": [null]}]}',
            '{"csaf": {"product_ids": [""]}}',
            '{"csaf": {"product_ids": [123]}}',
            '{"image": {"sources": "scalar"}}',
            '{',
        ):
            with self.subTest(content=content), TemporaryDirectory() as temporary:
                path = Path(temporary) / "identity.json"
                path.write_text(content)
                with self.assertRaises(ImageIdentityError):
                    read_identity(path)


if __name__ == "__main__":
    unittest.main()
