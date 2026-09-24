from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.identity import ImageIdentityError, resolve_image_identity


class ImageIdentityTests(unittest.TestCase):
    def test_loads_default_sidecar_and_applies_explicit_overrides(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".pygo-audit-image.json").write_text(
                json.dumps(
                    {
                        "reference": "registry.example.test/team/app:v1",
                        "digest": "sha256:" + "a" * 64,
                        "platform": "linux/amd64",
                        "extractor": "oc image extract",
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
        self.assertEqual(identity.platform, "linux/arm64")
        self.assertEqual(identity.extractor, "oc image extract")

    def test_returns_empty_identity_without_sidecar_or_flags(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            identity = resolve_image_identity(Path(temporary_directory))

        self.assertFalse(identity.is_present)

    def test_rejects_invalid_digest_and_platform(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with self.assertRaisesRegex(ImageIdentityError, "algorithm:hex"):
                resolve_image_identity(root, digest="not-a-digest")
            with self.assertRaisesRegex(ImageIdentityError, "OS/architecture"):
                resolve_image_identity(root, platform="amd64")


if __name__ == "__main__":
    unittest.main()
