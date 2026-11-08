from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from container_metadata import (  # noqa: E402
    collect_product_identities,
    read_os_release,
)

from pygo_audit.models import ImageIdentity  # noqa: E402


class ContainerMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.rootfs = Path(self.temporary.name) / "rootfs"
        (self.rootfs / "usr" / "lib").mkdir(parents=True)
        (self.rootfs / "usr" / "lib" / "os-release").write_text(
            'NAME="Red Hat Enterprise Linux CoreOS"\n'
            'VERSION_ID="9.6"\n'
            'OPENSHIFT_VERSION="4.20"\n'
            'CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"\n',
            encoding="utf-8",
        )

    def test_os_release_ignores_external_links_and_uses_safe_fallback(self):
        outside = self.rootfs.parent / "host-release"
        outside.write_text('VERSION_ID="0.0"\n', encoding="utf-8")
        path = self.rootfs / "usr/lib/os-release"
        path.unlink()
        path.symlink_to(outside)
        (self.rootfs / "etc").mkdir()
        (self.rootfs / "etc/os-release").write_text('VERSION_ID="9.7"\n')

        self.assertEqual(read_os_release(self.rootfs), {"VERSION_ID": "9.7"})

    def test_os_release_rejects_external_parent_links(self):
        library = self.rootfs / "usr/lib"
        library.rename(self.rootfs / "usr/saved-lib")
        outside = self.rootfs.parent / "outside"
        outside.mkdir()
        (outside / "os-release").write_text('VERSION_ID="0.0"\n')
        library.symlink_to(outside, target_is_directory=True)

        self.assertEqual(read_os_release(self.rootfs), {})

    def test_os_release_allows_contained_relative_links(self):
        path = self.rootfs / "usr/lib/os-release"
        path.rename(path.with_name("release-data"))
        path.symlink_to("release-data")

        self.assertEqual(read_os_release(self.rootfs), {
            "VERSION_ID": "9.6",
            "OPENSHIFT_VERSION": "4.20",
            "CPE_NAME": "cpe:/o:redhat:enterprise_linux:9::baseos",
        })

    def test_metadata_open_rejects_parent_symlink_swapped_after_resolution(self):
        outside = self.rootfs.parent / "outside"
        outside.mkdir()
        (outside / "os-release").write_text('VERSION_ID="0.0"\n')
        library = self.rootfs / "usr/lib"
        original_open = os.open
        swapped = False

        def swap_parent(path, flags, *arguments, **keywords):
            nonlocal swapped
            if path == "lib" and not swapped:
                swapped = True
                library.rename(self.rootfs / "usr/saved-lib")
                library.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, *arguments, **keywords)

        with patch("container_metadata.os.open", side_effect=swap_parent):
            self.assertEqual(read_os_release(self.rootfs), {})
        self.assertTrue(swapped)

    def test_os_release_ignores_fifo_and_oversized_files(self):
        path = self.rootfs / "usr/lib/os-release"
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(read_os_release(self.rootfs), {})
        path.unlink()
        path.write_text("VERSION_ID=" + "x" * (64 * 1024), encoding="utf-8")
        self.assertEqual(read_os_release(self.rootfs), {})

    def test_collects_contexts_and_deduplicates_label_copies(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs = root / "rootfs"
            layers = [root / "layers" / f"layer-{i:03}" for i in range(2)]
            for subject, name, cpe in (
                (rootfs, "final", "cpe:/a:example:final:1"),
                (layers[0], "base", "cpe:/a:example:base:2"),
                (layers[1], "final", "cpe:/a:example:final:1"),
            ):
                for relative in ("root/buildinfo/labels.json", "usr/share/buildinfo/labels.json"):
                    path = subject / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps({"name": name, "cpe": cpe, "version": "1.0"}))
            supplied = ImageIdentity(vendor_image_name="final", product_version="1.0", cpes=("cpe:/a:example:final:1",))
            identity = collect_product_identities(supplied, rootfs, layers)
            self.assertEqual(len(identity.products), 1)
            base = identity.products[0]
            self.assertEqual(len(identity.sources), 4)
            self.assertEqual(len(base.sources), 2)
            self.assertEqual(base.cpes, ("cpe:/a:example:base:2",))
            self.assertEqual(collect_product_identities(identity, rootfs, layers), identity)
            # A container-owned link must not import host identity information.
            escaped = root / "outside.json"
            escaped.write_text('{"name": "host", "cpe": "cpe:/a:example:host:1"}')
            for path in rootfs.rglob("labels.json"):
                path.unlink()
                path.symlink_to(escaped)
            self.assertEqual(collect_product_identities(ImageIdentity(), rootfs, []).products, ())


if __name__ == "__main__":
    unittest.main()
