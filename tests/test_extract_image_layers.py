from __future__ import annotations

import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import tarfile
import textwrap
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract-image-layers"
SYSTEM_PATH = ":".join(
    path for path in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
)


class ExtractImageLayersTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "layers with spaces"
        self.image_digest = "sha256:" + "a" * 64
        self.image = "registry.example.test/team/app@" + self.image_digest
        self.log = self.root / "tool-calls.jsonl"
        self.blobs = self.root / "blobs"
        self.blobs.mkdir()
        self.info = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:" + character * 64,
                    "size": 100,
                }
                for character in "bcd"
            ],
        }
        self.manifest_path = self.root / "manifest.json"
        self.manifest_path.write_text(json.dumps(self.info), encoding="utf-8")
        self.image_info = {
            "name": "registry.example.test/team/app:latest",
            "digest": self.image_digest,
            "config": {
                "config": {
                    "Env": [
                        "BUILD_VERSION=v4.20.0",
                        "SOURCE_GIT_TAG=v1.2.3-4-gabcdef0",
                        "SOURCE_GIT_URL=https://github.com/example/project",
                    ],
                    "Labels": {
                        "name": "openshift/example",
                        "com.redhat.component": "example-container",
                        "cpe": "cpe:/a:redhat:openshift:4.20::el9",
                        "io.openshift.maintainer.component": "Example",
                    },
                }
            },
        }
        self.image_info_path = self.root / "image-info.json"
        self.image_info_path.write_text(json.dumps(self.image_info), encoding="utf-8")
        for index, layer in enumerate(self.info["layers"]):
            self._write_layer(layer["digest"], index)

        self._write_command(
            "skopeo",
            """\
            import json
            import os
            from pathlib import Path
            import shutil
            import sys

            args = sys.argv[1:]
            with open(os.environ["EXTRACT_TEST_LOG"], "a") as log:
                log.write(json.dumps(["skopeo", *args]) + "\\n")
            if "copy" not in args:
                sys.exit(2)
            destination = Path(next(value[4:] for value in args if value.startswith("dir:")))
            destination.mkdir(parents=True, exist_ok=True)
            source_manifest = Path(os.environ["EXTRACT_TEST_MANIFEST"])
            shutil.copyfile(source_manifest, destination / "manifest.json")
            for layer in json.loads(source_manifest.read_text())["layers"]:
                digest = layer["digest"].split(":", 1)[1]
                shutil.copyfile(
                    Path(os.environ["EXTRACT_TEST_BLOBS"]) / digest,
                    destination / digest,
                )
            """,
        )
        self._write_command(
            "oc",
            """\
            import json
            import os
            from pathlib import Path
            import sys

            args = sys.argv[1:]
            with open(os.environ["EXTRACT_TEST_LOG"], "a") as log:
                log.write(json.dumps(["oc", *args]) + "\\n")
            if args[:2] == ["image", "info"]:
                print(Path(os.environ["EXTRACT_TEST_IMAGE_INFO"]).read_text())
            elif args[:2] != ["image", "extract"]:
                sys.exit(2)
            else:
                rootfs = Path(next(value[9:] for value in args if value.startswith("--path=/:")))
                (rootfs / "usr" / "bin").mkdir(parents=True, exist_ok=True)
                (rootfs / "usr" / "bin" / "app").write_text("merged rootfs")
                (rootfs / "usr" / "lib").mkdir(parents=True, exist_ok=True)
                (rootfs / "usr" / "lib" / "os-release").write_text(
                    'NAME="Red Hat Enterprise Linux CoreOS"\\n'
                    'VERSION_ID="9.6"\\n'
                    'OPENSHIFT_VERSION="4.20"\\n'
                    'CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"\\n'
                )
                if target := os.environ.get("EXTRACT_TEST_METADATA_TARGET"):
                    for name in (".pygo-audit-image.json", ".pygo-audit-container.json"):
                        (rootfs / name).symlink_to(target)
                if os.environ.get("EXTRACT_TEST_RESTRICTIVE_PERMISSIONS"):
                    (rootfs / "usr/bin/app").chmod(0o6777)
                    locked = rootfs / "locked"
                    locked.mkdir()
                    (locked / "data").write_text("readable after restriction")
                    (locked / "data").chmod(0)
                    locked.chmod(0)
            """,
        )
        self._write_command(
            "tar",
            """\
            import os
            import sys

            if os.environ.get("EXTRACT_TEST_FAIL_LAYER") == "1" and any(
                "layer-001" in argument for argument in sys.argv
            ):
                print("simulated layer extraction failure", file=sys.stderr)
                sys.exit(7)
            os.execv("/usr/bin/tar", ["tar", *sys.argv[1:]])
            """,
        )
        self.environment = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + SYSTEM_PATH,
            EXTRACT_TEST_LOG=str(self.log),
            EXTRACT_TEST_MANIFEST=str(self.manifest_path),
            EXTRACT_TEST_BLOBS=str(self.blobs),
            EXTRACT_TEST_IMAGE_INFO=str(self.image_info_path),
        )

    def _write_layer(self, digest: str, index: int) -> None:
        with tarfile.open(self.blobs / digest.split(":", 1)[1], "w") as archive:
            payload = f"layer {index}".encode()
            member = tarfile.TarInfo("etc/layer.txt")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    def _write_command(self, name: str, body: str) -> None:
        command = self.root / name
        command.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
        command.chmod(0o755)

    def run_command(self):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                self.image,
                str(self.destination),
            ],
            env=self.environment,
            capture_output=True,
            text=True,
        )

    def test_preserves_each_layer_and_extracts_merged_rootfs(self):
        result = self.run_command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Extracted all 3 layers", result.stdout)
        self.assertFalse((self.destination / "manifest.json").exists())
        self.assertFalse((self.destination / ".pygo-audit-layers.json").exists())
        for index in range(3):
            layer_file = self.destination / "layers" / f"layer-{index:03d}" / "etc" / "layer.txt"
            self.assertEqual(layer_file.read_text(), f"layer {index}")
        self.assertEqual(
            (self.destination / "rootfs" / "usr" / "bin" / "app").read_text(),
            "merged rootfs",
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(
            [call[0:2] for call in calls],
            [["oc", "image"], ["skopeo", "--override-os"], ["oc", "image"]],
        )
        self.assertIn("--override-os", calls[1])
        self.assertIn("--override-arch", calls[1])
        transport_cache = Path(next(value[4:] for value in calls[1] if value.startswith("dir:")))
        self.assertEqual(transport_cache.parent, self.destination)
        self.assertFalse(transport_cache.exists())
        self.assertIn("--filter-by-os=linux/amd64", calls[2])
        self.assertIn("--only-files", calls[2])
        self.assertIn("--filter-by-os", calls[0])
        sidecar = json.loads(
            (self.destination / ".pygo-audit-image.json").read_text()
        )
        self.assertEqual(sidecar["image-ref"], self.image)
        self.assertEqual(sidecar["image-name"], self.destination.name)
        self.assertEqual(sidecar["image-digest"], self.image_digest)
        self.assertEqual(sidecar["extractor"], "extract-image-layers")
        self.assertEqual(
            sidecar["source-git-url"],
            "https://github.com/example/project",
        )
        self.assertEqual(sidecar["component-version"], "v1.2.3-4-gabcdef0")
        self.assertEqual(sidecar["product-version"], "v4.20.0")
        self.assertEqual(sidecar["product-component"], "Example")
        container_facts = json.loads(
            (self.destination / ".pygo-audit-container.json").read_text()
        )
        self.assertEqual(container_facts["os-release"]["OPENSHIFT_VERSION"], "4.20")
        self.assertEqual(container_facts["rpmdb"]["package-count"], 0)

    def test_generated_metadata_never_overwrites_image_owned_paths(self):
        sentinel = self.root / "keep.json"
        sentinel.write_text('{"keep": true}', encoding="utf-8")
        self.environment["EXTRACT_TEST_METADATA_TARGET"] = str(sentinel)

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_text(), '{"keep": true}')
        for name in (".pygo-audit-image.json", ".pygo-audit-container.json"):
            self.assertTrue((self.destination / "rootfs" / name).is_symlink())
            self.assertTrue((self.destination / name).is_file())
            self.assertFalse((self.destination / name).is_symlink())

    def test_completed_subjects_are_owner_read_only_without_following_links(self):
        sentinel = self.root / "keep.json"
        sentinel.write_text("unchanged", encoding="utf-8")
        sentinel.chmod(0o640)
        self.environment["EXTRACT_TEST_METADATA_TARGET"] = str(sentinel)
        self.environment["EXTRACT_TEST_RESTRICTIVE_PERMISSIONS"] = "1"
        digest = self.info["layers"][0]["digest"].split(":", 1)[1]
        with tarfile.open(self.blobs / digest, "w") as archive:
            payload = b"unprivileged subject data"
            member = tarfile.TarInfo("privileged")
            member.mode = 0o6777
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
            link = tarfile.TarInfo("outside-link")
            link.type = tarfile.SYMTYPE
            link.linkname = str(sentinel)
            archive.addfile(link)
            directory_link = tarfile.TarInfo("outside-directory")
            directory_link.type = tarfile.SYMTYPE
            directory_link.linkname = str(self.root)
            archive.addfile(directory_link)

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        for subject in (self.destination / "rootfs", self.destination / "layers"):
            for current, directories, files in os.walk(subject, followlinks=False):
                self.assertEqual(stat.S_IMODE(Path(current).stat().st_mode), 0o500)
                for name in files:
                    path = Path(current) / name
                    if not path.is_symlink():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual((self.destination / "rootfs/locked/data").read_text(),
                         "readable after restriction")
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for name in (".pygo-audit-image.json", ".pygo-audit-container.json"):
            self.assertEqual(stat.S_IMODE((self.destination / name).stat().st_mode), 0o600)

    def test_tag_is_resolved_once_and_recorded_with_its_digest(self):
        self.image = "registry.example.test:5000/team/app:stable"

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        resolved = "registry.example.test:5000/team/app@" + self.image_digest
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(calls[0][-1], self.image)
        self.assertIn("docker://" + resolved, calls[1])
        self.assertEqual(calls[2][3], resolved)
        self.assertEqual(sum(call[:3] == ["oc", "image", "info"] for call in calls), 1)
        sidecar = json.loads((self.destination / ".pygo-audit-image.json").read_text())
        self.assertEqual(sidecar["image-ref"], self.image)
        self.assertEqual(sidecar["image-digest"], self.image_digest)

    def test_tag_with_no_resolved_digest_is_not_extracted(self):
        self.image = "registry.example.test/team/app:stable"
        self.image_info.pop("digest")
        self.image_info_path.write_text(json.dumps(self.image_info), encoding="utf-8")

        result = self.run_command()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot resolve an image digest", result.stderr)
        self.assertFalse(self.destination.exists())
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 1)

    def test_enriches_coreos_identity_from_labels_and_os_release(self):
        config = self.image_info["config"]["config"]
        config["Env"] = [
            value
            for value in config["Env"]
            if not value.startswith(("BUILD_VERSION=", "SOURCE_GIT_TAG="))
        ]
        config["Labels"] = {
            "name": "registry.example.test/team/app:latest",
            "io.openshift.build.version-display-names": (
                "machine-os=Red Hat Enterprise Linux CoreOS"
            ),
            "io.openshift.build.versions": "machine-os=9.6.20260504-0",
            "org.opencontainers.image.version": "9.6.20260504-0",
        }
        self.image_info_path.write_text(json.dumps(self.image_info), encoding="utf-8")

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        sidecar = json.loads(
            (self.destination / ".pygo-audit-image.json").read_text()
        )
        self.assertEqual(sidecar["image-component"], "Red Hat Enterprise Linux CoreOS")
        self.assertEqual(sidecar["component-version"], "9.6.20260504-0")
        self.assertEqual(sidecar["product-version"], "4.20")
        self.assertEqual(
            sidecar["cpe"],
            "cpe:/o:redhat:enterprise_linux:9::baseos",
        )

    def test_existing_destination_is_untouched_without_contacting_tools(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep.txt"
        sentinel.write_text("existing work")
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination already exists", result.stderr)
        self.assertEqual(sentinel.read_text(), "existing work")
        self.assertFalse(self.log.exists())

    def test_unsupported_host_has_a_clear_error_before_registry_access(self):
        script = runpy.run_path(str(SCRIPT))
        with patch("sys.platform", "darwin"):
            with self.assertRaisesRegex(script["ExtractionError"], "Linux with /proc"):
                script["required_commands"]()

    def test_missing_image_transport_has_helpful_error(self):
        missing_transport_path = self.root / "path-without-tools"
        missing_transport_path.mkdir()
        self.environment["PATH"] = str(missing_transport_path)
        result = self.run_command()
        self.assertEqual(result.returncode, 1)
        self.assertIn("required command not found: skopeo", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_layer_failure_retains_partial_output(self):
        self.environment["EXTRACT_TEST_FAIL_LAYER"] = "1"
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tar extraction for layer", result.stderr)
        self.assertTrue((self.destination / "layers" / "layer-000" / "etc" / "layer.txt").is_file())
        self.assertTrue((self.destination / "layers" / "layer-001").is_dir())
        self.assertFalse((self.destination / "layers" / "layer-002").exists())
        self.assertFalse((self.destination / "manifest.json").exists())

    def test_rejects_layer_path_traversal_before_extracting(self):
        digest = self.info["layers"][0]["digest"].split(":", 1)[1]
        with tarfile.open(self.blobs / digest, "w") as archive:
            payload = b"must not escape"
            member = tarfile.TarInfo("../escaped")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

        result = self.run_command()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe member path", result.stderr)
        self.assertFalse((self.root / "escaped").exists())
        self.assertFalse((self.destination / "layers" / "layer-000").exists())


if __name__ == "__main__":
    unittest.main()
