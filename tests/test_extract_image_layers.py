from __future__ import annotations

import io
import json
import os
from pathlib import Path
import runpy
import shutil
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
                        "release": "202604241817.p2.el9",
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
            if "--quiet" not in args:
                print("Copying blob fake", file=sys.stderr)
            if os.environ.get("EXTRACT_TEST_FAIL_COPY"):
                print("registry copy failed", file=sys.stderr)
                sys.exit(3)
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
                    (rootfs / ".pygo-audit-image.json").symlink_to(target)
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
            import subprocess
            import sys

            if os.environ.get("EXTRACT_TEST_FAIL_LAYER") == "1" and any(
                "layer-001" in argument for argument in sys.argv
            ):
                subprocess.run(["/usr/bin/tar", *sys.argv[1:]], check=False)
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
        self.assertIn("--quiet", calls[1])
        transport_cache = Path(next(value[4:] for value in calls[1] if value.startswith("dir:")))
        self.assertEqual(transport_cache.parent, self.destination)
        self.assertFalse(transport_cache.exists())
        self.assertIn("--filter-by-os=linux/amd64", calls[2])
        self.assertIn("--only-files", calls[2])
        self.assertIn("--filter-by-os", calls[0])
        self.assertNotIn("Copying blob fake", result.stdout + result.stderr)
        sidecar = json.loads(
            (self.destination / ".pygo-audit-image.json").read_text()
        )["image"]
        self.assertEqual(sidecar["reference"], self.image)
        self.assertEqual(sidecar["name"], self.destination.name)
        self.assertEqual(sidecar["vendor_image_name"], "openshift/example")
        self.assertEqual(sidecar["image_build_release"], "202604241817.p2.el9")
        self.assertEqual(sidecar["digest"], self.image_digest)
        self.assertEqual(sidecar["extractor"], "extract-image-layers")
        self.assertEqual(
            sidecar["source_git_url"],
            "https://github.com/example/project",
        )
        self.assertEqual(sidecar["component_version"], "v1.2.3-4-gabcdef0")
        self.assertEqual(sidecar["product_version"], "v4.20.0")
        self.assertEqual(sidecar["product_component"], "Example")

    def test_generated_metadata_never_overwrites_image_owned_paths(self):
        sentinel = self.root / "keep.json"
        sentinel.write_text('{"keep": true}', encoding="utf-8")
        self.environment["EXTRACT_TEST_METADATA_TARGET"] = str(sentinel)

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sentinel.read_text(), '{"keep": true}')
        name = ".pygo-audit-image.json"
        self.assertTrue((self.destination / "rootfs" / name).is_symlink())
        self.assertTrue((self.destination / name).is_file())
        self.assertFalse((self.destination / name).is_symlink())

    def test_completed_subjects_are_removable_without_following_links(self):
        sentinel = self.root / "keep.json"
        sentinel.write_text("unchanged", encoding="utf-8")
        sentinel.chmod(0o640)
        blocked_directory = self.root / "blocked-directory"
        blocked_directory.mkdir()
        blocked_directory.chmod(0)
        self.environment["EXTRACT_TEST_METADATA_TARGET"] = str(sentinel)
        self.environment["EXTRACT_TEST_RESTRICTIVE_PERMISSIONS"] = "1"
        digest = self.info["layers"][0]["digest"].split(":", 1)[1]
        with tarfile.open(self.blobs / digest, "w") as archive:
            directory = tarfile.TarInfo("etc/pki/ca-trust/extracted/pem/directory-hash")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o555
            archive.addfile(directory)
            certificate = tarfile.TarInfo(
                "etc/pki/ca-trust/extracted/pem/directory-hash/0a775a30.0"
            )
            certificate.mode = 0o444
            certificate.size = 0
            archive.addfile(certificate, io.BytesIO())
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
            blocked_link = tarfile.TarInfo("etc/httpd/run")
            blocked_link.type = tarfile.SYMTYPE
            blocked_link.linkname = str(blocked_directory)
            archive.addfile(blocked_link)

        result = self.run_command()

        self.assertEqual(result.returncode, 0, result.stderr)
        for subject in (self.destination / "rootfs", self.destination / "layers"):
            for current, directories, files in os.walk(subject, followlinks=False):
                self.assertEqual(stat.S_IMODE(Path(current).stat().st_mode), 0o700)
                for name in files:
                    path = Path(current) / name
                    if not path.is_symlink():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual((self.destination / "rootfs/locked/data").read_text(),
                         "readable after restriction")
        self.assertEqual(sentinel.read_text(), "unchanged")
        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(blocked_directory.stat().st_mode), 0o000)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((self.destination / ".pygo-audit-image.json").stat().st_mode),
            0o600,
        )
        shutil.rmtree(self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(sentinel.read_text(), "unchanged")

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
        sidecar = json.loads((self.destination / ".pygo-audit-image.json").read_text())["image"]
        self.assertEqual(sidecar["reference"], self.image)
        self.assertEqual(sidecar["digest"], self.image_digest)

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
        )["image"]
        self.assertEqual(sidecar["component"], "Red Hat Enterprise Linux CoreOS")
        self.assertNotIn("image_build_release", sidecar)
        self.assertEqual(sidecar["component_version"], "9.6.20260504-0")
        self.assertEqual(sidecar["product_version"], "4.20")
        self.assertEqual(
            sidecar["cpes"],
            ["cpe:/o:redhat:enterprise_linux:9::baseos"],
        )

    def test_extraction_records_layer_product_contexts_in_json(self):
        blob = self.blobs / self.info["layers"][0]["digest"].split(":", 1)[1]
        with tarfile.open(blob, "a") as archive:
            labels = json.dumps({"name": "base", "cpe": "cpe:/a:example:base:9.6", "version": "9.6"}).encode()
            for path in ("root/buildinfo/labels.json", "usr/share/buildinfo/labels.json"):
                member = tarfile.TarInfo(path)
                member.size = len(labels)
                archive.addfile(member, io.BytesIO(labels))
        result = self.run_command()
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads((self.destination / ".pygo-audit-image.json").read_text())
        product = document["products"][0]
        self.assertEqual(product["cpes"], ["cpe:/a:example:base:9.6"])
        self.assertEqual(product["version"], "9.6")
        self.assertEqual(len(product["sources"]), 2)
        self.assertTrue(all(path.startswith("layers/layer-000/") for path in product["sources"]))

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

    def test_skopeo_progress_is_hidden_and_copy_errors_are_kept(self):
        self.environment["EXTRACT_TEST_FAIL_COPY"] = "1"

        result = self.run_command()

        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Copying blob fake", result.stdout + result.stderr)
        self.assertIn("skopeo image copy failed with exit status 3", result.stderr)
        self.assertIn("registry copy failed", result.stderr)

    def test_layer_failure_retains_partial_output(self):
        self.environment["EXTRACT_TEST_FAIL_LAYER"] = "1"
        digest = self.info["layers"][1]["digest"].split(":", 1)[1]
        with tarfile.open(self.blobs / digest, "w") as archive:
            directory = tarfile.TarInfo("run")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o000
            archive.addfile(directory)
            file = tarfile.TarInfo("run/data")
            file.mode = 0o444
            payload = b"partial extraction"
            file.size = len(payload)
            archive.addfile(file, io.BytesIO(payload))

        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tar extraction for layer", result.stderr)
        self.assertTrue((self.destination / "layers" / "layer-000" / "etc" / "layer.txt").is_file())
        self.assertTrue((self.destination / "layers" / "layer-001").is_dir())
        self.assertEqual(
            stat.S_IMODE((self.destination / "layers/layer-001/run").stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE((self.destination / "layers/layer-001/run/data").stat().st_mode),
            0o400,
        )
        self.assertEqual(
            stat.S_IMODE((self.destination / "layers" / "layer-001").stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(
                (self.destination / "layers" / "layer-000" / "etc").stat().st_mode
            ),
            0o700,
        )
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
