from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract-image-layers"
DIGEST = "sha256:" + "a" * 64


class ExtractImageLayersTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "layers with spaces"
        self.log = self.root / "oc-calls.jsonl"
        self.info = {
            "name": "registry.example.test:5000/team/app:latest",
            "digest": DIGEST,
            "layers": [
                {"digest": "sha256:" + character * 64, "size": 100}
                for character in "bcd"
            ],
            "config": {"os": "linux", "architecture": "amd64"},
        }
        self.info_path = self.root / "info.json"
        self.info_path.write_text(json.dumps(self.info), encoding="utf-8")
        fake_oc = self.root / "oc"
        fake_oc.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent("""\
                import json
                import os
                from pathlib import Path
                import sys

                args = sys.argv[1:]
                with open(os.environ['EXTRACT_TEST_LOG'], 'a') as log:
                    log.write(json.dumps(args) + '\\n')
                if args[:2] == ['image', 'info']:
                    print(Path(os.environ['EXTRACT_TEST_INFO']).read_text())
                elif args[:2] == ['image', 'extract']:
                    index = int(args[2].rsplit('[', 1)[1].rstrip(']'))
                    target = Path(next(a for a in args if a.startswith('--path=/:'))[9:])
                    (target / 'bin').mkdir()
                    (target / 'bin' / 'app').write_text(f'version from layer {index}')
                    if str(index) == os.environ.get('EXTRACT_TEST_FAIL_LAYER'):
                        print('simulated layer download failure', file=sys.stderr)
                        sys.exit(7)
                else:
                    sys.exit(2)
                """),
            encoding="utf-8",
        )
        fake_oc.chmod(0o755)
        self.environment = dict(
            os.environ,
            PATH=str(self.root) + os.pathsep + os.environ.get("PATH", ""),
            EXTRACT_TEST_LOG=str(self.log),
            EXTRACT_TEST_INFO=str(self.info_path),
        )

    def run_command(self):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), self.info["name"], str(self.destination)],
            env=self.environment,
            capture_output=True,
            text=True,
        )

    def test_preserves_each_version_and_pins_the_resolved_image(self):
        result = self.run_command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Extracted all 3 layers", result.stdout)
        for index in range(3):
            binary = self.destination / f"layer-{index:03d}" / "bin" / "app"
            self.assertEqual(binary.read_text(), f"version from layer {index}")
        self.assertEqual(
            json.loads((self.destination / "image-info.json").read_text()), self.info
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(len(calls), 4)
        for index, call in enumerate(calls[1:]):
            self.assertEqual(call[2], f"registry.example.test:5000/team/app@{DIGEST}[{index}]")
            self.assertIn("--filter-by-os=linux/amd64", call)
            self.assertNotIn("--only-files", call)

    def test_existing_destination_is_untouched_without_contacting_oc(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep.txt"
        sentinel.write_text("existing work")
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("destination already exists", result.stderr)
        self.assertEqual(sentinel.read_text(), "existing work")
        self.assertFalse(self.log.exists())

    def test_missing_oc_has_helpful_error_and_creates_no_destination(self):
        self.environment["PATH"] = str(self.root / "no-commands")
        result = self.run_command()
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "OpenShift is unavailable. Please use your preferred container tools "
            "to extract container images.",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.log.exists())

    def test_failure_stops_before_later_layers_and_retains_partial_output(self):
        self.environment["EXTRACT_TEST_FAIL_LAYER"] = "1"
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated layer download failure", result.stderr)
        self.assertIn("extraction did not complete", result.stderr)
        self.assertNotIn("Extracted all", result.stdout)
        self.assertTrue((self.destination / "layer-000" / "bin" / "app").is_file())
        self.assertTrue((self.destination / "layer-001").is_dir())
        self.assertFalse((self.destination / "layer-002").exists())
        self.assertTrue((self.destination / "image-info.json").is_file())

    def test_invalid_metadata_creates_no_destination(self):
        self.info_path.write_text('{"digest": "invalid", "layers": []}')
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolved image digest", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_wrong_platform_creates_no_destination(self):
        self.info["config"]["architecture"] = "arm64"
        self.info_path.write_text(json.dumps(self.info))
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
