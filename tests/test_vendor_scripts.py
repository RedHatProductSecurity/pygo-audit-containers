from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from importlib.machinery import SourceFileLoader
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit import models


def load_script(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / name
    loader = SourceFileLoader(name.replace("-", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


FETCH = load_script("fetch-redhat-csaf")
TARGETS = load_script("gather-openshift-targets")
PREPARE = load_script("prepare-audits")


class VendorScriptsTests(unittest.TestCase):
    def test_preparation_dry_run_validates_without_writes_or_registry_access(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "inventory"
            inventory.write_text(
                "# images\nalpha registry.example/app:tag\nbeta registry.example/worker\n"
            )
            output = root / "run"
            with (
                patch.object(PREPARE.subprocess, "run") as command,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    PREPARE.main([str(inventory), str(output), "--dry-run"]), 0
                )
            command.assert_not_called()
            self.assertFalse(output.exists())
            inventory.write_text("alpha image\nalpha other\n")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    PREPARE.main([str(inventory), str(output), "--dry-run"]), 1
                )

    def test_preparation_owns_extractor_invocation(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "inventory"
            inventory.write_text("alpha registry.example/app:tag\n")
            with (
                patch.object(
                    PREPARE.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as command,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(PREPARE.main([str(inventory), str(root / "run")]), 0)
            self.assertIn("extract-image-layers", command.call_args.args[0][1])
            self.assertIn(str(root / "run" / "alpha"), command.call_args.args[0])
            self.assertNotIn("--image-name", command.call_args.args[0])

    def test_download_reuses_cache_and_keeps_failed_refresh_from_replacing_it(
        self,
    ) -> None:
        document = {"vulnerabilities": [{"cve": "CVE-2026-0001"}]}
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            with patch.object(
                FETCH, "urlopen", return_value=io.BytesIO(json.dumps(document).encode())
            ) as request:
                first = FETCH.fetch_cve("CVE-2026-0001", directory)
                second = FETCH.fetch_cve("CVE-2026-0001", directory)
            self.assertFalse(first.from_cache)
            self.assertTrue(second.from_cache)
            self.assertEqual(json.loads(first.path.read_text()), document)
            request.assert_called_once()
            self.assertEqual(
                request.call_args.args[0].full_url,
                "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-0001.json",
            )
            with patch.object(FETCH, "urlopen", side_effect=OSError("unavailable")):
                refreshed = FETCH.fetch_cve("CVE-2026-0001", directory, refresh=True)
            self.assertIn("unavailable", refreshed.error)
            self.assertEqual(json.loads(first.path.read_text()), document)

    def test_offline_fetch_never_creates_cache_or_lock(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory) / "missing"
            with (
                patch.object(FETCH, "cache_entry_lock") as lock,
                patch.object(FETCH, "urlopen") as request,
            ):
                result = FETCH.fetch_cve("CVE-2026-0001", directory, offline=True)
            self.assertEqual(result.error, "not present in cache")
            self.assertFalse(directory.exists())
            lock.assert_not_called()
            request.assert_not_called()

    def test_cache_root_must_not_be_a_symlink(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            alias = directory / "alias"
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(FETCH.CsafCheckError, "must not be a symlink"):
                FETCH.fetch_cve("CVE-2026-0001", alias, offline=True)

    def test_rejects_wrong_cve_without_publishing_a_document(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            with patch.object(
                FETCH,
                "urlopen",
                return_value=io.BytesIO(
                    b'{"vulnerabilities": [{"cve": "CVE-2026-0002"}]}'
                ),
            ):
                result = FETCH.fetch_cve("CVE-2026-0001", directory)
            self.assertIn("no CSAF record", result.error)
            self.assertFalse(result.path.exists())

    def test_product_release_generates_the_generic_batch_contract(self) -> None:
        document = {
            "metadata": {"version": "4.20.21"},
            "references": {
                "spec": {
                    "tags": [
                        {
                            "name": "example",
                            "from": {
                                "name": "registry.example/image@sha256:" + "a" * 64
                            },
                        },
                        {
                            "name": "longer-example",
                            "from": {
                                "name": "registry.example/other@sha256:" + "b" * 64
                            },
                        },
                    ]
                }
            },
        }
        response = subprocess.CompletedProcess([], 0, json.dumps(document), "")
        with TemporaryDirectory() as temporary_directory:
            target_file = Path(temporary_directory) / "targets.tsv"
            with patch.object(TARGETS.subprocess, "run", return_value=response):
                status = TARGETS.main(["4.20.21", "--output", str(target_file)])
            lines = target_file.read_text().splitlines()
            targets = PREPARE.parse_targets(target_file)
        self.assertEqual(status, 0)
        self.assertEqual(
            {line.index("registry.example/") for line in lines},
            {len("longer-example-4.20.21") + 2},
        )
        self.assertEqual(targets[0].name, "example-4.20.21")
        self.assertEqual(targets[1].name, "longer-example-4.20.21")

    def test_fetch_helper_handles_clean_audit_without_network_or_output(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit = root / "audit.json"
            report = models.AuditReport(
                metadata=models.ContainerMetadata(str(root)),
                go_command="go",
                go_tool_version="test",
                producer_name="pygo-audit",
                producer_version="test",
            )
            audit.write_text(json.dumps(report.to_dict()), encoding="utf-8")
            with (
                patch.object(FETCH, "urlopen") as request,
                redirect_stdout(io.StringIO()),
            ):
                status = FETCH.main([str(audit), str(root / "csaf")])
            self.assertFalse((root / "csaf").exists())
            request.assert_not_called()
        self.assertEqual(status, 0)
