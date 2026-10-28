from contextlib import chdir, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit import cli, models
from pygo_audit.cli import (
    resolve_settings,
    resolve_audit_settings,
    discover_audits,
    read_settings,
)


class WorkspaceTests(unittest.TestCase):
    def test_file_inputs_resolve_the_same_workspace_and_relative_settings(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "service"
            (workspace / "history").mkdir(parents=True)
            (workspace / "pygo-audit.json").write_text(
                json.dumps(
                    {
                        "audit-file": "configured.json",
                        "csaf": ["advisories"],
                        "output-dir": "reports",
                        "strict": True,
                    }
                )
            )
            (root / "pygo-audit.json").write_text(json.dumps({"strict": False}))
            for relative in (
                "service/audit.json",
                "service/history/audit-prior-date.json",
            ):
                for positional in (False, True):
                    with (
                        self.subTest(relative=relative, positional=positional),
                        chdir(root),
                    ):
                        selected = Path(relative)
                        settings = (
                            resolve_audit_settings(selected)
                            if positional
                            else resolve_audit_settings(
                                overrides={"audit_file": selected}
                            )
                        )
                    self.assertEqual(settings.audit_root, workspace)
                    self.assertEqual(settings.audit_file, root / relative)
                    self.assertEqual(settings.csaf, [workspace / "advisories"])
                    self.assertEqual(settings.output_dir, workspace / "reports")
                    self.assertTrue(settings.strict)

    def test_explicit_workspace_wins_over_file_location(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "service"
            workspace.mkdir()
            (workspace / "pygo-audit.json").write_text(json.dumps({"csaf": ["local"]}))
            selected = root / "elsewhere" / "audit.json"
            settings = resolve_audit_settings(workspace, {"audit_file": selected})
            self.assertEqual(settings.audit_root, workspace)
            self.assertEqual(settings.audit_file, selected)
            self.assertEqual(settings.csaf, [workspace / "local"])

    def test_batch_commands_default_to_child_audits_and_local_scan_outputs(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "service"
            (child / "rootfs").mkdir(parents=True)
            for command in ("audit", "aggregate"):
                with (
                    self.subTest(command=command),
                    chdir(root),
                    patch(
                        f"pygo_audit.{command if command == 'aggregate' else 'batch'}.run",
                        return_value=0,
                    ) as run,
                ):
                    self.assertEqual(cli.main([command]), 0)
                options, targets = run.call_args.args
                self.assertEqual(options.audit_root, root)
                self.assertEqual(len(targets), 1)
                self.assertEqual(targets[0].audit_root, child)
                self.assertEqual(targets[0].audit_file, child / "audit.json")
                self.assertEqual(targets[0].output_dir, child)
                self.assertEqual(targets[0].history_dir, child / "history")
                if command == "audit":
                    self.assertEqual(targets[0].cache_dir, root / "cache")
                    self.assertEqual(targets[0].work_dir, root / "work")
                else:
                    self.assertEqual(options.output_dir, root / "reports")

    def test_csaf_does_not_treat_an_unscanned_workspace_as_a_batch(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rootfs").mkdir()
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(cli.main(["csaf", str(root)]), 1)
            self.assertIn(str(root / "audit.json"), errors.getvalue())
            (root / "pygo-audit.json").write_text(
                json.dumps({"audit-file": "missing.json"})
            )
            with patch("pygo_audit.csaf.run", return_value=0) as run:
                self.assertEqual(cli.main(["csaf", str(root)]), 0)
            self.assertEqual(run.call_args.args[0][0].audit_file, root / "missing.json")

    def test_precedence_and_relative_path_origins(self):
        with TemporaryDirectory() as temporary:
            batch = Path(temporary)
            child = batch / "container"
            child.mkdir()
            (batch / "pygo-audit.json").write_text(
                json.dumps({"jobs": 1, "cache-dir": "shared"})
            )
            (child / "pygo-audit.json").write_text(
                json.dumps({"jobs": 2, "rootfs": "subject"})
            )
            with chdir(batch):
                settings = resolve_settings(
                    child,
                    {"jobs": 3, "work_dir": Path("cli-work")},
                    read_settings(batch),
                )
            self.assertEqual(settings.jobs, 3)
            self.assertEqual(settings.cache_dir, batch / "shared")
            self.assertEqual(settings.rootfs, child / "subject")
            self.assertEqual(settings.work_dir, batch / "cli-work")
            self.assertEqual(settings.output_dir, child)

    def test_layer_option_overrides_clear_conflicting_sidecar_choice(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "pygo-audit.json").write_text(
                json.dumps({"layer-dir": ["old"], "layers": False})
            )
            settings = resolve_settings(
                root, {"layers_dir": root / "discovered", "layers": True}
            )
            self.assertEqual(settings.layer_dir, [])
            self.assertTrue(settings.layers)

    def test_invalid_settings_fail_before_work(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for document in (
                {"typo": "x"},
                {"jobs": True},
                {"jobs": 1.5},
                {"timeout": float("nan")},
                {"layers": "yes"},
                {"layers": None},
                {"rootfs": []},
                {"rootfs": ""},
                {"layer-dir": "path"},
                {"layer-sort": "unknown"},
                {"csaf": "path"},
                {"csaf": [1]},
                {"image-name": 42},
                {"govulncheck": None},
            ):
                (root / "pygo-audit.json").write_text(json.dumps(document))
                with self.subTest(document=document), self.assertRaises(ValueError):
                    resolve_settings(root)
            self.assertFalse((root / "cache").exists())

    def test_discovery_and_selection_are_immediate_and_explicit(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("alpha", "beta"):
                (root / name / "rootfs").mkdir(parents=True)
            (root / "cache").mkdir()
            self.assertEqual([p.name for p in discover_audits(root)], ["alpha", "beta"])
            targets = root / "targets.txt"
            targets.write_text("# subset\nbeta\n")
            self.assertEqual(discover_audits(root, targets), [root / "beta"])
            for value in ("../alpha", "missing", "alpha\nalpha"):
                targets.write_text(value)
                with self.assertRaises(ValueError):
                    discover_audits(root, targets)

    def test_batch_passes_resolved_settings_and_local_identity_to_handler(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "service"
            (child / "rootfs").mkdir(parents=True)
            (root / "pygo-audit.json").write_text(json.dumps({"jobs": 1}))
            (child / "pygo-audit.json").write_text(
                json.dumps({"jobs": 2, "image-metadata": "container.json"})
            )
            (child / "container.json").write_text(json.dumps({"image-name": "service"}))
            with patch("pygo_audit.batch.run", return_value=0) as run:
                self.assertEqual(cli.main(["audit", str(root), "--jobs", "3"]), 0)
            options, targets = run.call_args.args
            self.assertEqual(options.cache_dir, root / "cache")
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].cache_dir, root / "cache")
            self.assertEqual(targets[0].jobs, 3)
            self.assertTrue(targets[0].strict)
            self.assertEqual(targets[0].image.name, "service")
            self.assertEqual(targets[0].image_metadata, child / "container.json")

    def test_csaf_paths_follow_batch_child_and_cli_precedence(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "service"
            child.mkdir()
            (child / "audit.json").write_text("{}")
            (root / "csaf").mkdir()
            with patch("pygo_audit.csaf.run", return_value=0) as run:
                self.assertEqual(cli.main(["csaf", str(root)]), 0)
                self.assertEqual(run.call_args.args[0][0].csaf, [root / "csaf"])
                (root / "pygo-audit.json").write_text(json.dumps({"csaf": ["shared"]}))
                self.assertEqual(cli.main(["csaf", str(root)]), 0)
                self.assertEqual(run.call_args.args[0][0].csaf, [root / "shared"])
                (child / "pygo-audit.json").write_text(json.dumps({"csaf": ["local"]}))
                self.assertEqual(cli.main(["csaf", str(root)]), 0)
                self.assertEqual(run.call_args.args[0][0].csaf, [child / "local"])
                with chdir(root):
                    self.assertEqual(
                        cli.main(["csaf", str(root), "--csaf", "explicit"]), 0
                    )
                self.assertEqual(run.call_args.args[0][0].csaf, [root / "explicit"])

    def test_only_default_csaf_directory_may_be_absent(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = models.AuditReport(
                metadata=models.ContainerMetadata(str(root)),
                go_command="go",
                go_tool_version="test",
                producer_name="pygo-audit",
                producer_version="test",
            )
            (root / "audit.json").write_text(json.dumps(report.to_dict()))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["csaf", str(root)]), 0)
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(
                    cli.main(["csaf", str(root), "--csaf", str(root / "missing")]), 1
                )
            self.assertIn("CSAF input does not exist", errors.getvalue())
            (root / "pygo-audit.json").write_text(json.dumps({"csaf": ["missing"]}))
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(cli.main(["csaf", str(root)]), 1)
            self.assertIn("CSAF input does not exist", errors.getvalue())

    def test_explicit_audit_file_overrides_the_positional_file(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "audit.json"
            previous = root / "previous.json"
            for path in (current, previous):
                path.write_text("{}")
            with patch("pygo_audit.csaf.run", return_value=0) as run:
                self.assertEqual(
                    cli.main(["csaf", str(current), "--audit-file", str(previous)]), 0
                )
            target = run.call_args.args[0][0]
            self.assertEqual(target.audit_root, root)
            self.assertEqual(target.audit_file, previous)
