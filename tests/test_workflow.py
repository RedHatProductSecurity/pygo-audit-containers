"""Exercise the CLI against real files/processes without network or registries."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pygo_audit.cli import main
from pygo_audit.storage import atomic_read_json
from pygo_audit.scanner import _go_environment


class WorkflowTests(unittest.TestCase):
    def test_batch_reuse_freshness_context_and_failed_refresh(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            batch = directory / "batch"
            alpha, beta = batch / "alpha", batch / "beta"
            for root in (alpha, beta):
                (root / "rootfs").mkdir(parents=True)
            (beta / "layers" / "layer-000").mkdir(parents=True)
            for binary in (
                alpha / "rootfs" / "app",
                beta / "layers" / "layer-000" / "old-app",
            ):
                binary.write_bytes(b"\x7fELFfixture")
            go = directory / "go-reader"
            go.write_text("""#!/usr/bin/env python3
import json, pathlib, sys
root = pathlib.Path(__file__).parent
if sys.argv[1:3] == ['version', '-m']:
    with (root / 'go-count').open('a') as f: f.write('read\\n')
    print(json.dumps({'GoVersion':'go1.26','Path':'example.test/app'}))
elif sys.argv[1] == 'help': print('-json')
else: print('go version test')
""")
            vuln = directory / "vulnerability-checker"
            vuln.write_text("""#!/usr/bin/env python3
import pathlib, sys
root = pathlib.Path(__file__).parent
if sys.argv[1:] == ['-version']:
    print('Scanner: test'); sys.exit(0)
with (root / 'vuln-count').open('a') as f: f.write('check\\n')
if (root / 'fail').exists(): sys.exit(1)
print('{"config":{"protocol_version":"v1.0.0","scan_mode":"binary","db":"test"}}')
""")
            for executable in (go, vuln):
                executable.chmod(0o700)
            arguments = [
                "audit",
                str(batch),
                "--go",
                str(go),
                "--govulncheck",
                str(vuln),
                "--workers",
                "2",
            ]
            with (
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(main(arguments), 0)
                self.assertEqual((directory / "go-count").read_text().count("read"), 1)
                self.assertEqual(
                    (directory / "vuln-count").read_text().count("check"), 1
                )
                first = json.loads((alpha / "audit.json").read_text())
                other = json.loads((beta / "audit.json").read_text())
                self.assertEqual(first["binaries"][0]["runtime_disposition"], "runtime")
                self.assertEqual(
                    other["binaries"][0]["runtime_disposition"],
                    "unaccounted",
                )
                self.assertEqual(other["binaries"][0]["paths"], ["/old-app"])
                cached = atomic_read_json(
                    next((batch / "cache" / "objects").glob("*.json")), checksum=True
                )
                self.assertEqual(
                    cached["binary"]["layer_history"], {"state": "requires-observation"}
                )
                self.assertEqual(main(arguments), 0)
                self.assertEqual((directory / "go-count").read_text().count("read"), 1)
                self.assertEqual(
                    (directory / "vuln-count").read_text().count("check"), 2
                )
                previous = (alpha / "audit.json").read_bytes()
                (directory / "fail").touch()
                self.assertEqual(main(arguments), 1)
                self.assertEqual((alpha / "audit.json").read_bytes(), previous)
                self.assertTrue(list((batch / "work").glob("failed-*/audit.json")))
                (batch / "csaf").mkdir()
                (batch / "csaf" / "advisory.json").write_text('{"product_tree": {}}')
                self.assertEqual(main(["csaf", str(batch)]), 0, errors.getvalue())
                self.assertEqual(main(["aggregate", str(batch)]), 0)
            self.assertTrue((alpha / "reports" / "comparison.json").is_file())
            self.assertTrue((batch / "reports" / "aggregate.json").is_file())
            self.assertTrue((batch / "reports" / "aggregate.txt").is_file())
            self.assertTrue((batch / "reports" / "aggregate.csv").is_file())
            self.assertFalse(list(batch.glob("*.csv")))
            self.assertEqual(len(list((alpha / "history").glob("audit-*.json"))), 1)

    def test_tool_defaults_stay_in_workspace_and_explicit_environment_wins(self):
        with TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            with patch.dict(os.environ, {"HOME": "/unused-home"}, clear=True):
                environment = _go_environment(work)
            for variable in (
                "GOCACHE",
                "GOMODCACHE",
                "GOPATH",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "TMPDIR",
            ):
                self.assertTrue(Path(environment[variable]).is_relative_to(work))
            with patch.dict(
                os.environ, {"GOCACHE": str(Path(temporary) / "explicit")}, clear=True
            ):
                self.assertEqual(
                    _go_environment(work)["GOCACHE"], str(Path(temporary) / "explicit")
                )
