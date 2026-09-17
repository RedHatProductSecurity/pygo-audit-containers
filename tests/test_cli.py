from __future__ import annotations

from pathlib import Path
import unittest

from pygo_audit.cli import build_parser


class CliTests(unittest.TestCase):
    def test_defaults_to_repository_sandbox(self) -> None:
        arguments = build_parser().parse_args([])

        self.assertEqual(arguments.root, Path("sandbox"))

    def test_accepts_explicit_root(self) -> None:
        arguments = build_parser().parse_args(["/tmp/rootfs"])

        self.assertEqual(arguments.root, Path("/tmp/rootfs"))


if __name__ == "__main__":
    unittest.main()
