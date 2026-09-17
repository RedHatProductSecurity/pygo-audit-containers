"""Command-line interface for pygo-audit."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from pygo_audit import __version__
from pygo_audit.report import render_json, render_text
from pygo_audit.scanner import ScanConfigurationError, scan_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygo-audit",
        description="Report Go dependencies embedded in an unpacked container rootfs.",
    )
    parser.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=Path("sandbox"),
        help="unpacked container root directory (default: ./sandbox)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--go",
        default="go",
        metavar="PATH",
        help="Go command to use (default: go on PATH)",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=30.0,
        metavar="SECONDS",
        help="timeout for each Go command (default: 30)",
    )
    parser.add_argument(
        "--jobs",
        type=_positive_integer,
        default=4,
        metavar="COUNT",
        help="maximum concurrent Go inspections (default: 4)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 when the completed scan contains any issues",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        report = scan_root(
            arguments.root,
            go_command=arguments.go,
            timeout=arguments.timeout,
            jobs=arguments.jobs,
        )
    except ScanConfigurationError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return 1

    output = render_json(report) if arguments.format == "json" else render_text(report)
    try:
        print(output)
    except BrokenPipeError:
        return 0
    return 1 if arguments.strict and report.issues else 0


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed
