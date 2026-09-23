"""Command-line interface for pygo-audit."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from pygo_audit import __version__
from pygo_audit.report import (
    render_checks,
    render_container,
    render_grouped,
    render_json,
    render_summary,
    render_text,
)
from pygo_audit.scanner import ScanConfigurationError, scan_root


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygo-audit",
        description=(
            "Report Go dependencies and known vulnerabilities embedded in an "
            "unpacked container rootfs."
        ),
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
        choices=("text", "container", "summary", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--group-by",
        choices=("container", "binary", "package", "vulnerability"),
        help="group findings along the selected dimension",
    )
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        metavar="ID",
        help=(
            "report an explicit result for a CVE, GHSA, or GO identifier; "
            "may be repeated"
        ),
    )
    parser.add_argument(
        "--go",
        default="go",
        metavar="PATH",
        help="Go command to use (default: go on PATH)",
    )
    parser.add_argument(
        "--govulncheck",
        default="govulncheck",
        metavar="PATH",
        help="govulncheck command to use (default: govulncheck on PATH)",
    )
    parser.add_argument(
        "--no-vulncheck",
        action="store_true",
        help="report build information without running vulnerability checks",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=30.0,
        metavar="SECONDS",
        help="timeout for each inspection command (default: 30)",
    )
    parser.add_argument(
        "--jobs",
        type=_positive_integer,
        default=4,
        metavar="COUNT",
        help="maximum concurrent binary inspections (default: 4)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 when the completed scan has actionable issues",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        report = scan_root(
            arguments.root,
            go_command=arguments.go,
            govulncheck_command=(
                None if arguments.no_vulncheck else arguments.govulncheck
            ),
            timeout=arguments.timeout,
            jobs=arguments.jobs,
        )
    except ScanConfigurationError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return 1

    if arguments.format == "json":
        output = render_json(
            report,
            group_by=arguments.group_by,
            checks=arguments.check,
        )
    elif arguments.group_by:
        output = render_grouped(report, arguments.group_by)
    elif arguments.format == "container":
        output = render_container(report)
    elif arguments.format == "summary":
        output = render_summary(report)
    else:
        output = render_text(report)
    if arguments.check and arguments.format != "json":
        output = f"{output}\n\n{render_checks(report, arguments.check)}"
    try:
        print(output)
    except BrokenPipeError:
        return 0
    return 1 if arguments.strict and report.actionable_issues else 0


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
