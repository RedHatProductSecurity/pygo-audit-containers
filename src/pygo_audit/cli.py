"""Command-line interface for pygo-audit."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from pygo_audit import __version__
from pygo_audit.artifacts import (
    ArtifactError,
    validate_artifact_directory,
    write_artifacts,
    write_check_artifacts,
)
from pygo_audit.identity import ImageIdentityError, resolve_image_identity
from pygo_audit.models import ScanReport
from pygo_audit.report import (
    render_checks,
    render_container,
    render_diagnostics,
    render_grouped,
    render_json,
    render_summary,
    render_text,
)
from pygo_audit.scanner import ScanConfigurationError, scan_root
from pygo_audit.snapshot import SnapshotError, load_snapshot, write_snapshot


def build_scan_parser(*, prog: str = "pygo-audit scan") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Scan Go dependencies and known vulnerabilities embedded in an "
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
    _add_output_directory_argument(parser)
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
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        metavar="PATH",
        help="content-addressed store for the immutable scan snapshot",
    )
    parser.add_argument(
        "--image-metadata",
        type=Path,
        metavar="PATH",
        help="image identity sidecar (default: ROOT/.pygo-audit-image.json)",
    )
    parser.add_argument(
        "--image-ref",
        dest="image_reference",
        metavar="REFERENCE",
        help="original image reference",
    )
    parser.add_argument(
        "--image-digest",
        metavar="DIGEST",
        help="resolved OCI manifest digest",
    )
    parser.add_argument(
        "--platform",
        metavar="OS/ARCH",
        help="selected image platform",
    )
    parser.add_argument(
        "--extractor",
        metavar="TOOL",
        help="tool used to produce the unpacked root",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def build_report_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygo-audit report",
        description="Render a view of a previously stored scan snapshot.",
    )
    views = parser.add_subparsers(dest="view", metavar="VIEW", required=True)
    for view, help_text in (
        ("overview", "show result, coverage, packages, and vulnerabilities"),
        ("findings", "show container findings and supporting evidence"),
        ("binaries", "show per-binary findings and declared dependencies"),
        ("diagnostics", "show scan issues and reconciliation details"),
        ("json", "show the complete machine-readable snapshot"),
    ):
        view_parser = views.add_parser(view, help=help_text)
        _add_snapshot_argument(view_parser)
        _add_output_directory_argument(view_parser)
        _add_strict_argument(view_parser)
        if view in {"findings", "json"}:
            _add_grouping_argument(view_parser)
    return parser


def build_check_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygo-audit check",
        description="Check a stored scan snapshot for specific vulnerabilities.",
    )
    _add_snapshot_argument(parser)
    parser.add_argument(
        "identifiers",
        nargs="+",
        metavar="ID",
        help="CVE, GHSA, or GO vulnerability identifier",
    )
    _add_output_directory_argument(
        parser,
        help_text="write only the requested checks under PATH/checks",
    )
    _add_strict_argument(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    if raw_arguments and raw_arguments[0] == "scan":
        arguments = build_scan_parser().parse_args(raw_arguments[1:])
        return _scan_main(arguments)
    if raw_arguments and raw_arguments[0] == "check":
        arguments = build_check_parser().parse_args(raw_arguments[1:])
        return _check_main(arguments)
    if raw_arguments and raw_arguments[0] == "report":
        return _report_main(build_report_parser().parse_args(raw_arguments[1:]))
    if raw_arguments and raw_arguments[0] in {"-h", "--help"}:
        _print_command_help()
        return 0
    if raw_arguments and raw_arguments[0] == "--version":
        print(f"pygo-audit {__version__}")
        return 0

    _print_command_help(file=sys.stderr)
    return 2


def _scan_main(arguments: argparse.Namespace) -> int:
    if (
        arguments.snapshot_dir is not None
        and arguments.output_dir is not None
        and arguments.snapshot_dir.resolve() == arguments.output_dir.resolve()
    ):
        print(
            "pygo-audit: --snapshot-dir and --output-dir must be different",
            file=sys.stderr,
        )
        return 2
    if not _validate_artifact_output(arguments.output_dir):
        return 1

    try:
        image_identity = resolve_image_identity(
            arguments.root,
            metadata_path=arguments.image_metadata,
            reference=arguments.image_reference,
            digest=arguments.image_digest,
            platform=arguments.platform,
            extractor=arguments.extractor,
        )
    except ImageIdentityError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return 2

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
    report.image_identity = image_identity

    output_failed = False
    if arguments.snapshot_dir is not None:
        try:
            snapshot_path = write_snapshot(report, arguments.snapshot_dir)
        except SnapshotError as error:
            print(f"pygo-audit: {error}", file=sys.stderr)
            output_failed = True
        else:
            print(f"Snapshot: {snapshot_path}", file=sys.stderr)
    if arguments.output_dir is not None:
        try:
            write_artifacts(report, arguments.output_dir)
        except ArtifactError as error:
            print(f"pygo-audit: {error}", file=sys.stderr)
            output_failed = True
        else:
            print(f"Artifacts: {arguments.output_dir}", file=sys.stderr)

    output = render_summary(report)
    if not _print_output(output):
        return 0
    if output_failed:
        return 1
    return _strict_status(report, arguments.strict)


def _report_main(arguments: argparse.Namespace) -> int:
    if not _validate_artifact_output(arguments.output_dir):
        return 1
    try:
        report = load_snapshot(arguments.snapshot_path)
    except SnapshotError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return 1

    if arguments.output_dir is not None:
        try:
            write_artifacts(report, arguments.output_dir)
        except ArtifactError as error:
            print(f"pygo-audit: {error}", file=sys.stderr)
            return 1
        print(f"Artifacts: {arguments.output_dir}", file=sys.stderr)

    output = _render_report_view(report, arguments)
    if not _print_output(output):
        return 0
    return _strict_status(report, arguments.strict)


def _check_main(arguments: argparse.Namespace) -> int:
    if not _validate_artifact_output(arguments.output_dir):
        return 1
    try:
        report = load_snapshot(arguments.snapshot_path)
    except SnapshotError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return 1

    if arguments.output_dir is not None:
        try:
            write_check_artifacts(
                report,
                arguments.output_dir,
                arguments.identifiers,
            )
        except ArtifactError as error:
            print(f"pygo-audit: {error}", file=sys.stderr)
            return 1
        print(f"Checks: {arguments.output_dir / 'checks'}", file=sys.stderr)

    if not _print_output(render_checks(report, arguments.identifiers)):
        return 0
    return _strict_status(report, arguments.strict)


def _render_report_view(report: ScanReport, arguments: argparse.Namespace) -> str:
    if arguments.view == "overview":
        return render_summary(report)
    if arguments.view == "binaries":
        return render_text(report)
    if arguments.view == "diagnostics":
        return render_diagnostics(report)
    if arguments.view == "json":
        return render_json(report, group_by=arguments.group_by)
    if arguments.group_by:
        return render_grouped(report, arguments.group_by)
    return render_container(report)


def _validate_artifact_output(output_directory: Path | None) -> bool:
    if output_directory is None:
        return True
    try:
        validate_artifact_directory(output_directory)
    except ArtifactError as error:
        print(f"pygo-audit: {error}", file=sys.stderr)
        return False
    return True


def _strict_status(report: ScanReport, strict: bool) -> int:
    return 1 if strict and report.actionable_issues else 0


def _print_output(output: str) -> bool:
    try:
        print(output)
    except BrokenPipeError:
        return False
    return True


def _print_command_help(*, file: object = sys.stdout) -> None:
    print(
        """usage: pygo-audit COMMAND ...

Scan and report Go dependencies and vulnerabilities in unpacked containers.

commands:
  scan ROOT                    scan an unpacked container rootfs
  report overview SNAPSHOT     show container result and complete lists
  report findings SNAPSHOT     show findings and supporting evidence
  report binaries SNAPSHOT     show per-binary findings and dependencies
  report diagnostics SNAPSHOT  show scan issues and reconciliation details
  report json SNAPSHOT         show the complete machine-readable snapshot
  check SNAPSHOT ID [ID ...]   show only results for requested vulnerabilities

Run 'pygo-audit COMMAND --help' for command-specific options.""",
        file=file,
    )


def _add_snapshot_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "snapshot_path",
        type=Path,
        help="snapshot JSON file or directory containing one snapshot",
    )


def _add_output_directory_argument(
    parser: argparse.ArgumentParser,
    *,
    help_text: str = "write audit.json and all current human-readable reports",
) -> None:
    parser.add_argument(
        "--output-dir",
        type=Path,
        metavar="PATH",
        help=help_text,
    )


def _add_grouping_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--group-by",
        choices=("container", "binary", "package", "vulnerability"),
        help="group findings along the selected dimension",
    )


def _add_strict_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 when the snapshot has actionable issues",
    )


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
