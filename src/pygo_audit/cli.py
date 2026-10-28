"""Define options once, resolve workspace settings, and dispatch commands."""

import argparse
import math
from pathlib import Path
import sys
from uuid import uuid4

from pygo_audit import __version__, aggregate, batch, comparison, csaf, report
from pygo_audit.artifacts import write_check_artifacts, write_report_artifacts
from pygo_audit.audit import load_audit
from pygo_audit.identity import SIDECAR_FIELDS, resolve_image_identity
from pygo_audit.models import AuditReport
from pygo_audit.result_cache import ResultCacheError
from pygo_audit.text_layout import RenderPolicy, Verbosity
from pygo_audit.scanner import ScanConfigurationError
from pygo_audit.storage import atomic_read_json
from pygo_audit.workspace import scan_workspace

CONFIG_NAME = "pygo-audit.json"
# Each entry defines the value type, workspace default, and CLI help together.
OPTIONS: dict[str, tuple[type, object, str]] = {
    "rootfs": (Path, "rootfs", "prepared container filesystem"),
    "layers_dir": (Path, "layers", "discover children of this layer directory"),
    "layer_dir": (Path, [], "repeat in known oldest-to-newest order"),
    "layers": (bool, True, "include historical layers"),
    "layer_sort": (
        str,
        "lexicographic",
        "order discovered layer names; does not establish chronology",
    ),
    "output_dir": (Path, ".", "directory for generated reports"),
    "history_dir": (Path, "history", "directory for previous audits"),
    "cache_dir": (Path, "cache", "shared binary cache directory"),
    "work_dir": (Path, "work", "temporary and failed-scan evidence directory"),
    "audit_file": (Path, "audit.json", "select current or previous audit JSON"),
    "csaf": (Path, ["csaf"], "local advisory files or directories"),
    "targets": (Path, None, "list of immediate child directory names"),
    "go": (str, "go", "host Go executable"),
    "govulncheck": (
        str,
        "govulncheck",
        "host govulncheck executable; checks each distinct Go binary in binary mode",
    ),
    "vulncheck": (bool, True, "run binary vulnerability checks"),
    "timeout": (float, 30.0, "seconds per inspection command"),
    "jobs": (int, 4, "concurrent binary inspections or aggregate CSAF workers"),
    "workers": (int, 4, "concurrent container scans"),
    "strict": (bool, False, "fail on actionable scan issues; audit defaults to strict"),
    "fail_fast": (bool, False, "cancel queued containers after a failure"),
    "image_metadata": (Path, None, "container identity JSON file"),
    **{
        name.replace("-", "_"): (str, None, f"container {field.replace('_', ' ')}")
        for name, field in SIDECAR_FIELDS.items()
    },
}
DEFAULTS = {name: definition[1] for name, definition in OPTIONS.items()}
SCAN_OPTIONS = [
    name
    for name in OPTIONS
    if name not in ("audit_file", "csaf", "targets", "workers", "fail_fast")
]
COMMANDS = {
    "scan": ("scan a prepared container and save findings", SCAN_OPTIONS),
    "report": (
        "render current or previous findings",
        "audit_file output_dir strict".split(),
    ),
    "audit": (
        "scan prepared child container directories",
        SCAN_OPTIONS + "targets workers fail_fast".split(),
    ),
    "aggregate": (
        "summarize saved container audits in text and JSON",
        "output_dir csaf jobs".split(),
    ),
    "check": (
        "check saved evidence for specific vulnerabilities",
        "audit_file output_dir strict".split(),
    ),
    "csaf": (
        "compare saved findings with local CSAF documents",
        "audit_file csaf output_dir".split(),
    ),
}
LAYER_SORTS = ("lexicographic", "numeric")


def normalize(values: dict[str, object], base: Path) -> dict[str, object]:
    """Validate settings and resolve paths relative to their source."""
    result = {}
    for name, value in values.items():
        kind, default, _ = OPTIONS[name]
        if value is None:
            if default is not None:
                raise ValueError(f"{name} must not be null")
            result[name] = None
            continue
        multiple = isinstance(default, list)
        if multiple and not isinstance(value, list):
            raise ValueError(f"{name} must contain a list of paths")
        items = value if isinstance(value, list) and multiple else [value]
        converted = []
        for item in items:
            if kind is Path:
                if not isinstance(item, (str, Path)) or not str(item):
                    raise ValueError(f"{name} must contain nonempty paths")
                item = (base / item).absolute()
            elif kind in (int, float):
                if (
                    not isinstance(item, (int, float))
                    or isinstance(item, bool)
                    or item <= 0
                    or not math.isfinite(item)
                ):
                    raise ValueError(f"{name} must be positive and finite")
                if kind is int and not isinstance(item, int):
                    raise ValueError(f"{name} must be an integer")
            elif not isinstance(item, kind):
                raise ValueError(f"{name} must be a {kind.__name__}")
            if name in {"go", "govulncheck"} and isinstance(item, str) and "/" in item:
                item = str((base / item).absolute())
            converted.append(item)
        result[name] = converted if multiple else converted[0]
    if "layer_sort" in result and result["layer_sort"] not in LAYER_SORTS:
        raise ValueError("layer-sort must be lexicographic or numeric")
    if result.get("layer_dir") and "layers_dir" in result:
        raise ValueError("layer-dir and layers-dir are mutually exclusive")
    return result


def read_settings(root: Path) -> dict[str, object]:
    path = root / CONFIG_NAME
    if path.is_symlink():
        raise ValueError(f"workspace settings must not be a symlink: {path}")
    if not path.exists():
        return {}
    document = atomic_read_json(path)
    if not isinstance(document, dict):
        raise ValueError(f"workspace settings must be an object: {path}")
    unknown = set(document) - {name.replace("_", "-") for name in OPTIONS}
    if unknown:
        raise ValueError(
            f"unknown workspace settings in {path}: {', '.join(sorted(unknown))}"
        )
    return normalize(
        {key.replace("-", "_"): value for key, value in document.items()}, root
    )


def resolve_settings(
    root: Path,
    overrides: dict[str, object] | None = None,
    inherited: dict[str, object] | None = None,
) -> argparse.Namespace:
    """CLI > container sidecar > batch settings > defaults."""
    root = root.absolute()
    result = normalize(DEFAULTS, root)
    explicit = normalize(
        {
            key: value
            for key, value in (overrides or {}).items()
            if key in OPTIONS and value is not None
        },
        Path.cwd(),
    )
    configured = {}
    for values in (inherited or {}, read_settings(root), explicit):
        if "layers_dir" in values:
            result["layer_dir"] = []
        if "layer_dir" in values:
            result["layers"] = True
        result.update(values)
        configured.update(values)
    return argparse.Namespace(**result, configured=configured, audit_root=root)


def discover_audits(root: Path, targets: Path | None = None) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"audit root must be a directory, not a symlink: {root}")
    if targets is None:
        directories = [
            path
            for path in sorted(root.iterdir())
            if path.is_dir()
            and (
                (path / "rootfs").exists()
                or (path / CONFIG_NAME).exists()
                or (path / "audit.json").is_file()
            )
        ]
    else:
        names = [
            line.strip()
            for line in targets.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(names) != len(set(names)):
            raise ValueError("target list contains duplicate directories")
        if any(Path(name).name != name or name in {".", ".."} for name in names):
            raise ValueError("targets must be immediate child directory names")
        directories = [root / name for name in names]
    if not directories:
        raise ValueError(f"no container audit directories found under {root}")
    for path in directories:
        if path.is_symlink() or not path.is_dir():
            raise ValueError(
                f"target must be an existing directory, not a symlink: {path}"
            )
    return directories


def resolve_audit_settings(
    root: Path | None = None, overrides: dict[str, object] | None = None
) -> argparse.Namespace:
    """Resolve saved evidence and its workspace from a directory or audit file."""
    explicit = dict(overrides or {})
    if root is not None and (
        root.is_file() or (root.suffix == ".json" and not root.is_dir())
    ):
        explicit["audit_file"] = explicit.get("audit_file") or root
        root = None
    selected = explicit.get("audit_file")
    if selected is not None and root is None:
        root = Path(selected).absolute().parent
        if root.name == "history":
            root = root.parent
    return resolve_settings(root or Path.cwd(), explicit)


def use_default_reports_directory(settings: argparse.Namespace) -> None:
    """Keep generated comparisons out of the audit workspace root."""
    if "output_dir" not in settings.configured:
        settings.output_dir = settings.audit_root / "reports"


def report_priorities(
    settings: argparse.Namespace, result: AuditReport
) -> dict[str, comparison.VulnerabilityPriority]:
    """Find conventional comparison evidence and verify it before display."""
    directories = []
    if "output_dir" in settings.configured:
        directories.append(settings.output_dir)
    directories.append(settings.audit_root / "reports")
    for directory in dict.fromkeys(directories):
        path = directory / "comparison.json"
        if path.exists() or path.is_symlink():
            return comparison.load_verified_priorities(path, result)
    return {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pygo-audit",
        description="Audit prepared containers. Roots default to cwd.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, (description, names) in COMMANDS.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument(
            "audit_root",
            type=Path,
            nargs="?",
            metavar="BATCH_AUDIT_ROOT"
            if name in {"audit", "aggregate"}
            else "AUDIT_ROOT",
            help=(
                "workspace or audit JSON (default: file's workspace, otherwise cwd)"
                if name in {"report", "check", "csaf"}
                else "workspace (default: current working directory)"
            ),
        )
        layers = (
            command.add_mutually_exclusive_group()
            if name in {"scan", "audit"}
            else command
        )
        for option in names:
            kind, default, help_text = OPTIONS[option]
            shown = True if name == "audit" and option == "strict" else default
            if option == "output_dir" and name in {"aggregate", "csaf"}:
                shown = "reports"
            description = help_text + (
                f" (default: {shown})" if shown is not None and shown != [] else ""
            )
            spec: dict[str, object] = {"default": None, "help": description}
            spec.update(
                {"action": argparse.BooleanOptionalAction}
                if kind is bool
                else {"type": kind}
            )
            if option == "layer_dir":
                spec["action"] = "append"
            elif isinstance(default, list):
                spec["nargs"] = "+"
            if option == "layer_sort":
                spec["choices"] = LAYER_SORTS
            owner = layers if option in {"layer_dir", "layers_dir"} else command
            owner.add_argument(f"--{option.replace('_', '-')}", **spec)
        if name == "report":
            command.add_argument(
                "--view",
                choices=report.REPORT_VIEWS,
                default="overview",
                help="view (default: overview)",
            )
        if name in {"report", "check"}:
            command.add_argument(
                "-v",
                "--verbose",
                action="count",
                default=0,
                help="increase text detail; repeat up to three times",
            )
            command.add_argument(
                "--wide",
                action="store_true",
                help="remove text entry limits and hash abbreviations",
            )
        if name == "check":
            command.add_argument(
                "--id",
                dest="identifiers",
                nargs="+",
                required=True,
                metavar="ID",
                help="CVE, GHSA, or GO identifiers",
            )
    return parser


def run(args: argparse.Namespace) -> int:
    command = args.command
    options = (
        resolve_audit_settings(args.audit_root, vars(args))
        if command in {"report", "check", "csaf"}
        else resolve_settings(args.audit_root or Path.cwd(), vars(args))
    )
    many = command in {"audit", "aggregate"} or (
        command == "csaf"
        and "audit_file" not in options.configured
        and not options.audit_file.is_file()
        and not options.rootfs.is_dir()
    )
    targets = [options]
    if many:
        inherited = {} if command == "aggregate" else options.configured
        if command == "audit":
            inherited = {
                "strict": True,
                **inherited,
                "cache_dir": options.cache_dir,
                "work_dir": options.work_dir,
            }
        targets = [
            resolve_settings(
                root, {} if command == "aggregate" else vars(args), inherited
            )
            for root in discover_audits(
                options.audit_root, options.targets if command == "audit" else None
            )
        ]
    if command in {"scan", "audit"}:
        for target in targets:
            target.image = resolve_image_identity(
                target.audit_root / "rootfs",
                metadata_path=target.image_metadata,
                **{
                    field: getattr(target, name.replace("-", "_"))
                    for name, field in SIDECAR_FIELDS.items()
                },
            )
        if command == "audit":
            return batch.run(options, targets)
        result = scan_workspace(options, run_id=uuid4().hex)[0]
        print(report.REPORT_VIEWS["overview"].render(result))
        return int(bool(options.strict and result.actionable_issues))
    if command == "csaf":
        for target in targets:
            use_default_reports_directory(target)
            if "csaf" not in target.configured:
                target.csaf = [source for source in options.csaf if source.exists()]
        return csaf.run(targets)
    if command == "aggregate":
        use_default_reports_directory(options)
        if "csaf" not in options.configured:
            options.csaf = []
        return aggregate.run(options, targets)
    result = load_audit(options.audit_file)
    policy = report_policy(args)
    priorities = (
        report_priorities(options, result)
        if command == "report" and (args.view == "binary-findings" or args.output_dir)
        else {}
    )
    if args.output_dir is not None:
        if command == "check":
            write_check_artifacts(result, options.output_dir, args.identifiers)
        else:
            write_report_artifacts(result, options.output_dir, priorities)
    if command == "check":
        output = report.render_checks(result, args.identifiers, policy)
    else:
        output = report.REPORT_VIEWS[args.view].render(
            result, policy, priorities=priorities
        )
    print(output)
    return int(bool(options.strict and result.actionable_issues))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"report", "check"}:
        if args.verbose > int(Verbosity.FORENSIC):
            parser.error("-v/--verbose may be repeated at most three times")
        if (
            args.command == "report"
            and report.REPORT_VIEWS[args.view].json
            and (args.verbose or args.wide)
        ):
            parser.error("text verbosity options cannot be used with --view json")
    try:
        return run(args)
    except (OSError, ValueError, ScanConfigurationError, ResultCacheError) as error:
        print(f"pygo-audit {args.command}: {error}", file=sys.stderr)
        return 1


def report_policy(args: argparse.Namespace) -> RenderPolicy:
    """Translate CLI verbosity into one immutable rendering policy."""
    return RenderPolicy(Verbosity(args.verbose), wide=args.wide)
