"""Human-readable and JSON report rendering."""

from __future__ import annotations

import json

from pygo_audit.models import Module, ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True)


def render_text(report: ScanReport) -> str:
    lines = [
        f"Found {report.stats.go_binaries} Go binaries "
        f"at {report.stats.go_binary_paths} paths under {report.root}.",
        "",
    ]

    for binary in report.binaries:
        lines.append(binary.paths[0])
        if len(binary.paths) > 1:
            lines.append(f"  hardlinks: {', '.join(binary.paths[1:])}")
        lines.append(f"  Go: {binary.go_version}")
        if binary.main_package:
            lines.append(f"  package: {binary.main_package}")
        if binary.main_module is not None:
            lines.append(f"  module: {_format_module(binary.main_module)}")
        lines.append(f"  dependencies ({len(binary.dependencies)}):")
        if binary.dependencies:
            for dependency in binary.dependencies:
                lines.append(f"    {_format_module(dependency)}")
        else:
            lines.append("    none")

        settings = {setting.key: setting.value for setting in binary.build_settings}
        selected_settings = []
        for key in ("GOOS", "GOARCH", "CGO_ENABLED", "vcs.revision", "vcs.modified"):
            if key in settings:
                selected_settings.append(f"{key}={settings[key]}")
        if selected_settings:
            lines.append(f"  build: {', '.join(selected_settings)}")
        lines.append("")

    summary = report.dependency_summary()
    lines.append(f"Dependency summary ({len(summary)} unique module versions):")
    if summary:
        for item in summary:
            used_by = item["used_by"]
            lines.append(
                f"  {_format_summary_module(item)} [{len(used_by)} path(s)]"
            )
    else:
        lines.append("  none")

    if report.issues:
        lines.extend(("", f"Issues ({len(report.issues)}):"))
        for issue in sorted(report.issues, key=lambda item: (item.path, item.stage)):
            lines.append(f"  {issue.path} [{issue.stage}]: {issue.message}")

    return "\n".join(lines)


def _format_module(module: Module) -> str:
    base = module.path
    if module.version:
        base = f"{base} {module.version}"
    if module.replace is not None:
        base = f"{base} => {_format_module(module.replace)}"
    return base or "(unknown module)"


def _format_summary_module(value: dict[str, object]) -> str:
    path = value.get("path")
    version = value.get("version")
    base = str(path) if path else "(unknown module)"
    if version:
        base = f"{base} {version}"
    replacement = value.get("replace")
    if isinstance(replacement, dict):
        base = f"{base} => {_format_summary_module(replacement)}"
    return base
