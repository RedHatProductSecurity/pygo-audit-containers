"""Stable public API for JSON and human-readable report rendering."""

from __future__ import annotations

import json
from typing import Sequence

from pygo_audit.models import ScanReport
from pygo_audit.report_views import (
    VALID_GROUPS,
    evaluate_checks,
    group_occurrences,
)
from pygo_audit.text_report import (
    render_binaries,
    render_check_result,
    render_checks,
    render_diagnostics,
    render_findings,
    render_grouped,
    render_overview,
)


def render_json(
    report: ScanReport,
    *,
    group_by: str | None = None,
    checks: Sequence[str] = (),
) -> str:
    if group_by not in {None, *VALID_GROUPS}:
        raise ValueError(f"unsupported finding group: {group_by}")
    document = report.to_dict()
    if group_by or checks:
        document["query"] = {
            "group_by": group_by,
            "result": report.result_state,
            "coverage": {
                "state": report.coverage_state,
                "complete": report.complete_vulnerability_scans,
                "incomplete": report.incomplete_vulnerability_scans,
            },
            "groups": _json_groups(report, group_by),
            "checks": [
                result.to_dict() for result in evaluate_checks(report, checks)
            ],
        }
    return json.dumps(document, indent=2, ensure_ascii=True)


def render_container(report: ScanReport) -> str:
    """Render visually grouped, container-level findings."""
    return render_findings(report)


def render_summary(report: ScanReport) -> str:
    """Render a compact but complete vulnerability overview."""
    return render_overview(report)


def render_text(report: ScanReport) -> str:
    """Render complete findings organized by binary."""
    return render_binaries(report)


def _json_groups(
    report: ScanReport,
    group_by: str | None,
) -> list[dict[str, object]]:
    if group_by is None:
        return []
    return [
        {
            "key": key,
            "findings": [occurrence.to_dict() for occurrence in occurrences],
        }
        for key, occurrences in group_occurrences(report, group_by).items()
    ]


__all__ = [
    "render_binaries",
    "render_check_result",
    "render_checks",
    "render_container",
    "render_diagnostics",
    "render_findings",
    "render_grouped",
    "render_json",
    "render_overview",
    "render_summary",
    "render_text",
]
