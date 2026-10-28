"""Stable public API for JSON and human-readable report rendering."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from typing import Mapping, Sequence

from pygo_audit.models import AuditReport
from pygo_audit.comparison import VulnerabilityPriority
from pygo_audit.report_views import evaluate_checks
from pygo_audit.text_report import (
    render_binaries,
    render_by_vulnerability,
    render_check_results,
    render_checks,
    render_diagnostics,
    render_module_reconciliation,
    render_overview,
)
from pygo_audit.text_layout import RenderPolicy, SUMMARY_POLICY, FULL_POLICY


@dataclass(slots=True, frozen=True)
class ReportView:
    """Bind one CLI view to its deterministic artifact renderer."""

    name: str
    filename: str
    renderer: Callable[[AuditReport, RenderPolicy], str]
    json: bool = False

    def render(
        self,
        report: AuditReport,
        policy: RenderPolicy = SUMMARY_POLICY,
        *,
        priorities: Mapping[str, VulnerabilityPriority] | None = None,
    ) -> str:
        if self.name == "binary-findings":
            return render_binaries(report, policy, priorities=priorities)
        return self.renderer(report, policy)


def render_json(
    report: AuditReport,
    *,
    checks: Sequence[str] = (),
) -> str:
    document = report.to_dict()
    if checks:
        document["query"] = {
            "result": report.result_state,
            "coverage": {
                "state": report.coverage_state,
                "complete": report.complete_vulnerability_scans,
                "incomplete": report.incomplete_vulnerability_scans,
            },
            "checks": [result.to_dict() for result in evaluate_checks(report, checks)],
        }
    return json.dumps(document, indent=2, ensure_ascii=True)


def render_json_view(report: AuditReport, policy: RenderPolicy) -> str:
    return render_json(report)


REPORT_VIEWS = {
    view.name: view
    for view in (
        ReportView("overview", "overview.txt", render_overview),
        ReportView("binary-findings", "binary-findings.txt", render_binaries),
        ReportView(
            "vulnerability-findings",
            "vulnerability-findings.txt",
            render_by_vulnerability,
        ),
        ReportView(
            "module-reconciliation",
            "module-reconciliation.txt",
            render_module_reconciliation,
        ),
        ReportView("diagnostics", "diagnostics.txt", render_diagnostics),
        ReportView(
            "json", "audit.json", render_json_view, json=True
        ),  # Publish canonical evidence last.
    )
}


def render_full_report(report: AuditReport) -> str:
    """Compose exhaustive text views using the same registry as saved reports."""
    return "\n\n".join(
        view.render(report, FULL_POLICY)
        for view in REPORT_VIEWS.values()
        if not view.json
    )


__all__ = [
    "render_full_report",
    "REPORT_VIEWS",
    "render_binaries",
    "render_by_vulnerability",
    "render_check_results",
    "render_checks",
    "render_diagnostics",
    "render_module_reconciliation",
    "render_json",
    "render_overview",
]
