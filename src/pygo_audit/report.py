"""Public API for human-readable reports and machine-readable exports."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import partial
import json

from pygo_audit.models import AuditReport
from pygo_audit.report_views import (
    index_cve_evidence,
    module_identifiers,
    package_identifiers,
)
from pygo_audit.text_report import (
    render_binaries,
    render_by_vulnerability,
    render_check_results,
    render_checks,
    render_diagnostics,
    render_module_reconciliation,
    render_overview,
)
from pygo_audit.text_layout import RenderPolicy, SUMMARY_POLICY


@dataclass(slots=True, frozen=True)
class ReportView:
    """Bind one CLI view to its deterministic artifact renderer."""

    filename: str
    render: Callable[[AuditReport, RenderPolicy], str]
    machine_readable: bool = False


def render_json(
    report: AuditReport,
    policy: RenderPolicy = SUMMARY_POLICY,
) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True)


def render_identifiers(
    report: AuditReport,
    policy: RenderPolicy = SUMMARY_POLICY,
    *,
    select: Callable[[AuditReport], Iterable[str]],
) -> str:
    """Export one unique identifier per line, without presentation limits."""
    return "\n".join(sorted(set(select(report)) - {""}))


REPORT_VIEWS = {
    name: ReportView(f"{name}.txt", renderer)
    for name, renderer in (
        ("overview", render_overview),
        ("binary-findings", render_binaries),
        ("vulnerability-findings", render_by_vulnerability),
        ("module-reconciliation", render_module_reconciliation),
        ("diagnostics", render_diagnostics),
    )
}
REPORT_VIEWS.update(
    (name, ReportView(f"{name}.txt", partial(render_identifiers, select=select), True))
    for name, select in (
        ("cves", index_cve_evidence),
        ("modules", module_identifiers),
        ("packages", package_identifiers),
    )
)
REPORT_VIEWS["json"] = ReportView("audit.json", render_json, True)  # Publish last.


__all__ = [
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
