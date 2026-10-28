"""Parse and normalize govulncheck's streaming JSON output."""

from __future__ import annotations

import json
from typing import Any

from pygo_audit.models import (
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)

EVIDENCE_RANK = {"module": 0, "package": 1, "symbol": 2}


class GovulncheckOutputError(ValueError):
    """Raised when govulncheck does not return a valid JSON message stream."""


def parse_govulncheck_json(output: str) -> VulnerabilityScan:
    messages = _decode_json_stream(output)
    config: dict[str, Any] | None = None
    sbom: dict[str, Any] | None = None
    advisories: dict[str, dict[str, Any]] = {}
    raw_findings: list[dict[str, Any]] = []

    for message in messages:
        if not isinstance(message, dict):
            raise GovulncheckOutputError("govulncheck emitted a non-object message")
        if isinstance(message.get("config"), dict):
            config = message["config"]
        elif isinstance(message.get("SBOM"), dict):
            sbom = message["SBOM"]
        elif isinstance(message.get("osv"), dict):
            advisory = message["osv"]
            identifier = _string(advisory.get("id"))
            if identifier:
                advisories[identifier] = advisory
        elif isinstance(message.get("finding"), dict):
            raw_findings.append(message["finding"])

    if config is None:
        raise GovulncheckOutputError(
            "govulncheck JSON does not contain a config message"
        )

    findings_by_id: dict[str, list[VulnerabilityFinding]] = {}
    for raw_finding in raw_findings:
        identifier = _string(raw_finding.get("osv"))
        if not identifier:
            continue
        finding = _normalize_finding(raw_finding)
        findings_by_id.setdefault(identifier, []).append(finding)

    scan_level = _string(config.get("scan_level"))
    minimum_evidence = EVIDENCE_RANK.get(scan_level, 0)
    vulnerabilities = []
    for identifier, findings in findings_by_id.items():
        if not any(
            EVIDENCE_RANK[finding.evidence] >= minimum_evidence for finding in findings
        ):
            continue
        vulnerabilities.append(
            _normalize_advisory(
                identifier,
                advisories.get(identifier, {}),
                _strongest_findings(findings),
            )
        )
    vulnerabilities.sort(key=lambda vulnerability: vulnerability.id)

    normalized_sbom = _normalize_sbom(sbom) if sbom is not None else None
    sbom_go_version = ""
    if normalized_sbom is not None:
        sbom_go_version = _string(normalized_sbom.get("go_version"))

    return VulnerabilityScan(
        status="complete",
        protocol_version=_string(config.get("protocol_version")),
        scanner_name=_string(config.get("scanner_name")),
        scanner_version=_string(config.get("scanner_version")),
        database=_string(config.get("db")),
        database_last_modified=_string(config.get("db_last_modified")),
        go_version=_string(config.get("go_version")) or sbom_go_version,
        scan_mode=_string(config.get("scan_mode")),
        scan_level=scan_level,
        sbom=normalized_sbom,
        vulnerabilities=vulnerabilities,
    )


def _decode_json_stream(output: str) -> list[object]:
    decoder = json.JSONDecoder()
    messages: list[object] = []
    position = 0

    while position < len(output):
        while position < len(output) and output[position].isspace():
            position += 1
        if position == len(output):
            break
        try:
            message, position = decoder.raw_decode(output, position)
        except json.JSONDecodeError as error:
            raise GovulncheckOutputError(
                f"invalid govulncheck JSON at character {error.pos}: {error.msg}"
            ) from error
        messages.append(message)

    if not messages:
        raise GovulncheckOutputError("govulncheck returned no JSON messages")
    return messages


def _normalize_finding(value: dict[str, Any]) -> VulnerabilityFinding:
    trace = value.get("trace")
    frame: dict[str, Any] = {}
    if isinstance(trace, list) and trace and isinstance(trace[0], dict):
        frame = trace[0]

    function = _string(frame.get("function"))
    receiver = _string(frame.get("receiver"))
    symbol = ".".join(part for part in (receiver, function) if part)

    package = _string(frame.get("package"))
    if symbol:
        evidence = "symbol"
    elif package:
        evidence = "package"
    else:
        evidence = "module"

    return VulnerabilityFinding(
        module=_string(frame.get("module")),
        found_version=_string(frame.get("version")),
        fixed_version=_string(value.get("fixed_version")),
        package=package,
        evidence=evidence,
        symbol=symbol or None,
    )


def _strongest_findings(
    findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    candidates = list(dict.fromkeys(findings))
    retained = []

    for candidate in candidates:
        candidate_rank = EVIDENCE_RANK[candidate.evidence]
        subsumed = any(
            EVIDENCE_RANK[other.evidence] > candidate_rank
            and other.module == candidate.module
            and (
                not candidate.found_version
                or not other.found_version
                or other.found_version == candidate.found_version
            )
            and (not candidate.package or other.package == candidate.package)
            for other in candidates
        )
        if not subsumed:
            retained.append(candidate)

    retained.sort(
        key=lambda finding: (
            finding.module,
            finding.found_version,
            finding.package,
            finding.fixed_version,
            finding.symbol or "",
        )
    )
    return retained


def _normalize_advisory(
    identifier: str,
    value: dict[str, Any],
    findings: list[VulnerabilityFinding],
) -> Vulnerability:
    database_specific = value.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}

    references = dict.fromkeys(
        (_string(reference.get("type")), _string(reference.get("url")))
        for reference in _objects(value.get("references"))
    )

    return Vulnerability(
        id=identifier,
        aliases=_unique_strings(value.get("aliases")),
        details=_string(value.get("details")),
        published=_string(value.get("published")),
        modified=_string(value.get("modified")),
        withdrawn=_string(value.get("withdrawn")),
        review_status=(_string(database_specific.get("review_status")) or "REVIEWED"),
        advisory_url=_string(database_specific.get("url")),
        references=[
            {"type": kind, "url": url} for kind, url in references if kind or url
        ],
        affected=[
            _normalize_affected(item) for item in _objects(value.get("affected"))
        ],
        findings=findings,
    )


def _normalize_affected(value: dict[str, Any]) -> dict[str, Any]:
    package = value.get("package")
    if not isinstance(package, dict):
        package = {}

    version_ranges = []
    for raw_range in _objects(value.get("ranges")):
        events = []
        for raw_event in _objects(raw_range.get("events")):
            event = {
                key: raw_event[key]
                for key in ("introduced", "fixed", "last_affected", "limit")
                if isinstance(raw_event.get(key), str)
            }
            if event:
                events.append(event)
        version_ranges.append(
            {"type": _string(raw_range.get("type")), "events": events}
        )

    ecosystem_specific = value.get("ecosystem_specific")
    if not isinstance(ecosystem_specific, dict):
        ecosystem_specific = {}

    return {
        "module": _string(package.get("name")),
        "ecosystem": _string(package.get("ecosystem")),
        "version_ranges": version_ranges,
        "packages": [
            {
                "path": _string(item.get("path")),
                "symbols": _strings(item.get("symbols")),
                "goos": _strings(item.get("goos")),
                "goarch": _strings(item.get("goarch")),
            }
            for item in _objects(ecosystem_specific.get("imports"))
        ],
    }


def _normalize_sbom(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "go_version": _string(value.get("go_version")),
        "modules": [
            {
                "path": _string(module.get("path")),
                "version": _string(module.get("version")),
            }
            for module in _objects(value.get("modules"))
        ],
        "roots": _strings(value.get("roots")),
    }


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _objects(value: object) -> list[dict[str, Any]]:
    return [item for item in _list(value) if isinstance(item, dict)]


def _strings(value: object) -> list[str]:
    return [item for item in _list(value) if isinstance(item, str)]


def _unique_strings(value: object) -> list[str]:
    return list(dict.fromkeys(_strings(value)))


def _string(value: object) -> str: return value if isinstance(value, str) else ""
