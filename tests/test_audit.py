from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.audit import AuditError, load_audit, parse_binary_report
from pygo_audit.storage import atomic_write_json, json_digest
from pygo_audit.models import (
    BinaryLayerObservation,
    BinaryReconciliation,
    BinaryReport,
    BuildSetting,
    ContainerMetadata,
    ImageIdentity,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
    ScanIssue,
    AuditReport,
    ScanStats,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)


class AuditTests(unittest.TestCase):
    def test_semantic_json_digest_remains_stable(self) -> None:
        self.assertEqual(
            json_digest(self._report().to_dict()),
            "3e1dcd63a34a5f5e43afc40bbeb5e3858be75844cae6c1a06a6dc8c4f25ca27e",
        )

    def test_current_and_historical_audits_use_the_same_reader(self) -> None:
        document = self._report().to_dict()
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name in (
                "audit.json",
                "history/audit-abc-20261024.json",
                "a" * 64 + ".json",
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    atomic_write_json(path, document)
                    self.assertEqual(load_audit(path).to_dict(), document)

    def test_requires_canonical_audit_provenance(self) -> None:
        document = self._report().to_dict()
        document.pop("producer_name")
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            atomic_write_json(path, document)
            with self.assertRaises(AuditError):
                load_audit(path)

    def test_observed_symbol_survives_saved_audit_and_cache_round_trip(self) -> None:
        report = self._report()
        binary = report.binaries[0]
        findings = binary.vulnerability_scan.vulnerabilities[0].findings
        findings[0] = replace(findings[0], symbol="Decoder.Decode")
        document = report.to_dict()
        cached = parse_binary_report(binary.to_dict())
        self.assertEqual(cached.finding_occurrences()[0].symbol, "Decoder.Decode")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            atomic_write_json(path, document)
            restored = load_audit(path)
        self.assertEqual(restored.to_dict(), document)
        self.assertEqual(restored.finding_occurrences()[0].symbol, "Decoder.Decode")

    def test_requires_the_current_integer_schema_version(self) -> None:
        canonical = self._report().to_dict()
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for version in (None, 1, 3, 5, True, 4.0, "4"):
                document = copy.deepcopy(canonical)
                if version is None:
                    document.pop("schema_version")
                else:
                    document["schema_version"] = version
                with self.subTest(version=version):
                    atomic_write_json(path, document, overwrite=True)
                    with self.assertRaises(AuditError):
                        load_audit(path)

    def test_optional_defaults_round_trip_with_required_provenance(self) -> None:
        report = AuditReport(
            metadata=ContainerMetadata("/tmp/root"),
            go_command="go",
            go_tool_version="go1.26",
            producer_name="pygo-audit",
            producer_version="test",
        )
        document = report.to_dict()
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            atomic_write_json(path, document)
            restored = load_audit(path)
        self.assertEqual(restored.to_dict(), document)
        self.assertEqual(restored.producer_name, "pygo-audit")
        self.assertEqual(restored.run_id, "")
        self.assertFalse(restored.metadata.image.is_present)

    def test_requires_an_explicit_existing_json_file(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            atomic_write_json(root / "audit.json", self._report().to_dict())
            for path in (root, root / "missing.json"):
                with self.subTest(path=path), self.assertRaises(AuditError):
                    load_audit(path)

    def test_invalid_json_or_nonobject_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for text, message in (("{", "not valid JSON"), ("[]", "not a JSON object")):
                path.write_text(text)
                with (
                    self.subTest(text=text),
                    self.assertRaisesRegex(AuditError, message),
                ):
                    load_audit(path)

    def test_digest_changes_with_toolchain_and_database(self) -> None:
        report = self._report()
        original = json_digest(report.to_dict())
        report.go_tool_version = "go version go1.26.9 linux/amd64"
        changed_toolchain = json_digest(report.to_dict())
        report.binaries[
            0
        ].vulnerability_scan.database_last_modified = "2026-09-24T00:00:00Z"
        changed_database = json_digest(report.to_dict())
        self.assertNotEqual(original, changed_toolchain)
        self.assertNotEqual(changed_toolchain, changed_database)

    def test_rejects_duplicate_keys_and_noninteger_json_numbers(self) -> None:
        document = json.dumps(self._report().to_dict())
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for text in (
                document.replace('"size": 123', '"size": 123, "size": 123'),
                *(
                    document.replace('"size": 123', f'"size": {value}')
                    for value in ("NaN", "Infinity", "-Infinity", "1e999", "123.0")
                ),
            ):
                with self.subTest(text=text):
                    path.write_text(text)
                    with self.assertRaises(AuditError):
                        load_audit(path)

    def test_reload_rechecks_mutated_model_invariants_with_field_context(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for field, value in (("runtime_disposition", "other"), ("sha256", "bad")):
                report = self._report()
                setattr(report.binaries[0], field, value)
                atomic_write_json(path, report.to_dict(), overwrite=True)
                with self.subTest(field=field), self.assertRaises(AuditError) as raised:
                    load_audit(path)
                self.assertIn(f"audit.binaries[0].{field} ", str(raised.exception))
                with self.assertRaises(AuditError) as cached:
                    parse_binary_report(report.binaries[0].to_dict())
                self.assertIn(f"binary.{field} ", str(cached.exception))

    def test_rejects_missing_unknown_malformed_and_inconsistent_fields(self) -> None:
        document = self._report().to_dict()
        mutations = (
            (("producer_name",), ""),
            (("producer_version",), ""),
            (("binaries", 0, "size"), True),
            (("binaries", 0, "size"), -1),
            (("binaries", 0, "size"), "123"),
            (("stats", "directories"), -1),
            (("stats", "directories"), True),
            (("metadata", "root"), None),
            (("metadata", "image"), None),
            (("binaries", 0, "extra"), "unexpected"),
            (("binaries", 0, "cgo_enabled"), False),
            (("runtime_dispositions",), {"runtime": 9}),
            (("dependency_summary",), []),
            (("vulnerability_databases",), []),
            (("unaccounted_historical",), {"binary_count": 0, "finding_count": 0}),
            (("metadata", "type"), "unpacked_rootfs"),
            (("binaries", 0, "paths"), []),
            (("binaries", 0, "paths"), [False]),
            (("binaries", 0, "sha256"), "a" * 63),
            (("binaries", 0, "sha256"), "A" * 64),
            (("binaries", 0, "sha256"), "z" * 64),
            (("binaries", 0, "runtime_disposition"), "maybe"),
            (("binaries", 0, "main_module", "replace"), []),
            (("binaries", 0, "dependencies", 0, "replace", "path"), None),
            (("binaries", 0, "layer_history", 0, "layer_index"), True),
            (("binaries", 0, "layer_history", 0, "layer_index"), -1),
            (("binaries", 0, "layer_history", 0, "status"), "maybe"),
            (("binaries", 0, "layer_history", 0, "paths"), [1]),
            (("govulncheck_status",), "maybe"),
            (("binaries", 0, "vulnerability_scan", "status"), "maybe"),
            (("binaries", 0, "vulnerability_scan", "scanner_name"), {}),
            (("binaries", 0, "vulnerability_scan", "database"), {}),
            (("binaries", 0, "vulnerability_scan", "sbom", "roots"), [False]),
            (
                (
                    "binaries",
                    0,
                    "vulnerability_scan",
                    "vulnerabilities",
                    0,
                    "affected",
                    0,
                    "packages",
                ),
                [{"path": "/app"}],
            ),
            (
                (
                    "binaries",
                    0,
                    "vulnerability_scan",
                    "vulnerabilities",
                    0,
                    "findings",
                    0,
                    "evidence",
                ),
                "maybe",
            ),
            (
                (
                    "binaries",
                    0,
                    "vulnerability_scan",
                    "vulnerabilities",
                    0,
                    "findings",
                    0,
                    "reachability",
                ),
                "maybe",
            ),
            (("binaries", 0, "reconciliation", "status"), "maybe"),
            (("binaries", 0, "reconciliation", "go_version_status"), "maybe"),
            (("binaries", 0, "reconciliation", "sbom_modules", 0, "status"), "maybe"),
            (
                ("binaries", 0, "reconciliation", "sbom_modules", 0, "inventory_entry"),
                [],
            ),
            (
                (
                    "binaries",
                    0,
                    "reconciliation",
                    "effective_module_inventory",
                    0,
                    "source",
                ),
                "maybe",
            ),
            (
                (
                    "binaries",
                    0,
                    "reconciliation",
                    "effective_module_inventory",
                    0,
                    "replacement",
                ),
                True,
            ),
        )
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for keys, replacement in mutations:
                value = copy.deepcopy(document)
                parent = value
                for key in keys[:-1]:
                    parent = parent[key]
                parent[keys[-1]] = replacement
                with self.subTest(keys=keys):
                    atomic_write_json(path, value, overwrite=True)
                    with self.assertRaises(AuditError):
                        load_audit(path)

    def test_every_nested_evidence_object_requires_its_declared_fields(self) -> None:
        canonical = self._report().to_dict()
        binary = ("binaries", 0)
        scan = (*binary, "vulnerability_scan")
        vulnerability = (*scan, "vulnerabilities", 0)
        reconciliation = (*binary, "reconciliation")
        object_paths = (
            (),
            ("metadata",),
            ("metadata", "image"),
            ("stats",),
            ("issues", 0),
            binary,
            (*binary, "main_module"),
            (*binary, "dependencies", 0),
            (*binary, "dependencies", 0, "replace"),
            (*binary, "build_settings", 0),
            (*binary, "layer_history", 0),
            scan,
            vulnerability,
            (*vulnerability, "findings", 0),
            (*vulnerability, "findings", 0, "reconciliation"),
            (*vulnerability, "findings", 0, "reconciliation", "inventory_entry"),
            reconciliation,
            (*reconciliation, "effective_module_inventory", 0),
            (*reconciliation, "sbom_modules", 0),
            (*reconciliation, "sbom_modules", 0, "inventory_entry"),
        )
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for keys in object_paths:
                evidence = canonical
                for key in keys:
                    evidence = evidence[key]
                for field in (*evidence, "unexpected"):
                    document = copy.deepcopy(canonical)
                    target = document
                    for key in keys:
                        target = target[key]
                    if field == "unexpected":
                        target[field] = "not evidence"
                    else:
                        target.pop(field)
                    with self.subTest(path=keys, field=field):
                        atomic_write_json(path, document, overwrite=True)
                        with self.assertRaises(AuditError):
                            load_audit(path)

    def test_raw_vulnerability_evidence_requires_its_recorded_structure(self) -> None:
        canonical = self._report().binaries[0].to_dict()
        scan = ("vulnerability_scan",)
        vulnerability = (*scan, "vulnerabilities", 0)
        affected = (*vulnerability, "affected", 0)
        mutations = (
            ((*scan, "sbom"), {}),
            ((*scan, "sbom", "extra"), "unknown"),
            ((*scan, "sbom", "modules"), [False]),
            ((*scan, "sbom", "modules"), [{"path": "example.test/library"}]),
            ((*scan, "sbom", "modules", 0, "version"), 1),
            ((*scan, "sbom", "modules", 0, "extra"), "unknown"),
            ((*vulnerability, "references"), ["https://example.test"]),
            ((*vulnerability, "references", 0), {"url": "https://example.test"}),
            ((*vulnerability, "references", 0, "url"), 1),
            ((*vulnerability, "references", 0, "extra"), "unknown"),
            ((*affected, "module"), []),
            ((*affected, "ecosystem"), False),
            ((*affected, "extra"), "unknown"),
            ((*affected, "version_ranges"), [{}]),
            ((*affected, "version_ranges"), [{"type": "SEMVER", "events": [{}]}]),
            (
                (*affected, "version_ranges"),
                [{"type": "SEMVER", "events": [{"fixed": 1}]}],
            ),
            (
                (*affected, "version_ranges"),
                [{"type": "SEMVER", "events": [{"extra": "v1"}]}],
            ),
            ((*affected, "packages"), [{"path": "/app", "symbols": [], "goos": []}]),
            (
                (*affected, "packages"),
                [
                    {
                        "path": "/app",
                        "symbols": [False],
                        "goos": [],
                        "goarch": [],
                    }
                ],
            ),
            (
                (*affected, "packages"),
                [
                    {
                        "path": "/app",
                        "symbols": [],
                        "goos": [],
                        "goarch": [],
                        "extra": "unknown",
                    }
                ],
            ),
        )
        for keys, replacement in mutations:
            value = copy.deepcopy(canonical)
            target = value
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = replacement
            with self.subTest(keys=keys, replacement=replacement):
                with self.assertRaises(AuditError):
                    parse_binary_report(value)

    def test_binary_parser_rejects_nonstring_object_keys(self) -> None:
        value = self._report().binaries[0].to_dict()
        value[1] = "unexpected"
        with self.assertRaisesRegex(AuditError, "keys must be strings"):
            parse_binary_report(value)

    def test_reconciliation_counters_preserve_recorded_comparisons(self) -> None:
        value = self._report().binaries[0].to_dict()
        finding = value["vulnerability_scan"]["vulnerabilities"][0]["findings"][0]
        finding["reconciliation"]["status"] = "representation_difference"
        value["reconciliation"]["sbom_modules"] *= 2
        loaded = parse_binary_report(value)
        self.assertEqual(loaded.finding_statuses, {"representation_difference": 1})
        self.assertEqual(loaded.reconciliation.sbom_statuses, {"exact": 2})
        self.assertEqual(loaded.to_dict(), value)

    def test_reconciliation_uses_declared_fields_without_computed_replacement_flag(
        self,
    ) -> None:
        binary = self._report().binaries[0].to_dict()
        reconciliation = binary["reconciliation"]
        self.assertEqual(reconciliation["go_version_status"], "exact")
        self.assertEqual(reconciliation["go_version_m"], "go1.26.8")
        self.assertEqual(reconciliation["govulncheck_go_version"], "go1.26.8")
        entry = reconciliation["effective_module_inventory"][0]
        self.assertEqual(
            entry,
            {
                "source": "dependency",
                "declared_path": "example.test/library",
                "declared_version": "v1.0.0",
                "effective_path": "example.test/library",
                "effective_version": "v1.0.0",
            },
        )
        finding = binary["vulnerability_scan"]["vulnerabilities"][0]["findings"][0]
        self.assertEqual(finding["reconciliation"]["inventory_entry"], entry)
        self.assertEqual(
            finding["reconciliation"]["govulncheck_path"], "example.test/library"
        )
        self.assertEqual(finding["reconciliation"]["govulncheck_version"], "v1.0.0")

    def test_key_order_and_formatting_do_not_change_evidence(self) -> None:
        document = self._report().to_dict()
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
            self.assertEqual(load_audit(path).to_dict(), document)

    def test_unsorted_model_evidence_serializes_into_a_valid_audit(self) -> None:
        report = self._report()
        other = copy.deepcopy(report.binaries[0])
        other.paths = ["/z-alias", "/z-app"]
        other.sha256 = "b" * 64
        report.binaries.insert(0, other)
        report.issues.insert(0, ScanIssue("/z-app", "open", "failed"))
        document = report.to_dict()
        self.assertEqual(document["binaries"][0]["paths"][0], "/bin/app")
        self.assertEqual(document["issues"][0]["path"], "/bin/app")
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            atomic_write_json(path, document)
            self.assertEqual(load_audit(path).to_dict(), document)
            for keys in (
                ("binaries",),
                ("issues",),
                ("binaries", 0, "paths"),
            ):
                reversed_document = copy.deepcopy(document)
                sequence = reversed_document
                for key in keys:
                    sequence = sequence[key]
                sequence.reverse()
                with self.subTest(reversed=keys):
                    atomic_write_json(path, reversed_document, overwrite=True)
                    with self.assertRaises(AuditError):
                        load_audit(path)
        binary = copy.deepcopy(document["binaries"][0])
        binary["paths"].reverse()
        with self.assertRaises(AuditError):
            parse_binary_report(binary)

    def test_evidence_sequences_keep_their_recorded_order(self) -> None:
        report = self._report()
        binary = report.binaries[0]
        binary.dependencies.append(Module(path="example.test/aaa", version="v2.0.0"))
        binary.build_settings.extend(
            [BuildSetting("Z", "last"), BuildSetting("A", "first")]
        )
        binary.layer_history.append(
            BinaryLayerObservation(1, "found", ("/z-app", "/a-app"))
        )
        vulnerability = binary.vulnerability_scan.vulnerabilities[0]
        vulnerability.aliases = ["GHSA-zzzz-yyyy-xxxx", "CVE-2026-0001"]
        vulnerability.findings.append(
            VulnerabilityFinding(
                module="example.test/aaa",
                evidence="symbol",
            )
        )
        binary.vulnerability_scan.vulnerabilities.append(
            Vulnerability(id="GO-2026-0000")
        )

        document = report.to_dict()

        evidence = document["binaries"][0]
        self.assertEqual(
            [item["path"] for item in evidence["dependencies"]],
            ["example.test/original", "example.test/aaa"],
        )
        self.assertEqual(
            [item["key"] for item in evidence["build_settings"]],
            ["CGO_ENABLED", "Z", "A"],
        )
        self.assertEqual(evidence["layer_history"][1]["paths"], ["/z-app", "/a-app"])
        self.assertEqual(
            [item["id"] for item in evidence["vulnerability_scan"]["vulnerabilities"]],
            ["GO-2026-0001", "GO-2026-0000"],
        )
        first = evidence["vulnerability_scan"]["vulnerabilities"][0]
        self.assertEqual(first["aliases"], ["GHSA-zzzz-yyyy-xxxx", "CVE-2026-0001"])
        self.assertEqual(
            [item["module"] for item in first["findings"]],
            ["example.test/library", "example.test/aaa"],
        )
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            atomic_write_json(path, document)
            self.assertEqual(load_audit(path).to_dict(), document)

    @staticmethod
    def _report() -> AuditReport:
        inventory_entry = ModuleInventoryEntry(
            source="dependency",
            declared_path="example.test/library",
            declared_version="v1.0.0",
            effective_path="example.test/library",
            effective_version="v1.0.0",
        )
        module_reconciliation = ModuleReconciliation(
            status="exact",
            govulncheck_path="example.test/library",
            govulncheck_version="v1.0.0",
            inventory_entry=inventory_entry,
            detail="matches",
        )
        vulnerability_scan = VulnerabilityScan(
            status="complete",
            protocol_version="v1.0.0",
            scanner_name="govulncheck",
            scanner_version="v1.2.3",
            database="https://vuln.go.dev",
            database_last_modified="2026-09-23T00:00:00Z",
            go_version="go1.26.8",
            scan_mode="binary",
            scan_level="symbol",
            sbom={
                "go_version": "go1.26.8",
                "modules": [{"path": "example.test/library", "version": "v1.0.0"}],
                "roots": [],
            },
            vulnerabilities=[
                Vulnerability(
                    id="GO-2026-0001",
                    aliases=["CVE-2026-0001"],
                    details="test vulnerability",
                    published="2026-01-01T00:00:00Z",
                    modified="2026-01-02T00:00:00Z",
                    review_status="REVIEWED",
                    advisory_url="https://pkg.go.dev/vuln/GO-2026-0001",
                    references=[{"type": "WEB", "url": "https://example.test"}],
                    affected=[
                        {
                            "module": "example.test/library",
                            "ecosystem": "Go",
                            "version_ranges": [],
                            "packages": [],
                        }
                    ],
                    findings=[
                        VulnerabilityFinding(
                            module="example.test/library",
                            found_version="v1.0.0",
                            fixed_version="v1.1.0",
                            package="example.test/library/decoder",
                            evidence="symbol",
                            reachability="unspecified",
                            reconciliation=module_reconciliation,
                        )
                    ],
                )
            ],
        )
        binary = BinaryReport(
            paths=["/usr/bin/app", "/bin/app"],
            size=123,
            sha256="a" * 64,
            runtime_disposition="runtime",
            layer_history=[
                BinaryLayerObservation(
                    layer_index=0,
                    status="found",
                    paths=("/usr/bin/app",),
                )
            ],
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=Module(path="example.test/app", version="v2.0.0"),
            dependencies=[
                Module(
                    path="example.test/original",
                    version="v1.0.0",
                    checksum="h1:abc",
                    replace=Module(
                        path="example.test/library",
                        version="v1.0.0",
                        checksum="h1:def",
                    ),
                )
            ],
            build_settings=[BuildSetting(key="CGO_ENABLED", value="1")],
            vulnerability_scan=vulnerability_scan,
            reconciliation=BinaryReconciliation(
                status="matched",
                go_version_status="exact",
                go_version_m="go1.26.8",
                govulncheck_go_version="go1.26.8",
                effective_module_inventory=[inventory_entry],
                sbom_modules=[module_reconciliation],
            ),
        )
        return AuditReport(
            metadata=ContainerMetadata(
                root="/tmp/root",
                image=ImageIdentity(
                    reference="registry.example.test/team/app:v1",
                    digest="sha256:" + "b" * 64,
                    platform="linux/amd64",
                    extractor="oc image extract",
                    name="openshift/example",
                    component="example-container",
                    source_git_url="https://github.com/example/project",
                    product_version="v4.20.0",
                    component_version="v1.2.3-4-gabcdef0",
                    product_component="Example",
                    cpes=("cpe:/a:redhat:openshift:4.20::el9",),
                ),
            ),
            binaries=[binary],
            issues=[
                ScanIssue(
                    path="/bin/app",
                    stage="reconciliation-difference",
                    message="equivalent representations",
                )
            ],
            stats=ScanStats(
                directories=2,
                entries=3,
                regular_files=2,
                unique_regular_files=1,
                elf_paths=2,
                unique_elf_files=1,
            ),
            go_command="/usr/bin/go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
            govulncheck_status="available",
            govulncheck_command="/usr/bin/govulncheck",
            govulncheck_tool_version="govulncheck@v1.2.3",
            scan_started_at="2026-09-23T12:00:00Z",
            scan_completed_at="2026-09-23T12:00:01Z",
        )


if __name__ == "__main__":
    unittest.main()
