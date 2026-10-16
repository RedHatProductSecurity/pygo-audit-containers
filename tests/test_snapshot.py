from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.snapshot import SnapshotError, load_snapshot, write_snapshot
from pygo_audit.models import (
    BinaryReconciliation,
    BinaryReport,
    BuildSetting,
    ImageIdentity,
    Module,
    ModuleInventoryEntry,
    ModuleReconciliation,
    ScanIssue,
    ScanReport,
    ScanStats,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilityScan,
)


class SnapshotTests(unittest.TestCase):
    def test_round_trips_an_immutable_content_addressed_report(self) -> None:
        report = self._report()
        with TemporaryDirectory() as temporary_directory:
            snapshot_directory = Path(temporary_directory) / "snapshots"

            snapshot_path = write_snapshot(report, snapshot_directory)
            original_mtime = snapshot_path.stat().st_mtime_ns
            repeated_path = write_snapshot(report, snapshot_directory)
            loaded = load_snapshot(snapshot_path)
            loaded_from_directory = load_snapshot(snapshot_directory)
            repeated_mtime = repeated_path.stat().st_mtime_ns

        self.assertEqual(len(snapshot_path.stem), 64)
        self.assertEqual(snapshot_path.suffix, ".json")
        self.assertEqual(repeated_path, snapshot_path)
        self.assertEqual(repeated_mtime, original_mtime)
        self.assertEqual(loaded.to_dict(), report.to_dict())
        self.assertEqual(loaded_from_directory.to_dict(), report.to_dict())

    def test_requires_canonical_snapshot_provenance(self) -> None:
        document = self._report().to_dict()
        document.pop("producer")
        with TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "report.json"
            report_path.write_text(
                json.dumps(document),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(SnapshotError, "producer must be an object"):
                load_snapshot(report_path)

    def test_refuses_to_replace_a_tampered_content_address(self) -> None:
        report = self._report()
        with TemporaryDirectory() as temporary_directory:
            snapshot_directory = Path(temporary_directory)
            snapshot_path = write_snapshot(report, snapshot_directory)
            snapshot_path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(SnapshotError, "content address"):
                write_snapshot(report, snapshot_directory)

    def test_rejects_tampered_content_address_when_loading(self) -> None:
        report = self._report()
        with TemporaryDirectory() as temporary_directory:
            snapshot_path = write_snapshot(report, Path(temporary_directory))
            document = json.loads(snapshot_path.read_text(encoding="utf-8"))
            document["root"] = "/tampered"
            snapshot_path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(SnapshotError, "content address"):
                load_snapshot(snapshot_path)

    def test_loads_generic_portable_snapshot_by_recomputed_identity(self) -> None:
        report = self._report()
        with TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "audit.json"
            report_path.write_text(
                json.dumps(report.to_dict()),
                encoding="utf-8",
            )

            loaded = load_snapshot(report_path)

        self.assertEqual(loaded.to_dict(), report.to_dict())

    def test_requires_file_when_directory_has_multiple_snapshots(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            snapshot_directory = Path(temporary_directory)
            (snapshot_directory / "one.json").write_text("{}", encoding="utf-8")
            (snapshot_directory / "two.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(SnapshotError, "contains 2 snapshots"):
                load_snapshot(snapshot_directory)

    def test_content_address_changes_with_toolchain_and_database(self) -> None:
        report = self._report()
        with TemporaryDirectory() as temporary_directory:
            snapshot_directory = Path(temporary_directory)
            original = write_snapshot(report, snapshot_directory)

            report.go_tool_version = "go version go1.26.9 linux/amd64"
            changed_toolchain = write_snapshot(report, snapshot_directory)

            report.binaries[0].vulnerability_scan.database_last_modified = (
                "2026-09-24T00:00:00Z"
            )
            changed_database = write_snapshot(report, snapshot_directory)

        self.assertNotEqual(original, changed_toolchain)
        self.assertNotEqual(changed_toolchain, changed_database)

    @staticmethod
    def _report() -> ScanReport:
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
                "modules": [
                    {"path": "example.test/library", "version": "v1.0.0"}
                ],
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
                    affected=[{"module": "example.test/library"}],
                    findings=[
                        VulnerabilityFinding(
                            module="example.test/library",
                            found_version="v1.0.0",
                            fixed_version="v1.1.0",
                            package="example.test/library/decoder",
                            symbol="Decode",
                            evidence="symbol",
                            reachability="unknown",
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
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=Module(path="example.test/app", version="v2.0.0"),
            dependencies=[
                Module(
                    path="example.test/original",
                    version="v1.0.0",
                    sum="h1:abc",
                    replace=Module(
                        path="example.test/library",
                        version="v1.0.0",
                        sum="h1:def",
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
                finding_statuses={"exact": 1},
                sbom_statuses={"exact": 1},
            ),
        )
        return ScanReport(
            root="/tmp/root",
            go_command="/usr/bin/go",
            go_tool_version="go version go1.26.8 linux/amd64",
            producer_name="pygo-audit",
            producer_version="0.1.0",
            govulncheck_status="available",
            govulncheck_command="/usr/bin/govulncheck",
            govulncheck_tool_version="govulncheck@v1.2.3",
            scan_started_at="2026-09-23T12:00:00Z",
            scan_completed_at="2026-09-23T12:00:01Z",
            image_identity=ImageIdentity(
                reference="registry.example.test/team/app:v1",
                digest="sha256:" + "b" * 64,
                platform="linux/amd64",
                extractor="oc image extract",
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
                go_binaries=1,
                go_binary_paths=2,
            ),
        )


if __name__ == "__main__":
    unittest.main()
