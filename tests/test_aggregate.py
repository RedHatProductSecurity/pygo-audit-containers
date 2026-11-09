from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import csv
from dataclasses import replace
from functools import partial
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest.mock import patch

from pygo_audit import aggregate, csaf, csaf_workflow, image_csaf, models
from pygo_audit.audit import load_audit
from pygo_audit.cli import main, resolve_settings, use_default_reports_directory
from pygo_audit.storage import atomic_write_text
from pygo_audit.text_layout import RenderPolicy, Verbosity


def make_workspace(
    root: Path,
    name: str,
    cves: tuple[str, ...],
    *,
    evidence: str = "symbol",
    identity: models.ImageIdentity | None = None,
) -> Path:
    directory = root / name
    (directory / "rootfs").mkdir(parents=True)
    binary = models.BinaryReport(
        paths=[f"/usr/bin/{name}"],
        size=123,
        go_version="go1.24",
        main_package="main",
        main_module=None,
        dependencies=[],
        build_settings=[],
        sha256="a" * 64,
        runtime_disposition="runtime",
        vulnerability_scan=models.VulnerabilityScan(
            status="complete",
            vulnerabilities=[
                models.Vulnerability(
                    cve,
                    findings=[
                        models.VulnerabilityFinding(
                            module="example.test/app",
                            found_version="v1.0.0",
                            fixed_version="v1.1.0",
                            package="example.test/app/pkg",
                            evidence=evidence,
                            symbol="Unsafe" if evidence == "symbol" else None,
                        )
                    ],
                )
                for cve in cves
            ],
        ),
    )
    report = models.AuditReport(
        metadata=models.ContainerMetadata(
            str(directory / "rootfs"),
            identity
            or models.ImageIdentity(name="app", csaf_product_ids=("component",)),
        ),
        binaries=[binary],
        go_command="go",
        go_tool_version="test",
        producer_name="pygo-audit",
        producer_version="test",
    )
    (directory / "audit.json").write_text(json.dumps(report.to_dict()))
    return directory


def write_document(
    directory: Path,
    name: str,
    statuses: dict[str, str],
    flags: dict[str, str] | None = None,
    *,
    purl: str = "pkg:oci/app@v1.0.0",
    scores: list[dict[str, Any]] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for cve, status in statuses.items():
        record: dict[str, Any] = {"cve": cve, "product_status": {status: ["component"]}}
        if scores:
            record["scores"] = scores
        if flags and cve in flags:
            record["flags"] = [{"label": flags[cve], "product_ids": ["component"]}]
        records.append(record)
    document = {
        "document": {
            "tracking": {"id": name.removesuffix(".json")},
            "references": [
                {"category": "self", "url": "https://vendor.example/" + name.lower()},
            ],
        },
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "component",
                    "product_identification_helper": {"purl": purl},
                }
            ]
        },
        "vulnerabilities": records,
    }
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def fail_publication(
    fail_at: Path, path: Path, content: str, *, overwrite: bool = False
) -> None:
    if path == fail_at:
        raise OSError("publication failed")
    atomic_write_text(path, content, overwrite=overwrite)


class AggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.csaf = self.root / "csaf"
        self.csaf.mkdir()

    def run_batch(self, *flags: str) -> dict[str, Any]:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(
                main(["aggregate", str(self.root), *flags]), 0, errors.getvalue()
            )
        return json.loads((self.root / "reports/aggregate.json").read_text())

    def test_batch_matches_standalone_and_parallel_results_without_cross_container_cves(
        self,
    ) -> None:
        cves = tuple(f"CVE-2026-{index:04d}" for index in range(1, 5))
        alpha = make_workspace(self.root, "alpha", cves[:2])
        beta = make_workspace(self.root, "beta", cves[1:3], evidence="module")
        paths = {
            cve: write_document(
                self.csaf,
                f"source-{index}.json",
                {cve: "known_not_affected" if index == 2 else "known_affected"},
                {cve: "component_not_present"} if index == 2 else None,
            )
            for index, cve in enumerate(cves, 1)
        }
        audits = {
            directory: (directory / "audit.json").read_bytes()
            for directory in (alpha, beta)
        }
        with patch("pygo_audit.scanner.scan_root") as scan:
            serial = self.run_batch("--jobs", "1", "--wide")
            parallel = self.run_batch("--jobs", "2", "--wide")
        scan.assert_not_called()
        self.assertEqual(serial, parallel)
        self.assertEqual(serial["summary"]["container_count"], 2)
        self.assertEqual(serial["summary"]["unique_cves"], 3)
        self.assertEqual(serial["summary"]["metrics"]["comparisons"], 4)
        self.assertEqual(serial["summary"]["metrics"]["discrepancies"], 2)
        for directory, selected in ((alpha, cves[:2]), (beta, cves[1:3])):
            actual = next(
                container
                for container in serial["containers"]
                if container["container_name"] == directory.name
            )
            source = image_csaf.prepare_image(
                directory / "audit.json", load_audit(directory / "audit.json")
            )
            expected = image_csaf.check_image(
                source.path,
                source.report,
                [paths[cve] for cve in selected],
                [self.csaf],
            )
            self.assertEqual({key: actual[key] for key in expected}, expected)
            self.assertEqual(set(actual["conclusions"]), set(selected))
            self.assertEqual(actual["summary"]["documents_checked"], 2)
            self.assertEqual((directory / "audit.json").read_bytes(), audits[directory])
            self.assertTrue((directory / "reports/comparison.txt").is_file())
        self.assertNotIn(
            cves[3], (self.root / "reports/pygo-audit-triage.csv").read_text()
        )

    def test_document_work_is_shared_but_local_conclusions_are_not(self) -> None:
        cve = "CVE-2026-0001"
        make_workspace(self.root, "alpha", (cve,))
        make_workspace(self.root, "beta", (cve,), evidence="module")
        write_document(
            self.csaf,
            "advisory.json",
            {cve: "known_not_affected"},
            {cve: "component_not_present"},
        )
        with (
            patch.object(csaf, "index_document", wraps=csaf.index_document) as index,
            patch.object(
                image_csaf, "match_candidates", wraps=image_csaf.match_candidates
            ) as match,
            patch.object(
                image_csaf, "summarize_cve", wraps=image_csaf.summarize_cve
            ) as summarize,
        ):
            result = self.run_batch("--jobs", "1")
        index.assert_called_once()
        match.assert_called_once()
        self.assertEqual(summarize.call_count, 2)
        states = {
            container["container_name"]: container["conclusions"][cve]["agreement"][
                "comparison"
            ]
            for container in result["containers"]
        }
        self.assertEqual(states, {"alpha": "no", "beta": "qualified_no"})
        self.assertEqual(result["summary"]["unique_cves"], 1)
        cases = aggregate.triage_cases(result)
        self.assertEqual([case.agreement for case in cases], ["no", "qualified_no"])
        self.assertEqual([case.evidence for case in cases], [("symbol",), ("module",)])

    def test_multi_cve_sources_keep_record_numbers_and_clean_containers_have_no_cases(
        self,
    ) -> None:
        first, second = "CVE-2026-0001", "CVE-2026-0002"
        for name, selected in (("alpha", (first,)), ("beta", (second,)), ("clean", ())):
            make_workspace(self.root, name, selected)
        write_document(
            self.csaf,
            "not-a-cve-filename.json",
            {first: "known_affected", second: "fixed"},
        )
        result = self.run_batch("--jobs", "1")
        for container in result["containers"]:
            name = container["container_name"]
            if name == "clean":
                self.assertEqual(container["conclusions"], {})
                self.assertEqual(container["documents"], [])
            else:
                record = container["documents"][0]["vulnerabilities"][0]
                self.assertEqual(record["id"], first if name == "alpha" else second)
                self.assertEqual(record["record"], 1 if name == "alpha" else 2)
        self.assertEqual(len(aggregate.triage_cases(result)), 2)

    def test_cached_absence_overrides_retained_json_and_other_cves_are_not_inherited(
        self,
    ) -> None:
        cve = "CVE-2026-0001"
        make_workspace(self.root, "alpha", (cve,))
        source = write_document(self.csaf, cve + ".json", {cve: "known_affected"})
        self.run_batch("--jobs", "1")
        source.with_suffix(".missing").write_text(
            json.dumps(
                {
                    "url": "https://vendor.example/missing",
                    "status": 404,
                    "checked_at": "2000-01-01T00:00:00Z",
                }
            )
        )
        (self.csaf / "CVE-2026-9999.missing").write_text(
            json.dumps(
                {
                    "url": "https://vendor.example/other",
                    "status": 404,
                    "checked_at": "2000-01-01T00:00:00Z",
                }
            )
        )
        result = self.run_batch("--jobs", "1")
        container = result["containers"][0]
        self.assertTrue(source.is_file())
        self.assertEqual(container["documents"], [])
        self.assertEqual(set(container["missing_documents"]), {cve})
        self.assertEqual(container["conclusions"][cve]["match"], "no_document")
        self.assertEqual(
            container["conclusions"][cve]["local_scan"]["status"], "affected"
        )

    def test_current_documents_are_re_read_and_prior_comparisons_are_not_inputs(
        self,
    ) -> None:
        cve = "CVE-2026-0001"
        make_workspace(self.root, "alpha", (cve,))
        for status, expected in (("known_affected", "yes"), ("fixed", "qualified_no")):
            with self.subTest(status=status):
                write_document(self.csaf, "advisory.json", {cve: status})
                result = self.run_batch("--jobs", "1")
                self.assertEqual(
                    result["containers"][0]["conclusions"][cve]["agreement"][
                        "comparison"
                    ],
                    expected,
                )

    def test_csv_preserves_qualifications_multiple_values_and_final_provenance(
        self,
    ) -> None:
        cve = "CVE-2026-0001"
        make_workspace(self.root, "=alpha,one", (cve,))
        source = self.root / "=alpha,one/audit.json"
        report = load_audit(source)
        report.metadata.image = replace(
            report.metadata.image,
            reference="registry.example.test/team/app:v1",
            platform="linux/amd64",
            csaf_product_ids=(),
            purls=("pkg:oci/app@v1.0.0?arch=amd64",),
        )
        source.write_text(json.dumps(report.to_dict()))
        write_document(
            self.csaf,
            "first.json",
            {cve: "known_affected"},
            purl="pkg:oci/app@v1.0.0?arch=arm64",
            scores=[{"cvss_v3": {"version": "3.1", "baseScore": 7.5}}],
        )
        write_document(
            self.csaf,
            "second.json",
            {cve: "fixed"},
            purl="pkg:oci/app@v1.0.0?arch=arm64",
            scores=[{"cvss_v3": {"version": "3.1", "baseScore": 8.1}}],
        )
        result = self.run_batch("--jobs", "1", "-v", "--wide")
        csv_path = self.root / "reports/pygo-audit-triage.csv"
        rows = list(csv.DictReader(io.StringIO(csv_path.read_text())))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(tuple(row), aggregate.TRIAGE_COLUMNS)
        self.assertEqual(row["CONTAINER"], "'=alpha,one")
        self.assertEqual(aggregate.csv_cell(("module", "symbol")), "module; symbol")
        self.assertEqual(row["CVSS SCORE"], "7.5; 8.1")
        self.assertEqual(row["PYGO ASSESSMENT"], "Affected")
        self.assertEqual(row["AGREEMENT"], "Mixed")
        self.assertEqual(row["EVIDENCE"], "symbol")
        self.assertEqual(row["BINARIES"], "1")
        self.assertEqual(
            row["CSAF URL"].split("; "),
            [
                "https://vendor.example/first.json",
                "https://vendor.example/second.json",
            ],
        )
        self.assertEqual(row["CONTAINER URL"], "registry.example.test/team/app:v1")
        text = (self.root / "reports/aggregate.txt").read_text()
        self.assertEqual(text.count("[PROVENANCE]"), 1)
        self.assertGreater(text.index("[PROVENANCE]"), text.index("CVSS SCORING"))
        for level in (Verbosity.SUMMARY, Verbosity.EXPANDED, Verbosity.DETAILED):
            preview = aggregate.render_text(result, RenderPolicy(level, wide=True))
            self.assertNotIn("[PROVENANCE]", preview)
            self.assertEqual(preview.count("More information:"), 1)
        self.assertEqual(aggregate.render_aggregate_report(result), text)

    def test_triage_cases_sort_by_cvss_then_container_then_agreement(self) -> None:
        cases = [
            aggregate.TriageCase(
                "zeta", "CVE-2026-0001", (9.0,), "affected", "", "no", (), 0, (), ""
            ),
            aggregate.TriageCase(
                "alpha",
                "CVE-2026-0002",
                (9.0,),
                "affected",
                "",
                "qualified_no",
                (),
                0,
                (),
                "",
            ),
            aggregate.TriageCase(
                "alpha", "CVE-2026-0003", (10.0,), "affected", "", "no", (), 0, (), ""
            ),
            aggregate.TriageCase(
                "alpha", "CVE-2026-0004", (9.0,), "affected", "", "no", (), 0, (), ""
            ),
            aggregate.TriageCase(
                "alpha", "CVE-2026-0005", (8.1,), "affected", "", "yes", (), 0, (), ""
            ),
            aggregate.TriageCase(
                "alpha", "CVE-2026-0006", (), "affected", "", "no", (), 0, (), ""
            ),
        ]
        ordered = sorted(cases, key=aggregate.TriageCase.review_key)
        self.assertEqual(
            [(case.container, case.agreement, case.cve) for case in ordered],
            [
                ("alpha", "no", "CVE-2026-0003"),
                ("alpha", "no", "CVE-2026-0004"),
                ("alpha", "qualified_no", "CVE-2026-0002"),
                ("zeta", "no", "CVE-2026-0001"),
                ("alpha", "yes", "CVE-2026-0005"),
                ("alpha", "no", "CVE-2026-0006"),
            ],
        )

    def test_binary_hashes_keep_different_contents_at_one_path_distinct(self) -> None:
        cve = "CVE-2026-0001"
        directory = make_workspace(self.root, "alpha", (cve,))
        source = directory / "audit.json"
        report = load_audit(source)
        report.binaries.append(
            replace(report.binaries[0], sha256="b" * 64, runtime_disposition="deleted")
        )
        source.write_text(json.dumps(report.to_dict()))
        write_document(self.csaf, "advisory.json", {cve: "known_affected"})
        result = self.run_batch("--jobs", "1")
        artifacts = result["containers"][0]["local_findings"][cve]
        self.assertEqual(
            {artifact["sha256"] for artifact in artifacts}, {"a" * 64, "b" * 64}
        )
        self.assertEqual(aggregate.triage_cases(result)[0].binary_count, 2)

    def test_all_outputs_roll_back_together_on_csv_failure(self) -> None:
        cve = "CVE-2026-0001"
        make_workspace(self.root, "alpha", (cve,))
        write_document(self.csaf, "advisory.json", {cve: "known_affected"})
        self.run_batch("--jobs", "1")
        paths = [
            *self.root.glob("reports/*aggregate*"),
            self.root / "reports" / aggregate.TRIAGE_FILENAME,
            *self.root.glob("alpha/reports/comparison.*"),
        ]
        previous = {path: path.read_bytes() for path in paths}
        write_document(self.csaf, "advisory.json", {cve: "fixed"})
        with (
            patch(
                "pygo_audit.artifacts.atomic_write_text",
                side_effect=partial(
                    fail_publication, self.root / "reports/pygo-audit-triage.csv"
                ),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(main(["aggregate", str(self.root), "--jobs", "1"]), 1)
        self.assertIn("publication failed", errors.getvalue())
        self.assertEqual({path: path.read_bytes() for path in paths}, previous)

    def test_invalid_audit_and_render_failure_preserve_existing_outputs(self) -> None:
        cve = "CVE-2026-0001"
        directory = make_workspace(self.root, "alpha", (cve,))
        write_document(self.csaf, "advisory.json", {cve: "known_affected"})
        self.run_batch("--jobs", "1")
        paths = [
            *self.root.glob("reports/*aggregate*"),
            self.root / "reports" / aggregate.TRIAGE_FILENAME,
            *self.root.glob("alpha/reports/comparison.*"),
        ]
        previous = {path: path.read_bytes() for path in paths}
        with (
            patch.object(
                image_csaf, "render_text", side_effect=ValueError("invalid view")
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["aggregate", str(self.root), "--jobs", "1"]), 1)
        self.assertEqual({path: path.read_bytes() for path in paths}, previous)
        (directory / "audit.json").write_text('{"binaries": []}')
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["aggregate", str(self.root), "--jobs", "1"]), 1)
        self.assertEqual({path: path.read_bytes() for path in paths}, previous)

    def test_inputs_and_scan_subjects_cannot_become_output_files(self) -> None:
        cve = "CVE-2026-0001"
        directory = make_workspace(self.root, "alpha", (cve,))
        source = write_document(self.csaf, "advisory.json", {cve: "known_affected"})
        collision = self.csaf / "pygo-audit-triage.csv"
        collision.write_bytes(source.read_bytes())
        before = collision.read_bytes()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "aggregate",
                        str(self.root),
                        "--csaf",
                        str(collision),
                        "--output-dir",
                        str(self.csaf),
                        "--jobs",
                        "1",
                    ]
                ),
                1,
            )
            self.assertEqual(
                main(
                    [
                        "aggregate",
                        str(self.root),
                        "--output-dir",
                        str(directory / "rootfs"),
                        "--jobs",
                        "1",
                    ]
                ),
                1,
            )
        self.assertEqual(collision.read_bytes(), before)
        self.assertFalse((directory / "reports/comparison.json").exists())

    def test_worker_read_failure_is_visible_in_serial_and_parallel_modes(self) -> None:
        cve = "CVE-2026-0001"
        directory = make_workspace(self.root, "alpha", (cve,))
        source = write_document(self.csaf, "first.json", {cve: "known_affected"})
        write_document(self.csaf, "second.json", {cve: "fixed"})
        settings = resolve_settings(directory, {"csaf": [self.csaf]})
        use_default_reports_directory(settings)
        targets = csaf_workflow.load_workspaces([settings])
        source.unlink()
        for jobs in (1, 2):
            with (
                self.subTest(jobs=jobs),
                self.assertRaisesRegex(csaf.CsafCheckError, "cannot read CSAF"),
            ):
                csaf_workflow.compare_workspaces(targets, jobs=jobs, recorded_only=True)
        self.assertFalse((directory / "reports").exists())
