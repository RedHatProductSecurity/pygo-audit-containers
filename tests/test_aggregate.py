from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


from pygo_audit import aggregate, comparison, models
from pygo_audit.audit import AuditError


def report(
    *binaries: models.BinaryReport, image: models.ImageIdentity = models.ImageIdentity()
) -> models.AuditReport:
    return models.AuditReport(
        metadata=models.ContainerMetadata("/rootfs", image),
        binaries=list(binaries),
        go_command="go",
        go_tool_version="go1.24.0",
        producer_name="pygo-audit",
        producer_version="0.1.0",
    )


def symbol_evidence(cve: str) -> models.CveEvidence:
    vulnerability = models.Vulnerability(cve, findings=[models.VulnerabilityFinding(evidence="symbol")])
    binary = models.BinaryReport(
        ["/app"], 1, "go1.26", "", None, [], [], runtime_disposition="runtime",
        vulnerability_scan=models.VulnerabilityScan(vulnerabilities=[vulnerability]),
    )
    return models.CveEvidence(cve, ((binary, vulnerability),))


def report_with_cves(cves: tuple[str, ...], *, image: models.ImageIdentity = models.ImageIdentity()) -> models.AuditReport:
    return report(models.BinaryReport(
        ["/app"], 1, "go1.26", "", None, [], [], runtime_disposition="runtime",
        vulnerability_scan=models.VulnerabilityScan(vulnerabilities=[models.Vulnerability(cve) for cve in cves]),
    ), image=image)


class AggregateAuditTests(unittest.TestCase):
    def test_build_result_evaluates_each_cve_once(self) -> None:
        target = aggregate.TargetAudit(
            1, Path("example"), report_with_cves(("CVE-2026-0001", "CVE-2026-0002"))
        )
        with patch("pygo_audit.comparison.evaluate", wraps=comparison.evaluate) as evaluate:
            result = aggregate.build_result([target])
        self.assertEqual(evaluate.call_count, len(target.evidence))
        container = result["containers"][0]
        self.assertEqual(container["summary"]["metrics"]["unknown_cves"], 2)
        self.assertEqual(container["audit_summary"]["pygo_cve_vex_unverified"], 2)

    def test_work_queue_processes_more_cves_than_workers_for_each_target(self) -> None:
        cves = tuple(f"CVE-2026-{index:04d}" for index in range(1, 8))
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for cve in cves[:-1]:
                (root / f"{cve}.json").write_text(json.dumps({
                    "vulnerabilities": [{
                        "cve": cve, "product_status": {"known_affected": ["app"]},
                    }],
                }))
            serial = None
            for jobs in (1, 2):
                targets = [
                    aggregate.TargetAudit(
                        index, root / str(index),
                        report_with_cves(selected, image=models.ImageIdentity(name="app")),
                    )
                    for index, selected in enumerate((cves[:5], cves[2:]), 1)
                ]
                with self.subTest(jobs=jobs):
                    aggregate.enrich_with_csaf(
                        targets, aggregate.argparse.Namespace(csaf=[root], jobs=jobs)
                    )
                    for target in targets:
                        self.assertEqual(set(target.assessments), set(tuple(target.evidence)))
                        for cve, assessment in target.assessments.items():
                            self.assertEqual(assessment["cve"], cve)
                            self.assertEqual(
                                assessment["assessment"],
                                "document_missing" if cve == cves[-1] else "component",
                            )
                    results = [target.assessments for target in targets]
                    if serial is None:
                        serial = results
                    else:
                        self.assertEqual(results, serial)

    def test_work_queue_propagates_worker_read_failures(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cve = "CVE-2026-0001"
            target = aggregate.TargetAudit(
                1, root, report_with_cves((cve,)),
            )
            for jobs in (1, 2):
                with (
                    self.subTest(jobs=jobs),
                    patch.object(aggregate.csaf, "document_locations", return_value={
                        cve: root / "removed-after-indexing.json",
                    }),
                    self.assertRaisesRegex(aggregate.csaf.CsafCheckError, "cannot read CSAF"),
                ):
                    aggregate.enrich_with_csaf(
                        [target], aggregate.argparse.Namespace(csaf=[root], jobs=jobs)
                    )

    def test_other_columns_only_count_unknown_tokens_in_their_category(self) -> None:
        cve = "CVE-2026-0001"
        statuses = [
            "status:known_affected",
            "flag:component_not_present",
            "remediation:vendor_fix",
        ]
        target = aggregate.TargetAudit(
            index=1,
            directory=Path("example"),
            report=report_with_cves((cve,)),
            assessments={cve: {"assessment": "component", "statuses": statuses}},
        )
        row = aggregate.summary_row(target)
        self.assertEqual(row["csaf_status_other"], 0)
        self.assertEqual(row["csaf_remediation_other"], 0)
        self.assertEqual(row["csaf_flag_component_not_present"], 1)
        self.assertEqual(row["csaf_remediation_vendor_fix"], 1)
        statuses.extend(
            [
                "status:future_status",
                "flag:future_flag",
                "remediation:future_remediation",
            ]
        )
        row = aggregate.summary_row(target)
        self.assertEqual(row["csaf_status_other"], 1)
        self.assertEqual(row["csaf_remediation_other"], 1)

    def test_json_preserves_counts_and_empty_cve_evidence(
        self,
    ) -> None:
        binary = models.BinaryReport(
            paths=["/historical"],
            size=123,
            go_version="go1.24.0",
            main_package="main",
            main_module=None,
            dependencies=[],
            build_settings=[],
            sha256="a" * 64,
            runtime_disposition="unaccounted",
            vulnerability_scan=models.VulnerabilityScan(
                status="complete",
                vulnerabilities=[
                    models.Vulnerability(
                        "GO-2026-0001",
                        aliases=[
                            "CVE-2026-0001",
                            "cve-2026-0001",
                            "CVE-2026-0002",
                            "GHSA-example",
                        ],
                    ),
                ],
            ),
        )
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "audit.json"
            source.write_text(json.dumps(report(binary).to_dict()))
            target = aggregate.load_target(root, source)
            row = aggregate.summary_row(target)
            json_path, text_path = aggregate.aggregate(
                [target], root, aggregate.argparse.Namespace(csaf=[], jobs=1)
            )
            document = json.loads(json_path.read_text())
            self.assertIn("N/A (0/0)", text_path.read_text())
        summary = document["containers"][0]["audit_summary"]
        self.assertEqual(summary, row)
        self.assertEqual(summary["finding_row_count"], 2)
        self.assertEqual(summary["unaccounted_historical_finding_count"], 2)
        self.assertEqual(document["summary"]["metrics"]["observed_cves"], 2)
        self.assertEqual(tuple(target.evidence), ("CVE-2026-0001", "CVE-2026-0002"))
        self.assertEqual(
            target.evidence[tuple(target.evidence)[0]].runtime_dispositions, {"unaccounted"}
        )
        self.assertEqual(target.evidence[tuple(target.evidence)[0]].evidence_types, set())

    def test_duplicate_identities_and_later_workers_reuse_csaf_assessments(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "advisory.json"
            cve = "CVE-2026-0001"
            source.write_text(
                json.dumps({"vulnerabilities": [{"cve": cve}]}), encoding="utf-8"
            )
            identities = {
                index: models.ImageIdentity() for index in (1, 2)
            }
            for _ in range(2):
                with patch.object(
                    aggregate.csaf,
                    "assess_indexed_document",
                    wraps=aggregate.csaf.assess_indexed_document,
                ) as matcher:
                    _, results = aggregate.assess_cve_worker(cve, source, identities)
                    self.assertEqual(results[1], results[2])
                    matcher.assert_called_once()

    def test_canonical_metadata_preserves_product_columns_and_csaf_matching(
        self,
    ) -> None:
        document = report(
            image=models.ImageIdentity(
                product_version="v4.20.0",
                product_component="Example",
            )
        ).to_dict()
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            path = root / "audit.json"
            path.write_text(json.dumps(document))
            target = aggregate.load_target(root, path)
        metadata = aggregate.image_metadata(target)
        self.assertEqual(metadata["product_version"], "v4.20.0")
        self.assertEqual(metadata["product_component"], "Example")
        self.assertTrue(aggregate.csaf.release_matches("product-4.20", target.report.metadata.image))

    def test_rejects_partial_audits(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            path = root / "audit.json"
            path.write_text(json.dumps({"binaries": []}))
            with self.assertRaises(AuditError):
                aggregate.load_target(root, path)

    def test_load_target_rejects_binary_cache_objects(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "001-example"
            target.mkdir(parents=True)
            (target / "audit.json").write_text(
                json.dumps(
                    {
                        "binary": {"runtime_disposition": {"state": "requires-observation"}},
                        "vulnerability_validity": {"run_id": "test-run", "profile": {}},
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(AuditError):
                aggregate.load_target(target, target / "audit.json")

    def test_cpe_candidates_are_reported_without_becoming_container_conclusions(
        self,
    ) -> None:
        target = aggregate.TargetAudit(
            index=1,
            directory=Path("example"),
            report=report_with_cves(("CVE-2026-0001",)),
        )
        target.evidence["CVE-2026-0001"] = symbol_evidence("CVE-2026-0001")
        for scope in [
            "cpe",
            "cpe_compatible",
            "cpe_version_family",
            "cpe_parent",
            "cpe_parent_compatible",
            "cpe_parent_version_family",
        ]:
            with self.subTest(scope=scope):
                target.assessments["CVE-2026-0001"] = {
                    "assessment": scope,
                    "match_level": "platform",
                    "statuses": [
                        "status:known_affected",
                        "status:fixed",
                        "flag:vulnerable_code_not_present",
                    ],
                    "cpe_candidate_count": 1,
                    "cpe_statuses": ["status:known_affected", "status:fixed"],
                    "cpe_known_affected": True,
                }
                details = comparison.vex_details(target.assessments.get("CVE-2026-0001"))
                self.assertEqual(details.comparison, "unverified")
                self.assertEqual(details.resolutions, frozenset())
                self.assertEqual(aggregate._csaf_counters(target)["product"], {})
                result = aggregate.build_result([target])
                metrics = result["summary"]["metrics"]
                self.assertEqual(metrics["comparable_cves"], 0)
                self.assertEqual(metrics["unknown_cves"], 1)
                self.assertIsNone(metrics["corroboration"]["percent"])
                summary = aggregate.summary_row(target)
                self.assertEqual(summary["csaf_cpe_candidate_count"], 1)
                self.assertEqual(summary["csaf_cpe_known_affected"], 1)
                self.assertEqual(summary["csaf_known_affected"], 0)
                self.assertEqual(summary[f"csaf_{scope}"], 1)

    def test_writes_text_json_and_preserves_reconciliation_counters(self) -> None:
        product_id = "red_hat_openshift_4.20/ose/example-rhel9_amd64"
        finding = models.VulnerabilityFinding(
            module="example/module",
            package="example/package",
            found_version="v1.0.0",
            fixed_version="v1.1.0",
            evidence="symbol",
            reconciliation=models.ModuleReconciliation(
                "representation_difference",
                "example/module",
                "v1.0.0",
                detail="same release",
            ),
        )
        binary = models.BinaryReport(
            paths=["/usr/bin/example"],
            size=123,
            go_version="go1.24.0",
            main_package="main",
            main_module=models.Module("example/module"),
            dependencies=[],
            build_settings=[],
            sha256="a" * 64,
            runtime_disposition="runtime",
            vulnerability_scan=models.VulnerabilityScan(
                status="complete",
                vulnerabilities=[
                    models.Vulnerability(
                        "GO-2026-0001", aliases=["CVE-2026-0001"], findings=[finding]
                    ),
                ],
            ),
            reconciliation=models.BinaryReconciliation(
                status="matched_with_differences",
                go_version_status="representation_difference",
                sbom_modules=[
                    models.ModuleReconciliation("unverifiable", "example/sbom-one", ""),
                    models.ModuleReconciliation("unverifiable", "example/sbom-two", ""),
                ],
            ),
        )
        audit = report(
            binary,
            image=models.ImageIdentity(
                reference="registry.example/example@sha256:" + "b" * 64,
                digest="sha256:" + "b" * 64,
                platform="linux/amd64",
                name="openshift/example-rhel9",
                component="example",
                source_git_url="https://github.com/example/example",
                product_version="v4.20.0",
                component_version="abc1234",
                product_component="example-maintainer",
                cpe="cpe:/a:example:example:4.20",
            ),
        ).to_dict()
        csaf_document = {
            "document": {
                "title": "Example CVE",
                "aggregate_severity": {"text": "Moderate"},
                "tracking": {
                    "id": "CVE-2026-0001",
                    "current_release_date": "2026-01-01T00:00:00Z",
                },
            },
            "product_tree": {"branches": [{"product": {"product_id": product_id}}]},
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "product_status": {"known_affected": [product_id]},
                }
            ],
        }
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "openshift-audit"
            target = root / "001-example"
            target.mkdir(parents=True)
            (target / "audit.json").write_text(json.dumps(audit), encoding="utf-8")
            csaf_path = root / "CVE-2026-0001.json"
            csaf_path.write_text(json.dumps(csaf_document), encoding="utf-8")
            args = aggregate.argparse.Namespace(
                csaf=[csaf_path], jobs=1
            )
            json_path, text_path = aggregate.aggregate(
                [aggregate.load_target(target, target / "audit.json")], root, args
            )
            args.jobs = 2
            parallel_json, parallel_text = aggregate.aggregate(
                [aggregate.load_target(target, target / "audit.json")], root / "parallel", args
            )
            self.assertEqual(parallel_json.read_bytes(), json_path.read_bytes())
            self.assertEqual(parallel_text.read_bytes(), text_path.read_bytes())
            document = json.loads(json_path.read_text())
            text = text_path.read_text()
            self.assertFalse(list(root.glob("*.csv")))

        self.assertEqual(len(document["containers"]), 1)
        container = document["containers"][0]
        summary = container["audit_summary"]
        self.assertEqual(container["image"]["source_git_url"], "https://github.com/example/example")
        self.assertEqual(container["image"]["component_version"], "abc1234")
        self.assertEqual(container["image"]["product_component"], "example-maintainer")
        self.assertEqual(container["image"]["product_version"], "v4.20.0")
        self.assertEqual(container["comparisons"]["CVE-2026-0001"]["comparison"], "agreement")
        self.assertIn("VEX COVERAGE", text)
        self.assertIn("100% (1/1)", text)
        self.assertIn("/usr/bin/example", text)
        self.assertIn("status:known_affected", text)
        self.assertEqual(summary["pygo_finding_reconciliation_representation_difference"], 1)
        self.assertEqual(summary["pygo_go_version_representation_difference"], 1)
        self.assertEqual(summary["pygo_sbom_reconciliation_unverifiable"], 2)
        self.assertEqual(summary["csaf_component_release_architecture"], 1)
        self.assertEqual(summary["csaf_known_affected"], 1)
        self.assertEqual(summary["pygo_cve_vex_agreement"], 1)

    def test_distinguishes_resolved_and_unexplained_not_affected_results(self) -> None:
        target = aggregate.TargetAudit(
            index=1,
            directory=Path("example"),
            report=report_with_cves(("CVE-2026-0001",)),
        )
        target.assessments["CVE-2026-0001"] = {
            "assessment": "component",
            "statuses": ["status:known_not_affected"],
        }
        self.assertEqual(
            comparison.vex_details(target.assessments.get("CVE-2026-0001")).comparison,
            "mismatch",
        )
        target.assessments["CVE-2026-0001"]["statuses"].append(
            "status:flag:vulnerable_code_not_present"
        )
        details = comparison.vex_details(target.assessments.get("CVE-2026-0001"))
        self.assertEqual(details.comparison, "resolved_difference")
        self.assertEqual(details.flags, frozenset({"vulnerable_code_not_present"}))
        self.assertEqual(details.resolutions, frozenset({"code_not_present"}))
        evidence = symbol_evidence("CVE-2026-0001")
        self.assertEqual(comparison.cve_comparison(details, evidence), "code_presence_conflict")
        target.assessments["CVE-2026-0001"]["statuses"].append("status:known_affected")
        details = comparison.vex_details(target.assessments["CVE-2026-0001"])
        self.assertEqual(details.comparison, "conflicting_vex")
        self.assertEqual(comparison.cve_comparison(details, evidence), "conflicting_vex")


class AggregatePublicationTests(unittest.TestCase):
    def test_render_failure_keeps_existing_reports(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            paths = [root / "aggregate.json", root / "aggregate.txt"]
            for path in paths:
                path.write_text("previous result\n")
            with (
                patch.object(aggregate, "render_text", side_effect=ValueError("invalid row")),
                self.assertRaisesRegex(ValueError, "invalid row"),
            ):
                aggregate.aggregate([], root, aggregate.argparse.Namespace(csaf=[], jobs=1))
            for path in paths:
                self.assertEqual(path.read_text(), "previous result\n")
            self.assertEqual(set(root.iterdir()), set(paths))

    def test_outputs_cannot_replace_audit_or_csaf_inputs(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_path = root / "aggregate.json"
            audit_path.write_text(json.dumps(report_with_cves(("CVE-2026-0001",)).to_dict()))
            original = audit_path.read_bytes()
            with self.assertRaisesRegex(ValueError, "must differ"):
                aggregate.aggregate(
                    [aggregate.load_target(root, audit_path)], root,
                    aggregate.argparse.Namespace(csaf=[], jobs=1),
                )
            self.assertEqual(audit_path.read_bytes(), original)
            source = root / "aggregate.txt"
            source.write_text(json.dumps({"vulnerabilities": [{"cve": "CVE-2026-0001"}]}))
            original = source.read_bytes()
            with self.assertRaisesRegex(ValueError, "must differ"):
                aggregate.aggregate([], root, aggregate.argparse.Namespace(csaf=[source], jobs=1))
            self.assertEqual(source.read_bytes(), original)

if __name__ == "__main__":
    unittest.main()
