from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit import aggregate, comparison, csaf, models
from pygo_audit.report_views import index_cve_evidence
from pygo_audit.storage import atomic_write_json, json_digest


def make_report(*cves: str) -> models.AuditReport:
    binary = models.BinaryReport(
        ["/app"],
        1,
        "go1.26",
        "",
        None,
        [],
        [],
        runtime_disposition="runtime",
        vulnerability_scan=models.VulnerabilityScan(
            status="complete",
            vulnerabilities=[models.Vulnerability(cve) for cve in cves],
        ),
    )
    return models.AuditReport(
        metadata=models.ContainerMetadata("/rootfs"),
        binaries=[binary],
        go_command="go",
        go_tool_version="go1.26",
    )


def assessment(*statuses: str, scope: str = "exact_image_digest") -> dict:
    return {"assessment": scope, "statuses": list(statuses)}


class ComparisonMetricsTests(unittest.TestCase):
    def test_priority_loader_verifies_audit_hash_and_ranks_evidence(self) -> None:
        report = make_report("CVE-2026-0001")
        document = {
            "audit_sha256": json_digest(report.to_dict()),
            "assessments": [
                {
                    "cve": "CVE-2026-0001",
                    "severity": "Important",
                    "cvss": {
                        "base_score": 7.5,
                        "source": "matched_product",
                    },
                }
            ],
        }
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "comparison.json"
            atomic_write_json(path, document)
            priority = comparison.load_verified_priorities(path, report)[
                "CVE-2026-0001"
            ]
            self.assertEqual(priority.cvss_score, 7.5)
            self.assertEqual(priority.severity, "Important")
            self.assertEqual(priority.score_source, "matched_product")

            document["audit_sha256"] = "0" * 64
            atomic_write_json(path, document, overwrite=True)
            with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
                comparison.load_verified_priorities(path, report)

    def test_headlines_count_distinct_cves_and_keep_uncertainty_out_of_corroboration(
        self,
    ):
        cves = [f"CVE-2026-{index:04d}" for index in range(1, 11)]
        report = make_report(*cves)
        # Repeated binaries must not inflate the CVE denominator.
        report.binaries.append(report.binaries[0])
        report.binaries[0].vulnerability_scan.vulnerabilities[5].findings.append(
            models.VulnerabilityFinding(evidence="symbol")
        )
        assessments = dict(
            zip(
                cves,
                [
                    assessment("status:known_affected"),
                    assessment("status:known_affected"),
                    assessment("status:fixed"),
                    assessment(
                        "status:known_not_affected",
                        "flag:vulnerable_code_not_in_execute_path",
                    ),
                    assessment("status:known_not_affected"),
                    assessment(
                        "status:known_not_affected", "flag:vulnerable_code_not_present"
                    ),
                    assessment(scope="document_missing"),
                    assessment("status:known_affected", scope="cpe_parent"),
                    assessment("status:under_investigation"),
                    assessment("status:known_affected", "status:fixed"),
                ],
            )
        )
        result = csaf.build_result(
            Path("audit.json"),
            report.metadata.image,
            index_cve_evidence(report),
            assessments,
        )
        metrics = result["summary"]["metrics"]
        self.assertEqual(
            metrics["coverage"], {"numerator": 6, "denominator": 10, "percent": 60}
        )
        self.assertEqual(metrics["corroboration"]["numerator"], 2)
        self.assertEqual(metrics["corroboration"]["denominator"], 6)
        self.assertAlmostEqual(metrics["corroboration"]["percent"], 100 / 3)
        self.assertEqual(metrics["explained_differences"], 2)
        self.assertEqual(metrics["unresolved_conflicts"], 2)
        self.assertEqual(metrics["unknown_cves"], 4)
        self.assertEqual(result["assessments"][0]["cve"], cves[5])
        text = csaf.render_text(result)
        self.assertIn("60% (6/10)", text)
        self.assertIn("33.3% (2/6)", text)
        self.assertLess(text.index(cves[5]), text.index(cves[0]))

    def test_empty_and_entirely_unknown_comparisons_show_na_instead_of_perfect_scores(
        self,
    ):
        for cves in ((), ("CVE-2026-0001",)):
            with self.subTest(cves=cves):
                report = make_report(*cves)
                result = csaf.build_result(
                    Path("audit.json"),
                    report.metadata.image,
                    index_cve_evidence(report),
                    {},
                )
                metrics = result["summary"]["metrics"]
                self.assertIsNone(metrics["corroboration"]["percent"])
                self.assertEqual(metrics["coverage"]["percent"], 0 if cves else None)
                self.assertIn("N/A (0/0)", csaf.render_text(result))
                self.assertNotIn("100%", csaf.render_text(result))

    def test_batch_headlines_use_counts_instead_of_averaging_percentages(self):
        first = aggregate.TargetAudit(1, Path("first"), make_report("CVE-2026-0001"))
        first.assessments["CVE-2026-0001"] = assessment("status:known_affected")
        cves = [f"CVE-2026-{index:04d}" for index in range(1, 10)]
        second = aggregate.TargetAudit(2, Path("second"), make_report(*cves))
        second.assessments.update(
            {
                cves[0]: assessment("status:known_affected"),
                cves[1]: assessment("status:fixed"),
                cves[2]: assessment("status:known_not_affected"),
            }
        )
        result = aggregate.build_result([first, second])
        metrics = result["summary"]["metrics"]
        self.assertEqual(
            metrics["coverage"], {"numerator": 4, "denominator": 10, "percent": 40}
        )
        self.assertEqual(
            metrics["corroboration"], {"numerator": 2, "denominator": 4, "percent": 50}
        )
        text = aggregate.render_text(result)
        self.assertIn("40% (4/10)", text)
        self.assertIn("50% (2/4)", text)
        self.assertLess(text.index("CONTAINER: second"), text.index("CONTAINER: first"))

    def test_investigations_and_conflicting_statuses_cannot_become_code_presence_agreement(
        self,
    ):
        report = make_report("CVE-2026-0001")
        vulnerability = report.binaries[0].vulnerability_scan.vulnerabilities[0]
        vulnerability.findings = [models.VulnerabilityFinding(evidence="symbol")]
        evidence = index_cve_evidence(report)[vulnerability.id]
        for statuses in (
            ("status:under_investigation", "flag:vulnerable_code_not_present"),
            (
                "status:known_affected",
                "status:known_not_affected",
                "flag:vulnerable_code_not_present",
            ),
        ):
            evaluation = comparison.evaluate(evidence, assessment(*statuses))
            self.assertFalse(comparison.evaluation_dict(evaluation)["usable_vex"])


if __name__ == "__main__":
    unittest.main()
