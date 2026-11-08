from __future__ import annotations

import unittest

from pygo_audit import comparison


class ComparisonTests(unittest.TestCase):
    def test_summary_counts_current_outcomes_without_reclassifying_them(self) -> None:
        conclusions = [
            {
                "agreement": {"comparison": kind},
                "local_scan": {"status": local},
                "match": match,
                "vendor_assessment": vendor,
            }
            for kind, local, match, vendor in (
                ("yes", "affected", "exact", "Affected"),
                ("qualified_yes", "affected", "fuzzy", "Not affected"),
                ("qualified_no", "affected", "fuzzy", "Fixed"),
                ("no", "affected", "exact", "Not affected"),
                ("mixed", "affected", "ambiguous", "Conflicting statements"),
                ("undetermined", "not_affected", "no_document", "Undetermined"),
                ("undetermined", "undetermined", "no_match", "Undetermined"),
            )
        ]
        metrics = comparison.summarize(conclusions)
        self.assertEqual(metrics["comparisons"], 7)
        self.assertEqual(metrics["discrepancies"], 3)
        self.assertEqual(
            metrics["agreement_counts"],
            {**dict.fromkeys(comparison.AGREEMENT_LABELS, 1), "undetermined": 2},
        )
        self.assertEqual(
            metrics["local_scan_counts"],
            {"affected": 5, "not_affected": 1, "undetermined": 1},
        )
        self.assertEqual(
            metrics["match_counts"],
            {"exact": 2, "fuzzy": 2, "ambiguous": 1, "no_document": 1, "no_match": 1},
        )
        empty = comparison.summarize([])
        self.assertEqual(empty["comparisons"], 0)
        self.assertEqual(empty["discrepancies"], 0)
        self.assertEqual(empty["agreement_counts"], {})

    def test_single_container_agreement_keeps_vendor_qualifications(self):
        cases = (
            ("known_affected", "", "symbol", "yes", "consistent"),
            ("first_affected", "", "module", "yes", "consistent"),
            ("fixed", "", "symbol", "qualified_no", "backport"),
            (
                "known_not_affected",
                "",
                "package",
                "qualified_no",
                "verifiable contradiction",
            ),
            (
                "known_not_affected",
                "vulnerable_code_not_present",
                "symbol",
                "qualified_no",
                "vulnerable implementation",
            ),
            (
                "known_not_affected",
                "component_not_present",
                "module",
                "qualified_no",
                "vulnerable implementation",
            ),
            (
                "known_not_affected",
                "component_not_present",
                "symbol",
                "no",
                "runtime binary",
            ),
            (
                "known_not_affected",
                "vulnerable_code_not_in_execute_path",
                "symbol",
                "qualified_yes",
                "does not establish reachability",
            ),
            (
                "known_not_affected",
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "symbol",
                "qualified_yes",
                "does not establish exploitability",
            ),
            (
                "under_investigation",
                "vulnerable_code_not_present",
                "symbol",
                "undetermined",
                "investigation",
            ),
        )
        for status, flag, evidence, expected, explanation in cases:
            for match in ("exact", "fuzzy", "ambiguous"):
                with self.subTest(
                    status=status, flag=flag, evidence=evidence, match=match
                ):
                    result = comparison.finding_agreement(
                        [evidence],
                        match,
                        [["status:" + status, "flag:" + flag]],
                        present_evidence=[evidence],
                    )
                    outcome = (
                        expected
                        if match == "exact"
                        else {"yes": "qualified_yes", "no": "qualified_no"}.get(
                            expected, expected
                        )
                    )
                    self.assertEqual(result["comparison"], outcome)
                    self.assertIn(explanation, result["text"])

    def test_mixed_means_conflicting_conclusions_not_different_status_labels(self):
        unreachable = [
            "status:known_not_affected",
            "flag:vulnerable_code_not_in_execute_path",
        ]
        cases = (
            ([["status:known_affected"], unreachable], "qualified_yes"),
            ([["status:known_affected"], ["status:fixed"]], "undetermined"),
            ([["status:known_not_affected"], ["status:fixed"]], "qualified_no"),
            (
                [["status:under_investigation"], ["status:known_affected"]],
                "undetermined",
            ),
            ([["status:known_affected"], ["status:known_affected"]], "qualified_yes"),
            ([["status:first_affected", "status:known_affected"]], "qualified_yes"),
        )
        for groups, expected in cases:
            with self.subTest(groups=groups):
                result = comparison.finding_agreement(["symbol"], "ambiguous", groups)
                self.assertEqual(result["comparison"], expected)
        statements = [["status:known_affected"], ["status:fixed"]]
        for candidate_agreements, expected in (
            (("yes", "no"), "mixed"),
            (("qualified_yes", "qualified_no"), "mixed"),
            (("qualified_yes", "qualified_no", "undetermined"), "mixed"),
            (("undetermined",), "undetermined"),
            (("qualified_yes", "undetermined"), "undetermined"),
        ):
            with self.subTest(candidate_agreements=candidate_agreements):
                result = comparison.finding_agreement(
                    ["symbol"],
                    "ambiguous",
                    statements,
                    candidate_agreements=candidate_agreements,
                )
                self.assertEqual(result["comparison"], expected)
                self.assertIn("conflicting", result["text"])

    def test_justifications_do_not_leak_between_product_statements(self):
        result = comparison.finding_agreement(
            ["symbol"],
            "ambiguous",
            [
                ["status:known_affected", "flag:vulnerable_code_not_in_execute_path"],
                ["status:known_not_affected"],
            ],
        )
        self.assertEqual(result["comparison"], "undetermined")
        self.assertIn("conflicting vendor statements", result["text"])

    def test_missing_unverified_and_inferred_evidence_qualifies_agreement(self):
        for evidence, statements, options, expected in (
            ([], [["status:known_not_affected"]], {}, "undetermined"),
            (["symbol"], [["flag:vulnerable_code_not_present"]], {}, "undetermined"),
            (
                ["symbol"],
                [["status:known_affected"]],
                {"inferred": True},
                "qualified_yes",
            ),
            (
                ["symbol"],
                [["status:known_not_affected", "flag:component_not_present"]],
                {},
                "qualified_no",
            ),
        ):
            with self.subTest(
                evidence=evidence, statements=statements, options=options
            ):
                result = comparison.finding_agreement(
                    evidence, "exact", statements, **options
                )
                self.assertEqual(result["comparison"], expected)
        for match in ("no_match", "no_document"):
            for status in ("known_affected", "known_not_affected", "fixed"):
                with self.subTest(match=match, status=status):
                    result = comparison.finding_agreement(
                        ["symbol"], match, [["status:" + status]]
                    )
                    self.assertEqual(result["comparison"], "undetermined")
