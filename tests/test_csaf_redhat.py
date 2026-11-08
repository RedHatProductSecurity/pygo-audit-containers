from dataclasses import replace
import unittest

from pygo_audit import comparison, csaf, csaf_redhat, image_csaf


class RedHatPolicyTests(unittest.TestCase):
    def test_numeric_cpe_rules_preserve_vendor_product_and_release_scope(self):
        for local, remote, relation in (
            ("redhat:openshift:4.20", "redhat:openshift:4.20.0", "normalized_version"),
            ("redhat:openshift:4.20.1", "redhat:openshift:4.20.3", "release_line"),
            ("redhat:openshift:4.20", "redhat:openshift:4.21", None),
            ("redhat:openshift:4.20::el8", "redhat:openshift:4.20.3::el9", None),
            ("other:openshift:4.20", "other:openshift:4.20.0", None),
            ("redhat:rhel:9.6", "redhat:rhel:9.6.0", None),
        ):
            with self.subTest(local=local, remote=remote):
                self.assertEqual(
                    csaf.cpe_relation("cpe:/a:" + local, "cpe:/a:" + remote), relation
                )

    def context(self, observed: str, boundary: str) -> comparison.PolicyContext:
        return comparison.PolicyContext(
            "https://www.redhat.com",
            "vendor-product",
            comparison.ProductContext(
                vendor="redhat",
                product="openshift",
                component="demo",
                versions=(
                    comparison.VersionEvidence(
                        observed, "component", "image.component_version"
                    ),
                ),
            ),
            comparison.ProductContext(
                vendor="redhat",
                product="openshift",
                component="demo",
                versions=(
                    comparison.VersionEvidence(
                        boundary, "component", "purl:vendor-product"
                    ),
                ),
            ),
        )

    def test_numeric_versions_pad_and_strip_recorded_suffixes(self):
        for raw, expected in (
            ("4", (4, 0, 0)),
            ("4.20", (4, 20, 0)),
            ("v4.20.0", (4, 20, 0)),
            ("v0.3.1-560-gb9134351", (0, 3, 1)),
            ("v0.3.1-rc.1", (0, 3, 1)),
            ("4.20.3+build.2", (4, 20, 3)),
            ("", None),
            ("sha256:abc", None),
            ("184a9601", None),
            ("directory-4.20.21", None),
            ("1.2.3.4", None),
            ("golang-github-prometheus-prometheus-4.0.0-0.102.0", None),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(csaf_redhat.normalize_version(raw), expected)

    def test_fixed_boundary_infers_only_within_the_same_release_line(self):
        for observed, status in (
            ("4.20", "known_affected"),
            ("v4.20.2", "known_affected"),
            ("v4.20.3", "fixed"),
            ("4.20.4", "fixed"),
            ("4.19.9", "undetermined"),
            ("4.21.0", "undetermined"),
        ):
            for statement in ("fixed", "first_fixed", "recommended"):
                with self.subTest(observed=observed, statement=statement):
                    (result,) = csaf_redhat.infer_assessment(
                        self.context(observed, "4.20.3"), ["status:" + statement]
                    )
                    self.assertEqual(result.status, status)
                    self.assertEqual(result.observed.value, observed)
                    self.assertEqual(result.policy, "redhat.openshift")
        (result,) = csaf_redhat.infer_assessment(
            self.context("v0.3.1-560-gabc", "0.3.2"), ["status:fixed"]
        )
        self.assertEqual(result.normalized_observed, "0.3.1")
        self.assertTrue(result.inferred)

    def test_explicit_declarations_and_introduction_boundaries_override_default(self):
        context = self.context("1.2.0", "1.2.3")
        for status in ("known_not_affected", "known_affected", "under_investigation"):
            self.assertEqual(
                csaf_redhat.infer_assessment(
                    context, ["status:fixed", "status:" + status]
                ),
                (),
            )
        (result,) = csaf_redhat.infer_assessment(context, ["status:first_affected"])
        self.assertEqual(result.status, "known_not_affected")
        for version, expected in (("1.2.0", "known_affected"), ("1.2.4", "fixed")):
            (result,) = csaf_redhat.infer_assessment(
                self.context(version, "1.2.3"), ["status:last_affected"]
            )
            self.assertEqual(result.status, expected)

    def test_policy_requires_matching_vendor_product_and_version_subject(self):
        context = self.context("1.2.0", "1.2.3")
        self.assertIsNotNone(image_csaf.select_policy(context))
        for vendor, product in (("other", "openshift"), ("redhat", "rhel")):
            other = replace(
                context, local=replace(context.local, vendor=vendor, product=product)
            )
            self.assertIsNone(image_csaf.select_policy(other))
            self.assertEqual(csaf_redhat.infer_assessment(other, ["status:fixed"]), ())
        unrelated = replace(
            context,
            local=replace(
                context.local,
                versions=(
                    comparison.VersionEvidence(
                        "1.2.0", "product", "image.product_version"
                    ),
                ),
            ),
        )
        self.assertEqual(csaf_redhat.infer_assessment(unrelated, ["status:fixed"]), ())
        enclosing = replace(
            context,
            candidate=replace(
                context.candidate,
                versions=(
                    comparison.VersionEvidence(
                        "1.2.3", "product", "cpe:enclosing-platform"
                    ),
                ),
            ),
        )
        self.assertEqual(csaf_redhat.infer_assessment(enclosing, ["status:fixed"]), ())

    def test_conflicting_recorded_versions_do_not_choose_an_arbitrary_boundary(self):
        context = self.context("1.2.0", "1.2.3")
        context = replace(
            context,
            local=replace(
                context.local,
                versions=(
                    *context.local.versions,
                    comparison.VersionEvidence("1.3.0", "component", "provided.purl"),
                ),
            ),
        )
        self.assertEqual(csaf_redhat.infer_assessment(context, ["status:fixed"]), ())

    def test_inferred_agreement_is_qualified_without_changing_findings(self):
        result = comparison.finding_agreement(
            ["symbol"], "exact", [["status:known_affected"]], inferred=True
        )
        self.assertEqual(result["comparison"], "qualified_yes")
        self.assertIn("version heuristic", result["text"])
