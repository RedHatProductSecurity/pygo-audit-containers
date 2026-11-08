from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit import audit, image_csaf, models
from pygo_audit.cli import main
from pygo_audit.text_layout import FULL_POLICY, RenderPolicy, Verbosity


class ImageCsafTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "csaf"
        self.sources.mkdir()
        self.digest = "sha256:" + "a" * 64
        self.identity = models.ImageIdentity(
            name="demo",
            digest=self.digest,
            platform="linux/amd64",
            product_version="4.20",
            cpes=("cpe:/a:redhat:openshift:4.20",),
        )
        self.write_audit()

    def write_audit(self, *cves: str) -> None:
        binary = models.BinaryReport(
            paths=["/app"],
            size=1,
            sha256="0" * 64,
            go_version="go1.24",
            main_package="main",
            main_module=None,
            dependencies=[],
            build_settings=[],
            vulnerability_scan=models.VulnerabilityScan(
                status="complete",
                vulnerabilities=[
                    models.Vulnerability(
                        cve,
                        findings=[
                            models.VulnerabilityFinding(
                                module="example.org/demo", found_version="v1.0.0"
                            )
                        ],
                    )
                    for cve in cves
                ],
            ),
        )
        report = models.AuditReport(
            metadata=models.ContainerMetadata("/rootfs", self.identity),
            binaries=[binary],
            go_command="go",
            go_tool_version="go1.24",
            producer_name="pygo-audit",
            producer_version="0.1",
        )
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))

    def write_source(self, name: str, document: dict) -> Path:
        path = self.sources / name
        path.write_text(json.dumps(document))
        return path

    def check(self, *flags: str) -> tuple[dict, str, str]:
        terminal = io.StringIO()
        with redirect_stdout(terminal):
            self.assertEqual(main(["csaf", str(self.root), *flags]), 0)
        reports = self.root / "reports"
        return (
            json.loads((reports / "comparison.json").read_text()),
            terminal.getvalue(),
            (reports / "comparison.txt").read_text(),
        )

    def product(self, identifier: str, purl: str = "", cpe: str = "") -> dict:
        return {
            "product_id": identifier,
            "product_identification_helper": {"purl": purl, "cpe": cpe},
        }

    def relation(self, component: str, platform: str, combined: str) -> dict:
        return {
            "category": "default_component_of",
            "product_reference": component,
            "relates_to_product_reference": platform,
            "full_product_name": {"product_id": combined},
        }

    def advisory(
        self,
        *,
        purl: str = "pkg:oci/demo",
        cpe: str = "cpe:/a:redhat:openshift:4.20",
        status: str = "known_affected",
    ) -> dict:
        return {
            "product_tree": {
                "full_product_names": [
                    self.product("component", purl),
                    self.product("platform", cpe=cpe),
                ],
                "relationships": [self.relation("component", "platform", "combined")],
            },
            "vulnerabilities": [
                {"cve": "CVE-2026-0001", "product_status": {status: ["combined"]}}
            ],
        }

    def test_supplied_and_derived_purls_remain_distinct(self):
        self.write_source("advisory.json", self.advisory())
        generated, terminal, _ = self.check("-v", "--wide")
        context = generated["match_inputs"]["contexts"][0]
        self.assertEqual(context["purls"], [])
        self.assertEqual(context["derived_purls"], [{"value": "pkg:oci/demo", "from": "image.name"}])
        self.assertIn("From image name", terminal)
        self.assertEqual(generated["image"]["purls"], [])
        self.assertEqual(generated["match_inputs"]["product_ids"], [])
        self.identity = replace(self.identity, purls=("pkg:oci/different",))
        self.write_audit()
        supplied, terminal, _ = self.check("-v", "--wide")
        context = supplied["match_inputs"]["contexts"][0]
        self.assertEqual(context["purls"], ["pkg:oci/different"])
        self.assertEqual(context["derived_purls"], [])
        self.assertNotIn("From image name", terminal)
        self.assertEqual(supplied["documents"][0]["presence"], "not_identified")

    def test_component_boundary_keeps_local_findings_and_vendor_statements_separate(
        self,
    ):
        self.write_source(
            "advisory.json", self.advisory(purl="pkg:oci/demo@v0.3.2", status="fixed")
        )
        for version, vendor, agreement in (
            ("v0.3.1-560-gabc", "Affected", "qualified_yes"),
            ("v0.3.2", "Fixed", "qualified_no"),
            ("v0.3.3", "Fixed", "qualified_no"),
            ("v0.4.0", "Undetermined", "undetermined"),
        ):
            with self.subTest(version=version):
                self.identity = replace(self.identity, component_version=version)
                self.write_audit("CVE-2026-0001")
                original = (self.root / "audit.json").read_bytes()
                result, detailed, _ = self.check("-vv", "--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["local_scan"]["status"], "affected")
                self.assertEqual(conclusion["vendor_assessment"], vendor)
                self.assertEqual(conclusion["agreement"]["comparison"], agreement)
                reference = result["documents"][0]["vulnerabilities"][0]["references"][
                    0
                ]
                self.assertEqual(reference["statements"], ["status:fixed"])
                self.assertEqual(
                    reference["version_assessments"][0]["observed"]["value"], version
                )
                self.assertRegex(detailed, r"Version policy:\s+redhat\.openshift")
                self.assertEqual((self.root / "audit.json").read_bytes(), original)
        pinned, _, _ = self.check("--csaf-product-id", "combined", "--wide")
        conclusion = pinned["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["match"], "exact")
        self.assertEqual(conclusion["vendor_assessment"], "Fixed")
        self.assertEqual(conclusion["candidates"][0]["version_assessments"], [])

    def test_explicit_version_statement_overrides_another_build_boundary(self):
        self.identity = replace(self.identity, component_version="0.3.1")
        self.write_audit("CVE-2026-0001")
        document = self.advisory(purl="pkg:oci/demo@0.3.2", status="fixed")
        document["product_tree"]["full_product_names"].append(
            self.product("observed", "pkg:oci/demo@0.3.1")
        )
        document["product_tree"]["relationships"].append(
            self.relation("observed", "platform", "observed-combined")
        )
        record = document["vulnerabilities"][0]
        record["product_status"]["known_not_affected"] = ["observed-combined"]
        record["flags"] = [
            {
                "label": "vulnerable_code_not_in_execute_path",
                "product_ids": ["observed-combined"],
            }
        ]
        self.write_source("advisory.json", document)
        result, _, _ = self.check("--wide")
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["agreement"]["comparison"], "qualified_yes")
        self.assertEqual(conclusion["vendor_assessment"], "Not affected")
        self.assertTrue(
            all(
                item["agreement"]["comparison"] == "qualified_yes"
                for item in conclusion["candidates"]
            )
        )

    def test_earlier_fix_is_not_undone_by_a_later_fixed_build(self):
        self.identity = replace(self.identity, component_version="0.3.3")
        self.write_audit("CVE-2026-0001")
        document = self.advisory(purl="pkg:oci/demo@0.3.2", status="fixed")
        document["product_tree"]["full_product_names"].append(
            self.product("later", "pkg:oci/demo@0.3.4")
        )
        document["product_tree"]["relationships"].append(
            self.relation("later", "platform", "later-combined")
        )
        document["vulnerabilities"][0]["product_status"]["fixed"].append(
            "later-combined"
        )
        self.write_source("advisory.json", document)
        result, _, _ = self.check("--wide")
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["vendor_assessment"], "Fixed")
        self.assertEqual(conclusion["agreement"]["comparison"], "qualified_no")

    def test_product_version_branch_is_used_without_borrowing_platform_cpe(self):
        self.identity = replace(self.identity, component_version="0.3.1")
        self.write_audit("CVE-2026-0001")
        document = self.advisory(status="fixed")
        product = document["product_tree"]["full_product_names"].pop(0)
        document["product_tree"]["branches"] = [
            {"category": "product_version", "name": "0.3.2", "product": product}
        ]
        self.write_source("advisory.json", document)
        result, _, _ = self.check("--wide")
        assessment = result["conclusions"]["CVE-2026-0001"]["candidates"][0][
            "version_assessments"
        ][0]
        self.assertEqual(
            assessment["boundary"],
            {
                "value": "0.3.2",
                "subject": "component",
                "source": "product_version:component",
            },
        )
        self.assertEqual(assessment["status"], "known_affected")
        self.write_source(
            "advisory.json",
            self.advisory(status="fixed", cpe="cpe:/a:redhat:openshift:4.20.3"),
        )
        result, _, _ = self.check("--wide")
        self.assertEqual(
            result["conclusions"]["CVE-2026-0001"]["candidates"][0][
                "version_assessments"
            ],
            [],
        )

    def test_directory_names_do_not_supply_versions(self):
        self.identity = replace(self.identity, product_version="", component_version="")
        self.write_audit("CVE-2026-0001")
        source = self.write_source(
            "advisory.json", self.advisory(purl="pkg:oci/demo@0.3.2", status="fixed")
        )
        report = audit.load_audit(self.root / "audit.json")
        conclusions = [
            image_csaf.check_image(
                self.root / directory / "audit.json", report, [source], [self.sources]
            )["conclusions"]
            for directory in ("demo-0.3.1", "demo-0.3.3")
        ]
        self.assertEqual(*conclusions)
        self.assertEqual(
            conclusions[0]["CVE-2026-0001"]["candidates"][0]["version_assessments"], []
        )

    def test_multiple_matching_ids_are_preserved_without_selecting_a_canonical_id(self):
        self.identity = replace(
            self.identity, purls=("pkg:oci/demo", "pkg:oci/alternate")
        )
        self.write_audit("CVE-2026-0001")
        document = self.advisory()
        document["product_tree"]["full_product_names"].append(
            self.product("alternative", "pkg:oci/alternate")
        )
        document["product_tree"]["relationships"].append(
            self.relation("alternative", "platform", "other-combined")
        )
        document["vulnerabilities"][0]["product_status"]["fixed"] = ["other-combined"]
        self.write_source("advisory.json", document)
        result, terminal, _ = self.check("--wide")
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(
            {item["product_id"] for item in record["matches"]},
            {"combined", "other-combined"},
        )
        self.assertEqual(record["match"], "ambiguous")
        self.assertIn("Agreement:              Mixed", terminal)
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match"], "ambiguous")
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match_count"], 2)
        self.assertEqual(result["image"]["csaf_product_ids"], [])
        self.assertIn(
            "[IDENTIFIED PRODUCTS]\n  demo\n      - alternative\n      - component",
            terminal,
        )

    def test_equal_exact_product_selections_remain_ambiguous(self):
        self.identity = replace(
            self.identity, csaf_product_ids=("component", "alternative")
        )
        self.write_audit("CVE-2026-0001")
        document = self.advisory()
        document["product_tree"]["full_product_names"].append(
            self.product("alternative", "pkg:oci/alternate")
        )
        document["vulnerabilities"][0]["product_status"] = {
            "known_affected": ["component", "alternative"]
        }
        self.write_source("advisory.json", document)
        result, _, _ = self.check("--wide")
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["match"], "ambiguous")
        self.assertEqual(conclusion["match_count"], 2)
        self.assertEqual(conclusion["agreement"]["comparison"], "qualified_yes")
        self.assertEqual(
            {candidate["match"] for candidate in conclusion["candidates"]}, {"exact"}
        )
        self.assertEqual(
            {
                candidate["agreement"]["comparison"]
                for candidate in conclusion["candidates"]
            },
            {"yes"},
        )

    def test_identity_mismatches_do_not_prevent_conditional_vendor_comparison(self):
        self.write_audit("CVE-2026-0001")
        for status, expected in (
            ("known_affected", "qualified_yes"),
            ("known_not_affected", "qualified_no"),
            ("fixed", "qualified_no"),
            ("under_investigation", "undetermined"),
        ):
            with self.subTest(status=status):
                self.write_source(
                    "advisory.json",
                    self.advisory(
                        purl="pkg:oci/demo@sha256:" + "b" * 64 + "?arch=arm64",
                        cpe="cpe:/a:redhat:openshift:4.19",
                        status=status,
                    ),
                )
                result, _, _ = self.check("--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["match"], "ambiguous")
                self.assertEqual(conclusion["agreement"]["comparison"], expected)
                candidate = conclusion["candidates"][0]
                self.assertEqual(
                    {item["field"] for item in candidate["mismatches"]},
                    {"digest", "cpe", "architecture"},
                )
                original = json.dumps(result, sort_keys=True)
                for level in Verbosity:
                    text = image_csaf.render_text(
                        result, RenderPolicy(level, wide=True)
                    )
                    self.assertIn("CSAF ID Match:          Ambiguous", text)
                    self.assertIn(
                        "Agreement:              "
                        + image_csaf.comparison.AGREEMENT_LABELS[expected],
                        text,
                    )
                    if level >= Verbosity.EXPANDED:
                        self.assertIn("Build digest differs from the image", text)
                        self.assertIn(
                            "CPE version differs: local 4.20; CSAF 4.19",
                            text,
                        )
                        self.assertEqual(
                            "Architecture differs:" in text, level >= Verbosity.DETAILED
                        )
                    self.assertEqual(json.dumps(result, sort_keys=True), original)

    def test_forensic_binary_metadata_precedes_package_and_symbol_details(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.symlinks = ["/usr/bin/demo"]
        binary.layer_history = [models.BinaryLayerObservation(0, "found", ("/app",))]
        binary.vulnerability_scan.vulnerabilities[0].findings[0] = (
            models.VulnerabilityFinding(
                module="example.org/demo", evidence="symbol", symbol="Unsafe"
            )
        )
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        self.write_source("advisory.json", self.advisory())
        result, _, forensic = self.check("--wide")
        section = forensic.split("BINARY: app", 1)[1].split("[PROVENANCE]", 1)[0]
        for label in (
            "Runtime disposition:",
            "CGO:",
            "Reachability:",
            "SHA-256:",
            "Layer observations:",
            "Symlinks:",
        ):
            self.assertLess(
                section.index(label), section.index("MODULE / PACKAGE FINDINGS")
            )
        self.assertIn("Layer observations:     1", section)
        self.assertNotIn("Layer observations (", section)
        self.assertIn("layer-000 FOUND", section)
        self.assertNotIn("Reachability explanation", section)
        self.assertNotIn("Recorded reachability", section)
        self.assertEqual(
            result["local_findings"]["CVE-2026-0001"][0]["findings"][0]["reachability"],
            "unspecified",
        )

    def test_broader_cpe_scope_requires_explicit_input(self):
        self.identity = replace(self.identity, cpes=(*self.identity.cpes, "cpe:/a:redhat:openshift:4"))
        self.write_audit()
        self.write_source("advisory.json", self.advisory(cpe="cpe:/a:redhat:openshift:4"))
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["presence"], "matched")
        self.assertEqual(result["documents"][0]["vulnerabilities"][0]["statuses"], ["known_affected"])

    def test_platform_variant_does_not_replace_architecture(self):
        self.identity = replace(self.identity, platform="linux/arm64/v8")
        self.write_audit()
        self.write_source("advisory.json", self.advisory(purl="pkg:oci/demo?arch=arm64"))
        result, _, _ = self.check()
        self.assertEqual(result["match_inputs"]["architecture"], "arm64")
        self.assertEqual(result["documents"][0]["presence"], "matched")

    def test_product_pins_are_exact_and_do_not_fall_back(self):
        document = self.advisory()
        self.write_source("advisory.json", document)
        before = (self.root / "audit.json").read_bytes()
        result, text, _ = self.check("--csaf-product-id", "combined", "--wide")
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(record["statuses"], ["known_affected"])
        self.assertEqual(
            result["documents"][0]["candidates"][0]["entries"][0]["basis"],
            "explicit_product_id",
        )
        self.assertIn("Exact (user-selected product ID)", text)
        expanded = image_csaf.render_text(
            result, RenderPolicy(Verbosity.EXPANDED, wide=True)
        )
        self.assertIn("[IDENTIFIED PRODUCTS]\n  demo", expanded)
        self.assertIn("CSAF product ID:        combined", expanded)
        self.assertNotIn("Matched product IDs:", expanded)
        self.assertEqual((self.root / "audit.json").read_bytes(), before)
        missing, text, forensic = self.check("--csaf-product-id", "typo")
        self.assertEqual(missing["documents"][0]["presence"], "not_identified")
        self.assertEqual(missing["documents"][0]["candidates"], [])
        self.assertEqual(missing["documents"][0]["vulnerabilities"][0]["statuses"], [])
        self.assertIn("Product IDs not found:  typo", forensic)
        # A component pin must not inherit statements about a combined product.
        direct, _, _ = self.check("--csaf-product-id", "component")
        self.assertEqual(direct["documents"][0]["vulnerabilities"][0]["statuses"], [])

    def test_json_override_uses_saved_findings_without_changing_audit(self):
        self.write_source("advisory.json", self.advisory())
        identity = self.root / "selection.json"
        identity.write_text(json.dumps({"image": {"name": "selected"}, "csaf": {"product_ids": ["combined"]}}))
        before = (self.root / "audit.json").read_bytes()
        original, _, _ = self.check()
        selected, summary, forensic = self.check("--image-metadata", str(identity))
        self.assertIn("SUBJECT: selected", summary)
        self.assertNotIn(str(identity), summary)
        self.assertIn(str(identity), forensic)
        self.assertEqual(selected["audit_sha256"], original["audit_sha256"])
        self.assertEqual((self.root / "audit.json").read_bytes(), before)

    def test_multiple_cpes_and_layer_contexts_do_not_cross_match(self):
        base_cpe = "cpe:/a:example:base:9.6"
        self.identity = replace(
            self.identity,
            products=(
                models.ProductIdentity(
                    name="base",
                    cpes=(base_cpe,),
                    sources=("layers/layer-000/root/buildinfo/labels.json",),
                ),
            ),
        )
        self.write_audit()
        self.write_source("advisory.json", self.advisory(cpe=base_cpe))
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["presence"], "ambiguous")
        self.assertEqual(result["documents"][0]["vulnerabilities"][0]["statuses"], [])
        self.write_source(
            "advisory.json", self.advisory(purl="pkg:oci/base", cpe=base_cpe)
        )
        result, summary, forensic = self.check()
        self.assertEqual(result["documents"][0]["presence"], "matched")
        self.assertEqual(result["documents"][0]["candidates"][0]["context"], "base")
        self.assertNotIn("layers/layer-000", summary)
        self.assertIn("layers/layer-000", forensic.split("PROVENANCE", 1)[1])
        self.assertIn("[IDENTIFIED PRODUCTS]\n  base", forensic)
        self.assertNotIn("\n  demo\n", forensic)
        self.identity = replace(self.identity, cpes=(base_cpe, *self.identity.cpes))
        self.write_audit()
        document = self.advisory()
        document["product_tree"]["full_product_names"].extend(
            [
                self.product("base-component", "pkg:oci/base"),
                self.product("base-platform", cpe=base_cpe),
            ]
        )
        document["product_tree"]["relationships"].append(
            self.relation("base-component", "base-platform", "base-combined")
        )
        self.write_source("advisory.json", document)
        result, expanded, _ = self.check("-v", "--wide")
        self.assertEqual(result["documents"][0]["presence"], "matched")
        for name, product_id, other_id in (
            ("demo", "component", "base-component"),
            ("base", "base-component", "component"),
        ):
            other_name = "base" if name == "demo" else "demo"
            section = expanded.split(f"\n  {name}\n", 1)[1].split(
                f"\n  {other_name}\n", 1
            )[0]
            self.assertIn("CSAF product ID:        " + product_id + "\n", section)
            self.assertNotIn("CSAF product ID:        " + other_id + "\n", section)

    def test_final_image_digest_does_not_confirm_a_layer_product(self):
        self.identity = replace(self.identity, products=(models.ProductIdentity(
            name="base", cpes=("cpe:/a:example:base:9.6",)
        ),))
        self.write_audit()
        self.write_source("advisory.json", self.advisory(
            purl=f"pkg:oci/base@{self.digest}", cpe="cpe:/a:example:base:9.6"
        ))
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["vulnerabilities"][0]["statuses"], [])

    def test_explicit_versioned_purl_matches_only_its_build(self):
        self.identity = replace(
            self.identity, digest="", purls=("pkg:oci/renamed@sha256:" + "b" * 64,)
        )
        self.write_audit()
        for digest, expected in (("b", "exact"), ("c", "fuzzy")):
            with self.subTest(digest=digest):
                self.write_source(
                    "advisory.json",
                    self.advisory(purl="pkg:oci/renamed@sha256:" + digest * 64),
                )
                result, _, _ = self.check()
                self.assertEqual(
                    result["conclusions"]["CVE-2026-0001"]["match"], expected
                )

    def test_unversioned_component_and_product_relationship_establish_match(
        self,
    ) -> None:
        self.identity = replace(
            self.identity,
            vendor_image_name="openshift/ose-demo-rhel9",
            name="workspace-folder",
        )
        self.write_audit()
        document = self.advisory(purl="pkg:oci/ose-demo-rhel9")
        document["product_tree"]["full_product_names"].append(
            self.product("alphabetically-first", "pkg:oci/demo-microshift-rhel9")
        )
        self.write_source("advisory.json", document)
        result, terminal, _ = self.check()
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(record["match"], "matched")
        self.assertEqual(record["statuses"], ["known_affected"])
        self.assertEqual(
            [item["product_id"] for item in record["matches"]], ["combined"]
        )
        self.assertEqual(
            result["match_inputs"]["contexts"][0]["derived_purls"][0]["value"], "pkg:oci/ose-demo-rhel9"
        )
        self.assertIn("SUBJECT: workspace-folder", terminal)
        self.assertNotIn("alphabetically-first", json.dumps(result))
        entry = result["documents"][0]["candidates"][0]["entries"][1]
        self.assertEqual(entry["basis"], "component_cpe")

    def test_exact_digest_can_match_without_a_name_or_platform(self) -> None:
        self.identity = models.ImageIdentity(digest=self.digest)
        self.write_audit()
        purl = "pkg:oci/unrelated@" + self.digest.replace(":", "%3A")
        self.write_source(
            "advisory.json",
            {
                "product_tree": {
                    "full_product_names": [self.product("opaque-id", purl)]
                },
                "vulnerabilities": [
                    {"cve": "CVE-2026-0001", "product_status": {"fixed": ["opaque-id"]}}
                ],
            },
        )
        result, _, _ = self.check()
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(record["match"], "matched")
        self.assertEqual(record["statuses"], ["fixed"])
        self.assertEqual(
            result["documents"][0]["candidates"][0]["entries"][0]["basis"],
            "image_digest",
        )

    def test_fuzzy_builds_preserve_each_vendor_statement(
        self,
    ) -> None:
        document = self.advisory()
        document["product_tree"]["full_product_names"].append(
            self.product(
                "fixed-build", "pkg:oci/demo@sha256:" + "b" * 64 + "?arch=amd64"
            )
        )
        document["product_tree"]["relationships"].append(
            self.relation("fixed-build", "platform", "fixed-combined")
        )
        document["vulnerabilities"][0]["product_status"]["fixed"] = ["fixed-combined"]
        self.write_source("advisory.json", document)
        result, terminal, saved = self.check()
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(record["statuses"], ["fixed", "known_affected"])
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(
            conclusion["agreement"]["statuses"], ["fixed", "known_affected"]
        )
        self.assertEqual(
            set(conclusion["candidate_statuses"]), {"fixed", "known_affected"}
        )
        self.assertIn("fixed", conclusion["agreement"]["statuses"])
        self.assertIn("status:fixed", saved)
        self.assertIn("Mismatches:", saved)
        self.assertNotIn("Match evidence:", saved)

    def test_conflicting_scoped_statuses_remain_ambiguous(self) -> None:
        self.write_audit("CVE-2026-0001")
        document = self.advisory()
        document["vulnerabilities"][0]["product_status"]["known_not_affected"] = [
            "combined"
        ]
        self.write_source("advisory.json", document)
        result, terminal, saved = self.check()
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(record["match"], "ambiguous")
        self.assertEqual(record["statuses"], ["known_affected", "known_not_affected"])
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["candidates"][0]["agreement"]["comparison"], "undetermined")
        self.assertIn("Agreement:              Undetermined", terminal)
        self.assertNotIn("Agreement:              Mixed", saved)
        self.assertIn("conflicting vendor statements", saved)
        self.assertIn("status:known_not_affected", saved)

    def test_redhat_family_matching_preserves_other_cpe_constraints(self) -> None:
        for cpe, matched in (
            ("cpe:/a:redhat:openshift:4.20", True),
            ("cpe:/a:redhat:openshift:4", True),
            ("cpe:/a:redhat:openshift:4.19", False),
            ("cpe:/a:redhat:microshift:4.20", False),
            ("cpe:/a:redhat:openshift:4.20::el8", False),
            ("", False),
        ):
            with self.subTest(cpe=cpe):
                self.write_source("advisory.json", self.advisory(cpe=cpe))
                result, _, _ = self.check()
                record = result["documents"][0]["vulnerabilities"][0]
                self.assertEqual(record["match"], "matched" if matched else "ambiguous")
                self.assertEqual(
                    record["statuses"], ["known_affected"] if matched else []
                )

    def test_version_family_is_not_generalized_to_other_publishers(self) -> None:
        self.identity = replace(self.identity, cpes=("cpe:/a:vendor:platform:4.20",))
        self.write_audit()
        self.write_source(
            "advisory.json", self.advisory(cpe="cpe:/a:vendor:platform:4")
        )
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["presence"], "ambiguous")

    def test_outer_platform_does_not_erase_an_intermediate_conflict(self) -> None:
        document = self.advisory(cpe="cpe:/a:redhat:openshift:4.19")
        document["product_tree"]["full_product_names"].append(
            self.product("outer-platform", cpe=self.identity.cpes[0])
        )
        document["product_tree"]["relationships"].append(
            self.relation("combined", "outer-platform", "outer-combined")
        )
        document["vulnerabilities"][0]["product_status"] = {
            "known_not_affected": ["outer-combined"]
        }
        self.write_source("advisory.json", document)
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["vulnerabilities"][0]["statuses"], [])

    def test_exact_component_does_not_authorize_an_unidentified_platform(self) -> None:
        document = self.advisory(purl=f"pkg:oci/demo@{self.digest}", cpe="")
        document["product_tree"]["full_product_names"][0][
            "product_identification_helper"
        ]["cpe"] = self.identity.cpes[0]
        self.write_source("advisory.json", document)
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["presence"], "matched")
        self.assertEqual(result["documents"][0]["vulnerabilities"][0]["statuses"], [])

    def test_architecture_and_build_constraints(self) -> None:
        for suffix, matched in (
            ("", True),
            ("?arch=x86_64", True),
            ("?arch=s390x", True),
            ("?tag=unverified-build", True),
            ("@v1.0", True),
        ):
            with self.subTest(suffix=suffix):
                self.write_source(
                    "advisory.json", self.advisory(purl="pkg:oci/demo" + suffix)
                )
                result, _, _ = self.check()
                self.assertEqual(
                    result["documents"][0]["presence"],
                    "matched" if matched else "ambiguous",
                )
        self.identity = replace(self.identity, platform="")
        self.write_audit()
        self.write_source(
            "advisory.json", self.advisory(purl="pkg:oci/demo?arch=amd64")
        )
        result, _, _ = self.check()
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match"], "fuzzy")

    def test_architecture_equivalence_preserves_identity_confidence(self):
        for purl, supplied in (
            ("pkg:oci/demo?arch=arm64", ()),
            (f"pkg:oci/demo@{self.digest}?arch=arm64", ()),
            ("pkg:oci/demo@v1?arch=arm64", ("pkg:oci/demo@v1?arch=amd64",)),
            ("pkg:oci/demo@v1?arch=arm64", ("pkg:oci/demo@v1",)),
        ):
            self.identity = replace(self.identity, purls=supplied)
            self.write_audit("CVE-2026-0001")
            report = audit.load_audit(self.root / "audit.json")
            report.binaries[0].runtime_disposition = "runtime"
            report.binaries[0].vulnerability_scan.vulnerabilities[0].findings = [
                models.VulnerabilityFinding(evidence="symbol", symbol="Observed")
            ]
            (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
            for status, expected in (
                ("known_affected", "qualified_yes"),
                ("known_not_affected", "qualified_no"),
                ("fixed", "qualified_no"),
                ("under_investigation", "undetermined"),
                ("", "undetermined"),
            ):
                with self.subTest(purl=purl, supplied=supplied, status=status):
                    document = self.advisory(purl=purl, status=status)
                    if status == "known_not_affected":
                        document["vulnerabilities"][0]["flags"] = [
                            {
                                "label": "component_not_present",
                                "product_ids": ["combined"],
                            }
                        ]
                    if not status:
                        document["vulnerabilities"][0]["product_status"] = {}
                    self.write_source("advisory.json", document)
                    result, expanded, _ = self.check("-v", "--wide")
                    conclusion = result["conclusions"]["CVE-2026-0001"]
                    exact = "@" in purl
                    self.assertEqual(conclusion["match"], "exact" if exact else "fuzzy")
                    if exact:
                        expected = {
                            "known_affected": "yes",
                            "known_not_affected": "no",
                        }.get(status, expected)
                    self.assertNotIn(
                        "architecture differs", conclusion["qualifications"]
                    )
                    self.assertEqual(conclusion["agreement"]["comparison"], expected)
                    self.assertEqual(
                        conclusion["candidates"][0]["agreement"]["comparison"], expected
                    )
                    self.assertNotIn("Architecture differs", expanded)
                    detailed = image_csaf.render_text(
                        result, RenderPolicy(Verbosity.DETAILED, wide=True)
                    )
                    self.assertIn(
                        "Architecture differs: image amd64; candidate arm64; treated as equivalent",
                        detailed,
                    )
                    if "@" in purl:
                        self.assertNotIn("Build unverified", expanded)

    def test_architecture_exception_does_not_hide_other_identity_failures(self):
        for purl, cpe, platform, supplied in (
            ("pkg:oci/demo-extra?arch=arm64", self.identity.cpes[0], "linux/amd64", ()),
            (
                "pkg:oci/demo@sha256:" + "b" * 64 + "?arch=arm64",
                self.identity.cpes[0],
                "linux/amd64",
                (),
            ),
            (
                "pkg:oci/demo@sha256:" + "b" * 64 + "?arch=arm64",
                self.identity.cpes[0],
                "linux/amd64",
                ("pkg:oci/demo@sha256:" + "b" * 64 + "?arch=amd64",),
            ),
            (
                "pkg:oci/demo@v2?arch=arm64",
                self.identity.cpes[0],
                "linux/amd64",
                ("pkg:oci/demo@v1?arch=amd64",),
            ),
            (
                "pkg:oci/demo?arch=arm64&tag=unverified",
                self.identity.cpes[0],
                "linux/amd64",
                (),
            ),
            (
                "pkg:oci/demo?arch=arm64",
                "cpe:/a:redhat:openshift:4.19",
                "linux/amd64",
                (),
            ),
            ("pkg:oci/demo?arch=arm64", self.identity.cpes[0], "", ()),
            (
                "pkg:oci/demo@v1?arch=arm64",
                self.identity.cpes[0],
                "linux/amd64",
                ("pkg:oci/demo@v1?arch=s390x",),
            ),
        ):
            with self.subTest(purl=purl, cpe=cpe, platform=platform, supplied=supplied):
                self.identity = replace(
                    self.identity, platform=platform, purls=supplied
                )
                self.write_audit("CVE-2026-0001")
                self.write_source("advisory.json", self.advisory(purl=purl, cpe=cpe))
                result, summary, _ = self.check("--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                rejected = "demo-extra" in purl or ":4.19" in cpe
                self.assertEqual(conclusion["match"] == "ambiguous", rejected)
                self.assertEqual(
                    conclusion["agreement"]["comparison"],
                    "yes" if conclusion["match"] == "exact" else "qualified_yes",
                )
                self.assertIn(
                    "[IDENTIFIED PRODUCTS]\n  demo\n      - component", summary
                )

    def test_similar_names_and_misleading_product_ids_never_apply_statuses(
        self,
    ) -> None:
        for purl, expected in (
            ("pkg:oci/demo-extra", "ambiguous"),
            ("pkg:oci/demo@sha256:" + "b" * 64, "matched"),
            (
                "pkg:oci/unrelated?repository_url=registry.example/demo",
                "not_identified",
            ),
            ("pkg:oci/unrelated?repository_url=" + self.digest, "not_identified"),
            ("pkg:golang/demo", "not_identified"),
            ("", "not_identified"),
        ):
            with self.subTest(purl=purl):
                document = self.advisory(purl=purl)
                document["product_tree"]["full_product_names"][0]["product_id"] = (
                    self.digest
                )
                document["product_tree"]["relationships"][0]["product_reference"] = (
                    self.digest
                )
                self.write_source("advisory.json", document)
                result, _, _ = self.check()
                self.assertEqual(result["documents"][0]["presence"], expected)
                self.assertEqual(
                    result["documents"][0]["vulnerabilities"][0]["statuses"],
                    ["known_affected"] if expected == "matched" else [],
                )

    def test_direct_cpe_and_nested_matches_retain_their_identity_evidence(self) -> None:
        document = self.advisory()
        document["product_tree"]["full_product_names"][0][
            "product_identification_helper"
        ]["cpe"] = self.identity.cpes[0]
        document["product_tree"]["full_product_names"].append(
            self.product("outer", cpe=self.identity.cpes[0])
        )
        document["product_tree"]["relationships"].append(
            self.relation("combined", "outer", "nested (variant) [detail]")
        )
        document["vulnerabilities"][0]["product_status"] = {
            "known_affected": ["component", "nested (variant) [detail]"]
        }
        self.write_source("advisory.json", document)
        result, terminal, _ = self.check("-vv")
        record = result["documents"][0]["vulnerabilities"][0]
        self.assertEqual(
            [match["product_id"] for match in record["matches"]],
            ["component", "nested (variant) [detail]"],
        )
        section = terminal.split("PRODUCT: nested (variant) [detail]", 1)[1]
        self.assertIn("Product CPE:            " + self.identity.cpes[0], section)
        result, expanded, _ = self.check("-v", "--wide")
        selected = result["conclusions"]["CVE-2026-0001"]["candidates"][0][
            "product_ids"
        ]
        self.assertGreater(len(selected), 1)
        for product_id in selected:
            self.assertIn("\n        - " + product_id + "\n", expanded)
        self.assertIn("CSAF product ID:        component", expanded)
        self.assertIn("Matched product IDs:\n", expanded)

    def test_purl_decoding_preserves_qualifier_boundaries(self) -> None:
        package = image_csaf.parse_oci_purl(
            "pkg:oci/DEMO?repository_url=example%26arch%3Ds390x&arch=amd64"
        )
        self.assertEqual(package["architecture"], "amd64")
        self.assertEqual(package["name"], "demo")
        for invalid in (
            "pkg:oci/demo?arch=amd64&arch=s390x",
            "pkg:oci/de%ZZmo",
            "pkg:oci/de%FFmo",
            "pkg:oci/demo#subpath",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(image_csaf.parse_oci_purl(invalid))

    def test_vendor_oci_namespace_can_match_with_product_scope(
        self,
    ) -> None:
        self.write_source("advisory.json", self.advisory(purl="pkg:oci/openshift/demo"))
        result, _, saved = self.check()
        self.assertEqual(result["documents"][0]["presence"], "matched")
        self.assertEqual(
            result["documents"][0]["vulnerabilities"][0]["statuses"], ["known_affected"]
        )
        self.assertIn("Publisher-supplied OCI namespace retained", saved)

    def test_statements_remain_per_record_and_document(self) -> None:
        document = self.advisory()
        document["vulnerabilities"].append(
            {
                "cve": "CVE-2026-0001",
                "product_status": {"known_not_affected": ["combined"]},
            }
        )
        document["vulnerabilities"].append(
            {
                "cve": "CVE-2026-0002",
                "flags": [
                    {
                        "label": "vulnerable_code_not_present",
                        "product_ids": ["combined"],
                    }
                ],
            }
        )
        self.write_source("first.json", document)
        self.write_source("second.json", self.advisory(status="under_investigation"))
        result, _, saved = self.check()
        records = result["documents"][0]["vulnerabilities"]
        self.assertEqual([item["record"] for item in records], [1, 2, 3])
        self.assertEqual(
            [item["statuses"] for item in records],
            [["known_affected"], ["known_not_affected"], []],
        )
        self.assertEqual(
            result["documents"][1]["vulnerabilities"][0]["statuses"],
            ["under_investigation"],
        )
        self.assertIn("flag:vulnerable_code_not_present", saved)
        first, second = saved.split("\nCVE-2026-0002\n", 1)
        self.assertEqual(first.count("\nCVE-2026-0001\n"), 1)
        self.assertEqual(first.count("LOCAL FINDINGS"), 1)
        self.assertIn("Document 1, record 1", first)
        self.assertIn("Document 1, record 2", first)
        self.assertIn("Document 2, record 1", first)
        self.assertIn("status:known_affected", first)
        self.assertNotIn("flag:vulnerable_code_not_present", first)
        self.assertNotIn("status:known_affected", second)
        self.assertNotIn("status:under_investigation", second)

    def test_single_cve_groups_vendor_and_local_evidence_without_document_heading(
        self,
    ) -> None:
        self.write_audit("CVE-2026-0001")
        self.write_source("advisory.json", self.advisory())
        for flags in ((), ("-v",), ("-vv",), ("-vvv",)):
            with self.subTest(flags=flags):
                _, terminal, _ = self.check(*flags)
                body = terminal.split("\n[PROVENANCE]\n", 1)[0]
                self.assertEqual(body.count("\nCVE-2026-0001\n"), 1)
                self.assertNotIn("DOCUMENT 1:", body)
                self.assertNotIn("Document 1, record", body)
                section = body.split("\nCVE-2026-0001\n", 1)[1]
                detailed = flags in (("-vv",), ("-vvv",))
                self.assertIn("vendor reports affected" if detailed else "Qualified yes", section)
                self.assertIn("[LOCAL FINDINGS]", section)
                self.assertLess(section.index("[LOCAL FINDINGS]"), section.index("[IDENTIFIED PRODUCTS]"))
                self.assertEqual("scope unknown: /app" in section, bool(flags))
                self.assertEqual("example.org/demo" in section, bool(flags))

    def test_cve_preview_keeps_status_and_artifacts_together(self) -> None:
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        report.binaries.append(
            replace(
                report.binaries[0],
                paths=["/second-only"],
                vulnerability_scan=models.VulnerabilityScan(
                    vulnerabilities=[models.Vulnerability("CVE-2026-0002")]
                ),
            )
        )
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        document = self.advisory()
        document["vulnerabilities"].append(
            {
                "cve": "CVE-2026-0002",
                "product_status": {"known_not_affected": ["combined"]},
            }
        )
        self.write_source("advisory.json", document)
        result, _, _ = self.check()
        limited = image_csaf.render_text(
            result, RenderPolicy(Verbosity.DETAILED, entry_limit=1)
        )
        self.assertIn("\nCVE-2026-0001\n", limited)
        self.assertIn("/app", limited)
        self.assertNotIn("CVE-2026-0002", limited)
        self.assertNotIn("second-only", limited)
        self.assertNotIn("known_not_affected", limited)
        self.assertIn("1 omitted; use --wide", limited)
        wide = image_csaf.render_text(
            result, RenderPolicy(Verbosity.DETAILED, entry_limit=1, wide=True)
        )
        section = wide.split("\nCVE-2026-0002\n", 1)[1]
        self.assertIn("second-only", section)
        self.assertIn("known_not_affected", section)
        self.assertNotIn("/app", section)

    def test_every_document_is_checked_independently_of_go_findings(self) -> None:
        self.write_source("advisory.json", self.advisory())
        empty = self.advisory()
        empty["vulnerabilities"] = []
        self.write_source("empty.json", empty)
        first, terminal, _ = self.check()
        self.assertEqual(first["summary"]["documents_checked"], 2)
        self.assertIn("Document 2: no CVE records", terminal)
        self.assertEqual(first["conclusions"]["Document 2: no CVE records"]["match"], "fuzzy")
        self.assertEqual(first["conclusions"]["Document 2: no CVE records"]["local_scan"]["status"], "undetermined")
        self.assertEqual(first["documents"][1]["vulnerabilities"], [])
        self.write_audit("CVE-2026-9999")
        second, _, _ = self.check()
        self.assertEqual(first["documents"], second["documents"])
        self.assertNotEqual(first["audit_sha256"], second["audit_sha256"])

    def test_local_artifacts_join_hashes_and_retain_location_observations(self) -> None:
        self.write_source("advisory.json", self.advisory(status="known_not_affected"))
        before, _, _ = self.check()
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.paths = ["/usr/bin/tap", "/usr/libexec/tap"]
        binary.sha256 = "b" * 64
        binary.runtime_disposition = "runtime"
        finding = models.VulnerabilityFinding(
            module="example.org/module",
            found_version="v1.2.0",
            fixed_version="v1.3.0",
            package="example.org/module/pkg",
            evidence="symbol",
            symbol="Unsafe",
            reachability="unspecified",
        )
        binary.vulnerability_scan.vulnerabilities = [
            models.Vulnerability(
                "GO-2026-0001",
                aliases=["cve-2026-0001", "CVE-2026-0001"],
                findings=[finding],
            ),
            models.Vulnerability(
                "GO-2026-0002", aliases=["CVE-2026-0001"], findings=[finding]
            ),
        ]
        report.binaries.append(
            replace(
                binary,
                paths=["/usr/bin/tap"],
                runtime_disposition="deleted",
                layer_history=[
                    models.BinaryLayerObservation(0, "found", ("/usr/bin/tap",)),
                    models.BinaryLayerObservation(2, "deleted", ("/usr/bin/tap",)),
                ],
            )
        )
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        result, terminal, saved = self.check("-v", "--wide")
        self.assertEqual(before["documents"], result["documents"])
        artifacts = result["local_findings"]["CVE-2026-0001"]
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(len(artifacts[0]["observations"]), 2)
        self.assertEqual(artifacts[0]["sha256"], "b" * 64)
        self.assertEqual(artifacts[0]["runtime_disposition"], "runtime")
        self.assertTrue(all(len(item["findings"]) == 1 for item in artifacts))
        self.assertTrue(
            all(
                item["advisories"] == ["GO-2026-0001", "GO-2026-0002"]
                for item in artifacts
            )
        )
        self.assertIn("usr/bin/tap", terminal)
        self.assertNotIn("rootfs/", terminal)
        self.assertIn("[LOCAL FINDINGS]", terminal)
        self.assertIn("LOCATION", terminal)
        self.assertIn("REACHABILITY", terminal)
        self.assertIn("example.org/module", terminal)
        self.assertNotIn("example.org/module/pkg", terminal)
        self.assertEqual(terminal.count("example.org/module"), 1)
        _, detailed, _ = self.check("-vv", "--wide")
        self.assertIn("usr/bin/tap", detailed)
        self.assertIn("usr/libexec/tap", detailed)
        self.assertNotIn("usr/bin/tap, usr/libexec/tap", detailed)
        self.assertNotIn("rootfs/", detailed)
        self.assertIn("layer-000/usr/bin/tap", detailed)
        self.assertNotIn("layer-002/usr/bin/tap", detailed)
        self.assertIn("known_not_affected", detailed)
        self.assertNotIn("example.org/module/pkg", detailed)
        package_table = (
            detailed.split("MODULE / PACKAGE FINDINGS\n", 1)[1]
            .split("\n\n", 1)[0]
            .splitlines()
        )
        self.assertLess(
            package_table[0].index("PACKAGE"), package_table[0].index("FOUND VERSION")
        )
        self.assertEqual(
            package_table[1].split()[:4],
            ["example.org/module", "pkg", "v1.2.0", "v1.3.0"],
        )
        self.assertIn("v1.2.0", detailed)
        self.assertIn("v1.3.0", detailed)
        self.assertNotIn("Unsafe", detailed)
        self.assertIn("example.org/module/pkg.Unsafe", saved)
        self.assertIn("layer-002 DELETED", saved)
        self.assertNotIn("Recorded reachability", saved)
        self.assertLess(saved.index("LOCAL FINDINGS"), saved.index("PROVENANCE"))

    def test_historical_artifacts_compare_and_different_hashes_remain_distinct(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.runtime_disposition = "deleted"
        report.binaries.append(replace(binary, sha256="1" * 64))
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        self.write_source("advisory.json", self.advisory())
        result, terminal, _ = self.check("--wide")
        artifacts = result["local_findings"]["CVE-2026-0001"]
        self.assertEqual({item["sha256"] for item in artifacts}, {"0" * 64, "1" * 64})
        self.assertEqual(len({tuple(item["paths"]) for item in artifacts}), 1)
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["local_scan"]["status"], "affected")
        self.assertEqual(conclusion["agreement"]["comparison"], "qualified_yes")
        self.assertIn("Runtime available:      No", terminal)

    def test_artifact_comparison_requires_full_hashes(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        for checksum in ("", "a" * 12):
            with self.subTest(checksum=checksum):
                report.binaries[0].sha256 = checksum
                (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
                with redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(main(["csaf", str(self.root)]), 1)
                message = (
                    "sha256 must be 64 lowercase hexadecimal digits"
                    if checksum
                    else "Binary SHA256 missing or invalid"
                )
                self.assertIn(message, errors.getvalue())

    def test_missing_local_evidence_is_not_inferred_from_vendor_status(self) -> None:
        self.write_source("advisory.json", self.advisory())
        result, terminal, saved = self.check()
        self.assertEqual(result["local_findings"], {"CVE-2026-0001": []})
        self.assertIn("Agreement:              Undetermined", terminal)
        self.assertIn("[LOCAL FINDINGS]\n  No local finding recorded in this audit.", terminal)
        self.assertIn("no local finding recorded; absence is not established", saved)
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        report.binaries[0].vulnerability_scan.vulnerabilities[0].findings = []
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        result, terminal, saved = self.check("-v", "--wide")
        artifact = result["local_findings"]["CVE-2026-0001"][0]
        self.assertEqual(artifact["findings"], [])
        self.assertIn("advisory only", terminal)
        self.assertIn("scope unknown: /app", terminal)
        self.assertIn("Local scan:             Not Affected", terminal)
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["agreement"]["comparison"], "undetermined")
        self.assertNotIn("rootfs/app", terminal)
        self.assertNotIn("symbol", saved.lower())

    def test_reachability_separates_presence_vendor_scope_and_execution(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.paths = ["/usr/bin/demo"]
        binary.vulnerability_scan.vulnerabilities[0].findings = [
            models.VulnerabilityFinding(evidence="symbol", symbol="Unsafe")
        ]
        flag = "vulnerable_code_not_in_execute_path"
        for runtime, exact, status, justification, expected in (
            ("runtime", True, "known_not_affected", flag, "NO"),
            ("runtime", False, "known_not_affected", flag, "UNDETERMINED"),
            ("runtime", True, "known_affected", flag, "UNDETERMINED"),
            ("runtime", True, "fixed", "", "UNDETERMINED"),
            (
                "runtime",
                True,
                "known_not_affected",
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "UNDETERMINED",
            ),
            (
                "runtime",
                True,
                "known_not_affected",
                "vulnerable_code_not_present",
                "UNDETERMINED",
            ),
            ("deleted", False, "known_affected", "", "NO"),
            ("replaced", False, "known_affected", "", "NO"),
            ("unknown", True, "known_not_affected", flag, "UNDETERMINED"),
            ("unaccounted", True, "known_not_affected", flag, "UNDETERMINED"),
        ):
            with self.subTest(
                runtime=runtime, exact=exact, status=status, flag=justification
            ):
                binary.runtime_disposition = runtime
                (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
                document = self.advisory(
                    purl=f"pkg:oci/demo@{self.digest}" if exact else "pkg:oci/demo",
                    status=status,
                )
                if justification:
                    document["vulnerabilities"][0]["flags"] = [
                        {"label": justification, "product_ids": ["combined"]}
                    ]
                self.write_source("advisory.json", document)
                result, expanded, _ = self.check("-vv", "--wide")
                table = expanded.split("[LOCAL FINDINGS]\n", 1)[1].split("\n\n", 1)[0].splitlines()
                self.assertEqual(result["local_findings"]["CVE-2026-0001"][0]["reachability"], expected)
                self.assertEqual(
                    table[0].split(),
                    [
                        "BINARY",
                        "RUNTIME",
                        "EVIDENCE",
                        "REACHABILITY",
                        "LOCATION",
                        "CGO",
                    ],
                )
                self.assertIn(f"  {expected}  ", table[1])
                self.assertIn(
                    "usr/bin/demo"
                    if runtime == "runtime"
                    else "scope unknown: /usr/bin/demo",
                    table[1],
                )
                self.assertIn("[LOCAL FINDINGS]", expanded)
                self.assertNotIn("Reachability explanation:", expanded)
                self.assertNotIn("Unsafe", expanded)
                detailed = image_csaf.render_text(
                    result, RenderPolicy(Verbosity.FORENSIC, wide=True)
                )
                self.assertIn("Reachability:           " + expected, detailed)
                self.assertNotIn("Reachability explanation:", detailed)
                self.assertIn(
                    "Location:               usr/bin/demo"
                    if runtime == "runtime"
                    else "scope unknown: /usr/bin/demo",
                    detailed,
                )
                self.assertIn("Vendor statement:", detailed)
                self.assertIn("Unsafe", detailed)
                self.assertEqual(
                    result["local_findings"]["CVE-2026-0001"][0]["findings"][0][
                        "reachability"
                    ],
                    "unspecified",
                )

    def test_reachability_cannot_borrow_other_product_or_conflicting_statements(self):
        self.identity = replace(
            self.identity,
            products=(
                models.ProductIdentity(
                    name="base",
                    cpes=self.identity.cpes,
                    purls=("pkg:oci/base@v1",),
                ),
            ),
        )
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        report.binaries[0].runtime_disposition = "runtime"
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        for purl, conflicting in (
            ("pkg:oci/base@v1", False),
            (f"pkg:oci/demo@{self.digest}", True),
        ):
            with self.subTest(purl=purl):
                document = self.advisory(purl=purl, status="known_not_affected")
                document["vulnerabilities"][0]["flags"] = [
                    {
                        "label": "vulnerable_code_not_in_execute_path",
                        "product_ids": ["combined"],
                    }
                ]
                self.write_source("advisory.json", document)
                if conflicting:
                    self.write_source(
                        "other.json", self.advisory(purl=purl, status="known_affected")
                    )
                result, expanded, _ = self.check("-vv", "--wide")
                self.assertEqual(
                    result["conclusions"]["CVE-2026-0001"]["match"], "exact"
                )
                row = expanded.split("[LOCAL FINDINGS]\n", 1)[1].split("\n\n", 1)[0].splitlines()[1]
                self.assertIn("  UNDETERMINED  ", row)
                if conflicting:
                    self.assertIn("Agreement:              Qualified yes", expanded)

    def test_local_scan_result_uses_findings_and_coverage_independently_of_csaf(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        cases = [
            ("complete", None, "runtime", False, "not_affected", False),
            ("failed", None, "runtime", False, "undetermined", False),
            ("not_run", None, "runtime", False, "undetermined", False),
            ("disabled", None, "runtime", False, "undetermined", False),
            ("complete", None, "runtime", True, "undetermined", False),
            ("no_go_binaries", None, "runtime", False, "not_affected", False),
            ("no_go_binaries", None, "runtime", True, "undetermined", False),
            ("failed", "module", "runtime", False, "affected", False),
            ("complete", "symbol", "deleted", False, "affected", True),
            ("complete", "symbol", "replaced", False, "affected", True),
            *(
                ("complete", kind, "runtime", False, "affected", False)
                for kind in ("module", "package", "symbol")
            ),
        ]
        for status, evidence, runtime, issue, expected, historical in cases:
            with self.subTest(
                status=status, evidence=evidence, runtime=runtime, issue=issue
            ):
                report.binaries = [] if status == "no_go_binaries" else [binary]
                binary.vulnerability_scan.status = (
                    "complete" if status == "no_go_binaries" else status
                )
                binary.runtime_disposition = runtime
                binary.vulnerability_scan.vulnerabilities[0].findings = (
                    [models.VulnerabilityFinding(evidence=evidence)] if evidence else []
                )
                report.issues = (
                    [models.ScanIssue("/unreadable", "discovery", "failed")]
                    if issue
                    else []
                )
                (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
                for vendor_status in ("known_affected", "known_not_affected"):
                    self.write_source(
                        "advisory.json", self.advisory(status=vendor_status)
                    )
                    result, terminal, _ = self.check("--wide")
                    local = result["conclusions"]["CVE-2026-0001"]["local_scan"]
                    self.assertEqual(local["status"], expected)
                    self.assertEqual(local["historical_only"], historical)
                    self.assertIn(
                        "Local scan:             "
                        + image_csaf.LOCAL_SCAN_LABELS[expected],
                        terminal,
                    )
                    self.assertEqual(
                        "Runtime available:      No" in terminal, historical
                    )
                    self.assertNotIn("Evidence:", terminal)

    def test_binary_rows_and_modules_are_unique_sorted_and_expand_by_verbosity(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.runtime_disposition = "runtime"
        binary.sha256 = "1" * 64
        binary.paths = ["/z/app"]
        finding = models.VulnerabilityFinding(
            module="example.org/a",
            found_version="v1.0.0",
            fixed_version="v1.1.0",
            package="example.org/a/pkg",
            evidence="symbol",
            symbol="Zulu",
        )
        binary.vulnerability_scan.vulnerabilities[0].findings = [
            finding,
            replace(finding, symbol="Alpha"),
            replace(finding, evidence="package", symbol=None),
            finding,
            replace(finding, package="example.org/a/other", symbol="Other"),
            replace(
                finding,
                module="example.org/z",
                package="",
                symbol=None,
                evidence="module",
            ),
        ]
        report.binaries = [
            replace(binary, paths=["/a/zeta"], sha256="3" * 64),
            binary,
            replace(binary),
            replace(binary, paths=["/other/app"], sha256="2" * 64),
        ]
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        first, expanded, forensic = self.check("-v", "--wide")
        self.assertEqual(len(first["local_findings"]["CVE-2026-0001"]), 3)
        self.assertEqual(expanded.count("example.org/a"), 1)
        self.assertEqual(expanded.count("example.org/z"), 1)
        self.assertLess(
            expanded.index("example.org/a"), expanded.index("example.org/z")
        )
        self.assertNotIn("PACKAGE", expanded)
        self.assertIn("BINARY", expanded)
        self.assertIn("[LOCAL FINDINGS]", expanded)
        self.assertLess(expanded.index("[LOCAL FINDINGS]"), expanded.index("MODULES"))
        detailed = image_csaf.render_text(
            first, RenderPolicy(Verbosity.DETAILED, wide=True)
        )
        summary = image_csaf.render_text(first, RenderPolicy(Verbosity.SUMMARY, wide=True))
        table = summary.split("[LOCAL FINDINGS]\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(table.splitlines()[0].split(), ["BINARY", "RUNTIME", "EVIDENCE"])
        self.assertEqual(table.count("module"), 3)
        self.assertEqual(table.count("package"), 3)
        self.assertEqual(table.count("symbol"), 3)
        self.assertNotIn("module, symbol", table)
        self.assertNotIn("REACHABILITY", table)
        for text in (expanded, detailed):
            header = text.split("[LOCAL FINDINGS]\n", 1)[1].splitlines()[0].split()
            self.assertEqual(header[:4], ["BINARY", "RUNTIME", "EVIDENCE", "REACHABILITY"])
            self.assertNotIn("Evidence:", text)
        self.assertIn("PACKAGE", detailed)
        self.assertNotIn("example.org/a/pkg", detailed)
        package_table = (
            detailed.split("MODULE / PACKAGE FINDINGS\n", 1)[1]
            .split("\n\n", 1)[0]
            .splitlines()
        )
        self.assertEqual(
            [row.split()[1] for row in package_table[1:3]], ["other", "pkg"]
        )
        self.assertNotIn("Zulu", detailed)
        table = detailed.split("[LOCAL FINDINGS]\n", 1)[1].split("\n\n", 1)[0].splitlines()
        binaries = [row for row in table[1:] if row.startswith(("  app ", "  zeta "))]
        self.assertEqual([row.split()[0] for row in binaries], ["app", "app", "zeta"])
        self.assertTrue(any("other/app" in row for row in binaries))
        self.assertTrue(any("z/app" in row for row in binaries))
        self.assertTrue(any("1" * 64 in row for row in binaries))
        self.assertTrue(any("2" * 64 in row for row in binaries))
        self.assertEqual(forensic.count("BINARY: app"), 2)
        self.assertEqual(forensic.count("example.org/a/pkg.Zulu"), 3)
        self.assertLess(
            forensic.index("example.org/a/pkg.Alpha"),
            forensic.index("example.org/a/pkg.Zulu"),
        )
        limited = image_csaf.render_text(
            first, RenderPolicy(Verbosity.DETAILED, entry_limit=2)
        )
        self.assertIn("Additional binaries:    1 omitted", limited)
        report.binaries.reverse()
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        second, _, _ = self.check("--wide")
        self.assertEqual(first["local_findings"], second["local_findings"])

    def test_summary_local_findings_show_runtime_and_evidence(self) -> None:
        self.write_audit("CVE-2026-0001")
        self.write_source("advisory.json", self.advisory())
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        cases = (
            ("current", "runtime", "YES"),
            ("deleted", "deleted", "NO"),
            ("replaced", "replaced", "NO"),
            ("historical", "unaccounted", "UNDETERMINED"),
            ("unknown", "unknown", "UNDETERMINED"),
        )
        report.binaries = [
            replace(binary, paths=[f"/bin/{case[0]}"], sha256=str(index) * 64, runtime_disposition=case[1])
            for index, case in enumerate(cases, 1)
        ]
        report.binaries.append(replace(report.binaries[0], paths=["/other/current"]))
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        result, terminal, forensic = self.check("--wide")
        section = terminal.split("[LOCAL FINDINGS]\n", 1)[1].split("\n[IDENTIFIED PRODUCTS]", 1)[0]
        table = section.strip().splitlines()
        self.assertEqual(table[0].split(), ["BINARY", "RUNTIME", "EVIDENCE"])
        self.assertEqual(
            [tuple(row.split()) for row in table[1:] if row.strip()],
            sorted((case[0], case[2], "module") for case in cases),
        )
        self.assertEqual(len(result["local_findings"]["CVE-2026-0001"]), 5)
        self.assertNotIn("MODULES", section)
        self.assertNotIn("LOCATION", section)
        self.assertNotIn("REACHABILITY", section)
        self.assertNotIn("example.org/demo", section)
        self.assertIn("Runtime disposition:    RUNTIME", forensic)

    def test_summary_keeps_distinct_binaries_with_the_same_abbreviated_hash(self) -> None:
        self.write_audit("CVE-2026-0001")
        self.write_source("advisory.json", self.advisory())
        report = audit.load_audit(self.root / "audit.json")
        report.binaries = [
            replace(report.binaries[0], paths=[f"/{index}/app"], sha256="a" * 63 + str(index), runtime_disposition="runtime")
            for index in (1, 2)
        ]
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        result, terminal, forensic = self.check()
        section = terminal.split("[LOCAL FINDINGS]\n", 1)[1].split("\n[IDENTIFIED PRODUCTS]", 1)[0]
        self.assertEqual(sum(row.lstrip().startswith("app ") for row in section.splitlines()), 2)
        wide = image_csaf.render_text(result, RenderPolicy(Verbosity.SUMMARY, wide=True))
        for binary in report.binaries:
            self.assertIn(binary.sha256, wide)
        self.assertEqual(forensic.count("BINARY: app"), 2)

    def test_package_cgo_reports_binary_settings_without_splitting_package_rows(self):
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        binary = report.binaries[0]
        binary.runtime_disposition = "runtime"
        binary.vulnerability_scan.vulnerabilities[0].findings = [
            models.VulnerabilityFinding(
                module="example.org/demo",
                found_version="v1.0.0",
                package="example.org/demo/pkg",
            )
        ]
        report.binaries = [
            replace(
                binary,
                paths=[f"/bin/{name}"],
                sha256=(value or "2") * 64,
                build_settings=[models.BuildSetting("CGO_ENABLED", value)]
                if value
                else [],
            )
            for name, value in (("enabled", "1"), ("disabled", "0"), ("unknown", ""))
        ]
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        result, expanded, forensic = self.check("-v", "--wide")
        self.assertNotIn("CGO", expanded)
        self.assertEqual(
            {item["cgo_enabled"] for item in result["local_findings"]["CVE-2026-0001"]},
            {True, False, None},
        )
        detailed = image_csaf.render_text(
            result, RenderPolicy(Verbosity.DETAILED, wide=True)
        )
        self.assertIn("BINARY CGO", detailed)
        cgo_lines = (
            detailed.split("MODULE / PACKAGE FINDINGS\n", 1)[1]
            .split("\n\n", 1)[0]
            .splitlines()
        )
        self.assertEqual(
            [line.split()[-1] for line in cgo_lines[1:]],
            ["Disabled", "Enabled", "Unknown"],
        )
        self.assertEqual(
            len(
                {
                    line.index(value)
                    for line, value in zip(
                        cgo_lines[1:], ("Disabled", "Enabled", "Unknown")
                    )
                }
            ),
            1,
        )
        self.assertNotIn("example.org/demo/pkg", detailed)
        self.assertEqual(
            cgo_lines[1].split()[:3], ["example.org/demo", "pkg", "v1.0.0"]
        )
        for name, value in (
            ("enabled", "Enabled"),
            ("disabled", "Disabled"),
            ("unknown", "Unknown"),
        ):
            section = forensic.split(f"BINARY: {name}", 1)[1].split("BINARY:", 1)[0]
            self.assertIn("CGO:                    " + value, section)

    def test_candidates_have_independent_agreement_and_expand_from_v(self):
        self.identity = replace(
            self.identity, purls=("pkg:oci/demo", "pkg:oci/alternate")
        )
        self.write_audit("CVE-2026-0001")
        report = audit.load_audit(self.root / "audit.json")
        report.binaries[0].runtime_disposition = "runtime"
        report.binaries[0].vulnerability_scan.vulnerabilities[0].findings = [
            models.VulnerabilityFinding(evidence="symbol", symbol="Observed")
        ]
        (self.root / "audit.json").write_text(json.dumps(report.to_dict()))
        document = self.advisory()
        document["product_tree"]["full_product_names"].append(
            self.product("alternative", "pkg:oci/alternate")
        )
        document["product_tree"]["relationships"].append(
            self.relation("alternative", "platform", "other-combined")
        )
        document["vulnerabilities"][0]["product_status"]["known_not_affected"] = [
            "other-combined"
        ]
        flag = "vulnerable_code_not_in_execute_path"
        for flagged, outcome in (
            ("combined", "mixed"),
            ("other-combined", "qualified_yes"),
        ):
            with self.subTest(flagged=flagged):
                document["vulnerabilities"][0]["flags"] = [
                    {"label": flag, "product_ids": [flagged]}
                ]
                self.write_source("advisory.json", document)
                result, expanded, _ = self.check("-v", "--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["agreement"]["comparison"], outcome)
                by_id = {
                    tuple(item["product_ids"]): item
                    for item in conclusion["candidates"]
                }
                self.assertEqual(
                    by_id[("combined",)]["agreement"]["comparison"], "qualified_yes"
                )
                self.assertEqual(
                    by_id[("other-combined",)]["agreement"]["comparison"],
                    "qualified_no" if flagged == "combined" else "qualified_yes",
                )
                self.assertTrue(
                    all(
                        item["agreement"]["comparison"] != "mixed"
                        for item in conclusion["candidates"]
                    )
                )
                if outcome == "mixed":
                    self.assertIn("Agreement:              Qualified no", expanded)
                    self.assertEqual(expanded.count("Agreement:              Mixed"), 1)
                self.assertEqual(expanded.count("[IDENTIFIED PRODUCTS]"), 1)
                self.assertIn("\n    demo\n", expanded)
                self.assertIn("\n    alternate\n", expanded)
                self.assertNotIn("CANDIDATE:", expanded)
                self.assertEqual(expanded.count("Agreement:"), 3)
                self.assertNotIn("Product IDs:", expanded)
                self.assertNotIn("Vendor status:", expanded)
                self.assertNotIn("Product CPEs:", expanded)
                self.assertNotIn("Product context:", expanded)
                self.assertNotIn("PURL:", expanded)
                self.assertNotIn("Checks:", expanded)
                self.assertIn("CSAF product ID:        component", expanded)
                self.assertIn("CSAF product ID:        alternative", expanded)
                self.assertIn("Matched product IDs:    combined", expanded)
                self.assertIn("Matched product IDs:    other-combined", expanded)
                self.assertRegex(expanded, r"Mismatches:\s+none established")
                detailed = image_csaf.render_text(
                    result, RenderPolicy(Verbosity.DETAILED, wide=True)
                )
                self.assertIn("Checks:", detailed)
                self.assertIn("Vendor statement:", detailed)
                self.assertEqual(detailed.count("PRODUCT: combined"), 1)
        pinned, _, _ = self.check("--csaf-product-id", "combined", "-v", "--wide")
        candidates = pinned["conclusions"]["CVE-2026-0001"]["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["match"], "exact")
        self.assertEqual(candidates[0]["agreement"]["comparison"], "yes")

    def test_compact_candidates_distinguish_architectures_and_missing_metadata(self):
        digest = "sha256:" + "b" * 64
        document = self.advisory(purl=f"pkg:oci/demo@{digest}?arch=arm64")
        document["product_tree"]["full_product_names"].append(
            self.product("second-build", f"pkg:oci/demo@{digest}?arch=amd64")
        )
        self.write_source("advisory.json", document)
        for platform, reason in (
            ("linux/amd64", "Architecture differs: image amd64, candidate arm64"),
            ("", "Image architecture missing; candidate requires arm64"),
        ):
            with self.subTest(platform=platform):
                self.identity = replace(self.identity, platform=platform)
                self.write_audit("CVE-2026-0001")
                result, terminal, saved = self.check("-v", "--wide")
                section = terminal.split("[IDENTIFIED PRODUCTS]", 1)[1].split(
                    "\nMODULES", 1
                )[0]
                self.assertIn("demo (sha256:bbbbbbbbbbbb…)", section)
                self.assertNotIn(reason, section)
                if platform:
                    self.assertIn(
                        "Architecture differs: image amd64; candidate arm64; treated as equivalent",
                        saved,
                    )
                self.assertNotIn("architecture not established", section)
                self.assertNotIn(digest, section)
                self.assertIn("CSAF product ID:        component", section)
                self.assertIn("CSAF product ID:        second-build", section)
                self.assertIn("Matched product IDs:    combined", section)
                self.assertNotIn("none (no supported match)", section)
                self.assertIn(digest, saved)
                self.assertIn("CSAF product ID:        second-build", saved)
                self.assertIn("PRODUCT: second-build", saved)
                self.assertEqual(
                    result["conclusions"]["CVE-2026-0001"]["match"], "fuzzy"
                )

    def test_display_inputs_verbosity_provenance_and_wide_output(self) -> None:
        self.identity = replace(
            self.identity,
            image_build_release="unused-build",
            component_version="unused-version",
        )
        self.write_audit()
        document = self.advisory()
        canonical_url = "https://vendor.example/csaf/cve-2026-0001.json"
        document["document"] = {
            "tracking": {"id": "CVE-2026-0001"},
            "references": [
                {"category": "self", "summary": "Advisory", "url": canonical_url}
            ],
        }
        document["vulnerabilities"] *= 12
        self.write_source("advisory.json", document)
        outputs = [self.check(*flags) for flags in ((), ("-v",), ("-vv",), ("-vvv",))]
        result, summary, saved = outputs[0]
        self.assertEqual(result["documents"][0]["canonical_urls"], [canonical_url])
        self.assertTrue(all(item[0] == result and item[2] == saved for item in outputs))
        for _, text, _ in outputs:
            self.assertNotIn("CANDIDATE:", text)
            self.assertNotIn("Match evidence:", text)
            self.assertNotIn("Reachability explanation:", text)
            self.assertNotIn("Recorded reachability:", text)
        expanded = outputs[1][1]
        self.assertEqual(summary.count("[LOCAL LOOKUP CANDIDATES]"), 1)
        self.assertNotIn("CSAF records", summary)
        self.assertEqual(expanded.count("[LOCAL LOOKUP CANDIDATES]"), 1)
        self.assertIn("pkg:oci/demo", expanded)
        self.assertIn("Image digest:           sha256:aaaaaaaaaaaa", expanded)
        self.assertIn("Additional CSAF records:", expanded)
        self.assertIn("2 omitted; use --wide", outputs[2][1])
        body = summary.split(f"CVE-2026-0001: {canonical_url}\n", 1)[1].split(
            "\n\n", 1
        )[0]
        self.assertEqual(
            [line.split(":", 1)[0] for line in body.splitlines() if ":" in line],
            [
                "Local scan",
                "CSAF ID Match",
                "Vendor assessment",
                "Agreement",
            ],
        )
        self.assertEqual(summary.count("      - component"), 1)
        self.assertIn("\n\nMore information:", summary)
        self.assertNotIn("unused-build", saved)
        self.assertNotIn("unused-version", saved)
        self.assertNotIn("Product IDs:", summary)
        self.assertNotIn("Product IDs:", outputs[1][1])
        self.assertIn("PRODUCT: combined", outputs[2][1])
        for _, text, _ in outputs:
            self.assertNotIn("[CSAF MATCH CANDIDATES:", text)
            self.assertEqual(text.count("[IDENTIFIED PRODUCTS]"), 1)
            self.assertLess(
                text.index("[LOCAL LOOKUP CANDIDATES]"),
                text.index(f"CVE-2026-0001: {canonical_url}"),
            )
        self.assertNotIn("[MATCH EVIDENCE]", saved)
        self.assertNotIn("[CANDIDATE EVIDENCE]", saved)
        for _, text, _ in outputs[:3]:
            self.assertNotIn("PROVENANCE", text)
            self.assertNotIn((self.sources / "advisory.json").as_uri(), text)
            self.assertIn(f"CVE-2026-0001: {canonical_url}\n", text)
        self.assertIn("PROVENANCE", outputs[3][1])
        self.assertNotIn("More information:", saved)
        provenance = saved.split("[PROVENANCE]", 1)[1]
        self.assertIn((self.sources / "advisory.json").as_uri(), provenance)
        self.assertIn("Canonical URLs:         " + canonical_url, provenance)
        self.assertTrue(saved.rstrip().endswith(canonical_url))
        wide = image_csaf.render_text(result, FULL_POLICY)
        self.assertIn(self.digest, wide)
        self.assertNotIn("omitted", wide)

    def test_lookup_inputs_are_shared_without_combining_cve_assessments(self):
        self.write_audit("CVE-2026-0001", "CVE-2026-0002")
        document = self.advisory()
        document["vulnerabilities"].append(
            {
                "cve": "CVE-2026-0002",
                "product_status": {"fixed": ["combined"]},
            }
        )
        self.write_source("advisory.json", document)
        outputs = [
            self.check(*flags, "--wide") for flags in ((), ("-v",), ("-vv",), ("-vvv",))
        ]
        result = outputs[0][0]
        for actual, text, _ in outputs:
            self.assertEqual(actual, result)
            self.assertEqual(text.count("[LOCAL LOOKUP CANDIDATES]"), 1)
            self.assertEqual(text.count("[IDENTIFIED PRODUCTS]"), 2)
            self.assertLess(text.index("pkg:oci/demo"), text.index("\nCVE-2026-0001\n"))
            first, second = text.split("\nCVE-2026-0001\n", 1)[1].split(
                "\nCVE-2026-0002\n", 1
            )
            self.assertIn("Agreement:              Qualified yes", first)
            self.assertNotIn("Agreement:              Qualified no", first)
            self.assertIn("Agreement:              Qualified no", second)
            self.assertNotIn("Agreement:              Qualified yes", second)
            for heading in (
                "SAME RELEASE",
                "BROADER PRODUCT FAMILY",
                "OTHER RELEASES OR PRODUCTS",
                "[CSAF MATCH CANDIDATES:",
            ):
                self.assertNotIn(heading, text)

    def test_preview_limits_retain_all_evidence_in_json(self) -> None:
        self.write_source("advisory.json", self.advisory())
        result, _, _ = self.check()
        limited = image_csaf.render_text(
            result, RenderPolicy(Verbosity.DETAILED, entry_limit=1)
        )
        self.assertIn("combined", limited)
        self.assertEqual(len(result["documents"][0]["candidates"][0]["entries"]), 2)

    def test_missing_or_invalid_documents_fail(self) -> None:
        with redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(main(["csaf", str(self.root)]), 1)
        self.assertIn("no CSAF JSON files supplied", errors.getvalue())
        for invalid in ([], {"product_tree": []}, {"vulnerabilities": {}}):
            with self.subTest(invalid=invalid):
                self.write_source("advisory.json", invalid)
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["csaf", str(self.root)]), 1)

    def test_summary_distinguishes_exact_fuzzy_and_unresolved_products(self):
        self.write_audit("CVE-2026-0001")
        cases = (
            (f"pkg:oci/demo@{self.digest}", self.identity.cpes[0], "exact"),
            ("pkg:oci/demo", self.identity.cpes[0], "fuzzy"),
            ("pkg:oci/demo", "cpe:/a:redhat:openshift:4", "fuzzy"),
            ("pkg:oci/demo@another-build", self.identity.cpes[0], "fuzzy"),
            ("pkg:oci/demo?arch=arm64", self.identity.cpes[0], "fuzzy"),
            ("pkg:oci/demo", "cpe:/a:redhat:openshift:4::el8", "ambiguous"),
            ("pkg:oci/other", self.identity.cpes[0], "no_match"),
        )
        for purl, cpe, match in cases:
            with self.subTest(purl=purl, cpe=cpe):
                self.write_source("advisory.json", self.advisory(purl=purl, cpe=cpe))
                result, _, _ = self.check("--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["match"], match)
                self.assertEqual(
                    conclusion["agreement"]["comparison"],
                    {
                        "exact": "yes",
                        "fuzzy": "qualified_yes",
                        "ambiguous": "qualified_yes",
                    }.get(match, "undetermined"),
                )

    def test_mixed_unconfirmed_builds_and_matching_products_are_distinguished(self):
        self.write_audit("CVE-2026-0001")
        for purl, second_purl, match, outcome in (
            (
                "pkg:oci/demo@first-build",
                "pkg:oci/demo@second-build",
                "ambiguous",
                "mixed",
            ),
            ("pkg:oci/demo", "pkg:oci/demo", "fuzzy", "mixed"),
            (
                f"pkg:oci/demo@{self.digest}",
                "pkg:oci/demo@another-build",
                "exact",
                "yes",
            ),
            (
                f"pkg:oci/demo@{self.digest}?arch=amd64",
                f"pkg:oci/demo@{self.digest}?arch=arm64",
                "exact",
                "mixed",
            ),
            ("pkg:oci/demo?arch=amd64", "pkg:oci/demo?arch=arm64", "fuzzy", "mixed"),
        ):
            with self.subTest(match=match):
                document = self.advisory(purl=purl)
                document["product_tree"]["full_product_names"].append(
                    self.product("alternative", second_purl)
                )
                document["product_tree"]["relationships"].append(
                    self.relation("alternative", "platform", "other-combined")
                )
                document["vulnerabilities"][0]["product_status"]["fixed"] = [
                    "other-combined"
                ]
                self.write_source("advisory.json", document)
                result, text, saved = self.check("--wide")
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["match"], match)
                self.assertEqual(conclusion["agreement"]["comparison"], outcome)
                if match == "exact" and outcome == "yes":
                    self.assertEqual(
                        conclusion["agreement"]["statuses"], ["known_affected"]
                    )
                    self.assertNotIn("other-combined", saved)
                    self.assertNotIn("alternative", json.dumps(result))

    def test_fuzzy_cpe_alternatives_are_order_independent_and_keep_constraints(self):
        cpes = ("cpe:/a:redhat:openshift:4", "cpe:/a:redhat:openshift:4.20::el9")
        self.write_source(
            "advisory.json", self.advisory(cpe="cpe:/a:redhat:openshift:4::el9")
        )
        for order in (cpes, cpes[::-1]):
            with self.subTest(order=order):
                self.identity = replace(self.identity, cpes=order)
                self.write_audit("CVE-2026-0001")
                result, _, _ = self.check()
                self.assertEqual(
                    result["conclusions"]["CVE-2026-0001"]["match"], "fuzzy"
                )
                self.assertEqual(result["documents"][0]["presence"], "matched")

    def test_cross_document_conflicting_statements_share_one_conclusion(self):
        self.write_audit("CVE-2026-0001")
        self.write_source("first.json", self.advisory())
        self.write_source("second.json", self.advisory(status="known_not_affected"))
        result, terminal, saved = self.check("--wide")
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["agreement"]["comparison"], "mixed")
        self.assertEqual(conclusion["match"], "fuzzy")
        self.assertEqual(conclusion["match_count"], 1)
        self.assertEqual(terminal.count("Agreement:"), 1)
        self.assertIn("Document 1, record 1", saved)
        self.assertIn("Document 2, record 1", saved)

    def test_exact_match_discards_weaker_records_without_dropping_other_cves(self):
        self.write_audit("CVE-2026-0001", "CVE-2026-0002")
        self.write_source("exact.json", self.advisory(purl=f"pkg:oci/demo@{self.digest}"))
        weaker = self.advisory(status="fixed")
        weak_path = self.write_source("weaker.json", weaker)
        result, _, saved = self.check("--wide")
        self.assertEqual(result["summary"]["documents_checked"], 2)
        self.assertEqual(len(result["documents"]), 1)
        self.assertNotIn("weaker.json", saved)
        first = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual((first["match"], first["agreement"]["comparison"]), ("exact", "yes"))
        self.assertEqual(first["candidate_statuses"], ["known_affected"])
        weaker["vulnerabilities"].append({"cve": "CVE-2026-0002", "product_status": {"known_affected": ["combined"]}})
        weak_path.write_text(json.dumps(weaker))
        result, _, _ = self.check()
        self.assertEqual(len(result["documents"]), 2)
        self.assertEqual([record["id"] for record in result["documents"][1]["vulnerabilities"]], ["CVE-2026-0002"])
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["agreement"]["comparison"], "yes")
        self.assertEqual(result["conclusions"]["CVE-2026-0002"]["agreement"]["comparison"], "qualified_yes")

    def test_exact_product_without_status_cannot_fall_back_to_weaker_status(self):
        self.write_audit("CVE-2026-0001")
        exact = self.advisory(purl=f"pkg:oci/demo@{self.digest}")
        exact["vulnerabilities"][0]["product_status"] = {}
        self.write_source("exact.json", exact)
        self.write_source("weaker.json", self.advisory())
        result, _, _ = self.check()
        conclusion = result["conclusions"]["CVE-2026-0001"]
        self.assertEqual(conclusion["match"], "exact")
        self.assertEqual(conclusion["agreement"]["comparison"], "undetermined")
        self.assertEqual(len(result["documents"]), 1)

    def test_multiple_matching_products_require_all_statements_to_support_agreement(
        self,
    ):
        self.identity = replace(
            self.identity, purls=("pkg:oci/demo", "pkg:oci/alternate")
        )
        self.write_audit("CVE-2026-0001")
        document = self.advisory()
        document["product_tree"]["full_product_names"].append(
            self.product("alternative", "pkg:oci/alternate")
        )
        document["product_tree"]["relationships"].append(
            self.relation("alternative", "platform", "other-combined")
        )
        for statuses, expected in (
            ({}, "undetermined"),
            ({"known_affected": ["combined", "other-combined"]}, "qualified_yes"),
        ):
            with self.subTest(statuses=statuses):
                document["vulnerabilities"][0]["product_status"] = statuses or {
                    "known_affected": ["combined"]
                }
                self.write_source("advisory.json", document)
                result, _, _ = self.check()
                conclusion = result["conclusions"]["CVE-2026-0001"]
                self.assertEqual(conclusion["match"], "ambiguous")
                self.assertEqual(conclusion["match_count"], 2)
                self.assertEqual(conclusion["agreement"]["comparison"], expected)

    def test_local_cves_without_documents_remain_in_the_summary(self):
        self.write_audit("CVE-2026-0001", "CVE-2026-0002")
        result, terminal, _ = self.check("--wide")
        self.assertEqual(
            {item["match"] for item in result["conclusions"].values()}, {"no_document"}
        )
        self.assertEqual(terminal.count("\nCVE-2026-0001\n"), 1)
        self.assertEqual(terminal.count("\nCVE-2026-0002\n"), 1)
        self.write_source("advisory.json", self.advisory())
        result, _, _ = self.check()
        self.assertEqual(result["conclusions"]["CVE-2026-0002"]["match"], "no_document")
        missing_path = self.sources / "CVE-2026-0001.json"
        result, _, _ = self.check("--csaf", str(missing_path))
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match"], "no_document")
        _, missing, _ = self.check("--csaf", str(self.root / "wrong-directory"))
        self.assertIn(
            "CSAF file not provided. Check whether one is available from your CSAF provider.",
            missing,
        )

    def test_cached_404_shadows_stale_file_but_not_another_document(self):
        self.write_audit("CVE-2026-0001")
        stale = self.write_source("CVE-2026-0001.json", self.advisory())
        marker = stale.with_suffix(".missing")
        marker.write_text(json.dumps({"url": "https://vendor.example/CVE-2026-0001.json", "status": 404, "checked_at": "2026-11-05T12:00:00+00:00"}))
        result, terminal, saved = self.check("--wide")
        self.assertEqual(result["documents"], [])
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match"], "no_document")
        self.assertIn("cached HTTP 404", result["conclusions"]["CVE-2026-0001"]["qualifications"])
        self.assertNotIn(str(marker), terminal)
        self.assertIn(str(marker), saved.split("PROVENANCE", 1)[1])
        self.assertTrue(stale.is_file())
        # Explicitly selecting the retained JSON must respect its absence marker too.
        result, _, _ = self.check("--csaf", str(stale))
        self.assertEqual(result["documents"], [])
        stale.unlink()
        result, terminal, _ = self.check("--csaf", str(stale))
        self.assertIn("cached HTTP 404", result["conclusions"]["CVE-2026-0001"]["qualifications"])
        self.assertEqual(result["documents"], [])
        self.write_source("fresh.json", self.advisory())
        result, _, _ = self.check()
        self.assertEqual(len(result["documents"]), 1)
        self.assertEqual(result["conclusions"]["CVE-2026-0001"]["match"], "fuzzy")
        marker.write_text('{"status":404}')
        with redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(main(["csaf", str(self.root)]), 1)
        self.assertIn("invalid CSAF missing marker", errors.getvalue())

    def test_missing_identity_does_not_match_a_truncated_digest(self) -> None:
        self.identity = models.ImageIdentity(digest="sha256:aaaa")
        self.write_audit()
        self.write_source(
            "advisory.json", self.advisory(purl="pkg:oci/demo@sha256:aaaa")
        )
        result, _, _ = self.check()
        self.assertEqual(result["documents"][0]["presence"], "not_identified")
        self.assertEqual(result["match_inputs"]["digest"], "")


if __name__ == "__main__":
    unittest.main()
