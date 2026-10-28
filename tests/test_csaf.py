from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


from pygo_audit import audit, csaf, models
from pygo_audit.cli import main
from pygo_audit.report_views import index_cve_evidence
from pygo_audit.result_cache import ResultCache, ResultCacheError
from pygo_audit.storage import atomic_read_json, atomic_write_json


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


def binary_report(
    path: str, *vulnerabilities: models.Vulnerability
) -> models.BinaryReport:
    return models.BinaryReport(
        paths=[path],
        size=123,
        go_version="go1.24.0",
        main_package="main",
        main_module=None,
        dependencies=[],
        build_settings=[],
        sha256="b" * 64,
        runtime_disposition="runtime",
        vulnerability_scan=models.VulnerabilityScan(
            status="complete", vulnerabilities=list(vulnerabilities)
        ),
    )


class CheckCsafTests(unittest.TestCase):
    def test_rejects_partial_and_malformed_audits_before_matching(self) -> None:
        malformed = report(
            binary_report("/app", models.Vulnerability("CVE-2026-0001"))
        ).to_dict()
        malformed["binaries"][0]["vulnerability_scan"]["vulnerabilities"][0][
            "aliases"
        ] = "CVE-2026-0002"
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            for document in ({"binaries": []}, malformed):
                with self.subTest(document=document):
                    path.write_text(json.dumps(document))
                    with self.assertRaises(audit.AuditError):
                        csaf.compare_audit(path, {})

    def test_cached_assessments_keep_current_audit_evidence_and_source_paths(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            document = report(
                binary_report("/original", models.Vulnerability("CVE-2026-0001"))
            ).to_dict()
            audit_file = root / "audit.json"
            source = root / "advisory.json"
            audit_file.write_text(json.dumps(document), encoding="utf-8")
            source.write_text(json.dumps(self.cpe_document()), encoding="utf-8")
            cache = ResultCache(root / "cache")
            first = csaf.compare_audit(
                audit_file, csaf.document_locations([source]), cache
            )
            self.assertEqual(first["summary"]["cves_checked"], 1)
            self.assertEqual(first["local_findings"]["CVE-2026-0001"]["findings"], [])
            cached = atomic_read_json(
                next((root / "cache" / "objects").glob("*.json")), checksum=True
            )
            self.assertEqual(
                cached,
                {
                    name: value
                    for name, value in first["assessments"][0].items()
                    if name != "url"
                },
            )
            moved_source = root / "moved.json"
            source.rename(moved_source)
            document["binaries"][0]["paths"] = ["/current"]
            audit_file.write_text(json.dumps(document), encoding="utf-8")
            with patch.object(
                csaf, "index_document", side_effect=AssertionError("miss")
            ):
                result = csaf.compare_audit(
                    audit_file,
                    csaf.document_locations([moved_source]),
                    ResultCache(root / "cache", run_id=cache.run_id),
                )
            self.assertEqual(result["assessments"][0]["url"], moved_source.as_uri())
            self.assertEqual(
                result["local_findings"]["CVE-2026-0001"]["binary_paths"], ["/current"]
            )
            with patch.object(
                csaf, "index_document", wraps=csaf.index_document
            ) as index:
                csaf.compare_audit(
                    audit_file,
                    csaf.document_locations([moved_source]),
                    ResultCache(root / "cache"),
                )
                index.assert_called_once()

    def test_assessment_cache_keys_cover_document_identity_cve_run_and_detail(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            fetch = csaf.DocumentResult(
                "CVE-2026-0001", "original", self.cpe_document()
            )
            identity = models.ImageIdentity(cpe="cpe:/a:redhat:openshift:4.20::el9")

            def assess(
                cve="CVE-2026-0001", image=identity, details=True, run_id="test-run"
            ):
                return csaf.CsafComparison(
                    cve, fetch, ResultCache(directory, run_id=run_id)
                ).assess(image, include_details=details)

            with patch.object(
                csaf, "assess_indexed_document", wraps=csaf.assess_indexed_document
            ) as matcher:
                original = assess()
                self.assertEqual(assess(), original)
                self.assertEqual(matcher.call_count, 1)
                assess(image=models.ImageIdentity())
                assess(cve="CVE-2026-0002")
                compact = assess(details=False)
                self.assertNotIn("cpe_matches", compact)
                assess(run_id="next-run")
                fetch.document["vulnerabilities"][0]["product_status"] = {
                    "fixed": ["combination"]
                }
                changed = assess()
                self.assertFalse(changed["cpe_known_affected"])
                self.assertEqual(matcher.call_count, 6)

    def test_corrupt_or_nonobject_assessments_are_recomputed(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            fetch = csaf.DocumentResult("CVE-2026-0001", "source", self.cpe_document())

            def assess():
                return csaf.CsafComparison(
                    fetch.cve, fetch, ResultCache(directory, run_id="test-run")
                ).assess(models.ImageIdentity())

            expected = assess()
            path = next((directory / "objects").glob("*.json"))
            original = path.read_bytes()
            for fault in ("truncated", "checksum", "nonobject"):
                with self.subTest(fault=fault):
                    if fault == "truncated":
                        path.write_bytes(original[:-10])
                    elif fault == "checksum":
                        path.write_bytes(
                            original.replace(b"CVE-2026-0001", b"CVE-2026-0002")
                        )
                    else:
                        atomic_write_json(path, [], overwrite=True, checksum=True)
                    with patch.object(
                        csaf,
                        "assess_indexed_document",
                        wraps=csaf.assess_indexed_document,
                    ) as matcher:
                        self.assertEqual(assess(), expected)
                        matcher.assert_called_once()
                    self.assertEqual(path.read_bytes(), original)

    def test_missing_documents_do_not_leave_cached_missing_coverage(self) -> None:
        cache = ResultCache(None)
        identity = models.ImageIdentity()
        missing = csaf.DocumentResult("CVE-2026-0001", "", error="missing")
        self.assertEqual(
            csaf.CsafComparison(missing.cve, missing, cache).assess(identity)[
                "assessment"
            ],
            "document_missing",
        )
        present = csaf.DocumentResult(missing.cve, "source", self.cpe_document())
        self.assertNotEqual(
            csaf.CsafComparison(present.cve, present, cache).assess(identity)[
                "assessment"
            ],
            "document_missing",
        )

    def test_cache_write_failure_is_not_downgraded_to_a_warning(self) -> None:
        cache = ResultCache(None)
        document = csaf.DocumentResult("CVE-2026-0001", "source", self.cpe_document())
        with (
            patch.object(cache, "store", side_effect=ResultCacheError("disk full")),
            self.assertRaisesRegex(ResultCacheError, "disk full"),
        ):
            csaf.CsafComparison(document.cve, document, cache).assess(
                models.ImageIdentity()
            )

    def test_comparison_output_cannot_replace_its_inputs(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_file = root / "audit.json"
            source = root / "comparison.json"
            audit_file.write_text(json.dumps(report().to_dict()))
            source.write_text('{"vulnerabilities": [{"cve": "CVE-2026-0001"}]}')
            original = source.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "csaf",
                            str(root),
                            "--csaf",
                            str(source),
                            "--output-dir",
                            str(root),
                        ]
                    ),
                    1,
                )
            self.assertEqual(source.read_bytes(), original)

    def test_cli_compares_local_csaf_and_reports_missing_coverage(self) -> None:
        audit_document = report(
            binary_report(
                "/app",
                models.Vulnerability("CVE-2026-0001"),
                models.Vulnerability("CVE-2026-0002"),
            ),
            image=models.ImageIdentity(digest="sha256:" + "a" * 64),
        ).to_dict()
        product = "image@sha256:" + "a" * 64
        document = {
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "product_status": {"known_affected": [product]},
                },
                {
                    "cve": "CVE-2026-9999",
                    "product_status": {"known_affected": [product]},
                },
            ]
        }
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_file = root / "audit.json"
            source = root / "advisory.json"
            output = root / "reports" / "comparison.json"
            audit_file.write_text(json.dumps(audit_document), encoding="utf-8")
            source.write_text(json.dumps(document), encoding="utf-8")
            with (
                patch(
                    "urllib.request.urlopen",
                    side_effect=AssertionError("network access"),
                ),
                redirect_stdout(io.StringIO()),
            ):
                status = main(
                    [
                        "csaf",
                        str(root),
                        "--csaf",
                        str(source),
                    ]
                )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(audit_file.read_text()), audit_document)

        self.assertEqual(status, 1)
        self.assertEqual(result["summary"]["documents_found"], 1)
        self.assertEqual(result["summary"]["documents_missing"], 1)
        assessments = {item["cve"]: item for item in result["assessments"]}
        self.assertEqual(
            assessments["CVE-2026-0001"]["assessment"], "exact_image_digest"
        )
        self.assertEqual(
            set(result["local_findings"]), {"CVE-2026-0001", "CVE-2026-0002"}
        )

    def test_local_document_index_supports_multi_cve_advisories_and_rejects_conflicting_revisions(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "advisory.json"
            source.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {"cve": "CVE-2026-0001"},
                            {"cve": "CVE-2026-0002"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                set(csaf.document_locations([root, source])),
                {"CVE-2026-0001", "CVE-2026-0002"},
            )
            (root / "another.json").write_text(source.read_text(), encoding="utf-8")
            with self.assertRaisesRegex(csaf.CsafCheckError, "multiple CSAF documents"):
                csaf.document_locations([root])

    def test_invalid_csaf_is_not_silently_skipped(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "invalid.json"
            source.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(csaf.CsafCheckError, "vulnerabilities array"):
                csaf.document_locations([source])

    def test_load_audit_rejects_binary_cache_objects(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "binary-cache.json"
            path.write_text(
                json.dumps(
                    {
                        "binary": {
                            "runtime_disposition": {"state": "requires-observation"}
                        },
                        "vulnerability_validity": {"run_id": "test-run", "profile": {}},
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(audit.AuditError):
                csaf.compare_audit(path, {})

    def cpe_document(self) -> dict:
        return {
            "product_tree": {
                "full_product_names": [
                    {
                        "product_id": "platform",
                        "name": "OpenShift 4",
                        "product_identification_helper": {
                            "cpe": "cpe:/a:redhat:openshift:4"
                        },
                    },
                    {"product_id": "component", "name": "Some component"},
                ],
                "relationships": [
                    {
                        "category": "default_component_of",
                        "product_reference": "component",
                        "relates_to_product_reference": "platform",
                        "full_product_name": {
                            "product_id": "combination",
                            "name": "Component on platform",
                        },
                    }
                ],
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "product_status": {"known_affected": ["combination"]},
                }
            ],
        }

    def assess_cpe_document(self, document: dict, **identity_fields: str) -> dict:
        return csaf.assess_document(
            "CVE-2026-0001",
            csaf.DocumentResult(
                "CVE-2026-0001", "https://example.test/cve.json", document
            ),
            models.ImageIdentity(
                cpe="cpe:/a:redhat:openshift:4.20::el9", **identity_fields
            ),
        )

    def test_cpe_compatibility_preserves_attributes_and_binding_semantics(self) -> None:
        cases = [
            (
                "cpe:/a:redhat:openshift:4.20::el9",
                "cpe:/a:redhat:openshift:4",
                "version_family",
            ),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/a:redhat:openshift:4.2", None),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/a:redhat:openshift:5", None),
            ("cpe:/a:redhat:openshift:4", "cpe:/a:redhat:openshift:4.20", None),
            (
                "cpe:/a:redhat:openshift:4.20::el9",
                "cpe:/a:redhat:openshift:4::el8",
                None,
            ),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/o:redhat:openshift:4", None),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/a:other:openshift:4", None),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/a:redhat:other:4", None),
            ("cpe:/a:redhat:openshift:4.20", "cpe:/a:redhat:openshift", "compatible"),
            (
                "cpe:/a:redhat:openshift:4.20",
                "cpe:/a:redhat:openshift:4.%02",
                "compatible",
            ),
            (
                "cpe:/a:redhat:openshift:4.20",
                "cpe:2.3:a:redhat:openshift:4.*:*:*:*:*:*:*:*",
                "compatible",
            ),
            (
                "cpe:/a:redhat:openshift:4.20::el9",
                "cpe:2.3:a:redhat:openshift:4.20:*:el9:*:*:*:*:*",
                "exact",
            ),
            ("cpe:/a:redhat:openshift:-", "cpe:/a:redhat:openshift:4", None),
            ("cpe:/a:redhat:openshift:-", "cpe:/a:redhat:openshift:-", "exact"),
            (
                "cpe:/a:redhat:openshift:4.20",
                "cpe:2.3:a:*:openshift:*:*:*:*:*:*:*:*",
                None,
            ),
            (
                "cpe:/a:vendor:some%3aproduct:1",
                r"cpe:2.3:a:vendor:some\:product:1:*:*:*:*:*:*:*",
                "exact",
            ),
            ("cpe:/a:vendor:product:%2a", "cpe:/a:vendor:product:1", None),
            (
                "cpe:/a:vendor:product:1::%7efoo",
                "cpe:/a:vendor:product:1",
                "compatible",
            ),
            (
                "cpe:/a:vendor:product:1::~edition~sw~linux~x86~other",
                "cpe:2.3:a:vendor:product:1:*:edition:*:sw:linux:x86:other",
                "exact",
            ),
            (
                "cpe:2.3:a:v:p:1:*:*:*:*:linux:x86:*",
                "cpe:2.3:a:v:p:1:*:*:*:*:linux:arm:*",
                None,
            ),
        ]
        for image, product, expected in cases:
            with self.subTest(image=image, product=product):
                self.assertEqual(csaf.cpe_relation(image, product), expected)
        for invalid in [
            "",
            "bad",
            "cpe:/",
            "cpe:2.3:a:v:p",
            "cpe:/a:v:p:%zz",
            "cpe:/a:v:p:%00",
            "cpe:/a:v:p:1::~bad",
            "cpe:/a:v:p:1:2:3:4:5",
        ]:
            with self.subTest(invalid=invalid):
                self.assertIsNone(csaf.cpe_relation(invalid, invalid))

    def test_parent_cpe_matches_opaque_product_ids_and_preserves_evidence(self) -> None:
        assessment = self.assess_cpe_document(self.cpe_document())
        self.assertEqual(assessment["assessment"], "cpe_parent_version_family")
        self.assertEqual(assessment["match_level"], "platform")
        self.assertTrue(assessment["cpe_known_affected"])
        match = assessment["matches"][0]
        self.assertEqual(match["product_id"], "combination")
        self.assertEqual(match["statuses"], ["status:known_affected"])
        self.assertEqual(
            match["cpe_evidence"]["relationship_path"], ["combination", "platform"]
        )
        self.assertEqual(
            match["cpe_evidence"]["relationship_categories"], ["default_component_of"]
        )
        self.assertEqual(match["cpe_evidence"]["source_product_id"], "platform")
        result = csaf.build_result(
            Path("audit.json"),
            models.ImageIdentity(),
            {"CVE-2026-0001": models.CveEvidence("CVE-2026-0001")},
            {"CVE-2026-0001": assessment},
        )
        text = csaf.render_text(result)
        self.assertIn("Container identity:   not established", text)
        self.assertIn("combination -> platform", text)
        self.assertIn("version_family", text)
        self.assertIn("CPE-related affected: yes", text)
        self.assertEqual(
            json.loads(json.dumps(result))["summary"]["cves_with_cpe_known_affected"], 1
        )

    def test_cvss_prefers_matched_product_then_highest_available(self) -> None:
        document = self.cpe_document()
        document["vulnerabilities"][0]["scores"] = [
            {
                "cvss_v3": {
                    "baseScore": 5.0,
                    "baseSeverity": "MEDIUM",
                    "vectorString": "CVSS:3.1/matched",
                },
                "products": ["combination"],
            },
            {
                "cvss_v3": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/fallback",
                },
                "products": ["unrelated"],
            },
        ]

        matched = self.assess_cpe_document(document)
        self.assertEqual(
            matched["cvss"],
            {
                "base_score": 5.0,
                "base_severity": "MEDIUM",
                "vector": "CVSS:3.1/matched",
                "source": "matched_product",
                "matched_products": ["combination"],
            },
        )

        document["vulnerabilities"][0]["scores"][0]["products"] = ["other"]
        fallback = self.assess_cpe_document(document)
        self.assertEqual(fallback["cvss"]["base_score"], 9.8)
        self.assertEqual(fallback["cvss"]["source"], "highest_available")

    def test_parent_cpe_does_not_attach_status_to_standalone_component_or_siblings(
        self,
    ) -> None:
        document = self.cpe_document()
        document["vulnerabilities"][0]["product_status"] = {
            "known_affected": ["component"]
        }
        self.assertEqual(
            self.assess_cpe_document(document)["assessment"], "no_matching_product"
        )
        document["vulnerabilities"][0]["product_status"] = {
            "known_affected": ["platform"]
        }
        assessment = self.assess_cpe_document(document)
        self.assertEqual(assessment["assessment"], "cpe_version_family")
        self.assertEqual([m["product_id"] for m in assessment["matches"]], ["platform"])

    def test_nested_parent_relationships_and_cycles(self) -> None:
        document = self.cpe_document()
        document["product_tree"]["relationships"].append(
            {
                "category": "installed_on",
                "product_reference": "component",
                "relates_to_product_reference": "combination",
                "full_product_name": {"product_id": "nested"},
            }
        )
        document["vulnerabilities"][0]["product_status"] = {
            "known_affected": ["nested"]
        }
        assessment = self.assess_cpe_document(document)
        self.assertEqual(
            assessment["matches"][0]["cpe_evidence"]["relationship_path"],
            ["nested", "combination", "platform"],
        )
        document["product_tree"]["relationships"][0]["relates_to_product_reference"] = (
            "nested"
        )
        self.assertEqual(
            self.assess_cpe_document(document)["assessment"], "no_matching_product"
        )

    def test_peer_dangling_and_explicit_conflicting_cpes_do_not_inherit(self) -> None:
        for change in ["peer", "missing", "conflicting"]:
            with self.subTest(change=change):
                document = self.cpe_document()
                relation = document["product_tree"]["relationships"][0]
                if change == "peer":
                    relation["category"] = "installed_with"
                elif change == "missing":
                    relation["relates_to_product_reference"] = "absent"
                else:
                    relation["full_product_name"]["product_identification_helper"] = {
                        "cpe": "cpe:/a:redhat:openshift:4.19"
                    }
                self.assertEqual(
                    self.assess_cpe_document(document)["assessment"],
                    "no_matching_product",
                )

    def test_stronger_container_status_wins_without_discarding_platform_candidates(
        self,
    ) -> None:
        document = self.cpe_document()
        document["product_tree"]["full_product_names"].append({"product_id": "ose-app"})
        document["vulnerabilities"][0]["product_status"]["fixed"] = ["ose-app"]
        assessment = self.assess_cpe_document(document, name="openshift/ose-app")
        self.assertEqual(assessment["assessment"], "component")
        self.assertEqual(assessment["match_level"], "component")
        self.assertEqual(assessment["statuses"], ["status:fixed"])
        self.assertTrue(assessment["cpe_known_affected"])
        self.assertEqual(
            assessment["cpe_matches"][0]["statuses"], ["status:known_affected"]
        )

    def test_tied_cpe_candidates_keep_each_products_conflicting_status(self) -> None:
        document = self.cpe_document()
        relation = dict(document["product_tree"]["relationships"][0])
        relation["full_product_name"] = {"product_id": "other-combination"}
        document["product_tree"]["relationships"].append(relation)
        document["vulnerabilities"][0]["product_status"]["fixed"] = [
            "other-combination"
        ]
        assessment = self.assess_cpe_document(document)
        self.assertEqual(
            [(m["product_id"], m["statuses"]) for m in assessment["matches"]],
            [
                ("combination", ["status:known_affected"]),
                ("other-combination", ["status:fixed"]),
            ],
        )

    def test_compact_batch_results_equal_detailed_results_and_keep_identity_specific(
        self,
    ) -> None:
        document = self.cpe_document()
        index = csaf.index_document("CVE-2026-0001", document)
        fetch = csaf.DocumentResult(
            "CVE-2026-0001", "https://example.test/cve.json", document
        )
        for cpe in ["cpe:/a:redhat:openshift:4.20::el9", "cpe:/a:redhat:openshift:5"]:
            identity = models.ImageIdentity(cpe=cpe)
            detailed = csaf.assess_indexed_document(
                "CVE-2026-0001", fetch, identity, index
            )
            compact = csaf.assess_indexed_document(
                "CVE-2026-0001", fetch, identity, index, include_details=False
            )
            self.assertEqual(
                compact,
                {
                    k: v
                    for k, v in detailed.items()
                    if k not in {"matches", "cpe_matches"}
                },
            )
            self.assertEqual(
                compact["cpe_candidate_count"], len(detailed["cpe_matches"])
            )
            self.assertEqual(
                compact["best_candidate_count"], len(detailed.get("matches", []))
            )
        self.assertEqual(compact["assessment"], "no_matching_product")

    def test_repeated_cve_records_merge_product_evidence_without_duplicate_candidates(
        self,
    ) -> None:
        document = self.cpe_document()
        document["vulnerabilities"].append(
            {"cve": "CVE-2026-0001", "product_status": {"fixed": ["combination"]}}
        )
        assessment = self.assess_cpe_document(document)
        self.assertEqual(assessment["cpe_candidate_count"], 1)
        self.assertEqual(
            assessment["matches"][0]["statuses"],
            ["status:fixed", "status:known_affected"],
        )

    def test_groups_local_cves_from_serialized_audit(self) -> None:
        document = report(
            binary_report(
                "/usr/bin/app",
                models.Vulnerability(
                    "GO-2026-0001",
                    aliases=["CVE-2026-0001"],
                    findings=[
                        models.VulnerabilityFinding(
                            module="example/module",
                            package="example/package",
                            found_version="v1.0.0",
                        )
                    ],
                ),
            ),
            image=models.ImageIdentity(
                reference="quay.io/example/app@sha256:" + "a" * 64,
                digest="sha256:" + "a" * 64,
                platform="linux/amd64",
                name="openshift/ose-example-rhel9",
                product_version="v4.20.0",
            ),
        ).to_dict()
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "audit.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = audit.load_audit(path)
            identity, findings = loaded.metadata.image, index_cve_evidence(loaded)

        self.assertEqual(identity.name, "openshift/ose-example-rhel9")
        self.assertEqual(list(findings), ["CVE-2026-0001"])
        self.assertEqual(findings["CVE-2026-0001"].binary_paths, {"/usr/bin/app"})

    def test_prefers_exact_digest_then_release_component_then_generic_component(
        self,
    ) -> None:
        identity = models.ImageIdentity(
            digest="sha256:" + "a" * 64,
            platform="linux/amd64",
            name="openshift/ose-example-rhel9",
            product_version="v4.20.0",
        )
        exact = csaf.product_scope(
            "Red Hat OpenShift Container Platform 4.20:"
            "registry.redhat.io/openshift4/ose-example-rhel9@sha256:"
            + "a" * 64
            + "_amd64",
            identity,
        )
        release = csaf.product_scope(
            "Red Hat OpenShift Container Platform 4.20:"
            "registry.redhat.io/openshift4/ose-example-rhel9@sha256:"
            + "b" * 64
            + "_amd64",
            identity,
        )
        generic = csaf.product_scope(
            "red_hat_openshift_container_platform_4:openshift4/ose-example-rhel9",
            identity,
        )

        self.assertEqual(exact, ("exact_image_digest", 100))
        self.assertEqual(release, ("component_release_architecture", 80))
        self.assertEqual(generic, ("component", 60))

    def test_version_matching_preserves_canonical_identity(self) -> None:
        for product_version, component_version, expected in (
            ("", "v4.20.1", "component_release_architecture"),
            ("v4.20.0", "v5.0.0", "component_release_architecture"),
            ("v5.0.0", "v4.20.1", "component"),
        ):
            image = models.ImageIdentity(
                name="example",
                platform="linux/x86_64",
                product_version=product_version,
                component_version=component_version,
                source_git_url="https://example.test/source",
                extractor="test-extractor",
            )
            with self.subTest(product=product_version, component=component_version):
                source = report(image=image)
                identity, local = source.metadata.image, index_cve_evidence(source)
                self.assertIs(identity, image)
                self.assertEqual(
                    csaf.product_scope("product-4.20:example_amd64", identity)[0],
                    expected,
                )
                result = csaf.build_result(Path("audit.json"), identity, local, {})
                self.assertEqual(result["image"], image.to_dict())
                self.assertEqual(result["image"]["product_version"], product_version)
                self.assertEqual(
                    result["image"]["component_version"], component_version
                )

    def test_assesses_matching_product_status_and_keeps_source_details(self) -> None:
        identity = models.ImageIdentity(
            digest="sha256:" + "a" * 64,
            platform="linux/amd64",
            name="openshift/ose-example-rhel9",
            product_version="v4.20.0",
        )
        product_id = (
            "Red Hat OpenShift Container Platform 4.20:"
            "registry.redhat.io/openshift4/ose-example-rhel9@sha256:"
            + "a" * 64
            + "_amd64"
        )
        document = {
            "document": {
                "title": "Example vulnerability",
                "tracking": {
                    "id": "CVE-2026-0001",
                    "current_release_date": "2026-01-01T00:00:00Z",
                },
            },
            "product_tree": {
                "branches": [
                    {
                        "product": {
                            "product_id": product_id,
                            "name": "Example product",
                        }
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "product_status": {"known_affected": [product_id]},
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": "Upgrade the image.",
                            "url": "https://example.test/fix",
                            "product_ids": [product_id],
                        }
                    ],
                }
            ],
        }
        assessment = csaf.assess_document(
            "CVE-2026-0001",
            csaf.DocumentResult(
                "CVE-2026-0001", "https://example.test/cve.json", document
            ),
            identity,
        )

        self.assertEqual(assessment["assessment"], "exact_image_digest")
        self.assertIn("status:known_affected", assessment["statuses"])
        self.assertEqual(assessment["matches"][0]["url"], "https://example.test/fix")


if __name__ == "__main__":
    unittest.main()
