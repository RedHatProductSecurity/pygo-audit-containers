from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest

from pygo_audit import csaf


class CsafIndexTests(unittest.TestCase):
    def test_document_names_disambiguate_collections(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first/csaf", root / "second/csaf"
            for directory in (first, second):
                directory.mkdir(parents=True)
            one, two = first / "advisory.json", second / "advisory.json"
            names = csaf.relative_document_names(
                {"one": one, "two": two}, [first, second]
            )
            self.assertEqual(names["one"], f"csaf/advisory.json — {first}")
            self.assertEqual(
                csaf.relative_document_names({"one": one}, [one])["one"],
                "csaf/advisory.json",
            )

    def test_parent_sources_are_directed_and_preserve_explicit_constraints(
        self,
    ) -> None:
        document = self.cpe_document()
        products = csaf.product_index(document)
        source = products["combination"].cpe_sources[0]
        self.assertEqual(source.path, ("combination", "platform"))
        self.assertEqual(source.categories, ("default_component_of",))
        self.assertEqual(products["component"].cpe_sources, ())
        document["product_tree"]["relationships"].append(
            {
                "category": "installed_on",
                "product_reference": "component",
                "relates_to_product_reference": "combination",
                "full_product_name": {"product_id": "nested"},
            }
        )
        self.assertEqual(
            csaf.product_index(document)["nested"].cpe_sources[0].path,
            ("nested", "combination", "platform"),
        )
        for change in ("peer", "missing", "cycle", "explicit"):
            with self.subTest(change=change):
                modified = self.cpe_document()
                relation = modified["product_tree"]["relationships"][0]
                if change == "peer":
                    relation["category"] = "installed_with"
                elif change == "missing":
                    relation["relates_to_product_reference"] = "absent"
                elif change == "cycle":
                    relation["relates_to_product_reference"] = "combination"
                else:
                    relation["full_product_name"]["product_identification_helper"] = {
                        "cpe": "cpe:/a:redhat:openshift:4.19"
                    }
                sources = csaf.product_index(modified)["combination"].cpe_sources
                self.assertEqual(
                    tuple(item.product_id for item in sources),
                    ("combination",) if change == "explicit" else (),
                )

    def test_index_retains_declared_versions_and_record_scoped_statements(self) -> None:
        document = {
            "document": {"publisher": {"namespace": "https://vendor.example"}},
            "product_tree": {
                "branches": [
                    {
                        "category": "product_version",
                        "name": "v1.2.3",
                        "product": {
                            "product_id": "build",
                            "product_identification_helper": {
                                "purl": "pkg:oci/app@v1.2.3"
                            },
                        },
                    }
                ]
            },
        }
        index = csaf.index_document(document)
        self.assertEqual(index.publisher_namespace, "https://vendor.example")
        self.assertEqual(index.products["build"].versions[0].value, "v1.2.3")
        self.assertEqual(index.products["build"].versions[0].subject, "component")
        record = {
            "product_status": {"known_affected": ["build"]},
            "flags": [{"label": "component_not_present", "product_ids": ["other"]}],
        }
        self.assertEqual(
            csaf.product_statuses([record]),
            {
                "build": ("status:known_affected",),
                "other": ("flag:component_not_present",),
            },
        )

    def test_loader_rejects_invalid_documents_without_skipping_them(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "advisory.json"
            for value in ([], {"vulnerabilities": {}}, {"product_tree": []}):
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(csaf.CsafCheckError):
                        csaf.load_document(path)
            path.write_text("not JSON")
            with self.assertRaises(csaf.CsafCheckError):
                csaf.load_document(path)

    def test_canonical_urls_use_document_self_references_and_tracking_filename(self):
        filename = "vendor_2026_01-a+b.json"
        first = "https://vendor.example/csaf/" + filename
        second = "https://mirror.example/csaf/" + filename
        references = [
            {"category": "self", "summary": "Advisory download", "url": url}
            for url in (
                first,
                second,
                first,
                first.replace(".json", ".html"),
                first.replace("https://", "http://"),
                first.replace(".json", "_1.json"),
                first + "?version=1",
                first + "#reference",
                first + "?",
                first + "#",
                "https://vendor.example/other.json?redirect=/" + filename,
                "https://[invalid/" + filename,
            )
        ]
        references.extend(
            [
                {
                    "category": "external",
                    "summary": "Canonical URL",
                    "url": "https://external.example/" + filename,
                },
                {
                    "summary": "Canonical URL",
                    "url": "https://unspecified.example/" + filename,
                },
                {"category": "self", "url": None},
                None,
            ]
        )
        document = {
            "document": {
                "tracking": {"id": "Vendor/2026__#01-A+B"},
                "references": references,
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2026-0001",
                    "references": [
                        {"category": "self", "url": "https://cve.example/" + filename}
                    ],
                }
            ],
        }
        index = csaf.index_document(document)
        self.assertEqual(index.canonical_urls, (second, first))
        for metadata in (
            None,
            {},
            {"references": references},
            {"tracking": {"id": 1}, "references": references},
            {"tracking": {"id": "Vendor/2026__#01-A+B"}, "references": None},
        ):
            with self.subTest(metadata=metadata):
                self.assertEqual(
                    csaf.index_document({"document": metadata}).canonical_urls, ()
                )

    def cpe_document(self) -> dict[str, Any]:
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
