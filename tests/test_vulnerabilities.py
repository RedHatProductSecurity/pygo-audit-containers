from __future__ import annotations

import json
import unittest

from pygo_audit.vulnerabilities import parse_govulncheck_json


class GovulncheckJsonTests(unittest.TestCase):
    def test_normalizes_only_findings_and_keeps_strongest_evidence(self) -> None:
        messages = [
            {
                "config": {
                    "protocol_version": "v1.0.0",
                    "scanner_name": "govulncheck",
                    "scanner_version": "v1.2.3",
                    "db": "https://vuln.go.dev",
                    "db_last_modified": "2026-09-18T00:00:00Z",
                    "scan_level": "symbol",
                    "scan_mode": "binary",
                }
            },
            {
                "SBOM": {
                    "go_version": "go1.26.1",
                    "modules": [
                        {"path": "example.test/library", "version": "v1.2.3"}
                    ],
                    "roots": ["example.test/app"],
                }
            },
            {
                "osv": {
                    "id": "GO-2026-0001",
                    "aliases": ["CVE-2026-0001"],
                    "summary": "Deliberately omitted from normalized output",
                    "details": "An example vulnerability.",
                    "published": "2026-09-01T00:00:00Z",
                    "modified": "2026-09-18T00:00:00Z",
                    "affected": [
                        {
                            "package": {
                                "ecosystem": "Go",
                                "name": "example.test/library",
                            },
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "1.2.4"},
                                    ],
                                }
                            ],
                            "ecosystem_specific": {
                                "imports": [
                                    {
                                        "path": "example.test/library/parser",
                                        "symbols": ["Decoder.Decode"],
                                        "goos": ["linux"],
                                        "goarch": ["amd64"],
                                    }
                                ]
                            },
                        }
                    ],
                    "references": [
                        {"type": "FIX", "url": "https://example.test/fix"}
                    ],
                    "database_specific": {
                        "url": "https://pkg.go.dev/vuln/GO-2026-0001",
                        "review_status": "REVIEWED",
                    },
                }
            },
            {"osv": {"id": "GO-2026-9999", "details": "Not a finding."}},
            {
                "finding": {
                    "osv": "GO-2026-9999",
                    "trace": [
                        {"module": "example.test/library", "version": "v1.2.3"}
                    ],
                }
            },
            {
                "finding": {
                    "osv": "GO-2026-0001",
                    "fixed_version": "v1.2.4",
                    "trace": [
                        {"module": "example.test/library", "version": "v1.2.3"}
                    ],
                }
            },
            {
                "finding": {
                    "osv": "GO-2026-0001",
                    "fixed_version": "v1.2.4",
                    "trace": [
                        {
                            "module": "example.test/library",
                            "version": "v1.2.3",
                            "package": "example.test/library/parser",
                        }
                    ],
                }
            },
            {
                "finding": {
                    "osv": "GO-2026-0001",
                    "fixed_version": "v1.2.4",
                    "trace": [
                        {
                            "module": "example.test/library",
                            "version": "v1.2.3",
                            "package": "example.test/library/parser",
                            "function": "Decode",
                            "receiver": "Decoder",
                        }
                    ],
                }
            },
        ]
        output = "\n".join(json.dumps(message, indent=2) for message in messages)

        scan = parse_govulncheck_json(output)

        self.assertEqual(scan.status, "complete")
        self.assertEqual(scan.go_version, "go1.26.1")
        self.assertEqual(len(scan.vulnerabilities), 1)
        vulnerability = scan.vulnerabilities[0]
        self.assertEqual(vulnerability.id, "GO-2026-0001")
        self.assertEqual(vulnerability.aliases, ["CVE-2026-0001"])
        self.assertEqual(len(vulnerability.findings), 1)
        self.assertEqual(vulnerability.findings[0].evidence, "symbol")
        self.assertEqual(vulnerability.findings[0].symbol, "Decoder.Decode")
        self.assertEqual(vulnerability.affected[0]["packages"][0]["goos"], ["linux"])
        self.assertNotIn("summary", vulnerability.to_dict())


if __name__ == "__main__":
    unittest.main()
