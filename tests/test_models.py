from __future__ import annotations

import unittest

from pygo_audit.models import BinaryReport, Module, ScanReport


class BinaryReportTests(unittest.TestCase):
    def test_parses_go_json_with_dependency_replacement(self) -> None:
        report = BinaryReport.from_go_json(
            {
                "GoVersion": "go1.26.8",
                "Path": "example.test/app",
                "Main": {"Path": "example.test/app", "Version": "(devel)"},
                "Deps": [
                    {
                        "Path": "example.test/library",
                        "Version": "v1.2.3",
                        "Sum": "h1:abc",
                        "Replace": {
                            "Path": "example.test/fork",
                            "Version": "v1.2.4",
                            "Sum": "h1:def",
                        },
                    }
                ],
                "Settings": [{"Key": "GOARCH", "Value": "amd64"}],
            },
            container_path="/usr/bin/app",
            size=123,
        )

        self.assertEqual(report.go_version, "go1.26.8")
        self.assertEqual(report.main_package, "example.test/app")
        self.assertEqual(report.dependencies[0].path, "example.test/library")
        self.assertIsNotNone(report.dependencies[0].replace)
        self.assertEqual(report.dependencies[0].replace.path, "example.test/fork")
        self.assertEqual(report.build_settings[0].value, "amd64")

    def test_rejects_json_without_go_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "GoVersion"):
            BinaryReport.from_go_json({}, container_path="/bin/app", size=1)


class ScanReportTests(unittest.TestCase):
    def test_dependency_summary_groups_binary_paths(self) -> None:
        dependency = Module(path="example.test/library", version="v1.0.0")
        binaries = [
            BinaryReport(
                paths=[path],
                size=1,
                go_version="go1.26",
                main_package=path,
                main_module=None,
                dependencies=[dependency],
                build_settings=[],
            )
            for path in ("/bin/one", "/bin/two")
        ]
        report = ScanReport(root="/tmp/root", go_command="go", go_tool_version="go")
        report.binaries.extend(binaries)

        summary = report.dependency_summary()

        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["used_by"], ["/bin/one", "/bin/two"])


if __name__ == "__main__":
    unittest.main()
