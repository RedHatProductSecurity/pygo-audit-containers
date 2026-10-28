from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pygo_audit.container_metadata import (  # noqa: E402
    collect_container_facts,
    read_os_release,
    write_container_facts,
)


class ContainerMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.rootfs = Path(self.temporary.name) / "rootfs"
        (self.rootfs / "usr" / "lib").mkdir(parents=True)
        (self.rootfs / "usr" / "lib" / "os-release").write_text(
            'NAME="Red Hat Enterprise Linux CoreOS"\n'
            'VERSION_ID="9.6"\n'
            'OPENSHIFT_VERSION="4.20"\n'
            'CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"\n',
            encoding="utf-8",
        )
        self.rpmdb = self.rootfs / "usr" / "share" / "rpm" / "rpmdb.sqlite"
        self.rpmdb.parent.mkdir(parents=True)
        self.rpmdb.write_bytes(b"rpm database marker")
        self.rpm = Path(self.temporary.name) / "rpm"
        self.rpm.write_text(
            "#! /bin/sh\n"
            "printf '%b' "
            "'bash\\t0\\t5.1.8\\t9.el9\\tx86_64\\tbash-5.1.8-9.el9.src.rpm\\n'"
            "'redhat-release\\t0\\t9.6\\t0.1.el9\\tx86_64\\tredhat-release-9.6-0.1.el9.src.rpm\\n'"
        )
        self.rpm.chmod(0o700)

    def test_collects_os_release_and_rpm_coordinates(self):
        facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))

        self.assertEqual(facts.os_release["NAME"], "Red Hat Enterprise Linux CoreOS")
        self.assertEqual(facts.os_release["OPENSHIFT_VERSION"], "4.20")
        self.assertEqual(facts.rpmdb_paths, ("usr/share/rpm/rpmdb.sqlite",))
        self.assertEqual([package.name for package in facts.rpm_packages], [
            "bash",
            "redhat-release",
        ])
        self.assertEqual(facts.rpm_packages[0].source_rpm, "bash-5.1.8-9.el9.src.rpm")
        self.assertEqual(facts.rpm_error, "")

    def test_missing_rpm_command_is_recorded_without_losing_os_facts(self):
        facts = collect_container_facts(self.rootfs, rpm_command="does-not-exist")

        self.assertEqual(facts.os_release["VERSION_ID"], "9.6")
        self.assertEqual(facts.rpm_packages, ())
        self.assertIn("RPM command not found", facts.rpm_error)

    def test_os_release_ignores_external_links_and_uses_safe_fallback(self):
        outside = self.rootfs.parent / "host-release"
        outside.write_text('NAME="host secret"\n', encoding="utf-8")
        path = self.rootfs / "usr/lib/os-release"
        path.unlink()
        path.symlink_to(outside)
        (self.rootfs / "etc").mkdir()
        (self.rootfs / "etc/os-release").write_text('NAME="safe fallback"\n')

        self.assertEqual(read_os_release(self.rootfs), {"NAME": "safe fallback"})

    def test_os_release_rejects_external_parent_links(self):
        library = self.rootfs / "usr/lib"
        library.rename(self.rootfs / "usr/saved-lib")
        outside = self.rootfs.parent / "outside"
        outside.mkdir()
        (outside / "os-release").write_text('NAME="host secret"\n')
        library.symlink_to(outside, target_is_directory=True)

        self.assertEqual(read_os_release(self.rootfs), {})

    def test_os_release_allows_contained_relative_links(self):
        path = self.rootfs / "usr/lib/os-release"
        path.rename(path.with_name("release-data"))
        path.symlink_to("release-data")

        self.assertEqual(read_os_release(self.rootfs)["VERSION_ID"], "9.6")

    def test_metadata_open_rejects_parent_symlink_swapped_after_resolution(self):
        outside = self.rootfs.parent / "outside"
        outside.mkdir()
        (outside / "os-release").write_text('NAME="host secret"\n')
        library = self.rootfs / "usr/lib"
        original_open = os.open
        swapped = False

        def swap_parent(path, flags, *arguments, **keywords):
            nonlocal swapped
            if path == "lib" and not swapped:
                swapped = True
                library.rename(self.rootfs / "usr/saved-lib")
                library.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, *arguments, **keywords)

        with patch("pygo_audit.container_metadata.os.open", side_effect=swap_parent):
            self.assertEqual(read_os_release(self.rootfs), {})
        self.assertTrue(swapped)

    def test_os_release_ignores_fifo_and_oversized_files(self):
        path = self.rootfs / "usr/lib/os-release"
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(read_os_release(self.rootfs), {})
        path.unlink()
        path.write_text("NAME=" + "x" * (64 * 1024), encoding="utf-8")
        self.assertEqual(read_os_release(self.rootfs), {})

    def test_rpm_database_rejects_leaf_and_parent_links_outside_subject(self):
        outside = self.rootfs.parent / "outside"
        outside.mkdir()
        host_database = outside / "rpmdb.sqlite"
        host_database.write_bytes(b"host database")
        self.rpmdb.unlink()
        self.rpmdb.symlink_to(host_database)
        with patch("pygo_audit.container_metadata.subprocess.run") as query:
            facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))
        self.assertEqual(facts.rpmdb_paths, ())
        query.assert_not_called()

        self.rpmdb.unlink()
        self.rpmdb.parent.rmdir()
        self.rpmdb.parent.symlink_to(outside, target_is_directory=True)
        with patch("pygo_audit.container_metadata.subprocess.run") as query:
            facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))
        self.assertEqual(facts.rpmdb_paths, ())
        query.assert_not_called()

    def test_rpm_database_allows_contained_parent_links(self):
        self.rpmdb.parent.rename(self.rpmdb.parent.with_name("rpm-data"))
        self.rpmdb.parent.symlink_to("rpm-data", target_is_directory=True)

        facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))

        self.assertEqual(len(facts.rpm_packages), 2)
        self.assertEqual(facts.rpm_error, "")

    def test_rpm_query_uses_disposable_copy_outside_subject(self):
        outside = self.rootfs.parent / "host-data"
        outside.write_bytes(b"do not copy")
        (self.rpmdb.parent / "host-link").symlink_to(outside)
        self.rpmdb.chmod(0o400)
        self.rpmdb.parent.chmod(0o500)
        working_directories = []

        def query(command, **options):
            working = Path(command[command.index("--dbpath") + 1])
            working_directories.append(working)
            self.assertEqual(working.parent, self.rootfs.parent)
            self.assertEqual((working / self.rpmdb.name).read_bytes(), b"rpm database marker")
            self.assertFalse((working / "host-link").exists())
            self.assertEqual(options["timeout"], 30.0)
            (working / ".rpm.lock").write_text("temporary query output")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("pygo_audit.container_metadata.subprocess.run", side_effect=query):
            facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))
        self.assertEqual(facts.rpm_error, "")
        self.assertFalse((self.rpmdb.parent / ".rpm.lock").exists())
        self.assertEqual(self.rpmdb.read_bytes(), b"rpm database marker")
        self.assertTrue(working_directories)
        self.assertTrue(all(not path.exists() for path in working_directories))

    def test_rpm_timeout_retains_os_facts_and_cleans_working_copy(self):
        self.rpm.write_text(
            f"#!{sys.executable}\nimport time\ntime.sleep(60)\n", encoding="utf-8"
        )

        facts = collect_container_facts(
            self.rootfs, rpm_command=str(self.rpm), rpm_timeout=0.05
        )

        self.assertEqual(facts.os_release["VERSION_ID"], "9.6")
        self.assertEqual(facts.rpm_packages, ())
        self.assertIn("timed out after 0.05 seconds", facts.rpm_error)
        self.assertEqual(list(self.rootfs.parent.glob("rpm-query-*")), [])

    def test_rpm_timeout_must_be_positive(self):
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            collect_container_facts(self.rootfs, rpm_timeout=0)

    def test_writes_separate_container_facts_sidecar(self):
        facts = collect_container_facts(self.rootfs, rpm_command=str(self.rpm))

        destination = write_container_facts(self.rootfs.parent, facts)
        self.assertEqual(destination.parent, self.rootfs.parent)
        self.assertFalse((self.rootfs / destination.name).exists())
        document = json.loads(destination.read_text(encoding="utf-8"))

        self.assertEqual(document["os-release"]["CPE_NAME"], facts.os_release["CPE_NAME"])
        self.assertEqual(document["rpmdb"]["package-count"], 2)
        self.assertEqual(document["rpmdb"]["packages"][0]["name"], "bash")


if __name__ == "__main__":
    unittest.main()
