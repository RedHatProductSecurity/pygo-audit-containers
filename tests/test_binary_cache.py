from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.binary_cache import BinaryResultCache
from pygo_audit.result_cache import ResultCacheError
from pygo_audit.models import BinaryReport, VulnerabilityScan
from pygo_audit.storage import atomic_read_json, atomic_write_json


def binary_result(digest: str = "a" * 64) -> BinaryReport:
    return BinaryReport(
        paths=["/app"],
        size=1,
        sha256=digest,
        go_version="go1.26.8",
        main_package="example.test/app",
        main_module=None,
        dependencies=[],
        build_settings=[],
        vulnerability_scan=VulnerabilityScan(status="complete"),
    )


class BinaryResultCacheTests(unittest.TestCase):
    def test_restored_binary_uses_the_strict_audit_contract(self) -> None:
        digest = "a" * 64
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            cache = BinaryResultCache(directory, {"mode": "binary"}, run_id="run")
            cache.store(digest, binary_result(digest))
            path = cache.cache.object_path(cache.cache_key(digest))
            document = atomic_read_json(path, checksum=True)
            document["binary"]["vulnerability_scan"]["unexpected"] = True
            atomic_write_json(path, document, overwrite=True, checksum=True)
            fresh = BinaryResultCache(directory, {"mode": "binary"}, run_id="run")
            self.assertIsNone(fresh.load(digest, paths=["/current"], size=1))

    def test_shared_json_hash_preserves_existing_cache_keys(self) -> None:
        cache = BinaryResultCache(None, {"mode": "binary"})
        self.assertEqual(
            cache.cache_key("a" * 64),
            "374a8e63c0323f56f96444aa0f1f05b41a1a81c12955fc6dbca1c0d0e2bac4d1",
        )

    def test_cached_result_rehydrates_runtime_observation(self) -> None:
        digest = "c" * 64
        binary = BinaryReport(
            paths=["/layer/usr/bin/app"],
            size=1,
            sha256=digest,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
            runtime_disposition="unaccounted",
            symlinks=["/layer/bin/app"],
        )

        with TemporaryDirectory() as temporary_directory:
            cache = BinaryResultCache(Path(temporary_directory), {"mode": "binary"})
            cache.store(digest, binary)
            loaded = cache.load(
                digest,
                paths=["/layer/usr/bin/app"],
                size=1,
                symlinks=["/layer/bin/app"],
                runtime_disposition="unaccounted",
            )

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.runtime_disposition, "unaccounted")
        self.assertEqual(loaded.symlinks, ["/layer/bin/app"])

    def test_disk_cache_stores_objects_and_symlink_views(self) -> None:
        digest = "a" * 64
        binary = BinaryReport(
            paths=["/old/path/app"],
            size=3,
            sha256=digest,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
            vulnerability_scan=VulnerabilityScan(status="complete"),
        )

        with TemporaryDirectory() as temporary_directory:
            cache_directory = Path(temporary_directory) / "cache"
            sentinel = cache_directory / "existing-report.json"
            sentinel.parent.mkdir()
            sentinel.write_text("leave me", encoding="utf-8")
            cache = BinaryResultCache(cache_directory, {"mode": "binary"})

            cache.store(digest, binary)
            self.assertEqual(cache_directory.stat().st_mode & 0o777, 0o700)
            objects = list((cache_directory / "objects").glob("*.json"))
            loaded = BinaryResultCache(cache_directory, {"mode": "binary"}).load(
                digest,
                paths=["/new/path/app"],
                size=3,
            )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "leave me")
            self.assertEqual(len(objects), 1)
            self.assertFalse((cache_directory / "links").exists())
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.paths, ["/new/path/app"])
            self.assertEqual(loaded.runtime_disposition, "runtime")
            self.assertEqual(loaded.sha256, digest)
            self.assertEqual(loaded.layer_history, [])
            self.assertEqual(loaded.symlinks, [])

            document = atomic_read_json(objects[0], checksum=True)
            self.assertEqual(set(document), {"binary", "vulnerability_validity"})
            self.assertEqual(
                document["vulnerability_validity"],
                {"run_id": cache.run_id, "profile": {"mode": "binary"}},
            )
            for field in ("paths", "symlinks", "runtime_disposition", "layer_history"):
                self.assertEqual(
                    document["binary"][field], {"state": "requires-observation"}
                )

    def test_dynamic_results_require_current_run_and_analysis_profile(self) -> None:
        binary = binary_result()
        binary.reconciliation.status = "matched"
        profile = {
            "mode": "binary",
            "govulncheck_version": "one",
            "vulnerability_mode": "binary",
        }
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            cache = BinaryResultCache(directory, profile, run_id="first")
            cache.store(binary.sha256, binary)
            for run_id, changes, current in (
                ("first", {}, True),
                ("second", {}, False),
                ("first", {"govulncheck_version": "two"}, False),
                ("first", {"vulnerability_mode": "disabled"}, False),
            ):
                with self.subTest(run_id=run_id, changes=changes):
                    fresh = BinaryResultCache(
                        directory, {**profile, **changes}, run_id=run_id
                    )
                    self.assertEqual(
                        fresh.cache_key(binary.sha256), cache.cache_key(binary.sha256)
                    )
                    loaded = fresh.load(binary.sha256, paths=["/current"], size=2)
                    self.assertIsNotNone(loaded)
                    assert loaded is not None
                    self.assertEqual(loaded.go_version, binary.go_version)
                    self.assertEqual(loaded.paths, ["/current"])
                    self.assertEqual(loaded.size, 2)
                    self.assertEqual(
                        loaded.vulnerability_scan.status,
                        "complete" if current else "not_run",
                    )
                    self.assertEqual(
                        loaded.reconciliation.status,
                        "matched" if current else "not_run",
                    )

    def test_corrupt_or_unchecksummed_entries_are_missed_and_replaced(self) -> None:
        binary = binary_result()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for corruption in ("result", "unchecksummed", "truncated"):
                with self.subTest(corruption=corruption):
                    cache = BinaryResultCache(
                        directory, {"mode": "binary"}, run_id="same-run"
                    )
                    cache.store(binary.sha256, binary)
                    path = cache.cache.object_path(cache.cache_key(binary.sha256))
                    original = path.read_bytes()
                    if corruption == "unchecksummed":
                        document = atomic_read_json(path, checksum=True)
                        atomic_write_json(path, document, overwrite=True)
                    elif corruption == "truncated":
                        path.write_bytes(original[:-10])
                    else:
                        path.write_bytes(original.replace(b"go1.26.8", b"go1.26.9"))
                    fresh = BinaryResultCache(
                        directory, {"mode": "binary"}, run_id="same-run"
                    )
                    self.assertIsNone(fresh.load(binary.sha256, paths=["/app"], size=1))
                    fresh.store(binary.sha256, binary)
                    loaded = BinaryResultCache(
                        directory, {"mode": "binary"}, run_id="same-run"
                    ).load(
                        binary.sha256,
                        paths=["/app"],
                        size=1,
                    )
                    self.assertIsNotNone(loaded)
                    self.assertEqual(path.read_bytes(), original)

    def test_valid_checksum_still_requires_valid_binary_and_context_tombstones(
        self,
    ) -> None:
        binary = binary_result()
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for mismatch in (
                "sha256",
                "go_version",
                "paths",
                "symlinks",
                "runtime_disposition",
                "layer_history",
            ):
                with self.subTest(mismatch=mismatch):
                    cache = BinaryResultCache(
                        directory, {"mode": "binary"}, run_id="same-run"
                    )
                    cache.store(binary.sha256, binary)
                    path = cache.cache.object_path(cache.cache_key(binary.sha256))
                    document = atomic_read_json(path, checksum=True)
                    if mismatch == "sha256":
                        document["binary"]["sha256"] = "b" * 64
                    elif mismatch == "go_version":
                        document["binary"].pop("go_version")
                    else:
                        document["binary"][mismatch] = binary.to_dict()[mismatch]
                    atomic_write_json(path, document, overwrite=True, checksum=True)
                    self.assertIsNone(
                        BinaryResultCache(
                            directory, {"mode": "binary"}, run_id="same-run"
                        ).load(
                            binary.sha256,
                            paths=["/app"],
                            size=1,
                        )
                    )

    def test_profile_is_part_of_the_cache_address(self) -> None:
        digest = "b" * 64
        binary = BinaryReport(
            paths=["/app"],
            size=1,
            sha256=digest,
            go_version="go1.26.8",
            main_package="example.test/app",
            main_module=None,
            dependencies=[],
            build_settings=[],
        )

        with TemporaryDirectory() as temporary_directory:
            cache_directory = Path(temporary_directory)
            BinaryResultCache(cache_directory, {"mode": "disabled"}).store(
                digest,
                binary,
            )
            other_profile = BinaryResultCache(cache_directory, {"mode": "binary"})

            self.assertIsNone(other_profile.load(digest, paths=["/app"], size=1))

    def test_cache_root_must_not_be_a_symlink(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            real_cache = temporary / "real-cache"
            real_cache.mkdir()
            cache_alias = temporary / "cache-alias"
            cache_alias.symlink_to(real_cache, target_is_directory=True)

            with self.assertRaisesRegex(ResultCacheError, "must not be a symlink"):
                BinaryResultCache(cache_alias, {"mode": "binary"})


if __name__ == "__main__":
    unittest.main()
