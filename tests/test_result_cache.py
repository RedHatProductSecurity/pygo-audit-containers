from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pygo_audit.result_cache import ResultCache, ResultCacheError
from pygo_audit.storage import file_lock, json_digest


def populate_shared_cache(directory, gate, output):
    cache = ResultCache(directory)
    key = json_digest({"inputs": "shared"})
    gate.wait(timeout=10)
    with cache.key_lock(key, wait_seconds=5):
        document = cache.load(key)
        if document is None:
            document = {"computed_by": os.getpid()}
            cache.store(key, document)
    output.put(document["computed_by"])


def hold_cache_lock(directory, ready, release):
    with ResultCache(directory).key_lock("shared"):
        ready.set()
        release.wait(timeout=30)


class ResultCacheTests(unittest.TestCase):
    def test_processes_compute_a_shared_result_once(self) -> None:
        context = multiprocessing.get_context("spawn")
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            gate = context.Barrier(2)
            output = context.Queue()
            workers = [
                context.Process(
                    target=populate_shared_cache, args=(directory, gate, output)
                )
                for _ in range(2)
            ]
            try:
                for worker in workers:
                    worker.start()
                owners = [output.get(timeout=15) for _ in workers]
                for worker in workers:
                    worker.join(timeout=5)
                    self.assertEqual(worker.exitcode, 0)
                self.assertEqual(len(set(owners)), 1)
                self.assertEqual(len(list((directory / "locks").iterdir())), 1)
            finally:
                for worker in workers:
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(timeout=5)
                output.close()
                output.join_thread()

    def test_computation_failure_releases_lock_without_masking_error(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            cache = ResultCache(Path(temporary_directory))
            with (
                self.assertRaisesRegex(ValueError, "computation failed"),
                cache.key_lock("a" * 64),
            ):
                raise ValueError("computation failed")
            with ResultCache(Path(temporary_directory)).key_lock("a" * 64):
                pass

    def test_timeout_and_symlink_lock_prevent_computation(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            cache = ResultCache(directory)
            lock = directory / "locks" / "shared.lock"
            with file_lock(lock):
                with self.assertRaisesRegex(ResultCacheError, "already in use"):
                    with cache.key_lock("shared", wait_seconds=0.01):
                        self.fail("computation ran without the lock")
            alias = directory / "locks" / "alias.lock"
            alias.symlink_to(lock)
            with self.assertRaisesRegex(ResultCacheError, "symlink"):
                with cache.key_lock("alias"):
                    self.fail("computation followed a symlink lock")

    def test_process_termination_releases_lock(self) -> None:
        context = multiprocessing.get_context("spawn")
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            ready, release = context.Event(), context.Event()
            worker = context.Process(
                target=hold_cache_lock, args=(directory, ready, release)
            )
            try:
                worker.start()
                self.assertTrue(ready.wait(timeout=10))
                worker.terminate()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                with ResultCache(directory).key_lock("shared", wait_seconds=0):
                    pass
            finally:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
