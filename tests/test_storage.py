from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import csv
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import patch

from pygo_audit.storage import (
    ChecksumError,
    atomic_read_json,
    atomic_read_text,
    atomic_text_writer,
    atomic_write_json,
    atomic_write_text,
    directory_lock,
    ensure_private_directory,
    file_lock,
    FileLockError,
    json_digest,
)


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.destination = self.directory / "result.json"

    def test_file_lock_rejects_concurrent_owner_and_reuses_inode(self) -> None:
        with file_lock(self.destination):
            inode = self.destination.stat().st_ino
            with self.assertRaisesRegex(FileLockError, "already in use"):
                with file_lock(self.destination):
                    self.fail("concurrent owner acquired the lock")
        with file_lock(self.destination):
            self.assertEqual(self.destination.stat().st_ino, inode)
            self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)

    def test_file_lock_reports_open_failures(self) -> None:
        with patch("pygo_audit.storage.os.open", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(FileLockError, "cannot open lock.*denied"):
                with file_lock(self.destination):
                    self.fail("lock open failure was ignored")

    def test_directory_lock_rejects_contention_without_leaving_an_artifact(
        self,
    ) -> None:
        with directory_lock(self.directory):
            with self.assertRaisesRegex(FileLockError, "already in use"):
                with directory_lock(self.directory):
                    self.fail("concurrent owner acquired the directory lock")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_text_reader_round_trips_plain_and_checksummed_content(self) -> None:
        for checksum in (False, True):
            for content in ("", "plain text", "\u00e9\nsecond line\r\n"):
                with self.subTest(checksum=checksum, content=content):
                    atomic_write_text(
                        self.destination,
                        content,
                        overwrite=True,
                        checksum=checksum,
                    )
                    self.assertEqual(
                        atomic_read_text(self.destination, checksum=checksum),
                        content,
                    )

    def test_reader_keeps_the_opened_version_when_the_path_is_replaced(self) -> None:
        for checksum in (False, True):
            with self.subTest(checksum=checksum):
                atomic_write_text(
                    self.destination,
                    "old version",
                    overwrite=True,
                    checksum=checksum,
                )
                with self.destination.open("rb") as opened:
                    atomic_write_text(
                        self.destination,
                        "new version",
                        overwrite=True,
                        checksum=checksum,
                    )
                    with patch(
                        "pygo_audit.storage.Path.open", return_value=opened
                    ) as open_file:
                        self.assertEqual(
                            atomic_read_text(self.destination, checksum=checksum),
                            "old version",
                        )
                        open_file.assert_called_once()
                self.assertEqual(
                    atomic_read_text(self.destination, checksum=checksum),
                    "new version",
                )

    def test_json_reader_delegates_file_and_checksum_handling_to_text_reader(
        self,
    ) -> None:
        with patch(
            "pygo_audit.storage.atomic_read_text", return_value='{"value": 1}'
        ) as read:
            self.assertEqual(
                atomic_read_json(self.destination, checksum=True), {"value": 1}
            )
        read.assert_called_once_with(self.destination, checksum=True)

    def test_readers_preserve_missing_file_and_utf8_errors(self) -> None:
        for reader in (atomic_read_text, atomic_read_json):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(FileNotFoundError):
                    reader(self.destination)
                self.destination.write_bytes(b"\xff")
                with self.assertRaises(UnicodeDecodeError):
                    reader(self.destination)
                self.destination.unlink()

    def test_json_digest_uses_the_existing_canonical_encoding(self) -> None:
        document = {"profile": {"z": "\u00e9", "a": True}, "binary": "abc"}
        canonical = b'{"binary":"abc","profile":{"a":true,"z":"\\u00e9"}}'
        self.assertEqual(json_digest(document), hashlib.sha256(canonical).hexdigest())
        self.assertEqual(
            json_digest(document), json_digest(dict(reversed(document.items())))
        )
        self.assertEqual(
            json_digest(document),
            json_digest(json.loads(json.dumps(document, indent=4))),
        )
        self.assertNotEqual(
            json_digest(document), json_digest(document | {"binary": "def"})
        )

    def test_create_only_publishes_complete_private_text(self) -> None:
        with atomic_text_writer(self.destination) as stream:
            stream.write("complete \u00e9\n")
            self.assertFalse(self.destination.exists())
        self.assertEqual(
            self.destination.read_text(encoding="utf-8"), "complete \u00e9\n"
        )
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_create_only_preserves_an_existing_file(self) -> None:
        self.destination.write_text("original", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            atomic_write_text(self.destination, "replacement")
        self.assertEqual(self.destination.read_text(encoding="utf-8"), "original")
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_create_only_preserves_live_and_dangling_symlinks(self) -> None:
        target = self.directory / "target"
        for exists in (False, True):
            with self.subTest(target_exists=exists):
                if exists:
                    target.write_text("original", encoding="utf-8")
                self.destination.symlink_to(target)
                with self.assertRaises(FileExistsError):
                    atomic_write_text(self.destination, "replacement")
                self.assertTrue(self.destination.is_symlink())
                if exists:
                    self.assertEqual(target.read_text(encoding="utf-8"), "original")
                else:
                    self.assertFalse(target.exists())
                self.destination.unlink()

    def test_replace_keeps_the_old_file_visible_until_publication(self) -> None:
        self.destination.write_text("original", encoding="utf-8")
        with atomic_text_writer(self.destination, overwrite=True) as stream:
            stream.write("replacement")
            self.assertEqual(self.destination.read_text(encoding="utf-8"), "original")
        self.assertEqual(self.destination.read_text(encoding="utf-8"), "replacement")
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_replace_replaces_a_symlink_without_writing_through_it(self) -> None:
        target = self.directory / "target"
        target.write_text("original", encoding="utf-8")
        self.destination.symlink_to(target)
        atomic_write_text(self.destination, "replacement", overwrite=True)
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(self.destination.read_text(encoding="utf-8"), "replacement")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_failed_body_keeps_existing_content_and_cleans_temporary(self) -> None:
        self.destination.write_text("original", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "interrupted"):
            with atomic_text_writer(self.destination, overwrite=True) as stream:
                stream.write("partial")
                raise ValueError("interrupted")
        self.assertEqual(self.destination.read_text(encoding="utf-8"), "original")
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_cleanup_failure_warns_on_stderr_without_failing_publication(self) -> None:
        errors, output = io.StringIO(), io.StringIO()
        with (
            redirect_stderr(errors),
            redirect_stdout(output),
            patch(
                "pygo_audit.storage.Path.unlink",
                side_effect=PermissionError("cleanup denied"),
            ),
        ):
            atomic_write_text(self.destination, "complete")
        self.assertEqual(self.destination.read_text(encoding="utf-8"), "complete")
        self.assertEqual(output.getvalue(), "")
        self.assertIn(
            "pygo-audit: warning: cannot remove temporary file", errors.getvalue()
        )
        self.assertIn(str(self.directory), errors.getvalue())
        self.assertIn("result.json-", errors.getvalue())
        self.assertIn("cleanup denied", errors.getvalue())

    def test_cleanup_warning_preserves_the_original_body_exception(self) -> None:
        errors = io.StringIO()
        original = ValueError("body failed")
        with (
            redirect_stderr(errors),
            patch(
                "pygo_audit.storage.Path.unlink", side_effect=OSError("cleanup failed")
            ),
        ):
            with self.assertRaises(ValueError) as caught:
                with atomic_text_writer(self.destination) as stream:
                    stream.write("partial")
                    raise original
        self.assertIs(caught.exception, original)
        self.assertFalse(self.destination.exists())
        self.assertIn("cleanup failed", errors.getvalue())

    def test_cleanup_warning_preserves_the_original_publication_exception(self) -> None:
        errors = io.StringIO()
        original = OSError("publication failed")
        with (
            redirect_stderr(errors),
            patch("pygo_audit.storage.os.link", side_effect=original),
            patch(
                "pygo_audit.storage.Path.unlink", side_effect=OSError("cleanup failed")
            ),
        ):
            with self.assertRaises(OSError) as caught:
                atomic_write_text(self.destination, "complete")
        self.assertIs(caught.exception, original)
        self.assertFalse(self.destination.exists())
        self.assertIn("cleanup failed", errors.getvalue())

    def test_sync_and_publication_failures_clean_the_temporary(self) -> None:
        for operation, overwrite in (
            ("fsync", False),
            ("link", False),
            ("replace", True),
        ):
            with self.subTest(operation=operation):
                with patch(
                    f"pygo_audit.storage.os.{operation}", side_effect=OSError("failed")
                ):
                    with self.assertRaisesRegex(OSError, "failed"):
                        atomic_write_text(
                            self.destination, "result", overwrite=overwrite
                        )
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_competing_create_only_writers_publish_one_complete_result(self) -> None:
        ready = Barrier(2)

        def publish(content: str) -> bool:
            try:
                with atomic_text_writer(self.destination) as stream:
                    stream.write(content)
                    ready.wait(timeout=5)
                return True
            except FileExistsError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(publish, ("first", "second")))
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertIn(self.destination.read_text(encoding="utf-8"), ("first", "second"))
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_json_output_preserves_readable_format_and_newline(self) -> None:
        document = {"z": "\u00e9", "a": {"value": 1}}
        atomic_write_json(self.destination, document, sort_keys=True)
        self.assertEqual(
            self.destination.read_text(encoding="utf-8"),
            json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        )
        self.assertEqual(atomic_read_json(self.destination), document)

    def test_private_json_footer_can_be_verified_without_cache_state(self) -> None:
        document = {
            "sha256": "a" * 64,
            "profile": {"mode": "binary"},
            "results": ["finding"],
        }
        atomic_write_json(self.destination, document, checksum=True)
        payload, digest, ending = self.destination.read_bytes().rsplit(b"\n", 2)
        self.assertEqual(ending, b"")
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest().encode("ascii"))
        self.assertEqual(json.loads(payload), document)
        self.assertEqual(atomic_read_json(self.destination, checksum=True), document)
        with self.assertRaises(json.JSONDecodeError):
            atomic_read_json(self.destination)

    def test_checked_text_and_stream_writers_use_the_same_footer(self) -> None:
        content = '{"value": "\u00e9"}\n'
        atomic_write_text(self.destination, content, checksum=True)
        original = self.destination.read_bytes()
        with atomic_text_writer(
            self.destination, overwrite=True, checksum=True
        ) as stream:
            stream.write(content)
            stream.seek(0)
        self.assertEqual(self.destination.read_bytes(), original)
        self.assertEqual(
            atomic_read_json(self.destination, checksum=True), {"value": "\u00e9"}
        )

    def test_checksum_rejects_corruption_and_truncation_before_json_parsing(
        self,
    ) -> None:
        atomic_write_json(self.destination, {"value": "original"}, checksum=True)
        original = self.destination.read_bytes()
        payload, digest, _ = original.rsplit(b"\n", 2)
        corruptions = (
            b"",
            payload,
            original[:-1],
            original[:-10],
            original.replace(b"original", b"modified"),
            payload + b"\n" + b"0" * 64 + b"\n",
            original + b"extra\n",
            payload + b"\n" + digest + b" \n",
        )
        for content in corruptions:
            with self.subTest(content=content):
                self.destination.write_bytes(content)
                with patch("pygo_audit.storage.json.loads") as parse:
                    with self.assertRaises(ChecksumError):
                        atomic_read_json(self.destination, checksum=True)
                    parse.assert_not_called()

    def test_checksum_covers_formatting_and_all_payload_bytes(self) -> None:
        atomic_write_json(self.destination, {"value": 1}, checksum=True)
        content = self.destination.read_bytes().replace(b'  "value"', b' "value"')
        self.destination.write_bytes(content)
        with self.assertRaises(ChecksumError):
            atomic_read_json(self.destination, checksum=True)

    def test_checksum_failure_keeps_the_previous_file_and_cleans_temporary(
        self,
    ) -> None:
        self.destination.write_text("previous result", encoding="utf-8")
        with patch(
            "pygo_audit.storage.hashlib.file_digest", side_effect=OSError("failed")
        ):
            with self.assertRaisesRegex(OSError, "failed"):
                atomic_write_json(self.destination, {}, overwrite=True, checksum=True)
        self.assertEqual(
            self.destination.read_text(encoding="utf-8"), "previous result"
        )
        self.assertEqual(list(self.directory.iterdir()), [self.destination])

    def test_invalid_json_input_does_not_publish_a_partial_document(self) -> None:
        with self.assertRaises(TypeError):
            atomic_write_json(self.destination, {"not_json": object()})
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_streaming_writer_preserves_csv_newlines(self) -> None:
        with atomic_text_writer(self.destination, newline="") as stream:
            csv.writer(stream).writerow(["line\nbreak", "value"])
        self.assertEqual(self.destination.read_bytes(), b'"line\nbreak",value\r\n')

    def test_parent_creation_is_left_to_the_caller(self) -> None:
        with self.assertRaises(FileNotFoundError):
            atomic_write_text(self.directory / "missing" / "result", "content")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_private_directory_creates_parents_and_restricts_existing_mode(
        self,
    ) -> None:
        directory = self.directory / "cache" / "objects"
        ensure_private_directory(directory)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        directory.chmod(0o777)
        ensure_private_directory(directory)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_private_directory_rejects_symlinks_and_regular_files(self) -> None:
        target = self.directory / "target"
        target.mkdir(mode=0o750)
        original_mode = target.stat().st_mode
        self.destination.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(OSError, "must not be a symlink"):
            ensure_private_directory(self.destination)
        self.assertEqual(target.stat().st_mode, original_mode)
        self.destination.unlink()
        self.destination.write_text("original", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            ensure_private_directory(self.destination)


if __name__ == "__main__":
    unittest.main()
