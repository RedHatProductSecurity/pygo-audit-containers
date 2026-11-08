from __future__ import annotations

from contextlib import chdir, redirect_stderr, redirect_stdout
from datetime import datetime
from importlib.machinery import SourceFileLoader
import importlib.util
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Barrier, Event, Lock
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError, URLError

from pygo_audit import cve_data as FETCH
from pygo_audit.image_csaf import comparison_inputs


def load_script(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / name
    loader = SourceFileLoader(name.replace("-", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


REDHAT = load_script("fetch-redhat-csaf")
DATA = load_script("fetch-cve-data")
TARGETS = load_script("gather-openshift-targets")
PREPARE = load_script("prepare-audits")


class VendorScriptsTests(unittest.TestCase):
    def test_generic_fetch_only_requires_a_cve_list(self) -> None:
        cve = "CVE-2026-53359"
        document = {"cve_id": cve, "affects": [{"component": "example"}]}
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cves.txt"
            source.write_text(f"{cve.lower()}\n{cve}\n", encoding="utf-8")
            with (
                chdir(root),
                patch.object(
                    FETCH, "urlopen", return_value=io.BytesIO(json.dumps(document).encode())
                ) as request,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(DATA.main([str(source)]), 0)
            request.assert_called_once()
            self.assertEqual(
                request.call_args.args[0].full_url,
                f"https://osidb.prodsec.redhat.com/osidb/api/v1/flaws/{cve}",
            )
            self.assertIsNone(request.call_args.args[0].get_header("Authorization"))
            destination = root / "cve-data" / f"{cve}.json"
            original = destination.read_bytes()
            self.assertEqual(original.decode(), json.dumps(document, indent=2) + "\n")
            self.assertIn("CVE data documents checked: 1", output.getvalue())
            for mode in ([], ["--offline"]):
                with (
                    self.subTest(mode=mode),
                    patch.object(FETCH, "urlopen") as request,
                    redirect_stdout(io.StringIO()) as output,
                ):
                    self.assertEqual(DATA.main([str(source), str(destination.parent), *mode]), 0)
                    self.assertIn("cached", output.getvalue())
                    request.assert_not_called()
                    self.assertEqual(destination.read_bytes(), original)

    def test_generic_fetch_accepts_an_explicit_url_template_and_stdin(self) -> None:
        template = "https://advisories.example/{year}/{cve_lower}.json"
        with (
            TemporaryDirectory() as temporary,
            patch.object(FETCH.sys, "stdin", io.StringIO("CVE-2026-53359\n")),
            patch.object(FETCH, "urlopen", return_value=io.BytesIO(b'{"data": "saved"}')) as request,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(DATA.main(["-", temporary, "--url-template", template]), 0)
            self.assertEqual(
                request.call_args.args[0].full_url,
                "https://advisories.example/2026/cve-2026-53359.json",
            )
            self.assertEqual(
                (Path(temporary) / "source.url").read_text(), template + "\n"
            )

    def test_generic_fetch_rejects_invalid_templates_before_downloads(self) -> None:
        for template in (
            "https://example.test/fixed.json",
            "file:///tmp/{cve}",
            "https://example.test/{unknown}",
            "https://example.test/{cve.__class__}",
            "https://example.test/{cve!r}",
            "https://example.test/{cve:>50}",
            "https://example.test/{cve",
            "https://example.test/{cve}#ignored",
            "https://example.test/ {cve}",
        ):
            with (
                self.subTest(template=template),
                TemporaryDirectory() as temporary,
                patch.object(FETCH, "urlopen") as request,
                redirect_stderr(io.StringIO()) as errors,
                self.assertRaises(SystemExit) as raised,
            ):
                DATA.main(["-", temporary, "--url-template", template])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("invalid URL template", errors.getvalue())
            request.assert_not_called()

    def test_generic_cache_rejects_a_different_source_without_network_access(self) -> None:
        cve = "CVE-2026-53359"
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(FETCH, "urlopen", return_value=io.BytesIO(b'{"data": 1}')):
                result = FETCH.fetch_cve(cve, directory, source=DATA.SOURCE)
            original = result.path.read_bytes()
            other = FETCH.DownloadSource("https://other.example/{cve}", "cve-data", "CVE data")
            for mode in ({}, {"refresh": True}, {"offline": True}):
                with (
                    self.subTest(mode=mode),
                    patch.object(FETCH, "urlopen") as request,
                    self.assertRaisesRegex(FETCH.DownloadError, "different URL template"),
                ):
                    FETCH.fetch_cve(cve, directory, source=other, **mode)
                request.assert_not_called()
                self.assertEqual(result.path.read_bytes(), original)

    def test_preparation_dry_run_validates_without_writes_or_registry_access(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "inventory"
            inventory.write_text(
                "# images\nalpha registry.example/app:tag\nbeta registry.example/worker\n"
            )
            output = root / "run"
            with (
                patch.object(PREPARE.subprocess, "run") as command,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    PREPARE.main([str(inventory), str(output), "--dry-run"]), 0
                )
            command.assert_not_called()
            self.assertFalse(output.exists())
            inventory.write_text("alpha image\nalpha other\n")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    PREPARE.main([str(inventory), str(output), "--dry-run"]), 1
                )

    def test_preparation_owns_extractor_invocation(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = root / "inventory"
            inventory.write_text("alpha registry.example/app:tag\n")
            with (
                patch.object(
                    PREPARE.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as command,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(PREPARE.main([str(inventory), str(root / "run")]), 0)
            self.assertIn("extract-image-layers", command.call_args.args[0][1])
            self.assertIn(str(root / "run" / "alpha"), command.call_args.args[0])
            self.assertNotIn("--image-name", command.call_args.args[0])

    def test_download_reuses_cache_and_keeps_failed_refresh_from_replacing_it(
        self,
    ) -> None:
        document = {"vulnerabilities": [{"cve": "CVE-2026-0001"}]}
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            with patch.object(
                FETCH, "urlopen", return_value=io.BytesIO(json.dumps(document).encode())
            ) as request:
                first = FETCH.fetch_cve("CVE-2026-0001", directory, source=REDHAT.SOURCE)
                second = FETCH.fetch_cve("CVE-2026-0001", directory, source=REDHAT.SOURCE)
            self.assertFalse(first.from_cache)
            self.assertTrue(second.from_cache)
            self.assertEqual(json.loads(first.path.read_text()), document)
            request.assert_called_once()
            self.assertEqual(
                request.call_args.args[0].full_url,
                "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-0001.json",
            )
            with (
                patch.object(
                    FETCH, "urlopen", side_effect=OSError("unavailable")
                ) as request,
                patch.object(FETCH.time, "sleep") as sleep,
            ):
                refreshed = FETCH.fetch_cve("CVE-2026-0001", directory, refresh=True, source=REDHAT.SOURCE)
            self.assertIn("unavailable", refreshed.error)
            self.assertEqual(request.call_count, 4)
            self.assertEqual(sleep.call_args_list, [call(1), call(2), call(4)])
            self.assertEqual(json.loads(first.path.read_text()), document)

    def test_download_retries_network_errors_and_server_retry_delays(self):
        cve = "CVE-2026-0001"
        document = {"vulnerabilities": [{"cve": cve}]}
        failures = [
            (URLError("connection reset"), 1),
            (TimeoutError("timed out"), 1),
            (IncompleteRead(b"partial"), 1),
        ]
        for status, header, delay in (
            (408, "", 1),
            (429, "3", 3),
            (500, "invalid", 1),
            (502, "-5", 1),
            (503, "Thu, 01 Jan 1970 00:00:05 GMT", 5),
            (504, "Wed, 31 Dec 1969 23:59:00 GMT", 1),
            (503, "60", 60),
        ):
            failures.append(
                (
                    HTTPError(
                        REDHAT.SOURCE.url(cve),
                        status,
                        "retry",
                        {"Retry-After": header},
                        io.BytesIO(b"error"),
                    ),
                    delay,
                )
            )
        for error, delay in failures:
            with (
                self.subTest(error=str(error), delay=delay),
                TemporaryDirectory() as temporary,
                patch.object(
                    FETCH,
                    "urlopen",
                    side_effect=[error, io.BytesIO(json.dumps(document).encode())],
                ) as request,
                patch.object(FETCH.time, "time", return_value=0),
                patch.object(FETCH.time, "sleep") as sleep,
            ):
                result = FETCH.fetch_cve(cve, Path(temporary), source=REDHAT.SOURCE)
                self.assertFalse(result.error)
                self.assertEqual(json.loads(result.path.read_text()), document)
                self.assertEqual(request.call_count, 2)
                sleep.assert_called_once_with(delay)
                if isinstance(error, HTTPError):
                    self.assertTrue(error.closed)

    def test_server_retry_delays_cannot_extend_attempt_or_wait_limits(self):
        cve = "CVE-2026-0001"
        for header, attempts, waits in (
            ("1", 4, [1, 2, 4]),
            ("120", 1, []),
            ("Thu, 01 Jan 1970 00:02:00 GMT", 1, []),
        ):
            with (
                self.subTest(header=header),
                TemporaryDirectory() as temporary,
                patch.object(
                    FETCH,
                    "urlopen",
                    side_effect=HTTPError(
                        REDHAT.SOURCE.url(cve),
                        429,
                        "busy",
                        {"Retry-After": header},
                        None,
                    ),
                ) as request,
                patch.object(FETCH.time, "time", return_value=0),
                patch.object(FETCH.time, "sleep") as sleep,
            ):
                result = FETCH.fetch_cve(cve, Path(temporary), source=REDHAT.SOURCE)
                self.assertIn("HTTP Error 429", result.error)
                if not waits:
                    self.assertIn("Retry-After exceeds", result.error)
                self.assertEqual(request.call_count, attempts)
                self.assertEqual(sleep.call_args_list, [call(wait) for wait in waits])
                self.assertFalse(result.path.exists())

    def test_offline_fetch_never_creates_cache_or_lock(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory) / "missing"
            with (
                patch.object(FETCH, "cache_entry_lock") as lock,
                patch.object(FETCH, "urlopen") as request,
            ):
                result = FETCH.fetch_cve("CVE-2026-0001", directory, offline=True, source=REDHAT.SOURCE)
            self.assertEqual(result.error, "not present in cache")
            self.assertFalse(directory.exists())
            lock.assert_not_called()
            request.assert_not_called()

    def test_cache_root_must_not_be_a_symlink(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            alias = directory / "alias"
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(FETCH.DownloadError, "must not be a symlink"):
                FETCH.fetch_cve("CVE-2026-0001", alias, offline=True, source=REDHAT.SOURCE)

    def test_permanent_errors_and_invalid_documents_are_not_retried(self) -> None:
        cve = "CVE-2026-0001"
        for response in (
            *(
                HTTPError(REDHAT.SOURCE.url(cve), code, "permanent", {}, None)
                for code in (403, 404, 501)
            ),
            io.BytesIO(b"invalid json"),
            io.BytesIO(b"{}"),
            io.BytesIO(b'{"vulnerabilities": [{"cve": "CVE-2026-0002"}]}'),
        ):
            with (
                patch.object(FETCH, "urlopen", side_effect=[response]) as request,
                patch.object(FETCH.time, "sleep") as sleep,
                TemporaryDirectory() as temporary,
            ):
                result = FETCH.fetch_cve(cve, Path(temporary), source=REDHAT.SOURCE)
                self.assertTrue(result.error or result.missing_at)
                self.assertFalse(result.path.exists())
                self.assertEqual(
                    result.path.with_suffix(".missing").exists(),
                    isinstance(response, HTTPError) and response.code == 404,
                )
                request.assert_called_once()
                sleep.assert_not_called()

    def test_404_markers_persist_until_refresh_and_clear_after_success(self):
        cve = "CVE-2026-0001"
        url = REDHAT.SOURCE.url(cve)
        document = {"vulnerabilities": [{"cve": cve}]}
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(
                FETCH, "urlopen", side_effect=HTTPError(url, 404, "missing", {}, None)
            ) as request:
                first = FETCH.fetch_cve(cve, directory, source=REDHAT.SOURCE)
            request.assert_called_once()
            self.assertTrue(first.missing_at)
            self.assertIn("missing (404; checked", first.message)
            self.assertFalse(first.from_cache)
            self.assertFalse(first.path.exists())
            marker = first.path.with_suffix(".missing")
            record = json.loads(marker.read_text())
            self.assertEqual(
                record, {"url": url, "status": 404, "checked_at": first.missing_at}
            )
            self.assertIsNotNone(datetime.fromisoformat(record["checked_at"]).tzinfo)

            record["checked_at"] = "2000-01-01T00:00:00Z"
            marker.write_text(json.dumps(record))
            saved_marker = marker.read_bytes()
            for options in ([], ["--offline"]):
                with (
                    self.subTest(options=options),
                    patch.object(FETCH.sys, "stdin", io.StringIO(cve)),
                    patch.object(FETCH, "urlopen") as request,
                    redirect_stdout(io.StringIO()) as output,
                ):
                    self.assertEqual(REDHAT.main(["-", temporary, *options]), 1)
                    self.assertIn(
                        "cached missing (404; checked 2000-01-01T00:00:00Z)",
                        output.getvalue(),
                    )
                    request.assert_not_called()
                    self.assertEqual(marker.read_bytes(), saved_marker)

            with (
                patch.object(FETCH, "urlopen", side_effect=OSError("unavailable")),
                patch.object(FETCH.time, "sleep"),
            ):
                failed = FETCH.fetch_cve(cve, directory, refresh=True, source=REDHAT.SOURCE)
            self.assertIn("unavailable", failed.error)
            self.assertEqual(marker.read_bytes(), saved_marker)

            with patch.object(
                FETCH, "urlopen", side_effect=HTTPError(url, 404, "missing", {}, None)
            ):
                missing = FETCH.fetch_cve(cve, directory, refresh=True, source=REDHAT.SOURCE)
            self.assertNotEqual(missing.missing_at, record["checked_at"])
            self.assertEqual(
                json.loads(marker.read_text())["checked_at"], missing.missing_at
            )

            with patch.object(
                FETCH, "urlopen", return_value=io.BytesIO(json.dumps(document).encode())
            ) as request:
                downloaded = FETCH.fetch_cve(cve, directory, refresh=True, source=REDHAT.SOURCE)
            request.assert_called_once()
            self.assertFalse(downloaded.error or downloaded.missing_at)
            self.assertEqual(json.loads(downloaded.path.read_text()), document)
            self.assertFalse(marker.exists())

    def test_404_refresh_keeps_the_old_document_and_reports_the_missing_marker(self):
        cve = "CVE-2026-0001"
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / f"{cve}.json"
            destination.write_text(json.dumps({"vulnerabilities": [{"cve": cve}]}))
            original = destination.read_bytes()
            with patch.object(
                FETCH,
                "urlopen",
                side_effect=HTTPError(REDHAT.SOURCE.url(cve), 404, "missing", {}, None),
            ):
                missing = FETCH.fetch_cve(cve, directory, refresh=True, source=REDHAT.SOURCE)
            with patch.object(FETCH, "urlopen") as request:
                for offline in (False, True):
                    cached = FETCH.fetch_cve(cve, directory, offline=offline, source=REDHAT.SOURCE)
                    self.assertEqual(cached.missing_at, missing.missing_at)
                    self.assertTrue(cached.from_cache)
                request.assert_not_called()
            self.assertEqual(destination.read_bytes(), original)
            files, missing = comparison_inputs([directory])
            self.assertEqual(files, [])
            self.assertEqual(missing[cve][0]["status"], 404)

    def test_failed_document_write_preserves_the_missing_marker(self):
        cve = "CVE-2026-0001"
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / f"{cve}.missing"
            record = {
                "url": REDHAT.SOURCE.url(cve),
                "status": 404,
                "checked_at": "2000-01-01T00:00:00Z",
            }
            marker.write_text(json.dumps(record))
            with (
                patch.object(
                    FETCH,
                    "urlopen",
                    return_value=io.BytesIO(
                        json.dumps({"vulnerabilities": [{"cve": cve}]}).encode()
                    ),
                ),
                patch.object(
                    FETCH, "atomic_write_json", side_effect=OSError("write failed")
                ),
            ):
                with self.assertRaisesRegex(OSError, "write failed"):
                    FETCH.fetch_cve(cve, directory, refresh=True, source=REDHAT.SOURCE)
            self.assertEqual(json.loads(marker.read_text()), record)
            self.assertFalse(marker.with_suffix(".json").exists())

    def test_completion_output_is_flushed_while_a_slow_download_is_running(self):
        for workers, options in ((8, []), (2, ["--jobs", "2"])):
            barrier, printed, lock = Barrier(workers, timeout=5), Event(), Lock()
            active = peak = 0

            class Progress(io.StringIO):
                def flush(self):
                    printed.set()

            def fetch(cve, directory, *options, **settings):
                nonlocal active, peak
                index = int(cve.rsplit("-", 1)[1])
                with lock:
                    active += 1
                    peak = max(peak, active)
                try:
                    if index < workers:
                        barrier.wait()
                    if index == 0:
                        self.assertTrue(
                            printed.wait(5), "completed downloads were not reported"
                        )
                    return FETCH.DownloadResult(directory / f"{cve}.json")
                finally:
                    with lock:
                        active -= 1

            source = "\n".join(f"CVE-2026-{index:04d}" for index in range(workers * 2))
            with (
                self.subTest(workers=workers),
                TemporaryDirectory() as temporary,
                patch.object(FETCH.sys, "stdin", io.StringIO(source)),
                patch.object(FETCH, "fetch_cve", side_effect=fetch),
                redirect_stdout(Progress()) as output,
            ):
                self.assertEqual(REDHAT.main(["-", temporary, *options]), 0)
                lines = output.getvalue().splitlines()
                self.assertNotIn("CVE-2026-0000", lines[0])
                self.assertEqual(len(lines), workers * 2 + 1)
                self.assertEqual(peak, workers)

    def test_cache_lock_and_write_failures_do_not_hide_other_results(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            corrupt = directory / "CVE-2026-0001.json"
            corrupt.write_text("invalid json")
            write_json = FETCH.atomic_write_json
            entry_lock = FETCH.cache_entry_lock

            def lock(path, url):
                if "0004" in url:
                    raise PermissionError("lock denied")
                return entry_lock(path, url)

            def publish(path, document, **options):
                if "0002" in path.name:
                    raise OSError("write failed")
                write_json(path, document, **options)

            def download(request, **options):
                cve = request.full_url.rsplit("/", 1)[1].removesuffix(".json").upper()
                return io.BytesIO(
                    json.dumps({"vulnerabilities": [{"cve": cve}]}).encode()
                )

            source = "\n".join(f"CVE-2026-{index:04d}" for index in range(1, 5))
            with (
                patch.object(FETCH.sys, "stdin", io.StringIO(source)),
                patch.object(FETCH, "cache_entry_lock", side_effect=lock),
                patch.object(FETCH, "atomic_write_json", side_effect=publish),
                patch.object(FETCH, "urlopen", side_effect=download) as request,
                patch.object(FETCH.time, "sleep") as sleep,
                redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(REDHAT.main(["-", temporary]), 1)
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 5)
            self.assertEqual(lines[-1], "CSAF documents checked: 4")
            for detail in (
                "cannot read CSAF",
                "write failed",
                "lock denied",
                "CVE-2026-0003.json: downloaded",
            ):
                self.assertIn(detail, output.getvalue())
            self.assertEqual(corrupt.read_text(), "invalid json")
            self.assertFalse((directory / "CVE-2026-0002.json").exists())
            self.assertTrue((directory / "CVE-2026-0003.json").is_file())
            self.assertEqual(request.call_count, 2)
            sleep.assert_not_called()

    def test_product_release_generates_the_generic_batch_contract(self) -> None:
        document = {
            "metadata": {"version": "4.20.21"},
            "references": {
                "spec": {
                    "tags": [
                        {
                            "name": "example",
                            "from": {
                                "name": "registry.example/image@sha256:" + "a" * 64
                            },
                        },
                        {
                            "name": "longer-example",
                            "from": {
                                "name": "registry.example/other@sha256:" + "b" * 64
                            },
                        },
                    ]
                }
            },
        }
        response = subprocess.CompletedProcess([], 0, json.dumps(document), "")
        with TemporaryDirectory() as temporary_directory:
            target_file = Path(temporary_directory) / "targets.tsv"
            with patch.object(TARGETS.subprocess, "run", return_value=response):
                status = TARGETS.main(["4.20.21", "--output", str(target_file)])
            lines = target_file.read_text().splitlines()
            targets = PREPARE.parse_targets(target_file)
        self.assertEqual(status, 0)
        self.assertEqual(
            {line.index("registry.example/") for line in lines},
            {len("longer-example-4.20.21") + 2},
        )
        self.assertEqual(targets[0].name, "example-4.20.21")
        self.assertEqual(targets[1].name, "longer-example-4.20.21")

    def test_fetch_helper_accepts_cve_files_and_stdin(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "cves.txt"
            content = " cve-2026-0002 \n\nCVE-2026-0001\nCVE-2026-0002\n"
            source.write_text(content, encoding="utf-8")
            for input_path in (str(source), "-"):
                with (
                    self.subTest(input=input_path),
                    patch.object(FETCH.sys, "stdin", io.StringIO(content)) as stdin,
                    patch.object(
                        FETCH,
                        "fetch_cve",
                        side_effect=lambda cve, directory, *options, **settings: FETCH.DownloadResult(
                            directory / f"{cve}.json"
                        ),
                    ) as fetch,
                    redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(
                        REDHAT.main(
                            [
                                "--input-format",
                                "cves",
                                input_path,
                                str(root / "csaf"),
                                "--jobs",
                                "1",
                            ]
                        ),
                        0,
                    )
                    self.assertEqual(
                        [call.args[0] for call in fetch.call_args_list],
                        ["CVE-2026-0001", "CVE-2026-0002"],
                    )
                    self.assertFalse(stdin.closed)

    def test_fetch_helper_validates_all_lines_before_any_download(self) -> None:
        for invalid in (
            "GO-2026-0001",
            "CVE-2026-1",
            "CVE-２０２６-0001",
            "CVE-2026-0001 CVE-2026-0002",
            '{"binaries": []}',
        ):
            with (
                self.subTest(invalid=invalid),
                TemporaryDirectory() as temporary,
                patch.object(
                    FETCH.sys, "stdin", io.StringIO(f"CVE-2026-0001\n{invalid}\n")
                ),
                patch.object(FETCH, "fetch_cve") as fetch,
                redirect_stderr(io.StringIO()) as errors,
            ):
                destination = Path(temporary) / "csaf"
                self.assertEqual(REDHAT.main(["-", str(destination)]), 1)
                self.assertIn("invalid CVE on line 2", errors.getvalue())
                fetch.assert_not_called()
                self.assertFalse(destination.exists())

    def test_fetch_helper_handles_empty_list_without_network_or_output_files(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "cves.txt"
            source.write_text("\n \n", encoding="utf-8")
            with (
                patch.object(FETCH, "urlopen") as request,
                redirect_stdout(io.StringIO()),
            ):
                status = REDHAT.main([str(source), str(root / "csaf")])
            self.assertFalse((root / "csaf").exists())
            request.assert_not_called()
        self.assertEqual(status, 0)
