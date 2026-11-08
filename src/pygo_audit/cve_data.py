"""Shared CVE-list downloads, cache handling, and command-line options."""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
from string import Formatter
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


from pygo_audit.report_views import normalize_cve
from pygo_audit.storage import (
    atomic_read_json,
    atomic_write_json,
    atomic_write_text,
    ensure_private_directory,
)


MAX_ATTEMPTS = 4
MAX_RETRY_DELAY = 60
RETRYABLE_STATUSES = {408, 429, 500, 502, 503, 504}


class DownloadError(ValueError):
    """A supplied document, URL template, or cache cannot be used."""


@dataclass(frozen=True, slots=True)
class DownloadSource:
    template: str
    destination: str
    label: str
    require_csaf: bool = False

    def url(self, cve: str) -> str:
        return self.template.format(
            cve=cve, cve_lower=cve.lower(), year=cve.split("-")[1]
        )


@dataclass(frozen=True)
class DownloadResult:
    path: Path
    from_cache: bool = False
    error: str = ""
    missing_at: str = ""

    @property
    def message(self) -> str:
        if self.missing_at:
            status = "cached missing" if self.from_cache else "missing"
            return f"{status} (404; checked {self.missing_at})"
        return self.error or ("cached" if self.from_cache else "downloaded")


def url_template(value: str) -> str:
    """Accept a regular HTTP URL with explicit CVE substitutions only."""
    try:
        parts = list(Formatter().parse(value))
        if not {"cve", "cve_lower"}.intersection(part[1] for part in parts) or any(
            part[1] not in {None, "cve", "cve_lower", "year"} or part[2] or part[3]
            for part in parts
        ):
            raise ValueError("use {cve} or {cve_lower}, with optional {year}")
        parsed = urlsplit(DownloadSource(value, "", "").url("CVE-2026-0001"))
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.fragment
            or any(character.isspace() for character in value)
        ):
            raise ValueError("expected an HTTP(S) URL without whitespace or a fragment")
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid URL template: {error}") from error
    return value


@contextmanager
def cache_entry_lock(directory: Path, url: str) -> Iterator[None]:
    """Lock one download; closing the descriptor releases the kernel lock."""
    locks = directory / "locks"
    lock = locks / f"{hashlib.sha256(url.encode()).hexdigest()}.lock"
    if directory.is_symlink() or locks.is_symlink() or lock.is_symlink():
        raise DownloadError("download cache and lock paths must not be symlinks")
    ensure_private_directory(directory)
    ensure_private_directory(locks)
    with lock.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def validate_document(document: object, cve: str, source: DownloadSource) -> None:
    """The CSAF preset checks CVE membership; generic downloads only decode JSON."""
    if not source.require_csaf:
        return
    records = document.get("vulnerabilities") if isinstance(document, dict) else None
    if not isinstance(records, list) or not any(
        isinstance(item, dict) and normalize_cve(item.get("cve")) == cve
        for item in records
    ):
        raise DownloadError(f"response contains no CSAF record for {cve}")


def cache_source(directory: Path, source: DownloadSource, *, offline: bool) -> None:
    """Keep different URL templates from sharing the same CVE filenames."""
    record = directory / "source.url"
    if record.is_symlink():
        raise DownloadError(f"download source must not be a symlink: {record}")
    if record.exists():
        if record.read_text(encoding="utf-8") != source.template + "\n":
            raise DownloadError(
                "cache uses a different URL template; select another destination"
            )
    elif not offline:
        atomic_write_text(record, source.template + "\n")


def is_cached(path: Path, cve: str, source: DownloadSource) -> bool:
    if path.is_symlink():
        raise DownloadError(f"download output must not be a symlink: {path}")
    if not path.exists():
        return False
    try:
        document = atomic_read_json(path)
        validate_document(document, cve, source)
    except (OSError, UnicodeError, ValueError) as error:
        raise DownloadError(
            f"cannot read {source.label} document {path}: {error}"
        ) from error
    return True


def cached_result(
    destination: Path, cve: str, source: DownloadSource
) -> DownloadResult | None:
    """Prefer the most recent missing observation over a retained VEX file."""
    marker = destination.with_suffix(".missing")
    if marker.exists():
        record = atomic_read_json(marker)
        if (
            not isinstance(record, dict)
            or record.get("url") != source.url(cve)
            or record.get("status") != 404
            or not isinstance(record.get("checked_at"), str)
        ):
            raise DownloadError(f"invalid missing marker: {marker}")
        checked = datetime.fromisoformat(record["checked_at"])
        if checked.tzinfo is None:
            raise DownloadError(f"missing marker timestamp has no timezone: {marker}")
        return DownloadResult(destination, True, missing_at=record["checked_at"])
    if is_cached(destination, cve, source):
        return DownloadResult(destination, True)
    return None


def retry_after(value: str) -> float:
    """Return the server's minimum wait, ignoring malformed header values."""
    value = value.strip()
    try:
        if value.isascii() and value.isdecimal():
            return int(value)
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, date.timestamp() - time.time())
    except ValueError, TypeError, OverflowError:
        return 0


def download_document(url: str) -> object:
    """Retry transport failures without retrying invalid JSON or local writes."""
    request = Request(url, headers={"User-Agent": "pygo-audit-cve-data/1.0"})
    attempt = 0
    while True:
        try:
            with urlopen(request, timeout=60) as response:
                return json.load(response)
        except (OSError, HTTPException) as error:
            delay = 2**attempt
            if isinstance(error, HTTPError):
                error.close()
                if error.code not in RETRYABLE_STATUSES:
                    raise
                header = error.headers.get("Retry-After", "") if error.headers else ""
                delay = max(delay, retry_after(header))
            attempt += 1
            if attempt >= MAX_ATTEMPTS:
                raise
            if delay > MAX_RETRY_DELAY:
                raise DownloadError(
                    f"{error}; Retry-After exceeds the {MAX_RETRY_DELAY}-second retry limit"
                ) from error
            time.sleep(delay)


def fetch_cve(
    cve: str,
    directory: Path,
    refresh: bool = False,
    offline: bool = False,
    *,
    source: DownloadSource,
) -> DownloadResult:
    """Reuse a complete document or atomically publish a downloaded one."""
    destination = directory / f"{cve}.json"
    marker = destination.with_suffix(".missing")
    for path in (directory, destination, marker):
        if path.is_symlink():
            raise DownloadError(f"download path must not be a symlink: {path}")
    if offline:
        cache_source(directory, source, offline=True)
        return cached_result(destination, cve, source) or DownloadResult(
            destination, error="not present in cache"
        )
    with cache_entry_lock(directory, "source"):
        cache_source(directory, source, offline=False)
    url = source.url(cve)
    with cache_entry_lock(directory, url):
        if (
            not refresh
            and (cached := cached_result(destination, cve, source)) is not None
        ):
            return cached
        try:
            document = download_document(url)
            validate_document(document, cve, source)
        except (OSError, ValueError, HTTPException) as error:
            if isinstance(error, HTTPError) and error.code == 404:
                checked_at = (
                    datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                )
                atomic_write_json(
                    marker,
                    {"url": url, "status": 404, "checked_at": checked_at},
                    overwrite=True,
                )
                return DownloadResult(destination, missing_at=checked_at)
            return DownloadResult(destination, error=str(error))
        atomic_write_json(destination, document, overwrite=True)
        marker.unlink(missing_ok=True)
    return DownloadResult(destination)


def input_cves(lines: Iterable[str]) -> list[str]:
    """Validate the complete input before allowing downloads or cache writes."""
    cves = set()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        cve = normalize_cve(line)
        if cve is None:
            raise ValueError(f"invalid CVE on line {number}: {line.strip()!r}")
        cves.add(cve)
    return sorted(cves)


def positive_jobs(value: str) -> int:
    jobs = int(value)
    if jobs < 1:
        raise argparse.ArgumentTypeError("--jobs must be positive")
    return jobs


def add_arguments(
    parser: argparse.ArgumentParser, source: DownloadSource | None = None
) -> None:
    """Share the CLI between the generic command and source presets."""
    parser.add_argument(
        "input",
        metavar="CVE_LIST",
        help="CVE list file, or - to read from stdin (one CVE per line)",
    )
    parser.add_argument(
        "destination",
        type=Path,
        nargs="?",
        default=Path(source.destination if source else "cve-data"),
        help="directory for downloaded CVE-*.json files (default: %(default)s)",
    )
    parser.add_argument(
        "--url-template",
        type=url_template,
        default=source.template if source else None,
        required=source is None,
        help="source URL with {cve}, {cve_lower}, and {year} substitutions"
        + (" (default: %(default)s)" if source else ""),
    )
    parser.add_argument(
        "--jobs",
        type=positive_jobs,
        default=8,
        help="concurrent downloads (default: 8)",
    )
    if source and source.require_csaf:
        parser.add_argument("--input-format", choices=("cves",), default="cves")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--refresh",
        action="store_true",
        help="refresh cached documents and recheck cached 404s",
    )
    mode.add_argument(
        "--offline",
        action="store_true",
        help="check existing documents without network access or cache writes",
    )


def run(args: argparse.Namespace, source: DownloadSource | None = None) -> int:
    """Resolve parsed CLI input once, then use the shared typed downloader."""
    source = (
        replace(source, template=args.url_template)
        if source is not None
        else DownloadSource(args.url_template, str(args.destination), "CVE data")
    )
    with (
        nullcontext(sys.stdin)
        if args.input == "-"
        else Path(args.input).open(encoding="utf-8")
    ) as stream:
        cves = input_cves(stream)
    failed = False
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(
                fetch_cve,
                cve,
                args.destination,
                args.refresh,
                args.offline,
                source=source,
            ): cve
            for cve in cves
        }
        for future in as_completed(futures):
            try:
                result = future.result()
            except (OSError, ValueError, HTTPException) as error:
                result = DownloadResult(
                    args.destination / f"{futures[future]}.json", error=str(error)
                )
            print(f"{result.path}: {result.message}", flush=True)
            failed |= bool(result.error or result.missing_at)
    print(f"{source.label} documents checked: {len(cves)}")
    return int(failed)


def main(source: DownloadSource, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Download {source.label} documents from a newline-separated CVE list."
    )
    add_arguments(parser, source)
    args = parser.parse_args(argv)
    try:
        return run(args, source)
    except (OSError, ValueError) as error:
        print(f"{parser.prog}: {error}", file=sys.stderr)
        return 1
