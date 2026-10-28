"""Persistent binary facts with run-scoped vulnerability validity."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from pygo_audit.models import BinaryReport, VulnerabilityScan, BinaryReconciliation
from pygo_audit.result_cache import ResultCache
from pygo_audit.audit import parse_binary_report
from pygo_audit.storage import json_digest


class BinaryResultCache:
    """Share binary results, restoring paths and disposition for each scan."""

    def __init__(
        self,
        directory: Path | None,
        profile: dict[str, str],
        *,
        run_id: str | None = None,
    ):
        self.cache = ResultCache(directory, run_id=run_id)
        self.run_id = self.cache.run_id
        self.profile = {
            key: value
            for key, value in profile.items()
            if not key.startswith("govulncheck_") and key != "vulnerability_mode"
        }
        self.analysis_profile = dict(profile)

    def load(
        self,
        sha256: str,
        *,
        paths: list[str],
        size: int,
        symlinks: Sequence[str] = (),
        runtime_disposition: str = "runtime",
    ) -> BinaryReport | None:
        document = self.cache.load(self.cache_key(sha256))
        if document is None:
            return None
        value = document.get("binary")
        if not isinstance(value, dict) or any(
            value.get(field) != {"state": "requires-observation"}
            for field in ("paths", "symlinks", "runtime_disposition", "layer_history")
        ):
            return None
        # Context tombstones are consumed here, never exposed as audit conclusions.
        value = {
            **value,
            "paths": sorted(paths),
            "symlinks": sorted(symlinks),
            "runtime_disposition": runtime_disposition,
            "layer_history": [],
        }
        if document.get("vulnerability_validity") != {
            "run_id": self.run_id,
            "profile": self.analysis_profile,
        }:
            value["vulnerability_scan"] = VulnerabilityScan(status="not_run").to_dict()
            value["reconciliation"] = BinaryReconciliation().to_dict()
        try:
            binary = parse_binary_report(value)
        except ValueError:
            return None
        if binary.sha256 != sha256:
            return None
        binary.size = size
        return binary

    def store(self, sha256: str, binary: BinaryReport) -> None:
        if not sha256 or binary.sha256 != sha256:
            return
        value = binary.to_dict()
        for field in ("paths", "symlinks", "runtime_disposition", "layer_history"):
            value[field] = {"state": "requires-observation"}
        self.cache.store(
            self.cache_key(sha256),
            {
                "binary": value,
                "vulnerability_validity": {
                    "run_id": self.run_id,
                    "profile": self.analysis_profile,
                },
            },
        )

    def key_lock(
        self, sha256: str, *, wait_seconds: float
    ) -> AbstractContextManager[None]:
        return self.cache.key_lock(self.cache_key(sha256), wait_seconds=wait_seconds)

    def cache_key(self, sha256: str) -> str:
        return json_digest({"sha256": sha256, "profile": self.profile})

    def object_path(self, key: str) -> Path:
        return self.cache.object_path(key)
