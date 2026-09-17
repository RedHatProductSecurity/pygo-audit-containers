"""Data models for scan results and serialized reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class Module:
    path: str = ""
    version: str = ""
    sum: str = ""
    replace: Module | None = None

    @classmethod
    def from_go_json(cls, value: object) -> Module | None:
        if not isinstance(value, dict) or not value:
            return None

        return cls(
            path=_string(value.get("Path")),
            version=_string(value.get("Version")),
            sum=_string(value.get("Sum")),
            replace=cls.from_go_json(value.get("Replace")),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "version": self.version,
            "sum": self.sum,
        }
        if self.replace is not None:
            result["replace"] = self.replace.to_dict()
        return result

    def identity(self) -> tuple[object, ...]:
        replacement = self.replace.identity() if self.replace is not None else None
        return (self.path, self.version, self.sum, replacement)


@dataclass(slots=True, frozen=True)
class BuildSetting:
    key: str
    value: str

    @classmethod
    def from_go_json(cls, value: object) -> BuildSetting | None:
        if not isinstance(value, dict):
            return None
        key = value.get("Key")
        setting_value = value.get("Value")
        if not isinstance(key, str) or not isinstance(setting_value, str):
            return None
        return cls(key=key, value=setting_value)

    def to_dict(self) -> dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass(slots=True)
class BinaryReport:
    paths: list[str]
    size: int
    go_version: str
    main_package: str
    main_module: Module | None
    dependencies: list[Module]
    build_settings: list[BuildSetting]

    @classmethod
    def from_go_json(
        cls,
        value: object,
        *,
        container_path: str,
        size: int,
    ) -> BinaryReport:
        if not isinstance(value, dict):
            raise ValueError("Go returned a JSON value that is not an object")

        go_version = value.get("GoVersion")
        if not isinstance(go_version, str) or not go_version:
            raise ValueError("Go JSON output does not contain GoVersion")

        raw_dependencies = value.get("Deps", [])
        if not isinstance(raw_dependencies, list):
            raise ValueError("Go JSON output contains a non-list Deps field")
        dependencies = [
            module
            for raw_module in raw_dependencies
            if (module := Module.from_go_json(raw_module)) is not None
        ]

        raw_settings = value.get("Settings", [])
        if not isinstance(raw_settings, list):
            raise ValueError("Go JSON output contains a non-list Settings field")
        settings = [
            setting
            for raw_setting in raw_settings
            if (setting := BuildSetting.from_go_json(raw_setting)) is not None
        ]

        return cls(
            paths=[container_path],
            size=size,
            go_version=go_version,
            main_package=_string(value.get("Path")),
            main_module=Module.from_go_json(value.get("Main")),
            dependencies=dependencies,
            build_settings=settings,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": sorted(self.paths),
            "size": self.size,
            "go_version": self.go_version,
            "main_package": self.main_package,
            "main_module": (
                self.main_module.to_dict() if self.main_module is not None else None
            ),
            "dependencies": [module.to_dict() for module in self.dependencies],
            "build_settings": [setting.to_dict() for setting in self.build_settings],
        }


@dataclass(slots=True, frozen=True)
class ScanIssue:
    path: str
    stage: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "stage": self.stage, "message": self.message}


@dataclass(slots=True)
class ScanStats:
    directories: int = 0
    entries: int = 0
    regular_files: int = 0
    unique_regular_files: int = 0
    elf_paths: int = 0
    unique_elf_files: int = 0
    go_binaries: int = 0
    go_binary_paths: int = 0
    symlinks_skipped: int = 0
    special_files_skipped: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "directories": self.directories,
            "entries": self.entries,
            "regular_files": self.regular_files,
            "unique_regular_files": self.unique_regular_files,
            "elf_paths": self.elf_paths,
            "unique_elf_files": self.unique_elf_files,
            "go_binaries": self.go_binaries,
            "go_binary_paths": self.go_binary_paths,
            "symlinks_skipped": self.symlinks_skipped,
            "special_files_skipped": self.special_files_skipped,
        }


@dataclass(slots=True)
class ScanReport:
    root: str
    go_command: str
    go_tool_version: str
    binaries: list[BinaryReport] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def dependency_summary(self) -> list[dict[str, Any]]:
        usages: dict[tuple[object, ...], tuple[Module, set[str]]] = {}
        for binary in self.binaries:
            for module in binary.dependencies:
                key = module.identity()
                if key not in usages:
                    usages[key] = (module, set())
                usages[key][1].update(binary.paths)

        summary: list[dict[str, Any]] = []
        for module, paths in usages.values():
            item = module.to_dict()
            item["used_by"] = sorted(paths)
            summary.append(item)
        summary.sort(key=lambda item: (item["path"], item["version"], item["sum"]))
        return summary

    def to_dict(self) -> dict[str, Any]:
        binaries = sorted(self.binaries, key=lambda binary: min(binary.paths))
        issues = sorted(self.issues, key=lambda issue: (issue.path, issue.stage))
        return {
            "schema_version": 1,
            "root": self.root,
            "toolchain": {
                "command": self.go_command,
                "version": self.go_tool_version,
            },
            "binaries": [binary.to_dict() for binary in binaries],
            "dependency_summary": self.dependency_summary(),
            "issues": [issue.to_dict() for issue in issues],
            "stats": self.stats.to_dict(),
        }


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""
