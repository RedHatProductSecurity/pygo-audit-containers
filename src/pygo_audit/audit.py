"""Read and validate current or historical audit JSON."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from functools import cache
import json
from pathlib import Path
from types import UnionType
from typing import Literal, Union, get_args, get_origin, get_type_hints

from pygo_audit.models import (
    BinaryReport,
    JsonModel,
    AuditReport,
    Vulnerability,
    VulnerabilityScan,
)
from pygo_audit.storage import atomic_read_text


class AuditError(ValueError):
    """Raised when saved audit evidence cannot be reconstructed."""


def load_audit(path: Path) -> AuditReport:
    """Read the selected audit JSON file without inferring identity from its name."""
    document = read_json_document(path)
    try:
        report = parse_model(document, AuditReport, "audit")
        for name in ("producer_name", "producer_version"):
            if not getattr(report, name):
                raise AuditError(f"audit.{name} must not be empty")
        validate_document(document, report.to_dict(), "audit")
        return report
    except (KeyError, TypeError, ValueError) as error:
        raise AuditError(f"invalid audit {path}: {error}") from error


def read_json_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            atomic_read_text(path),
            object_pairs_hook=unique_object,
            parse_constant=invalid_number,
            parse_float=invalid_number,
        )
    except FileNotFoundError as error:
        raise AuditError(f"audit does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise AuditError(
            f"audit is not valid JSON at line {error.lineno}, "
            f"column {error.colno}: {path}"
        ) from error
    except UnicodeError as error:
        raise AuditError(f"audit is not valid UTF-8: {path}") from error
    except ValueError as error:
        raise AuditError(f"invalid audit {path}: {error}") from error
    except OSError as error:
        raise AuditError(
            f"cannot read audit {path}: {error.strerror or str(error)}"
        ) from error
    if not isinstance(value, dict):
        raise AuditError(f"audit is not a JSON object: {path}")
    return value


def parse_binary_report(value: object) -> BinaryReport:
    """Validate canonical binary evidence, including restored cache observations."""
    binary = parse_model(value, BinaryReport, "binary")
    validate_document(value, binary.to_dict(), "binary")
    return binary


@cache
def model_annotations(model: type[JsonModel]) -> dict[str, object]:
    if not is_dataclass(model):
        raise AuditError(f"unsupported audit model: {model.__name__}")
    annotations = get_type_hints(model)
    return {item.name: annotations[item.name] for item in fields(model)}


def parse_model[T: JsonModel](value: object, model: type[T], path: str) -> T:
    annotations = model_annotations(model)
    optional = set(model.optional_fields)
    value = validate_fields(value, path, set(annotations) - optional, optional)
    parsed: dict[str, object] = {}
    for name, annotation in annotations.items():
        if name not in value:
            continue
        field_path = f"{path}.{name}"
        item: object
        if model is Vulnerability and name == "affected":
            affected_items = parse_mapping_list(value[name], field_path)
            for index, affected in enumerate(affected_items):
                validate_affected(affected, f"{field_path}[{index}]")
            item = affected_items
        elif model is VulnerabilityScan and name == "sbom":
            item = parse_sbom(value[name], field_path)
        else:
            item = parse_value(value[name], annotation, field_path)
        parsed[name] = item
    try:
        result = model(**parsed)
    except ValueError as error:
        raise AuditError(f"{path}.{error}") from error
    if isinstance(result, Vulnerability):
        for index, reference in enumerate(result.references):
            validate_fields(reference, f"{path}.references[{index}]", {"type", "url"})
    return result


def parse_value(value: object, annotation: object, path: str) -> object:
    if isinstance(annotation, type) and annotation in (str, int, bool):
        if type(value) is not annotation:
            raise AuditError(f"{path} must be {annotation.__name__}")
        if isinstance(value, int) and not isinstance(value, bool) and value < 0:
            raise AuditError(f"{path} must be a nonnegative integer")
        return value
    origin, arguments = get_origin(annotation), get_args(annotation)
    if origin is Literal:
        if not any(type(value) is type(item) and value == item for item in arguments):
            raise AuditError(f"unsupported {path}: {value!r}; expected {arguments!r}")
        return value
    if origin in (UnionType, Union) and len(arguments) == 2 and type(None) in arguments:
        if value is None:
            return None
        member = next(item for item in arguments if item is not type(None))
        return parse_value(value, member, path)
    if (origin is list and len(arguments) == 1) or (
        origin is tuple and len(arguments) == 2 and arguments[1] is Ellipsis
    ):
        if type(value) is not list:
            raise AuditError(f"{path} must be a list")
        items = [
            parse_value(item, arguments[0], f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
        return tuple(items) if origin is tuple else items
    if origin is dict and len(arguments) == 2 and arguments[0] is str:
        return {
            key: parse_value(item, arguments[1], f"{path}.{key}")
            for key, item in parse_mapping(value, path).items()
        }
    if isinstance(annotation, type) and issubclass(annotation, JsonModel):
        return parse_model(value, annotation, path)
    raise AuditError(f"{path} has unsupported annotation: {annotation!r}")


def parse_sbom(value: object, path: str) -> dict[str, object] | None:
    if value is None:
        return None
    value = validate_fields(value, path, {"go_version", "modules", "roots"})
    parse_value(value["go_version"], str, f"{path}.go_version")
    parse_value(value["roots"], list[str], f"{path}.roots")
    for index, module in enumerate(
        parse_mapping_list(value["modules"], f"{path}.modules")
    ):
        validate_string_fields(module, f"{path}.modules[{index}]", {"path", "version"})
    return value


def validate_affected(value: object, path: str) -> None:
    value = validate_fields(
        value, path, {"module", "ecosystem", "version_ranges", "packages"}
    )
    for name in ("module", "ecosystem"):
        parse_value(value[name], str, f"{path}.{name}")
    for index, interval in enumerate(
        parse_mapping_list(value["version_ranges"], f"{path}.version_ranges")
    ):
        interval_path = f"{path}.version_ranges[{index}]"
        validate_fields(interval, interval_path, {"type", "events"})
        parse_value(interval["type"], str, f"{interval_path}.type")
        for index, event in enumerate(
            parse_mapping_list(interval["events"], f"{interval_path}.events")
        ):
            event_path = f"{interval_path}.events[{index}]"
            validate_fields(
                event,
                event_path,
                set(),
                {"introduced", "fixed", "last_affected", "limit"},
            )
            if not event:
                raise AuditError(f"{event_path} must not be empty")
            for name, version in event.items():
                parse_value(version, str, f"{event_path}.{name}")
    for index, package in enumerate(
        parse_mapping_list(value["packages"], f"{path}.packages")
    ):
        package_path = f"{path}.packages[{index}]"
        validate_fields(package, package_path, {"path", "symbols", "goos", "goarch"})
        parse_value(package["path"], str, f"{package_path}.path")
        for name in ("symbols", "goos", "goarch"):
            parse_value(package[name], list[str], f"{package_path}.{name}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def invalid_number(value: str) -> object:
    raise AuditError(f"audit numbers must be finite integers: {value}")


def validate_document(value: object, expected: object, path: str) -> None:
    """Compare already validated evidence with its canonical serialization."""
    if value != expected:
        raise AuditError(f"{path} disagrees with canonical evidence")


def validate_fields(
    value: object,
    path: str,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, object]:
    value = parse_mapping(value, path)
    missing, unknown = required - value.keys(), value.keys() - required - optional
    if missing or unknown:
        raise AuditError(
            f"{path} fields: missing {sorted(missing)}, unknown {sorted(unknown)}"
        )
    return value


def validate_string_fields(value: object, path: str, required: set[str]) -> None:
    for name, item in validate_fields(value, path, required).items():
        parse_value(item, str, f"{path}.{name}")


def parse_mapping(value: object, path: str) -> dict[str, object]:
    if type(value) is not dict:
        raise AuditError(f"{path} must be an object")
    if any(type(key) is not str for key in value):
        raise AuditError(f"{path} keys must be strings")
    return value


def parse_mapping_list(value: object, path: str) -> list[dict[str, object]]:
    if type(value) is not list:
        raise AuditError(f"{path} must be a list of objects")
    return [parse_mapping(item, f"{path}[{index}]") for index, item in enumerate(value)]
