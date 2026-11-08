"""Composable plain-text layout, independent of audit evidence and configuration."""

from __future__ import annotations

import textwrap
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from itertools import zip_longest

DEFAULT_PREVIEW_LIMIT = 10


class Verbosity(IntEnum):
    """Ordered human-readable report detail levels."""

    SUMMARY = 0
    EXPANDED = 1
    DETAILED = 2
    FORENSIC = 3


@dataclass(frozen=True, slots=True)
class RenderPolicy:
    """Control section visibility and cardinality without mutable state."""

    verbosity: Verbosity = Verbosity.SUMMARY
    wide: bool = False
    entry_limit: int = DEFAULT_PREVIEW_LIMIT

    def __post_init__(self) -> None:
        if self.entry_limit < 1:
            raise ValueError("report entry limit must be positive")

    def shows(self, minimum: Verbosity) -> bool:
        return self.verbosity >= minimum

    def preview[Item](self, values: Iterable[Item]) -> tuple[list[Item], int]:
        return preview_items(values, None if self.wide else self.entry_limit)

    def omission(self, count: int) -> str:
        return f"{count} omitted; use --wide to show all"

    def hash(self, value: str) -> str:
        return single_line(value) if self.wide else short_hash(value)


SUMMARY_POLICY = RenderPolicy()
EXPANDED_POLICY = RenderPolicy(Verbosity.EXPANDED)
DETAILED_POLICY = RenderPolicy(Verbosity.DETAILED)
FORENSIC_POLICY = RenderPolicy(Verbosity.FORENSIC)
FULL_POLICY = RenderPolicy(Verbosity.FORENSIC, wide=True)


class TextLayout(list[str]):
    """Collect sections and fields with one set of presentation conventions."""

    width = 100
    label_width = 24

    def __init__(
        self, values: Iterable[str] = (), *, policy: RenderPolicy = SUMMARY_POLICY
    ) -> None:
        super().__init__(values)
        self.policy = policy

    @classmethod
    def titled(cls, title: str, *, policy: RenderPolicy = SUMMARY_POLICY) -> TextLayout:
        return cls([title, "=" * min(len(title), cls.width)], policy=policy)

    def section(
        self,
        title: str,
        *,
        rule_width: int | None = width,
        rule_char: str = "-",
    ) -> None:
        """Add a heading; None fits its rule to the title and zero omits it."""
        if self and self[-1]:
            self.append("")
        width = min(len(title) if rule_width is None else rule_width, self.width)
        self.append(title)
        if width:
            self.append(rule_char * width)

    def field(
        self,
        label: str,
        value: object,
        *,
        wrap: bool = False,
        label_width: int | None = None,
    ) -> None:
        """Render a value; None explicitly omits an optional field."""
        if value is None:
            return
        label = f"{label}:" if label else ""
        prefix = f"{label:<{max(label_width or self.label_width, len(label) + 1)}}"
        if not wrap:
            self.append(prefix + str(value))
            return
        segments = textwrap.wrap(
            single_line(str(value)),
            width=max(8, self.width - len(prefix)),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        self.append(prefix + segments[0])
        self.extend(" " * len(prefix) + segment for segment in segments[1:])

    def banner(self, title: str) -> None:
        """Give a primary result a distinct, full-width boundary."""
        if self and self[-1]:
            self.append("")
        self.extend(("=" * self.width, title, "=" * self.width))

    @contextmanager
    def subsection(self, title: str, *, indent: int = 2) -> Iterator[TextLayout]:
        """Nest content under a heading without using separator length as hierarchy."""
        self.section(title, rule_width=0)
        child = TextLayout(policy=self.policy)
        child.width = max(8, self.width - indent)
        yield child
        self.extend(" " * indent + line if line else "" for line in child)

    def fields(
        self,
        *rows: tuple[str, object],
        wrap: bool = False,
        label_width: int | None = None,
    ) -> None:
        for label, value in rows:
            self.field(label, value, wrap=wrap, label_width=label_width)

    def preview_field(
        self,
        label: str,
        values: Iterable[object],
        *,
        empty: str = "(none)",
        omitted_label: str | None = None,
        wrap: bool = False,
    ) -> None:
        """Render a bounded list and its omitted count consistently."""
        with self.preview(
            label.lower(), values, omitted_label=omitted_label
        ) as visible:
            self.field(label, ", ".join(map(str, visible)) or empty, wrap=wrap)

    def bullets(
        self,
        values: Iterable[str],
        *,
        indent: str = "  ",
        wrap: bool = False,
    ) -> None:
        for value in values:
            prefix = f"{indent}- "
            if not wrap:
                self.append(prefix + value)
                continue
            self.extend(
                textwrap.wrap(
                    single_line(value),
                    width=self.width,
                    initial_indent=prefix,
                    subsequent_indent=" " * len(prefix),
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                or [prefix.rstrip()]
            )

    def list_field(
        self, label: str, values: Iterable[str], *, empty: str = "(none)"
    ) -> None:
        """Keep one value compact and list multiple values on separate lines."""
        with self.preview(label.lower(), values) as visible:
            if len(visible) > 1:
                self.append(f"{label}:")
                self.bullets(visible)
            else:
                self.field(label, visible[0] if visible else empty)

    def preview_bullets(
        self,
        label: str,
        values: Iterable[str],
        *,
        indent: str = "  ",
        wrap: bool = False,
    ) -> None:
        """Render list entries and the omitted count together."""
        self.bullets(self.limited(label, values), indent=indent, wrap=wrap)

    def limited[Item](self, label: str, values: Iterable[Item]) -> Iterator[Item]:
        """Yield visible entries, then append their omission notice."""
        with self.preview(label, values) as visible:
            yield from visible

    @contextmanager
    def preview[Item](
        self, label: str, values: Iterable[Item], *, omitted_label: str | None = None
    ) -> Iterator[list[Item]]:
        """Keep a grouped list's omission notice after its table or nested sections."""
        visible, omitted = self.policy.preview(values)
        yield visible
        if omitted:
            self.field(
                omitted_label or f"Additional {label}", self.policy.omission(omitted)
            )

    def columns(self, rows: Iterable[Iterable[object]], *, gap: int = 2) -> None:
        """Append aligned columns, stacking list-valued cells within each row."""
        values = [
            [
                [single_line(str(part)) for part in value] or [""]
                if isinstance(value, (list, tuple))
                else [single_line(str(value))]
                for value in row
            ]
            for row in rows
        ]
        if not values:
            return
        column_count = max(len(row) for row in values)
        values = [row + [[""]] * (column_count - len(row)) for row in values]
        widths = [
            max(len(part) for row in values for part in row[index])
            for index in range(column_count)
        ]
        available = self.width - gap * (column_count - 1)
        while not self.policy.wide and sum(widths) > available:
            index = max(range(column_count), key=lambda item: widths[item])
            if widths[index] <= 8:
                break
            widths[index] -= 1
        for row in values:
            for parts in zip_longest(*row, fillvalue=""):
                cells = [shrink_middle(value, widths[index]) for index, value in enumerate(parts)]
                self.append(
                    (" " * gap)
                    .join(
                        cell.ljust(widths[index]) if index < column_count - 1 else cell
                        for index, cell in enumerate(cells)
                    )
                    .rstrip()
                )

    def render(self) -> str:
        return "\n".join(self).rstrip()


def single_line(value: str) -> str:
    return "; ".join(line.strip() for line in value.splitlines() if line.strip())


def short_hash(value: str, length: int = 12) -> str:
    """Shorten a hash for display while retaining its prefix."""
    normalized = single_line(value)
    if len(normalized) <= length:
        return normalized
    algorithm, separator, digest = normalized.partition(":")
    if separator and digest:
        return f"{algorithm}:{digest[:length]}..."
    return normalized[:length] + "..."


def shrink_middle(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    left = (width - 1) // 2
    return f"{value[:left]}…{value[-(width - left - 1):]}"


def count_phrase(count: int, singular: str) -> str:
    return f"{count} {singular}{'' if count == 1 else 's'}"


def preview_items[Item](
    values: Iterable[Item], limit: int | None = DEFAULT_PREVIEW_LIMIT
) -> tuple[list[Item], int]:
    """Return a bounded presentation preview and its omitted-item count."""
    items = list(values)
    if limit is None:
        return items, 0
    return items[:limit], max(0, len(items) - limit)
