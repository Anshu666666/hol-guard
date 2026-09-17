"""One bounded traversal of the text lockfile syntax already supported by Guard.

This is deliberately the existing line grammar, not a general YAML interpreter.
The manifest and direct-selector views have different duplicate semantics; both
are retained without reparsing source text or selecting a target during parsing.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from .package_manifest_diff import (
    _exact_dependency_version,
    _pnpm_entry_name_version,
    _yarn_selector_name,
)

_VERSION_RE = re.compile(r'^version\s+"([^"]+)"$|^version:\s*"?([^"\s]+)"?$')
_SPEC_RE = re.compile(r"^\s{4}([A-Za-z0-9_.:-]+) \(([^)]+)\)")
_HEADING_RE = re.compile(r"[A-Z][A-Z0-9_ ]+")
_BRACKET_RE = re.compile(r"[\[\]{}]")
_LINE_END_RE = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")


class TextLockfileValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TextLockfileEntries:
    dependencies: tuple[tuple[str, str], ...]
    # pnpm: inline value then the first nested version, in source order. The
    # consumer applies its existing exact/source rules and takes the first valid
    # value per record, retaining last-write behavior across records.
    direct_candidates: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # Yarn: first occurrence of each selector, including its source ordinal.
    # Choosing the earliest matched ordinal preserves first-match resolution.
    selector_versions: tuple[tuple[str, str, int], ...] = ()


@dataclass(slots=True)
class _Budget:
    check_deadline: Callable[[], None]
    max_entries: int
    max_nodes: int
    max_depth: int
    nodes: int = 1  # document root
    bracket_depth: int = 0
    indents: list[int] = field(default_factory=lambda: [0])

    def node(self, count: int = 1) -> None:
        self.check_deadline()
        self.nodes += count
        if self.nodes > self.max_nodes:
            raise TextLockfileValidationError("node_limit_exceeded")

    def entries(self, count: int) -> None:
        if count > self.max_entries:
            raise TextLockfileValidationError("entry_limit_exceeded")

    def validate_line(self, name: str, raw: str, stripped: str, indent: int) -> None:
        self.node()
        while indent < self.indents[-1]:
            self.indents.pop()
        if indent > self.indents[-1]:
            self.indents.append(indent)
        if len(self.indents) - 1 > self.max_depth:
            raise TextLockfileValidationError("depth_limit_exceeded")
        for bracket in _BRACKET_RE.finditer(raw):
            self.check_deadline()
            self.bracket_depth += 1 if bracket.group() in "[{" else -1
            if self.bracket_depth + len(self.indents) - 1 > self.max_depth:
                raise TextLockfileValidationError("depth_limit_exceeded")
        # Preserve the existing line-level bracket accounting, including its
        # treatment of quoted scalars. This does not claim full YAML validation.
        if self.bracket_depth < 0:
            raise TextLockfileValidationError("syntax_error")
        if name == "pnpm-lock.yaml" and ":" not in stripped and not stripped.startswith("-"):
            raise TextLockfileValidationError("syntax_error")
        if name == "yarn.lock" and not raw.startswith((" ", "\t")) and not stripped.endswith(":"):
            raise TextLockfileValidationError("syntax_error")


@dataclass(slots=True)
class _Pnpm:
    dependencies: dict[str, str] = field(default_factory=dict)
    package_versions: dict[str, str] = field(default_factory=dict)
    direct: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    section: str | None = None
    snapshot_dependencies: bool = False
    importer: str | None = None
    direct_block: bool = False
    pending: int | None = None

    def line(self, stripped: str, indent: int, budget: _Budget) -> None:
        if indent == 0:
            self.section = stripped.removesuffix(":")
            self.snapshot_dependencies = False
            self.importer = None
            self.direct_block = False
            self.pending = None
            return
        if self.section in {"packages", "snapshots"}:
            self.package_line(stripped, indent)
        elif self.section in {"dependencies", "devDependencies", "optionalDependencies"}:
            self.direct_line(stripped, indent, 2, budget)
        elif self.section == "importers":
            if indent == 2 and stripped.endswith(":"):
                self.importer = stripped[:-1].strip('"').strip("'")
                self.direct_block = False
                self.pending = None
            elif self.importer in {".", "default"}:
                if indent == 4 and stripped.endswith(":"):
                    self.direct_block = "dependencies" in stripped.removesuffix(":").lower()
                    self.pending = None
                elif self.direct_block:
                    self.direct_line(stripped, indent, 6, budget)
        budget.entries(len(self.dependencies))

    def package_line(self, stripped: str, indent: int) -> None:
        if indent == 2 and stripped.endswith(":"):
            self.snapshot_dependencies = False
            name, version = _pnpm_entry_name_version(stripped[:-1].strip().strip('"').strip("'"))
            if name is not None and version is not None:
                self.package_versions[name] = version
                self.dependencies[name] = version
            return
        if self.section == "snapshots" and indent == 4 and stripped == "dependencies:":
            self.snapshot_dependencies = True
            return
        if self.section == "snapshots" and indent <= 4:
            self.snapshot_dependencies = False
        if not self.snapshot_dependencies or indent < 6 or ":" not in stripped:
            return
        name, _, value = stripped.partition(":")
        name = name.strip().strip('"').strip("'")
        value = value.strip().strip('"').strip("'")
        version = self.package_versions.get(name) or _exact_dependency_version(value)
        if version is not None:
            self.dependencies[name] = version

    def direct_line(self, stripped: str, indent: int, entry_indent: int, budget: _Budget) -> None:
        if indent == entry_indent and ":" in stripped:
            name, _, value = stripped.partition(":")
            name = name.strip().strip('"').strip("'")
            value = value.strip().strip('"').strip("'")
            budget.entries(len(self.direct) + 1)
            self.pending = len(self.direct)
            self.direct.append((name, (value,)))
        elif self.pending is not None and indent >= entry_indent + 2 and stripped.startswith("version:"):
            name, values = self.direct[self.pending]
            value = stripped.partition(":")[2].strip().strip('"').strip("'")
            self.direct[self.pending] = (name, (*values, value))
            self.pending = None


@dataclass(slots=True)
class _Yarn:
    dependencies: dict[str, str] = field(default_factory=dict)
    selectors: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    versions: dict[str, tuple[str, int]] = field(default_factory=dict)
    ordinal: int = 0

    def line(self, raw: str, stripped: str, budget: _Budget) -> None:
        if not raw.startswith((" ", "\t")):
            selectors: dict[str, None] = {}
            names: dict[str, None] = {}
            for part in _iter_selector_parts(stripped.removesuffix(":")):
                budget.node()
                selector = part.strip().strip('"').strip("'")
                if not selector or selector == "__metadata":
                    continue
                selectors[selector] = None
                name = _yarn_selector_name(selector)
                if name:
                    names[name] = None
                budget.entries(len(selectors))
            self.selectors, self.names = tuple(selectors), tuple(names)
            return
        match = _VERSION_RE.match(stripped) if self.selectors else None
        if match is None:
            return
        version = match.group(1) or match.group(2)
        for name in self.names:
            budget.check_deadline()
            self.dependencies[name] = version
            budget.entries(len(self.dependencies))
        for selector in self.selectors:
            budget.check_deadline()
            self.versions.setdefault(selector, (version, self.ordinal))
            budget.entries(len(self.versions))
        self.ordinal += 1


def _iter_selector_parts(text: str) -> Iterator[str]:
    start = 0
    for separator in re.finditer(",", text):
        yield text[start : separator.start()]
        start = separator.end()
    yield text[start:]


def _iter_lines(text: str) -> Iterator[str]:
    """Match str.splitlines without allocating all line objects before admission."""

    start = 0
    for ending in _LINE_END_RE.finditer(text):
        yield text[start : ending.start()]
        start = ending.end()
    if start < len(text):
        yield text[start:]


def parse_text_lockfile(
    name: str,
    text: str,
    *,
    check_deadline: Callable[[], None],
    max_entries: int,
    max_nodes: int,
    max_depth: int,
) -> TextLockfileEntries:
    budget = _Budget(check_deadline, max_entries, max_nodes, max_depth)
    pnpm, yarn = _Pnpm(), _Yarn()
    gems: dict[str, str] = {}
    in_specs = False
    # Validation and both extraction views share one admitted line iterator.
    for raw in _iter_lines(text):
        check_deadline()
        if "\x00" in raw or ("\t" in raw and name == "pnpm-lock.yaml"):
            raise TextLockfileValidationError("syntax_error")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        budget.validate_line(name, raw, stripped, indent)
        if name == "pnpm-lock.yaml":
            pnpm.line(stripped, indent, budget)
        elif name == "yarn.lock":
            yarn.line(raw, stripped, budget)
        elif indent == 2 and stripped == "specs:":
            in_specs = True
        elif indent == 0 and _HEADING_RE.fullmatch(stripped):
            in_specs = False
        elif in_specs:
            if match := _SPEC_RE.fullmatch(raw.rstrip()):
                gems[match.group(1)] = match.group(2)
                budget.entries(len(gems))
            elif indent == 4:
                # A recognized top-level gem spec cannot be silently omitted
                # after a valid prefix. Nested dependency constraints and other
                # sections remain outside this deliberately bounded grammar.
                raise TextLockfileValidationError("syntax_error")
    check_deadline()
    if budget.bracket_depth != 0:
        raise TextLockfileValidationError("syntax_error")
    if name == "pnpm-lock.yaml":
        return TextLockfileEntries(tuple(pnpm.dependencies.items()), tuple(pnpm.direct))
    if name == "yarn.lock":
        return TextLockfileEntries(
            tuple(yarn.dependencies.items()),
            selector_versions=tuple(
                (selector, version, ordinal) for selector, (version, ordinal) in yarn.versions.items()
            ),
        )
    return TextLockfileEntries(tuple(gems.items()))
