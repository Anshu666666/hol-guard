"""Conservative Python call-graph resolution for the Rust I/O ownership gate."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from scripts.ci.rust_io_ownership_symbols import (
    ImportedCallable,
    _bindings,
    _import_target_path,
    _repository_module_path,
    require_exact_import,
    resolve_import,
    resolve_member,
)


class FunctionRecordLike(Protocol):
    """Minimum function-record shape needed by the resolver."""

    @property
    def path(self) -> str: ...

    @property
    def qualname(self) -> str: ...

    @property
    def node(self) -> ast.FunctionDef | ast.AsyncFunctionDef: ...


RecordT = TypeVar("RecordT", bound=FunctionRecordLike)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


@dataclass(frozen=True, slots=True)
class _VisibleImport:
    node: ast.Import | ast.ImportFrom
    scope: int


def _function_scopes(tree: ast.Module, qualname: str) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    """Return enclosing function scopes for a qualified function name."""

    def visit(
        body: list[ast.stmt],
        prefix: str,
        enclosing: tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...],
    ) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...] | None:
        for item in body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                current = f"{prefix}.{item.name}" if prefix else item.name
                if current == qualname:
                    return (*enclosing, item)
                if qualname.startswith(f"{current}."):
                    nested = visit(item.body, current, (*enclosing, item))
                    if nested is not None:
                        return nested
            elif isinstance(item, ast.ClassDef):
                current = f"{prefix}.{item.name}" if prefix else item.name
                if qualname.startswith(f"{current}."):
                    nested = visit(item.body, current, enclosing)
                    if nested is not None:
                        return nested
        return None

    return visit(tree.body, "", ()) or ()


def _scope_imports(body: list[ast.stmt]) -> tuple[ast.Import | ast.ImportFrom, ...]:
    """Collect imports in one lexical scope, excluding nested scopes."""

    imports: list[ast.Import | ast.ImportFrom] = []

    class Collector(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            imports.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            imports.append(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    collector = Collector()
    for statement in body:
        collector.visit(statement)
    return tuple(imports)


def _visible_imports(root: Path, record: FunctionRecordLike) -> tuple[_VisibleImport, ...]:
    """Return module and enclosing-function imports visible to ``record``."""

    tree = ast.parse(_read(root / record.path), filename=record.path)
    visible = [_VisibleImport(node, 0) for node in _scope_imports(tree.body)]
    for scope, function in enumerate(_function_scopes(tree, record.qualname), start=1):
        visible.extend(_VisibleImport(node, scope) for node in _scope_imports(function.body))
    return tuple(visible)


def _qualified_imported_callable(root: Path, record: FunctionRecordLike, name: str) -> ImportedCallable | None:
    parts = tuple(name.split("."))
    if len(parts) < 2 or any(not part for part in parts):
        return None
    tree = ast.parse(_read(root / record.path), filename=record.path)
    scopes = _function_scopes(tree, record.qualname)
    if record.qualname.endswith(".<constructor>") and parts[:-1] == tuple(record.qualname.split(".")[:-1]):
        return resolve_member(root, record.path, parts)
    bodies = [tree.body, *(scope.body for scope in scopes)]
    imports = sorted(_visible_imports(root, record), key=lambda item: (item.scope, item.node.lineno))
    for visible in reversed(imports):
        node = visible.node
        for alias in node.names:
            local_name = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
            if local_name != parts[0]:
                continue
            target = (
                _import_target_path(root, record.path, node, alias.name)
                if isinstance(node, ast.ImportFrom)
                else _repository_module_path(root, alias.name)
            )
            if target is None:
                if isinstance(node, ast.ImportFrom) and node.level:
                    raise RuntimeError(f"unresolved repository import {name!r}")
                continue
            for index in range(visible.scope, len(bodies)):
                require_exact_import(
                    bodies[index],
                    parts[0],
                    node if index == visible.scope else None,
                    allow_conditional_local=index > 0,
                )
            for scope in scopes[max(visible.scope - 1, 0) :]:
                arguments = scope.args
                names = [arg.arg for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)]
                names.extend(arg.arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None)
                if parts[0] in names:
                    raise RuntimeError(f"ambiguous repository-qualified parameter binding {parts[0]!r}")
            result = resolve_import(root, record.path, node, alias, parts[1:])
            if result is None:
                raise RuntimeError(
                    f"unresolved repository-qualified helper call {name!r} from {record.path}:{record.qualname}"
                )
            return result
    return None


def _bare_imported_callable(root: Path, record: FunctionRecordLike, name: str) -> ImportedCallable | None:
    """Resolve one bare name using function closures then the module, never classes."""
    tree = ast.parse(_read(root / record.path), filename=record.path)
    scopes = _function_scopes(tree, record.qualname)

    def qualified_name(body: list[ast.stmt], target: ast.AST, prefix: str = "") -> str | None:
        for item in body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                current = f"{prefix}.{item.name}" if prefix else item.name
                if item is target:
                    return current
                nested = qualified_name(item.body, target, current)
                if nested is not None:
                    return nested
        return None

    for scope in (*reversed(scopes), tree):
        sites = _bindings(scope.body, name)
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = scope.args
            parameters = (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
            if any(arg is not None and arg.arg == name for arg in parameters):
                if sites:
                    raise RuntimeError(f"ambiguous lexical parameter binding {name!r}")
                return None
        if not sites:
            continue
        if len(sites) != 1:
            raise RuntimeError(f"ambiguous lexical helper binding {name!r}")
        node, direct = sites[0]
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            raise RuntimeError(f"unresolved explicit lexical declaration {name!r}")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not direct:
                raise RuntimeError(f"ambiguous conditional lexical helper {name!r}")
            qualname = qualified_name(tree.body, node)
            if qualname is None:
                raise RuntimeError(f"unresolved lexical helper {name!r}")
            return ImportedCallable(record.path, qualname)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # One local import makes this name local throughout the function.
            # If its branch does not execute, lookup is unbound, never an outer
            # callable. Retain the possible exact edge instead of dropping it.
            local = isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            if (not direct and not local) or any(alias.name == "*" for alias in node.names):
                raise RuntimeError(f"ambiguous lexical import binding {name!r}")
            alias = next(
                a
                for a in node.names
                if (a.asname or (a.name.split(".")[0] if isinstance(node, ast.Import) else a.name)) == name
            )
            path = (
                _import_target_path(root, record.path, node, alias.name)
                if isinstance(node, ast.ImportFrom)
                else _repository_module_path(root, alias.name)
            )
            if path is None:
                if isinstance(node, ast.ImportFrom) and node.level:
                    raise RuntimeError(f"unresolved repository import {name!r}")
                return None
            result = resolve_import(root, record.path, node, alias, ())
            if result is None:
                raise RuntimeError(f"unresolved repository lexical helper {name!r}")
            return result
        if isinstance(node, ast.ClassDef):
            target = resolve_member(root, record.path, (name,)) if scope is tree and direct else None
            if target is None:
                raise RuntimeError(f"unresolved lexical constructor {name!r}")
            return target
        # A value binding shadows outer helpers. It is not a static repository callable.
        return None
    return None


def _receiver_callable(root: Path, record: FunctionRecordLike, name: str) -> ImportedCallable | None:
    """Keep explicit self/cls edges separate from Python bare-name lookup."""
    tree = ast.parse(_read(root / record.path), filename=record.path)

    def containing_class(
        body: list[ast.stmt], prefix: str = "", enclosing: tuple[str, ast.ClassDef] | None = None
    ) -> tuple[str, ast.ClassDef] | None:
        for item in body:
            if not isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            current = f"{prefix}.{item.name}" if prefix else item.name
            if current == record.qualname:
                return enclosing
            if record.qualname.startswith(f"{current}."):
                return containing_class(
                    item.body, current, (current, item) if isinstance(item, ast.ClassDef) else enclosing
                )
        return None

    enclosing = containing_class(tree.body)
    if enclosing is None:
        return None
    class_name, cls = enclosing
    member = name.split(".")[1]
    sites = _bindings(cls.body, member)
    if not sites:
        if cls.bases:
            raise RuntimeError(f"unresolved inherited receiver helper {name!r}")
        return None
    if len(sites) != 1 or not sites[0][1] or not isinstance(sites[0][0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise RuntimeError(f"ambiguous receiver helper {name!r}")
    return ImportedCallable(record.path, f"{class_name}.{member}")


def _callable_target(root: Path, record: FunctionRecordLike, name: str) -> ImportedCallable | None:
    parts = name.split(".")
    if len(parts) == 2 and parts[0] in {"self", "cls"}:
        return _receiver_callable(root, record, name)
    if len(parts) > 1:
        return _qualified_imported_callable(root, record, name)
    return _bare_imported_callable(root, record, name)


def imported_symbol_path(root: Path, record: FunctionRecordLike, name: str) -> str | None:
    """Return the exact lexical or repository-qualified callable source path."""
    target = _callable_target(root, record, name)
    return target.path if target is not None else None


def resolve_call(
    root: Path,
    record: RecordT,
    name: str,
    records: Mapping[tuple[str, str], list[RecordT]],
) -> RecordT | None:
    """Resolve an exact visible callable, never an unrelated same-named helper."""
    target = _callable_target(root, record, name)
    if target is None:
        return None
    exact = [
        candidate
        for values in records.values()
        for candidate in values
        if candidate.path == target.path and candidate.qualname == target.qualname
    ]
    if len(exact) != 1:
        raise RuntimeError(f"ambiguous repository helper {name!r}: {target}")
    return exact[0]
