"""Conservative Python call-graph resolution for the Rust I/O ownership gate."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from scripts.ci.rust_io_ownership_symbols import (
    ImportedCallable,
    _import_target_path,
    _repository_module_path,
    require_exact_import,
    resolve_import,
)


class FunctionRecordLike(Protocol):
    """Minimum function-record shape needed by the resolver."""

    path: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


RecordT = TypeVar("RecordT", bound=FunctionRecordLike)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def _local_binding_names(record: FunctionRecordLike) -> frozenset[str]:
    """Return names bound as local values in a function body.

    A direct call such as ``close()`` may invoke a callable stored in a local
    variable rather than a repository helper. Treating every such name as a
    global helper creates false ambiguities and does not improve reachability.
    """

    names: set[str] = set()
    arguments = record.node.args
    for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
        names.add(argument.arg)
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)

    def collect_target(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect_target(item)

    for node in ast.walk(record.node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                collect_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            collect_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    collect_target(item.optional_vars)
        elif isinstance(node, ast.comprehension):
            collect_target(node.target)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return frozenset(names)


def _resolve_exported_symbol(
    root: Path,
    module_path: str,
    name: str,
    seen: set[tuple[str, str]],
) -> str | None:
    """Find the source file defining an exported symbol, following re-exports."""

    identity = (module_path, name)
    if identity in seen:
        return None
    seen.add(identity)
    tree = ast.parse(_read(root / module_path), filename=module_path)
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name:
            return module_path
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom):
            continue
        for alias in item.names:
            if alias.name == "*":
                target = _import_target_path(root, module_path, item)
                if target is not None:
                    resolved = _resolve_exported_symbol(root, target, name, seen)
                    if resolved is not None:
                        return resolved
                continue
            local_name = alias.asname or alias.name
            if local_name != name:
                continue
            target = _import_target_path(root, module_path, item, alias.name)
            if target is None:
                continue
            resolved = _resolve_exported_symbol(root, target, alias.name, seen)
            if resolved is not None:
                return resolved
    return None


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

        def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, _node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, _node: ast.Lambda) -> None:
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
                continue
            for index in range(visible.scope, len(bodies)):
                require_exact_import(bodies[index], parts[0], node if index == visible.scope else None)
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


def imported_symbol_path(root: Path, record: FunctionRecordLike, name: str) -> str | None:
    """Return the repository path imported for a callable at a call site."""

    if "." in name:
        target = _qualified_imported_callable(root, record, name)
        return target.path if target is not None else None
    imports = sorted(_visible_imports(root, record), key=lambda item: (item.scope, item.node.lineno))
    for visible in reversed(imports):
        node = visible.node
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name != "*" and local_name != name:
                    continue
                target = _import_target_path(root, record.path, node, alias.name if alias.name != "*" else None)
                if target is None:
                    continue
                if alias.name == "*":
                    resolved = _resolve_exported_symbol(root, target, name, set())
                    if resolved is not None:
                        return resolved
                else:
                    return _resolve_exported_symbol(root, target, alias.name, set()) or target
        else:
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                if local_name == name:
                    target = _repository_module_path(root, alias.name if alias.asname else local_name)
                    if target is not None:
                        return target
    return None


def resolve_call(
    root: Path,
    record: RecordT,
    name: str,
    records: Mapping[tuple[str, str], list[RecordT]],
) -> RecordT | None:
    """Resolve a call or fail closed when duplicate helpers remain ambiguous."""

    if "." not in name and name in _local_binding_names(record):
        return None
    if "." in name:
        target = _qualified_imported_callable(root, record, name)
        if target is None:
            return None
        exact = [
            candidate
            for values in records.values()
            for candidate in values
            if candidate.path == target.path and candidate.qualname == target.qualname
        ]
        if len(exact) != 1:
            raise RuntimeError(f"ambiguous repository-qualified helper {name!r}: {target}")
        return exact[0]
    imported_path = imported_symbol_path(root, record, name)
    matches = [
        candidate
        for (_path, candidate_name), values in records.items()
        if candidate_name == name
        for candidate in values
    ]
    if not matches:
        return None
    if imported_path is not None:
        imported_matches = [candidate for candidate in matches if candidate.path == imported_path]
        if len(imported_matches) == 1:
            return imported_matches[0]
        if len(imported_matches) > 1:
            matches = imported_matches
    caller_scope = record.qualname.rsplit(".", 1)[0] if "." in record.qualname else ""
    local_scope = [
        candidate
        for candidate in matches
        if candidate.path == record.path
        and (candidate.qualname.rsplit(".", 1)[0] if "." in candidate.qualname else "") == caller_scope
    ]
    if len(local_scope) == 1:
        return local_scope[0]
    if len(local_scope) > 1:
        matches = local_scope
    if len(matches) == 1:
        return matches[0]
    candidates = ", ".join(f"{item.path}:{item.qualname}" for item in matches)
    raise RuntimeError(f"ambiguous helper call {name!r} from {record.path}:{record.qualname}: {candidates}")
