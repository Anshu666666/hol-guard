"""Exact optional external imports retain their local fallback callable edges."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from scripts.ci.rust_io_ownership_symbols import _bindings, _import_target_path, _repository_module_path


def lexical_definitions(body: list[ast.stmt]) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
    """Find definitions across statements without entering another lexical scope."""

    def visit(node: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node
        elif not isinstance(node, ast.expr):
            for child in ast.iter_child_nodes(node):
                yield from visit(child)

    for statement in body:
        yield from visit(statement)


def _type_checking_guard(node: ast.If, body: list[ast.stmt]) -> bool:
    if not isinstance(node.test, ast.Name):
        return False
    sites = _bindings(body, node.test.id)
    if len(sites) != 1 or not sites[0][1]:
        return False
    imported = sites[0][0]
    return (
        isinstance(imported, ast.ImportFrom)
        and imported.level == 0
        and imported.module == "typing"
        and imported.lineno < node.lineno
        and any(a.name == "TYPE_CHECKING" and (a.asname or a.name) == node.test.id for a in imported.names)
    )


def _external_import(root: Path, path: str, body: list[ast.stmt], name: str) -> ast.ImportFrom | None:
    sites = _bindings(body, name)
    if len(sites) != 1 or not sites[0][1]:
        return None
    node = sites[0][0]
    if not isinstance(node, ast.ImportFrom) or node.level or not node.module:
        return None
    if any(a.name == "*" for a in node.names):
        return None
    if (
        _import_target_path(root, path, node) is not None
        or _repository_module_path(root, node.module) is not None
        or _repository_module_path(root, node.module.split(".")[0]) is not None
    ):
        return None
    return node


def optional_external_class(root: Path, path: str, tree: ast.Module, name: str) -> ast.ClassDef | None:
    """Recognize a verified import/ModuleNotFoundError fallback, not arbitrary branches."""
    for statement in tree.body:
        guard = statement if isinstance(statement, ast.If) else None
        if guard is not None:
            if not _type_checking_guard(guard, tree.body) or len(guard.orelse) != 1:
                continue
            candidate = guard.orelse[0]
        else:
            candidate = statement
        if (
            not isinstance(candidate, ast.Try)
            or len(candidate.handlers) != 1
            or candidate.orelse
            or candidate.finalbody
        ):
            continue
        handler = candidate.handlers[0]
        if (
            not isinstance(handler.type, ast.Name)
            or handler.type.id != "ModuleNotFoundError"
            or handler.name is not None
            or _bindings(tree.body, handler.type.id)
        ):
            continue
        imported = _external_import(root, path, candidate.body, name)
        fallback = _bindings(handler.body, name)
        if imported is None or len(fallback) != 1 or not fallback[0][1] or not isinstance(fallback[0][0], ast.ClassDef):
            continue
        cls = fallback[0][0]
        accepted: list[ast.AST] = [imported, cls]
        if guard is not None:
            typing_import = _external_import(root, path, guard.body, name)
            actual_alias = next(a.name for a in imported.names if (a.asname or a.name) == name)
            if (
                typing_import is None
                or typing_import.module != imported.module
                or not any(a.name == actual_alias and (a.asname or a.name) == name for a in typing_import.names)
            ):
                continue
            accepted.append(typing_import)
        sites = _bindings(tree.body, name)
        if len(sites) == len(accepted) and {id(node) for node, _direct in sites} == {id(node) for node in accepted}:
            return cls
    return None


def optional_external_classes(root: Path, path: str, tree: ast.Module) -> Iterator[ast.ClassDef]:
    for node in lexical_definitions(tree.body):
        if (
            isinstance(node, ast.ClassDef)
            and node not in tree.body
            and optional_external_class(root, path, tree, node.name) is node
        ):
            yield node
