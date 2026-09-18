"""Prove constructor defaults from bounded literal source, without importing it."""

from __future__ import annotations

import ast
from pathlib import Path

from scripts.ci.rust_io_ownership_symbols import (
    _bindings,
    _import_target_path,
    _module_file,
    _read,
    _repository_module_path,
)


def static_default(
    value: ast.expr,
    module_body: list[ast.stmt],
    class_body: list[ast.stmt],
    *,
    root: Path | None,
    module_path: str | None,
) -> bool:
    """Reject dynamic/descriptor values; prove only literal expression graphs."""
    budget = 128
    modules: dict[str, list[ast.stmt]] = {}
    if module_path is not None:
        modules[module_path] = module_body

    def body_for(path: str) -> list[ast.stmt] | None:
        if root is None:
            return None
        if path not in modules:
            modules[path] = ast.parse(_read(root / path), filename=path).body
        return modules[path]

    def reference(
        parts: tuple[str, ...],
        body: list[ast.stmt],
        path: str | None,
        before: int,
        seen: frozenset[tuple[str | None, tuple[str, ...]]],
    ) -> bool:
        nonlocal budget
        budget -= 1
        if budget < 0:
            return False
        identity = (path, parts)
        if not parts or identity in seen:
            return False
        seen = seen | {identity}
        sites = _bindings(body, parts[0])
        if not sites:
            if root is not None and path is not None and Path(path).name == "__init__.py" and len(parts) > 1:
                child = _module_file(root, Path(path).parent / parts[0])
                child_body = body_for(child) if child is not None else None
                if child is not None and child_body is not None:
                    return reference(parts[1:], child_body, child, 10**12, seen)
            return False
        if len(sites) != 1:
            return False
        node, direct = sites[0]
        if getattr(node, "lineno", before) >= before:
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if not direct or root is None or path is None:
                return False
            alias = next(
                (
                    a
                    for a in node.names
                    if (a.asname or (a.name.split(".")[0] if isinstance(node, ast.Import) else a.name)) == parts[0]
                ),
                None,
            )
            if alias is None:
                return False
            if isinstance(node, ast.ImportFrom):
                target = _import_target_path(root, path, node, alias.name)
                suffix = ((alias.name,) if node.module else ()) + parts[1:]
            else:
                target = _repository_module_path(root, alias.name)
                prefix = tuple(alias.name.split("."))[1:] if alias.asname is None else ()
                if parts[1 : 1 + len(prefix)] != prefix:
                    return False
                suffix = parts[1 + len(prefix) :]
            target_body = body_for(target) if target is not None else None
            return (
                target is not None and target_body is not None and reference(suffix, target_body, target, 10**12, seen)
            )
        if len(parts) != 1:
            return False
        for statement in body:
            if isinstance(statement, ast.AnnAssign) and statement.target is node and statement.value is not None:
                return prove(statement.value, body, path, (), seen)
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and statement.targets[0] is node:
                return prove(statement.value, body, path, (), seen)
        return False

    def prove(
        node: ast.expr,
        body: list[ast.stmt],
        path: str | None,
        local: list[ast.stmt] | tuple[()],
        seen: frozenset[tuple[str | None, tuple[str, ...]]],
    ) -> bool:
        nonlocal budget
        budget -= 1
        if budget < 0:
            return False
        if isinstance(node, ast.Constant):
            return type(node.value) in {str, bytes, int, float, complex, bool, type(None), type(Ellipsis)}
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(prove(item, body, path, local, seen) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                key is not None and prove(key, body, path, local, seen) and prove(item, body, path, local, seen)
                for key, item in zip(node.keys, node.values, strict=True)
            )
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert, ast.Not)):
            return prove(node.operand, body, path, local, seen)
        if isinstance(node, ast.BinOp) and isinstance(
            node.op,
            (
                ast.Add,
                ast.Sub,
                ast.Mult,
                ast.FloorDiv,
                ast.Div,
                ast.Mod,
                ast.BitAnd,
                ast.BitOr,
                ast.BitXor,
                ast.LShift,
                ast.RShift,
            ),
        ):
            return prove(node.left, body, path, local, seen) and prove(node.right, body, path, local, seen)
        if isinstance(node, ast.Call):
            return (
                isinstance(node.func, ast.Name)
                and node.func.id == "frozenset"
                and not _bindings(list(local), "frozenset")
                and not _bindings(body, "frozenset")
                and not node.keywords
                and len(node.args) <= 1
                and all(prove(item, body, path, local, seen) for item in node.args)
            )
        parts: list[str] = []
        head: ast.expr = node
        while isinstance(head, ast.Attribute):
            parts.insert(0, head.attr)
            head = head.value
        if not isinstance(head, ast.Name) or _bindings(list(local), head.id):
            return False
        return reference((head.id, *parts), body, path, node.lineno, seen)

    return prove(value, module_body, module_path, class_body, frozenset())
