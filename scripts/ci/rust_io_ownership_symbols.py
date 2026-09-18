"""Strict repository-qualified callable identities for the I/O ownership gate."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ImportedCallable:
    path: str
    qualname: str


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def _module_file(root: Path, target: Path) -> str | None:
    candidate = root / target
    if candidate.is_file() and candidate.suffix == ".py":
        return target.as_posix()
    init_file = candidate / "__init__.py"
    if init_file.is_file():
        return init_file.relative_to(root).as_posix()
    module_file = candidate.with_suffix(".py")
    if module_file.is_file():
        return module_file.relative_to(root).as_posix()
    return None


def _import_target_path(
    root: Path, source_path: str, node: ast.ImportFrom, imported_name: str | None = None
) -> str | None:
    if node.level:
        base = (root / source_path).parent
        for _ in range(node.level - 1):
            base = base.parent
        parts = tuple((node.module or "").split(".")) if node.module else ()
    else:
        if not node.module:
            return None
        parts = tuple(node.module.split("."))
        base = root / "src"
    if not node.module and imported_name:
        parts = (imported_name,)
    try:
        target = (base / Path(*parts)).relative_to(root)
    except ValueError:
        return None
    return _module_file(root, target)


def _repository_module_path(root: Path, module_name: str) -> str | None:
    parts = tuple(part for part in module_name.split(".") if part)
    if not parts:
        return None
    for base in (root / "src", root):
        resolved = _module_file(root, base.joinpath(*parts).relative_to(root))
        if resolved is not None:
            return resolved
    return None


def _bindings(body: list[ast.stmt], name: str) -> list[tuple[ast.AST, bool]]:
    """Find explicit binding/mutation sites, without entering nested scopes."""
    found: list[tuple[ast.AST, bool]] = []

    class Visitor(ast.NodeVisitor):
        direct = True

        def visit(self, node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == name:
                    found.append((node, self.direct))
                return
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    binding = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                    if binding == name or alias.name == "*":
                        found.append((node, self.direct and alias.name != "*"))
                return
            if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                target = node
                while isinstance(target, ast.Attribute):
                    target = target.value
                if isinstance(target, ast.Name) and target.id == name:
                    found.append((node, False))
                return
            if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
                found.append((node, False))
            if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name == name:
                found.append((node, False))
            if isinstance(node, ast.MatchMapping) and node.rest == name:
                found.append((node, False))
            previous = self.direct
            self.direct = False
            super().visit(node)
            self.direct = previous

    visitor = Visitor()
    for item in body:
        visitor.visit(item)
    # A later unconditional explicit definition/import replaces values from
    # preceding stars. No other rebinding or later wildcard is made exact.
    if (
        len(found) > 1
        and found[-1][1]
        and all(
            isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names)
            for node, _direct in found[:-1]
        )
    ):
        return found[-1:]
    return found


def require_exact_import(body: list[ast.stmt], name: str, node: ast.AST | None) -> None:
    sites = _bindings(body, name)
    if node is None:
        valid = not sites
    else:
        valid = (
            len(sites) == 1
            and sites[0][1]
            and type(sites[0][0]) is type(node)
            and getattr(sites[0][0], "lineno", None) == getattr(node, "lineno", None)
        )
    if not valid:
        raise RuntimeError(f"ambiguous repository-qualified import binding {name!r}")


def _known_dataclass(decorator: ast.expr, body: list[ast.stmt]) -> bool:
    value = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(value, ast.Name):
        bindings = _bindings(body, value.id)
        return (
            len(bindings) == 1
            and bindings[0][1]
            and isinstance(bindings[0][0], ast.ImportFrom)
            and bindings[0][0].lineno < decorator.lineno
            and (
                bindings[0][0].module == "dataclasses"
                and bindings[0][0].level == 0
                and any(
                    alias.name == "dataclass" and (alias.asname or alias.name) == value.id
                    for alias in bindings[0][0].names
                )
            )
        )
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.attr == "dataclass":
        bindings = _bindings(body, value.value.id)
        return (
            len(bindings) == 1
            and bindings[0][1]
            and isinstance(bindings[0][0], ast.Import)
            and bindings[0][0].lineno < decorator.lineno
            and (
                any(
                    alias.name == "dataclasses" and (alias.asname or alias.name) == value.value.id
                    for alias in bindings[0][0].names
                )
            )
        )
    return False


def _class_method(
    module_path: str, cls: ast.ClassDef, parts: tuple[str, ...], module_body: list[ast.stmt]
) -> ImportedCallable | None:
    if (
        len(parts) != 1
        or cls.bases
        or cls.keywords
        or any(not _known_dataclass(d, module_body) for d in cls.decorator_list)
    ):
        return None
    sites = _bindings(cls.body, parts[0])
    if len(sites) != 1 or not sites[0][1]:
        return None
    method = sites[0][0]
    if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for decorator in method.decorator_list:
        if not isinstance(decorator, ast.Name) or decorator.id not in {"classmethod", "staticmethod"}:
            return None
        if _bindings(module_body, decorator.id) or _bindings(cls.body, decorator.id):
            return None
    return ImportedCallable(module_path, f"{cls.name}.{method.name}")


def resolve_member(
    root: Path, module_path: str, parts: tuple[str, ...], seen: frozenset[tuple[str, tuple[str, ...]]] = frozenset()
) -> ImportedCallable | None:
    """Resolve exact source identity, refusing implicit inheritance and dynamic exports."""
    identity = (module_path, parts)
    if not parts or identity in seen:
        return None
    seen = seen | {identity}
    tree = ast.parse(_read(root / module_path), filename=module_path)
    sites = _bindings(tree.body, parts[0])
    if not sites:
        if Path(module_path).name != "__init__.py" or any(
            isinstance(item, ast.ImportFrom) and any(alias.name == "*" for alias in item.names) for item in tree.body
        ):
            return None
        child = _module_file(root, Path(module_path).parent / parts[0])
        return resolve_member(root, child, parts[1:], seen) if child else None
    if len(sites) != 1 or not sites[0][1]:
        return None
    node = sites[0][0]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ImportedCallable(module_path, node.name) if len(parts) == 1 else None
    if isinstance(node, ast.ClassDef):
        return _class_method(module_path, node, parts[1:], tree.body)
    if isinstance(node, (ast.ImportFrom, ast.Import)):
        alias = next(
            a
            for a in node.names
            if (a.asname or (a.name.split(".")[0] if isinstance(node, ast.Import) else a.name)) == parts[0]
        )
        return resolve_import(root, module_path, node, alias, parts[1:], seen)
    return None


def resolve_import(
    root: Path,
    source_path: str,
    node: ast.Import | ast.ImportFrom,
    alias: ast.alias,
    suffix: tuple[str, ...],
    seen: frozenset[tuple[str, tuple[str, ...]]] = frozenset(),
) -> ImportedCallable | None:
    if isinstance(node, ast.ImportFrom):
        target = _import_target_path(root, source_path, node, alias.name)
        parts = ((alias.name,) if node.module else ()) + suffix
    else:
        target = _repository_module_path(root, alias.name)
        prefix = tuple(alias.name.split("."))[1:] if alias.asname is None else ()
        if suffix[: len(prefix)] != prefix:
            return None
        parts = suffix[len(prefix) :]
    return resolve_member(root, target, parts, seen) if target is not None else None
