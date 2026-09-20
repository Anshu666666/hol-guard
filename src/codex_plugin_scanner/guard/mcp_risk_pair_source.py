"""Compile-only declaration provenance for the private MCP risk-pair guard.

This module never executes a declaration read from an application module.
A declaration match is one admission condition, not a purity certificate:
callers must separately admit every reached provider, descriptor and value.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import sys
from types import CodeType, FunctionType, ModuleType
from typing import cast


class UnsupportedDeclaration(ValueError):
    """The installed source or live declaration has an unsupported shape."""


def _constant_key(value: object) -> object:
    kind = type(value)
    if kind is CodeType:
        return ("code", _code_key(cast(CodeType, value)))
    if kind is tuple:
        return ("tuple", tuple(_constant_key(item) for item in cast(tuple[object, ...], value)))
    if kind is frozenset:
        return ("frozenset", frozenset(_constant_key(item) for item in cast(frozenset[object], value)))
    if kind is float or kind is complex:
        # Distinguish signed zero and NaN spellings without caller operators.
        return (kind.__name__, repr(value))
    if value is None or value is Ellipsis or (kind is str or kind is bytes or kind is int or kind is bool):
        return (kind.__name__, value)
    raise UnsupportedDeclaration("unsupported_code_constant")


def _code_key(code: CodeType) -> tuple[object, ...]:
    return (
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        tuple(_constant_key(value) for value in code.co_consts),
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        getattr(code, "co_exceptiontable", b""),
    )


def plain_constant(value: object) -> object:
    """Copy an immutable default; unknown objects must not run comparisons."""
    kind = type(value)
    if value is None or (kind is str or kind is bytes or kind is int or kind is bool):
        return (kind.__name__, value)
    if kind is float:
        return ("float", cast(float, value).hex())
    if kind is tuple:
        return ("tuple", tuple(plain_constant(item) for item in cast(tuple[object, ...], value)))
    raise UnsupportedDeclaration("unsupported_default")


def _literal_default(node: ast.expr) -> object:
    try:
        return plain_constant(ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, RecursionError) as error:
        raise UnsupportedDeclaration("nonliteral_default") from error


def _function_nodes(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    ambiguous: set[str] = set()

    def walk(node: ast.AST, parents: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, (*parents, child.name))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = ".".join((*parents, child.name))
                if name in result:
                    ambiguous.add(name)
                result[name] = child
                walk(child, (*parents, child.name, "<locals>"))
            else:
                walk(child, parents)

    walk(tree, ())
    return {name: node for name, node in result.items() if name not in ambiguous}


def _declaration_code(module_code: CodeType, names: tuple[str, ...]) -> CodeType:
    current = module_code
    for name in names:
        if name == "<locals>":
            continue
        matches = [
            value for value in current.co_consts if type(value) is CodeType and value.co_name == name
        ]
        if len(matches) != 1:
            raise UnsupportedDeclaration("ambiguous_compiled_declaration")
        current = cast(CodeType, matches[0])
    return current


class SourceDeclarations:
    """Immutable compiled expectations; no retained live application functions."""

    __slots__ = ("_codes", "_defaults", "_module_name")

    def __init__(self, module_name: str, source: bytes, expected_sha256: str) -> None:
        if type(source) is not bytes or hashlib.sha256(source).hexdigest() != expected_sha256:
            raise UnsupportedDeclaration("source_digest_mismatch")
        try:
            tree = ast.parse(source, filename=module_name)
            compiled = compile(source, module_name, "exec", dont_inherit=True, optimize=sys.flags.optimize)
            declarations = _function_nodes(tree)
            codes: dict[str, tuple[object, ...]] = {}
            defaults: dict[str, tuple[object, tuple[tuple[str, object], ...]] | None] = {}
            for name, node in declarations.items():
                codes[name] = _code_key(_declaration_code(compiled, tuple(name.split("."))))
                try:
                    positional = tuple(_literal_default(value) for value in node.args.defaults)
                    keyword = tuple(
                        (argument.arg, _literal_default(value))
                        for argument, value in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
                        if value is not None
                    )
                    defaults[name] = (positional, keyword)
                except UnsupportedDeclaration:
                    defaults[name] = None
        except (SyntaxError, ValueError, TypeError, RecursionError) as error:
            raise UnsupportedDeclaration("source_declaration_unavailable") from error
        self._module_name = module_name
        self._codes = tuple(codes.items())
        self._defaults = tuple(defaults.items())

    def matches(
        self,
        function: object,
        module: ModuleType,
        qualified_name: str,
        *,
        closure: tuple[object, ...] = (),
    ) -> bool:
        """Match code, literal defaults, original globals and exact closure cells.

        The caller must prove each supplied closure object separately. Passing a
        live opaque closure value back as its expectation is not admission.
        """
        if (
            type(function) is not FunctionType
            or type(module) is not ModuleType
            or type(qualified_name) is not str
            or type(closure) is not tuple
        ):
            return False
        candidate = cast(FunctionType, function)
        namespace = ModuleType.__getattribute__(module, "__dict__")
        if any(type(key) is not str for key in namespace):
            return False
        module_name = namespace.get("__name__")
        if type(module_name) is not str or module_name != self._module_name:
            return False
        if candidate.__globals__ is not namespace:
            return False
        if candidate.__builtins__ is not vars(builtins):
            return False
        expected_code = dict(self._codes).get(qualified_name)
        expected_defaults = dict(self._defaults).get(qualified_name)
        if expected_code is None or expected_defaults is None:
            return False
        try:
            if _code_key(candidate.__code__) != expected_code:
                return False
            raw_defaults = candidate.__defaults__
            if raw_defaults is not None and type(raw_defaults) is not tuple:
                return False
            actual_defaults = tuple(plain_constant(value) for value in raw_defaults or ())
            raw_keywords = candidate.__kwdefaults__
            if raw_keywords is not None and type(raw_keywords) is not dict:
                return False
            actual_keywords = tuple(
                (key, plain_constant(value)) for key, value in (raw_keywords or {}).items()
            )
            if any(type(key) is not str for key, _ in actual_keywords):
                return False
            if (actual_defaults, actual_keywords) != expected_defaults:
                return False
            cells = candidate.__closure__ or ()
            if len(cells) != len(closure):
                return False
            return all(cell.cell_contents is expected for cell, expected in zip(cells, closure, strict=True))
        except (UnsupportedDeclaration, ValueError, TypeError, RecursionError):
            return False
