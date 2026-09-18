"""Strict constructor call records for the decision-critical I/O graph.

Only source-visible classes with no repository inheritance are modeled. A generated dataclass
initializer includes all named factory and post-init edges; no input arguments
are used to prune possible calls. Unsupported construction is left unresolved.
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Callable
from pathlib import Path

from scripts.ci.rust_io_ownership_defaults import static_default
from scripts.ci.rust_io_ownership_symbols import _bindings, _known_dataclass, _known_exception_base, _known_typing_final

CONSTRUCTOR = "<constructor>"
_PURE_FACTORIES = frozenset({"dict", "list", "set", "tuple", "frozenset", "str", "bytes", "int", "float", "bool"})
_DYNAMIC_HOOKS = frozenset({"__getattribute__", "__getattr__", "__setattr__", "__delattr__", "__del__"})


def _literal(node: ast.expr) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except (ValueError, TypeError, SyntaxError):
        return False


def _known_field(value: ast.expr, body: list[ast.stmt], class_body: list[ast.stmt]) -> bool:
    head = value.value if isinstance(value, ast.Attribute) else value
    if not isinstance(head, ast.Name) or _bindings(class_body, head.id):
        return False
    if isinstance(value, ast.Name):
        sites = _bindings(body, value.id)
        return (
            len(sites) == 1
            and sites[0][1]
            and isinstance(sites[0][0], ast.ImportFrom)
            and sites[0][0].level == 0
            and sites[0][0].module == "dataclasses"
            and sites[0][0].lineno < value.lineno
            and any(a.name == "field" and (a.asname or a.name) == value.id for a in sites[0][0].names)
        )
    if isinstance(value, ast.Attribute) and value.attr == "field" and isinstance(value.value, ast.Name):
        sites = _bindings(body, value.value.id)
        return (
            len(sites) == 1
            and sites[0][1]
            and isinstance(sites[0][0], ast.Import)
            and sites[0][0].lineno < value.lineno
            and any(a.name == "dataclasses" and (a.asname or a.name) == value.value.id for a in sites[0][0].names)
        )
    return False


def _factory_reference(value: ast.expr, body: list[ast.stmt], class_body: list[ast.stmt]) -> bool:
    # Dataclasses capture the factory object at class definition, unlike a
    # runtime function's global lookup. Refuse later or mutable bindings.
    if not isinstance(value, ast.Name) or _bindings(class_body, value.id):
        return False
    sites = _bindings(body, value.id)
    if not sites:
        return value.id in _PURE_FACTORIES or value.id == "open"
    return (
        len(sites) == 1
        and sites[0][1]
        and isinstance(sites[0][0], (ast.FunctionDef, ast.ClassDef))
        and sites[0][0].lineno < value.lineno
        and (not isinstance(sites[0][0], ast.FunctionDef) or not sites[0][0].decorator_list)
    )


def _field_factory(
    value: ast.expr, body: list[ast.stmt], class_body: list[ast.stmt], literal: Callable[[ast.expr], bool]
) -> tuple[bool, ast.expr | None]:
    if not isinstance(value, ast.Call) or not _known_field(value.func, body, class_body) or value.args:
        return False, None
    seen: set[str] = set()
    factory = None
    for keyword in value.keywords:
        if keyword.arg is None or keyword.arg in seen:
            return False, None
        seen.add(keyword.arg)
        if keyword.arg == "default_factory":
            if not _factory_reference(keyword.value, body, class_body):
                return False, None
            factory = keyword.value
        elif keyword.arg in {"init", "repr", "compare", "kw_only"}:
            if not isinstance(keyword.value, ast.Constant) or type(keyword.value.value) is not bool:
                return False, None
        elif keyword.arg == "hash":
            if not isinstance(keyword.value, ast.Constant) or keyword.value.value not in (True, False, None):
                return False, None
        elif keyword.arg in {"default", "metadata"}:
            if not literal(keyword.value):
                return False, None
        else:
            return False, None
    return not {"default", "default_factory"} <= seen, factory


def _dataclass_init(cls: ast.ClassDef, body: list[ast.stmt]) -> bool | None:
    if len(cls.decorator_list) != 1 or not _known_dataclass(cls.decorator_list[0], body):
        return None
    decorator = cls.decorator_list[0]
    enabled = True
    if isinstance(decorator, ast.Call):
        if decorator.args:
            return None
        seen: set[str] = set()
        for keyword in decorator.keywords:
            if (
                keyword.arg
                not in {
                    "init",
                    "repr",
                    "eq",
                    "order",
                    "unsafe_hash",
                    "frozen",
                    "match_args",
                    "kw_only",
                    "slots",
                    "weakref_slot",
                }
                or keyword.arg in seen
                or not isinstance(keyword.value, ast.Constant)
                or type(keyword.value.value) is not bool
            ):
                return None
            seen.add(keyword.arg)
            if keyword.arg == "init":
                enabled = keyword.value.value
    return enabled


def _new_returns_known_type(method: ast.FunctionDef, body: list[ast.stmt]) -> bool:
    # type.__call__ may initialize a different returned subclass. Only model
    # a same-class object allocation (or no instance) without inferring type.
    positional = (*method.args.posonlyargs, *method.args.args)
    if not positional:
        return False
    receiver = positional[0].arg
    parameters = (*positional, *method.args.kwonlyargs, method.args.vararg, method.args.kwarg)
    if (
        _bindings(body, "object")
        or _bindings(method.body, "object")
        or _bindings(method.body, receiver)
        or any(item is not None and item.arg == "object" for item in parameters)
    ):
        return False
    for node in ast.walk(method):
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return False
        if not isinstance(node, ast.Return):
            continue
        value = node.value
        if value is None or (isinstance(value, ast.Constant) and value.value is None):
            continue
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id == "object"
            and value.func.attr == "__new__"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == receiver
        ):
            return False
    return True


def constructor_node(
    cls: ast.ClassDef, module_body: list[ast.stmt], *, root: Path | None = None, module_path: str | None = None
) -> ast.FunctionDef | None:
    """Return a strict aggregate of actual construction calls, never an I/O waiver."""

    def literal(value: ast.expr) -> bool:
        return _literal(value) or static_default(value, module_body, cls.body, root=root, module_path=module_path)

    exception_base = _known_exception_base(cls, module_body)
    if (cls.bases and not exception_base) or cls.keywords:
        return None
    markers = [d for d in cls.decorator_list if _known_typing_final(d, module_body, root)]
    if len(markers) > 1:
        return None
    decorated = copy.copy(cls)
    decorated.decorator_list = [d for d in cls.decorator_list if d not in markers]
    is_dataclass = bool(decorated.decorator_list)
    dataclass_init = _dataclass_init(decorated, module_body) if is_dataclass else False
    if is_dataclass and dataclass_init is None:
        return None
    methods: dict[str, ast.FunctionDef] = {}
    factories: list[ast.expr] = []
    fields: set[str] = set()
    for item in cls.body:
        if isinstance(item, ast.FunctionDef):
            if item.name in methods or item.name in fields or item.name in _DYNAMIC_HOOKS:
                return None
            methods[item.name] = item
            if item.name in {"__new__", "__init__", "__post_init__"} and item.decorator_list:
                return None
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            name = item.target.id
            if name in fields or name in methods or len(_bindings(cls.body, name)) != 1:
                return None
            fields.add(name)
            if item.value is not None and not literal(item.value):
                if not is_dataclass:
                    return None
                valid, factory = _field_factory(item.value, module_body, cls.body, literal)
                if not valid:
                    return None
                if factory is not None:
                    factories.append(factory)
        elif isinstance(item, ast.Assign):
            if not literal(item.value) or any(not isinstance(t, ast.Name) for t in item.targets):
                return None
            for target in item.targets:
                assert isinstance(target, ast.Name)
                if target.id in fields or target.id in methods or len(_bindings(cls.body, target.id)) != 1:
                    return None
                fields.add(target.id)
        elif isinstance(item, ast.Pass) or (
            isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
        ):
            continue
        else:
            return None
    if "__new__" in methods and (exception_base or not _new_returns_known_type(methods["__new__"], module_body)):
        return None
    calls: list[ast.stmt] = []

    def append_call(value: ast.expr, location: ast.AST) -> None:
        call = ast.Expr(value=ast.Call(func=copy.deepcopy(value), args=[], keywords=[]))
        calls.append(ast.copy_location(call, location))

    for hook in ("__new__", "__init__"):
        if hook in methods:
            append_call(
                ast.Attribute(value=ast.Name(id=cls.name, ctx=ast.Load()), attr=hook, ctx=ast.Load()), methods[hook]
            )
    if dataclass_init and "__init__" not in methods:
        for factory in factories:
            append_call(factory, factory)
        if "__post_init__" in methods:
            append_call(
                ast.Attribute(value=ast.Name(id=cls.name, ctx=ast.Load()), attr="__post_init__", ctx=ast.Load()),
                methods["__post_init__"],
            )
    result = ast.FunctionDef(
        name=CONSTRUCTOR,
        args=ast.arguments(
            posonlyargs=[], args=[], vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]
        ),
        body=calls or [ast.Pass()],
        decorator_list=[],
    )
    return ast.fix_missing_locations(ast.copy_location(result, cls))
