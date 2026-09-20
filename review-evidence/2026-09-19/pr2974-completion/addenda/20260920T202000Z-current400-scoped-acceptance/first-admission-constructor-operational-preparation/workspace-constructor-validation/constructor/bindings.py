"""Hash-bound source and actual code-object call-site registry."""

from __future__ import annotations

import hashlib
import importlib
import json
import types
from pathlib import Path
from typing import Any

TARGETS = frozenset(
    {
        "scripts.native_slo_workspace_lifecycle_service:replace_service",
        "scripts.native_slo_workspace_lifecycle:run_lifecycle_cell",
        "scripts.native_slo_workspace_lifecycle:run_lifecycle_cell.<locals>.prepare_service",
        "scripts.native_slo_workspace_startup:prepare_owned_publisher.<locals>.observed",
        "codex_plugin_scanner.guard.daemon.server_service:GuardDaemonServer.__init__",
        "codex_plugin_scanner.guard.daemon.server_http:_GuardDaemonHTTPServer.__init__",
        "codex_plugin_scanner.guard.daemon.server_http:_GuardDaemonHTTPServer._initialize_request_services",
        "codex_plugin_scanner.guard.daemon.hook_worker:HookWorker.__init__",
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher:NativePolicySnapshotPublisher.wait_until_ready",
    }
)


CODE_FIELDS = (
    "co_argcount",
    "co_posonlyargcount",
    "co_kwonlyargcount",
    "co_nlocals",
    "co_stacksize",
    "co_flags",
    "co_code",
    "co_consts",
    "co_names",
    "co_varnames",
    "co_filename",
    "co_name",
    "co_qualname",
    "co_firstlineno",
    "co_linetable",
    "co_exceptiontable",
    "co_freevars",
    "co_cellvars",
)


def code_image(code: types.CodeType) -> tuple[Any, ...]:
    # Marshal reference/interning flags can differ for equal imported and freshly
    # compiled code. Compare every stored semantic/position field instead.
    return tuple(constant_image(getattr(code, name)) for name in CODE_FIELDS)


def constant_image(value: Any) -> Any:
    kind = type(value)
    if kind is types.CodeType:
        return ("code", code_image(value))
    if value is None or value is Ellipsis:
        return ("none" if value is None else "ellipsis",)
    if kind in {bool, int, str, bytes}:
        return (kind.__name__, value)
    if kind is float:
        return ("float", value.hex())
    if kind is complex:
        return ("complex", value.real.hex(), value.imag.hex())
    if kind is tuple:
        return ("tuple", tuple(constant_image(item) for item in value))
    if kind is frozenset:
        return ("frozenset", tuple(sorted((constant_image(item) for item in value), key=repr)))
    raise RuntimeError("constructor_code_constant_shape")


def compiled_codes(code: types.CodeType) -> dict[str, tuple[Any, ...]]:
    result = {code.co_qualname: code_image(code)}
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            result.update(compiled_codes(item))
    return result


class Registry:
    def __init__(self, source: Path, manifest: Path) -> None:
        self.codes: dict[int, tuple[types.CodeType, str]] = {}
        self.sites: dict[tuple[types.CodeType, int], str] = {}
        self.expected: dict[str, dict[str, tuple[Any, ...]]] = {}
        entries = json.loads(manifest.read_text())
        for row in entries:
            relative = row["path"]
            module_path = relative.removeprefix("src/").removesuffix(".py").replace("/", ".")
            module = importlib.import_module(module_path)
            if type(module.__file__) is not str:
                raise RuntimeError("predicate_module_file")
            path = Path(module.__file__).resolve(strict=True)
            expected = source / relative if not relative.startswith("src/") else path
            # Installed package paths differ; exact bytes are still mandatory.
            raw = path.read_bytes()
            if path != expected or len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise RuntimeError("predicate_source_identity")
            self.expected[module.__name__] = compiled_codes(
                compile(raw, str(path), "exec", dont_inherit=True, optimize=0)
            )
            for value in vars(module).values():
                if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
                    self.add_function(value, module.__name__)
                elif isinstance(value, type) and value.__module__ == module.__name__:
                    for child in vars(value).values():
                        if isinstance(child, (staticmethod, classmethod)):
                            child = child.__func__
                        if isinstance(child, property):
                            child = child.fget
                        if isinstance(child, types.FunctionType) and child.__module__ == module.__name__:
                            self.add_function(child, module.__name__)
        if {label for _code, label in self.codes.values()} != TARGETS:
            raise RuntimeError("constructor_registry_incomplete")

    def add_function(self, function: types.FunctionType, module: str) -> None:
        # A contextmanager exposes a functools wrapper; its original generator
        # owns the real nested factory code. Bind that exact imported code too.
        for _ in range(8):
            self.add(function.__code__, module)
            wrapped = vars(function).get("__wrapped__")
            if wrapped is None:
                return
            if not isinstance(wrapped, types.FunctionType) or wrapped.__module__ != module:
                raise RuntimeError("predicate_wrapped_function_shape")
            function = wrapped
        raise RuntimeError("predicate_wrapper_depth")

    def add(self, code: types.CodeType, module: str) -> None:
        # Labels derive only from the reviewed exact source, never live paths.
        label = module + ":" + code.co_qualname
        if label in TARGETS:
            if code_image(code) != self.expected[module].get(code.co_qualname):
                raise RuntimeError("constructor_live_code_mismatch")
            self.codes[id(code)] = (code, label)
        for child in code.co_consts:
            if isinstance(child, types.CodeType):
                self.add(child, module)

    def site(self, frame: types.FrameType) -> str:
        code = frame.f_code
        entry = self.codes.get(id(code))
        if entry is None or entry[0] is not code:
            raise RuntimeError("predicate_unknown_call_site")
        return entry[1] + ":" + str(frame.f_lineno)
