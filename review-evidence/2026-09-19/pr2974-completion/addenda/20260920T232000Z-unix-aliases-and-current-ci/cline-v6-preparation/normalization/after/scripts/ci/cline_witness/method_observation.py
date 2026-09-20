"""Observe two admitted HookWorker methods without an all-event profiler."""

from __future__ import annotations

import hashlib
import importlib.machinery
import sys
import threading
from pathlib import Path
from types import CodeType, FunctionType, ModuleType
from typing import Any, cast

MODULE = "codex_plugin_scanner.guard.daemon.hook_worker"
METHODS = {"review_http_payload": "worker", "_review_raw_hook_native": "edge"}
DEFAULTS = {"review_http_payload": "deadline", "_review_raw_hook_native": "policy_snapshot"}
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


def code_image(value: Any) -> Any:
    """Closed typed code image; no hashing or equality on unknown constants."""
    kind = type(value)
    if kind is CodeType:
        return ["code", [code_image(getattr(value, name)) for name in CODE_FIELDS]]
    if value is None or value is Ellipsis:
        return ["none" if value is None else "ellipsis"]
    if any(kind is allowed for allowed in (bool, int, str)):
        return [kind.__name__, value]
    if kind is bytes:
        return ["bytes", value.hex()]
    if kind is float:
        return ["float", value.hex()]
    if kind is complex:
        return ["complex", value.real.hex(), value.imag.hex()]
    if kind is tuple:
        return ["tuple", [code_image(item) for item in value]]
    if kind is frozenset:
        return ["frozenset", sorted((code_image(item) for item in value), key=repr)]
    raise ValueError("cline_method_constant_type")


def selected_codes(body: bytes, filename: str) -> dict[str, CodeType]:
    module = compile(body, filename, "exec", dont_inherit=True, optimize=sys.flags.optimize)
    classes = [code for code in module.co_consts if type(code) is CodeType and code.co_name == "HookWorker"]
    if len(classes) != 1:
        raise ValueError("cline_method_class_code")
    result = {code.co_name: code for code in classes[0].co_consts if type(code) is CodeType and code.co_name in METHODS}
    if set(result) != set(METHODS):
        raise ValueError("cline_method_code_roster")
    return result


class _Loader:
    """Forward the original selected loader once, restoring its public owner first."""

    def __init__(self, observer: MethodObservation, original: Any, spec: Any) -> None:
        self.observer = observer
        self.original = original
        self.spec = spec

    def create_module(self, spec: Any) -> Any:
        spec.loader = self.original
        try:
            result = self.original.create_module(spec)
        except BaseException:
            self.observer.fault("module_creation_failed")
            self.observer.remove_finder()
            raise
        spec.loader = self
        return result

    def exec_module(self, module: ModuleType) -> None:
        # The original module body sees its original loader/spec identities.
        self.spec.loader = self.original
        module.__loader__ = self.original
        try:
            self.original.exec_module(module)
        except BaseException:
            self.observer.fault("module_execution_failed")
            self.observer.remove_finder()
            raise
        try:
            self.observer.bind(module)
        except BaseException:
            self.observer.fault("method_binding_failed")
            self.observer.restore_methods()
        finally:
            self.observer.remove_finder()


class MethodObservation:
    """Retain the original capture/oracle while intercepting selected methods only."""

    def __init__(self, config: dict[str, Any], capture: Any) -> None:
        self.config = config
        self.capture = capture
        self.thread_id = threading.get_ident()
        self.finders = tuple(sys.meta_path)
        self.owner: type[Any] | None = None
        self.originals: dict[str, Any] = {}
        self.images: dict[str, Any] = {}
        self.hooks: dict[str, Any] = {}
        self.installed: list[str] = []
        self.finder_installed = False
        self.finder_restored = False
        self.methods_restored = False
        self.bound = False
        self.selected_imports = 0
        self.faults: list[str] = []
        self.tokens: dict[str, object] = {}

    def fault(self, label: str) -> None:
        try:
            if label not in self.faults and len(self.faults) < 8:
                self.faults.append(label)
            self.capture.fault("method_observation_failed")
        except BaseException:
            return

    def start(self) -> bool:
        if MODULE in sys.modules or sys.getprofile() is not None or threading.getprofile() is not None:
            self.fault("preexisting_module_or_profile")
            return False
        try:
            sys.meta_path.insert(0, self)
            self.finder_installed = True
            self.capture.enabled = True
            return True
        except BaseException:
            self.fault("finder_install_failed")
            self.remove_finder()
            return False

    def remove_finder(self) -> None:
        try:
            matches = [index for index, finder in enumerate(sys.meta_path) if finder is self]
            if self.finder_installed and len(matches) != 1:
                self.fault("finder_ownership_lost")
            for index in reversed(matches):
                del sys.meta_path[index]
            self.finder_installed = False
            self.finder_restored = len(sys.meta_path) == len(self.finders) and all(
                actual is expected for actual, expected in zip(sys.meta_path, self.finders, strict=True)
            )
            if not self.finder_restored:
                self.fault("finder_state_changed")
        except BaseException:
            self.fault("finder_restore_failed")

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname != MODULE:
            return None
        self.selected_imports = min(2, self.selected_imports + 1)
        current = tuple(finder for finder in sys.meta_path if finder is not self)
        if (
            self.selected_imports != 1
            or len(current) != len(self.finders)
            or any(actual is not expected for actual, expected in zip(current, self.finders, strict=True))
        ):
            self.fault("finder_state_changed")
            self.remove_finder()
            return None
        for finder in self.finders:
            spec = finder.find_spec(fullname, path, target)
            if spec is None:
                continue
            if (
                type(spec) is not importlib.machinery.ModuleSpec
                or type(spec.loader) is not importlib.machinery.SourceFileLoader
                or spec.origin != self.config["method_source"]
            ):
                self.fault("selected_loader_unavailable")
                self.remove_finder()
                return spec
            cast(Any, spec).loader = _Loader(self, spec.loader, spec)
            return spec
        self.fault("selected_module_unavailable")
        self.remove_finder()
        return None

    def bind(self, module: ModuleType) -> None:
        path = Path(self.config["method_source"])
        body = path.read_bytes()
        if len(body) > 1_048_576 or hashlib.sha256(body).hexdigest() != self.config["sources"][str(path)]:
            raise ValueError("cline_method_source")
        if type(module) is not ModuleType or module.__name__ != MODULE or module.__file__ != str(path):
            raise ValueError("cline_method_module")
        owner = module.__dict__.get("HookWorker")
        if type(owner) is not type or owner.__module__ != MODULE:
            raise ValueError("cline_method_owner")
        expected = selected_codes(body, str(path))
        originals = {name: owner.__dict__.get(name) for name in METHODS}
        for name, original in originals.items():
            if (
                type(original) is not FunctionType
                or original.__module__ != MODULE
                or original.__globals__ is not module.__dict__
                or code_image(original.__code__) != code_image(expected[name])
                or original.__code__.co_argcount != 1
                or original.__code__.co_posonlyargcount != 0
                or original.__code__.co_flags & 12
                or original.__defaults__ is not None
                or type(original.__kwdefaults__) is not dict
                or set(original.__kwdefaults__) != {DEFAULTS[name]}
                or original.__kwdefaults__[DEFAULTS[name]] is not None
            ):
                raise ValueError("cline_method_code")
        self.owner = owner
        self.originals = originals
        self.images = {name: code_image(original.__code__) for name, original in self.originals.items()}
        for name, original in originals.items():
            hook = self.make_hook(name, original)
            self.hooks[name] = hook
            self.installed.append(name)
            setattr(owner, name, hook)
        self.bound = True

    def before(self, name: str, instance: Any, args: tuple[Any, ...], kwargs: dict[str, Any], token: object) -> None:
        role = METHODS[name]
        key = role + "_call"
        self.capture.counts[key] = min(2, self.capture.counts[key] + 1)
        if self.capture.counts[key] != 1:
            self.fault("duplicate_selected_call")
            return
        if code_image(self.originals[name].__code__) != self.images[name]:
            self.fault("selected_code_changed")
        defaults = self.originals[name].__kwdefaults__
        if type(defaults) is not dict or set(defaults) != {DEFAULTS[name]} or defaults[DEFAULTS[name]] is not None:
            self.fault("selected_defaults_changed")
        if threading.get_ident() != self.thread_id or type(instance) is not self.owner:
            self.fault("selected_owner_changed")
        if role == "worker":
            self.capture.worker = instance
        elif instance is not self.capture.worker:
            self.fault("selected_worker_changed")
        self.tokens[role] = token
        self.capture.open_frames[role] = id(token)
        if role == "edge":
            original = self.originals[name]
            code = original.__code__
            names = code.co_varnames[1 : 1 + code.co_kwonlyargcount]
            defaults = original.__kwdefaults__ or {}
            if args or set(kwargs) - set(names) or any(key not in kwargs and key not in defaults for key in names):
                self.fault("selected_call_shape")
                return
            self.capture.arguments = {"self": instance, **defaults, **kwargs}
            self.capture.entry_image = self.capture.entry_snapshot(self.capture.arguments)

    def after(self, name: str, token: object, result: object) -> None:
        role = METHODS[name]
        key = role + "_return_or_unwind"
        self.capture.counts[key] = min(2, self.capture.counts[key] + 1)
        if self.capture.counts[key] != 1 or self.tokens.get(role) is not token:
            self.fault("duplicate_or_unpaired_return")
            return
        self.tokens.pop(role)
        self.capture.open_frames.pop(role, None)
        if role == "edge":
            self.capture.edge = result
            self.capture.edge_image = self.capture.snapshot(result)
        else:
            self.capture.worker_result = result
            self.capture.worker_result_image = self.capture.snapshot(result)

    def make_hook(self, name: str, original: Any) -> Any:
        def observed(instance: Any, *args: Any, **kwargs: Any) -> Any:
            token = object()
            try:
                self.before(name, instance, args, kwargs, token)
            except BaseException:
                self.fault("entry_capture_failed")
            try:
                result = original(instance, *args, **kwargs)
            except BaseException:
                try:
                    self.after(name, token, None)
                except BaseException:
                    self.fault("unwind_capture_failed")
                raise
            try:
                self.after(name, token, result)
            except BaseException:
                self.fault("return_capture_failed")
            return result

        observed.__name__ = original.__name__
        observed.__qualname__ = original.__qualname__
        observed.__module__ = original.__module__
        observed.__doc__ = original.__doc__
        observed.__annotations__ = dict(original.__annotations__)
        observed.__dict__.update(original.__dict__)
        setattr(observed, "__wrapped__", original)
        return observed

    def restore_methods(self) -> None:
        if self.owner is not None:
            for name in reversed(self.installed):
                try:
                    if code_image(self.originals[name].__code__) != self.images[name]:
                        self.fault("selected_code_changed")
                    defaults = self.originals[name].__kwdefaults__
                    if (
                        type(defaults) is not dict
                        or set(defaults) != {DEFAULTS[name]}
                        or defaults[DEFAULTS[name]] is not None
                    ):
                        self.fault("selected_defaults_changed")
                except BaseException:
                    self.fault("selected_code_unavailable")
                try:
                    if self.owner.__dict__.get(name) is self.hooks[name]:
                        setattr(self.owner, name, self.originals[name])
                    else:
                        self.fault("method_ownership_lost")
                except BaseException:
                    self.fault("method_restore_failed")
        try:
            self.methods_restored = (
                bool(self.bound)
                and self.owner is not None
                and all(self.owner.__dict__.get(name) is original for name, original in self.originals.items())
            )
        except BaseException:
            self.fault("method_restore_failed")

    def restore(self) -> None:
        if self.finder_installed:
            self.remove_finder()
        self.restore_methods()

    def document(self) -> dict[str, Any]:
        return {
            "schema": "hol-guard.cline-selected-method-observation.v1",
            "selected_imports": self.selected_imports,
            "bound": self.bound,
            "finder_restored": self.finder_restored,
            "methods_restored": self.methods_restored,
            "faults": list(self.faults),
            "global_profile_installed": False,
            "complete": self.bound and self.finder_restored and self.methods_restored and not self.faults,
        }
