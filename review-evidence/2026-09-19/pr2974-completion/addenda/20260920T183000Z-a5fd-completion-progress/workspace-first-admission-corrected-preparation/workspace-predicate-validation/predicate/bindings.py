"""Hash-bound source and actual code-object call-site registry."""

from __future__ import annotations

import hashlib
import importlib
import json
import types
from pathlib import Path


class Registry:
    def __init__(self, source: Path, manifest: Path) -> None:
        self.codes: dict[int, tuple[types.CodeType, str]] = {}
        self.sites: dict[tuple[types.CodeType, int], str] = {}
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
            for value in vars(module).values():
                if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
                    self.add_function(value, module.__name__)
                elif isinstance(value, type) and value.__module__ == module.__name__:
                    for child in vars(value).values():
                        if isinstance(child, (staticmethod, classmethod)):
                            child = child.__func__
                        if isinstance(child, property):
                            child = child.fget
                        if isinstance(child, types.FunctionType):
                            self.add_function(child, module.__name__)

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
        self.codes[id(code)] = (code, module + ":" + code.co_qualname)
        for child in code.co_consts:
            if isinstance(child, types.CodeType):
                self.add(child, module)

    def site(self, frame: types.FrameType) -> str:
        code = frame.f_code
        entry = self.codes.get(id(code))
        if entry is None or entry[0] is not code:
            raise RuntimeError("predicate_unknown_call_site")
        return entry[1] + ":" + str(frame.f_lineno)
