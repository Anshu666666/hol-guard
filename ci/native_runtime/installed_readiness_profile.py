"""Opt-in profiling of the first real publisher calls with fixed public labels."""

from __future__ import annotations

import cProfile
import inspect
import math
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from types import CodeType
from typing import Any

_LIMIT = 999_999
_WINDOWS = ("start", "publication")
_LABELS = frozenset(
    {
        "publisher_start", "publication", "publication_context", "command_preparation", "configuration",
        "metadata_load", "metadata_validate", "control_projection", "control_authority_key", "source_capture",
        "store_connect", "store_permissions", "integrity_secret", "runtime_status", "runtime_binary_validation",
        "runtime_capabilities", "resident_transport", "stream_start", "stream_request",
    }
)


def _code(function: object) -> CodeType | None:
    with suppress(BaseException):
        candidate = getattr(inspect.unwrap(function), "__code__", None)
        if isinstance(candidate, CodeType):
            return candidate
    return None


def _number(value: object) -> int | float | None:
    if type(value) is int and value >= 0:
        return min(_LIMIT, value)
    if type(value) is float and math.isfinite(value) and value >= 0:
        return round(min(_LIMIT, value), 3)
    return None


class ReadinessProfile:
    """Never replace an authority result or serialize profiler names, paths or arguments."""

    def __init__(self, targets: Mapping[str, object], *, enabled: bool) -> None:
        self.enabled = enabled
        self._codes: dict[int, tuple[CodeType, str]] = {}
        for label, function in targets.items():
            if label not in _LABELS:
                continue
            code = _code(function)
            if code is not None:
                self._codes[id(code)] = (code, label)
        self._lock = threading.Lock()
        self._records: dict[str, dict[str, object]] = {}

    def _finish(self, window: str, profiler: cProfile.Profile | None, available: bool) -> None:
        rows: list[dict[str, object]] = []
        if available and profiler is not None:
            try:
                profiler.disable()
                for entry in profiler.getstats():
                    admitted = self._codes.get(id(entry.code))
                    if admitted is None or entry.code is not admitted[0]:
                        continue
                    rows.append(
                        {
                            "label": admitted[1],
                            "calls": _number(entry.callcount),
                            "recursive_calls": _number(entry.reccallcount),
                            "inclusive_ms": _number(entry.totaltime * 1000),
                            "self_ms": _number(entry.inlinetime * 1000),
                            "values_capped_at": _LIMIT,
                        }
                    )
            except BaseException:
                available = False
                rows = []
        rows.sort(key=lambda item: str(item["label"]))
        with self._lock:
            self._records[window] = {"completed": True, "available": available, "rows": rows}

    def _wrap(self, window: str, original: Callable[..., Any]) -> Callable[..., Any]:
        def run(*args: Any, **kwargs: Any) -> Any:
            with self._lock:
                first = window not in self._records
                if first:
                    self._records[window] = {"completed": False, "available": False, "rows": []}
            if not first:
                return original(*args, **kwargs)
            profiler = None
            available = False
            try:
                if sys.getprofile() is None:
                    profiler = cProfile.Profile()
                    profiler.enable()
                    available = True
            except BaseException:
                if profiler is not None:
                    with suppress(BaseException):
                        profiler.disable()
                profiler = None
            try:
                return original(*args, **kwargs)
            finally:
                with suppress(BaseException):
                    self._finish(window, profiler, available)

        return run

    @contextmanager
    def attach(self, publisher: object) -> Iterator[None]:
        if not self.enabled:
            yield
            return
        namespace = vars(publisher)
        missing = object()
        installed: list[tuple[str, object, Callable[..., Any]]] = []
        try:
            for name, window in (("start", "start"), ("_publish_once", "publication")):
                original = getattr(publisher, name)
                wrapped = self._wrap(window, original)
                previous = namespace.get(name, missing)
                namespace[name] = wrapped
                installed.append((name, previous, wrapped))
            yield
        finally:
            for name, previous, wrapped in reversed(installed):
                if namespace.get(name) is wrapped:
                    if previous is missing:
                        del namespace[name]
                    else:
                        namespace[name] = previous

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            windows = [
                {
                    "window": name,
                    **self._records.get(name, {"completed": False, "available": False, "rows": []}),
                }
                for name in _WINDOWS
            ]
        return {
            "enabled": self.enabled,
            "window_semantics": "whole_first_call_may_complete_after_readiness_deadline",
            "count_semantics": "profiler_calls_include_generator_resumptions",
            "timing_semantics": "instrumented_inclusive_and_self_wall_time_not_additive_across_windows",
            "acceptance_claim": False,
            "windows": windows,
        }


def publisher_targets(publisher: Any) -> dict[str, object]:
    """Resolve actual implementation code objects without reading authority values."""
    from codex_plugin_scanner.guard import (
        native_command_control_authority_store,
        native_command_control_binding,
        native_command_control_projection,
        native_policy_authority_read,
        native_resident_client,
        native_resident_stream,
        native_runtime,
    )

    return {
        "publisher_start": publisher.start,
        "publication": publisher._publish_once,
        "publication_context": publisher._publication_context,
        "command_preparation": publisher._compiled_command_extensions,
        "configuration": publisher._compiled_effective_policy,
        "metadata_load": native_command_control_binding.load_native_command_program_metadata,
        "metadata_validate": native_command_control_binding._metadata_from_bytes,
        "control_projection": native_command_control_projection.read_control_projection,
        "control_authority_key": native_command_control_authority_store._key,
        "source_capture": native_policy_authority_read.read_native_policy_authority_inputs,
        "store_connect": publisher.store._connect,
        "store_permissions": publisher.store._repair_store_permissions,
        "integrity_secret": publisher.store._policy_integrity_secret_material,
        "runtime_status": native_runtime.native_runtime_status,
        "runtime_binary_validation": native_runtime._validate_binary,
        "runtime_capabilities": native_runtime._capabilities_for_identity,
        "resident_transport": native_resident_client.native_resident_client_request,
        "stream_start": native_resident_stream._PersistentNativeClient._start,
        "stream_request": native_resident_stream._PersistentNativeClient.request,
    }
