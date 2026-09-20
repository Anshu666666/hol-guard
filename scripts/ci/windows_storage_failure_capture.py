"""Failure-only fixed-origin observations for an unchanged installed writer."""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from types import CodeType, FunctionType
from typing import cast

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer

_LIMIT = 32
_MAX_COUNT = 2_147_483_647
_ORIGINS = frozenset(
    {"storage_gate", "schema_initialization", "advisory_lock", "unattributed", "traceback_limit", "not_timeout"}
)


def timeout_origins() -> dict[CodeType, str]:
    """Bind known functions, without recording source paths or traceback text."""
    owner = store_connection_schema.StoreConnectionSchemaMixin
    return {
        cast(FunctionType, inspect.unwrap(owner._hold_storage_gate)).__code__: "storage_gate",
        owner._initialize_serialized_once.__code__: "schema_initialization",
        cast(FunctionType, inspect.unwrap(owner._hold_advisory_file_lock)).__code__: "advisory_lock",
    }


def failure_origin(error: BaseException, registry: dict[CodeType, str]) -> str:
    if type(error) is not TimeoutError:
        return "not_timeout"
    traceback = error.__traceback__
    innermost: CodeType | None = None
    for _ in range(_LIMIT):
        if traceback is None:
            origin = registry.get(innermost, "unattributed") if innermost is not None else "unattributed"
            return origin if origin in _ORIGINS else "unattributed"
        innermost = traceback.tb_frame.f_code
        traceback = traceback.tb_next
    if traceback is not None:
        return "traceback_limit"
    origin = registry.get(innermost, "unattributed") if innermost is not None else "unattributed"
    return origin if origin in _ORIGINS else "unattributed"


class FailureOriginCapture:
    """Forward the existing classifier and preserve its exact returned code.

    The writer calls this boundary only after a failed persistence operation.
    The observation never changes the error, retry, queue, deadline, or counters.
    No exception, traceback, local variable, or message is retained.
    """

    def __init__(self) -> None:
        self._registry = timeout_origins()
        self._lock = threading.Lock()
        self._counts = dict.fromkeys(sorted(_ORIGINS), 0)
        self._complete = True
        self._restored = False
        self._original: Callable[[BaseException], str] | None = None
        self._callback: Callable[[BaseException], str] | None = None

    def __enter__(self) -> FailureOriginCapture:
        if self._original is not None:
            raise RuntimeError("diagnostic_capture_already_entered")
        original = writer.evidence_failure_code
        self._original = original

        def observe(error: BaseException) -> str:
            code = original(error)
            try:
                origin = failure_origin(error, self._registry)
                if self._lock.acquire(blocking=False):
                    try:
                        count = self._counts[origin]
                        self._counts[origin] = min(_MAX_COUNT, count + 1)
                        if count == _MAX_COUNT:
                            self._complete = False
                    finally:
                        self._lock.release()
                else:
                    self._complete = False
            except BaseException:
                self._complete = False
            return code

        self._callback = observe
        writer.evidence_failure_code = observe
        return self

    def __exit__(self, *_args: object) -> None:
        if self._callback is not None and writer.evidence_failure_code is self._callback:
            assert self._original is not None
            writer.evidence_failure_code = self._original
            self._restored = True
        else:
            self._complete = False

    def snapshot(self) -> dict[str, object]:
        return {
            "schema": "hol-guard.storage-failure-origins.v1",
            "scope": "failure_code_callback_invocations_not_failed_record_units",
            "origin_counts": dict(self._counts),
            "diagnostic_complete": self._complete and self._restored,
            "callbacks_restored": self._restored,
            "traceback_frame_limit": _LIMIT,
            "captured_messages": False,
            "captured_paths": False,
            "captured_locals": False,
            "captured_payloads": False,
            "headline_qualification": False,
        }
