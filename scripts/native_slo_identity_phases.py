"""Bounded observers of identity work during real, unchanged hook dispatch.

This module is diagnostic-only. It never clears a cache, retries a lookup,
changes admission, or stores arguments, paths, identities or exception text.
"""

from __future__ import annotations

import contextvars
import functools
import sys
import threading
import time
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

from scripts.native_slo_phase_calls import ModuleProbe, byte_size

_INSTALL_LOCK = threading.Lock()
_ROW = contextvars.ContextVar[dict[str, Any] | None]("identity_diagnostic_row", default=None)
_VALIDATING = contextvars.ContextVar[bool]("identity_diagnostic_validating", default=False)
_COUNTERS = (
    "status_calls",
    "status_raised",
    "status_wall_ns",
    "status_thread_cpu_ns",
    "validation_calls",
    "validation_returned_identity",
    "validation_raised",
    "executable_hashed_bytes",
    "live_proof_calls",
    "live_proof_hits",
    "capability_calls",
    "capability_cache_hits",
    "capability_cache_misses",
    "capability_cache_ambiguous",
    "capability_raised",
    "capability_process_calls",
)


class IdentityObserver:
    """Observe at most three serial hooks on a separate prepared fixture."""

    def __init__(self, *, runtime: Any = None, handler: Any = None) -> None:
        if runtime is None or handler is None:
            from codex_plugin_scanner.guard import native_runtime
            from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

            runtime, handler = native_runtime, _GuardDaemonHandler
        self.runtime, self.handler = runtime, handler
        self._stack = ExitStack()
        self._condition = threading.Condition()
        self._rows: list[dict[str, Any]] = []
        self._active_hooks = self._unexpected = 0
        self._installed = False
        self._drained = True
        self._initial_cache_entries = 0

    def _hook(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            payload = args[1] if len(args) > 1 else kwargs.get("payload")
            expected = (
                kwargs.get("default_harness") == "claude-code"
                and isinstance(payload, dict)
                and payload.get("hook_event_name") == "PostToolUse"
            )
            row: dict[str, Any] | None
            with self._condition:
                if not expected or len(self._rows) >= 3 or self._active_hooks:
                    self._unexpected += 1
                    row = None
                else:
                    row = dict.fromkeys(_COUNTERS, 0)
                    row.update(
                        index=len(self._rows),
                        phase="first_hook_prepared_resident" if not self._rows else "warm_hook",
                        dispatch_outcome="inflight",
                        hook_wall_ns=None,
                    )
                    self._rows.append(row)
                self._active_hooks += 1
            token = _ROW.set(row)
            started = time.perf_counter_ns()
            outcome = "raised"
            try:
                result = original(*args, **kwargs)
                outcome = "returned"
                return result
            finally:
                if row is not None:
                    row.update(dispatch_outcome=outcome, hook_wall_ns=time.perf_counter_ns() - started)
                _ROW.reset(token)
                with self._condition:
                    self._active_hooks -= 1
                    self._condition.notify_all()

        return observed

    def _status(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            row = _ROW.get()
            if row is None:
                return original(*args, **kwargs)
            row["status_calls"] += 1
            wall, cpu = time.perf_counter_ns(), time.thread_time_ns()
            try:
                return original(*args, **kwargs)
            except BaseException:
                row["status_raised"] += 1
                raise
            finally:
                row["status_wall_ns"] += time.perf_counter_ns() - wall
                row["status_thread_cpu_ns"] += time.thread_time_ns() - cpu

        return observed

    def _validate(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            row = _ROW.get()
            if row is None:
                return original(*args, **kwargs)
            row["validation_calls"] += 1
            token = _VALIDATING.set(True)
            try:
                value = original(*args, **kwargs)
                row["validation_returned_identity"] += int(value is not None)
                return value
            except BaseException:
                row["validation_raised"] += 1
                raise
            finally:
                _VALIDATING.reset(token)

        return observed

    def _live(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            row = _ROW.get()
            if row is not None:
                row["live_proof_calls"] += 1
            value = original(*args, **kwargs)
            if row is not None:
                row["live_proof_hits"] += int(value is not None)
            return value

        return observed

    def _capabilities(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            row = _ROW.get()
            if row is None:
                return original(*args, **kwargs)
            row["capability_calls"] += 1
            before = original.cache_info()
            processes = row["capability_process_calls"]
            raised = False
            try:
                return original(*args, **kwargs)
            except BaseException:
                raised = True
                row["capability_raised"] += 1
                raise
            finally:
                after = original.cache_info()
                delta = (after.hits - before.hits, after.misses - before.misses)
                calls = row["capability_process_calls"] - processes
                if not raised and delta == (1, 0) and calls == 0:
                    row["capability_cache_hits"] += 1
                elif delta == (0, 1) and calls == 1:
                    row["capability_cache_misses"] += 1
                else:
                    # Cache counters are process-global. Concurrent lookups or
                    # an exceptional lookup cannot be attributed as a cache hit.
                    row["capability_cache_ambiguous"] += 1

        wrapper: Any = observed
        wrapper.cache_info = original.cache_info
        wrapper.cache_clear = original.cache_clear
        return observed

    def _process(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(path: Any, args: Any, **kwargs: Any) -> Any:
            row = _ROW.get()
            if row is not None and args == ("capabilities", "--json"):
                row["capability_process_calls"] += 1
            return original(path, args, **kwargs)

        return observed

    def _hash_factory(self, original: Any) -> Any:
        def add(value: Any) -> None:
            row, size = _ROW.get(), byte_size(value)
            if row is not None and _VALIDATING.get() and size is not None:
                row["executable_hashed_bytes"] += size

        class Digest:
            def __init__(self, inner: Any) -> None:
                self.inner = inner

            def __getattr__(self, name: str) -> Any:
                return getattr(self.inner, name)

            def update(self, value: Any) -> Any:
                result = self.inner.update(value)
                add(value)  # Count only bytes actually accepted by SHA-256.
                return result

            def copy(self) -> Any:
                return Digest(self.inner.copy())

        def sha256(*args: Any, **kwargs: Any) -> Any:
            value = original(*args, **kwargs)
            add(args[0] if args else kwargs.get("string", b""))
            return Digest(value)

        return sha256

    def __enter__(self) -> IdentityObserver:
        if self._installed or not _INSTALL_LOCK.acquire(blocking=False):
            raise RuntimeError("qualification identity observer already active")
        self._installed = True
        try:
            runtime = self.runtime
            self._initial_cache_entries = runtime._capabilities_for_identity.cache_info().currsize
            status_name = (
                "_inspect_native_runtime_status"
                if hasattr(runtime, "_inspect_native_runtime_status")
                else "native_runtime_status"
            )
            original_status = getattr(runtime, status_name)
            status = self._status(original_status)
            self._stack.enter_context(patch.object(runtime, status_name, status))
            if status_name == "native_runtime_status":
                # Frozen v1 has no canonical private implementation. Preserve
                # exact existing imported aliases, including native_hook_edge.
                for name, module in tuple(sys.modules.items()):
                    if module is not None and name.startswith("codex_plugin_scanner.guard"):
                        for key, value in tuple(vars(module).items()):
                            if value is original_status:
                                self._stack.enter_context(patch.object(module, key, status))
            self._stack.enter_context(
                patch.object(runtime, "_validate_binary", self._validate(runtime._validate_binary))
            )
            self._stack.enter_context(
                patch.object(
                    runtime, "_capabilities_for_identity", self._capabilities(runtime._capabilities_for_identity)
                )
            )
            self._stack.enter_context(
                patch.object(runtime, "_run_native_process", self._process(runtime._run_native_process))
            )
            self._stack.enter_context(
                patch.object(
                    runtime,
                    "hashlib",
                    ModuleProbe(runtime.hashlib, {"sha256": self._hash_factory(runtime.hashlib.sha256)}),
                )
            )
            if hasattr(runtime, "live_native_identity"):
                self._stack.enter_context(
                    patch.object(runtime, "live_native_identity", self._live(runtime.live_native_identity))
                )
            self._stack.enter_context(
                patch.object(self.handler, "_handle_runtime_hook", self._hook(self.handler._handle_runtime_hook))
            )
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_args: Any) -> None:
        try:
            with self._condition:
                self._drained = self._condition.wait_for(lambda: self._active_hooks == 0, timeout=1.0)
            self._stack.close()
        finally:
            if self._installed:
                self._installed = False
                _INSTALL_LOCK.release()

    def report(self) -> dict[str, Any]:
        with self._condition:
            rows = [dict(row) for row in self._rows]
            return {
                "schema": "hol-guard.evaluated-hook-identity.v1",
                "scope": "prepared_resident_first_hook_and_warm",
                "headline_timing_eligible": False,
                "cold_resident_measured": False,
                "cache_state_modified": False,
                "initial_capability_cache_entries": self._initial_cache_entries,
                "live_proof_observable": hasattr(self.runtime, "live_native_identity"),
                "drained": self._drained and not self._active_hooks,
                "unexpected_hooks": self._unexpected,
                "rows": rows,
                "complete": self._drained
                and not self._active_hooks
                and not self._unexpected
                and len(rows) == 3
                and all(
                    row.get("dispatch_outcome") == "returned"
                    and row["status_calls"] > 0
                    and row["capability_cache_ambiguous"] == 0
                    for row in rows
                ),
            }


def validate_identity_report(value: Any) -> dict[str, Any]:
    """Admit only this finite observer projection from the private child."""
    fields = {
        "schema",
        "scope",
        "headline_timing_eligible",
        "cold_resident_measured",
        "cache_state_modified",
        "initial_capability_cache_entries",
        "live_proof_observable",
        "drained",
        "unexpected_hooks",
        "rows",
        "complete",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("qualification identity observer fields invalid")
    if (
        value["schema"] != "hol-guard.evaluated-hook-identity.v1"
        or value["scope"] != "prepared_resident_first_hook_and_warm"
    ):
        raise RuntimeError("qualification identity observer scope invalid")
    for name in ("headline_timing_eligible", "cold_resident_measured", "cache_state_modified"):
        if value[name] is not False:
            raise RuntimeError("qualification identity observer qualification invalid")
    for name in ("live_proof_observable", "drained", "complete"):
        if type(value[name]) is not bool:
            raise RuntimeError("qualification identity observer flag invalid")
    for name in ("initial_capability_cache_entries", "unexpected_hooks"):
        if type(value[name]) is not int or value[name] < 0:
            raise RuntimeError("qualification identity observer count invalid")
    rows = value["rows"]
    if not isinstance(rows, list) or len(rows) > 3:
        raise RuntimeError("qualification identity observer rows invalid")
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != set(_COUNTERS) | {
            "index",
            "phase",
            "dispatch_outcome",
            "hook_wall_ns",
        }:
            raise RuntimeError("qualification identity observer row fields invalid")
        if (
            row["index"] != index
            or type(row["index"]) is not int
            or row["phase"] != ("warm_hook" if index else "first_hook_prepared_resident")
        ):
            raise RuntimeError("qualification identity observer order invalid")
        if any(type(row[k]) is not int or row[k] < 0 for k in _COUNTERS):
            raise RuntimeError("qualification identity observer metric invalid")
        if row["dispatch_outcome"] not in {"returned", "raised", "inflight"} or (
            row["hook_wall_ns"] is not None and (type(row["hook_wall_ns"]) is not int or row["hook_wall_ns"] < 0)
        ):
            raise RuntimeError("qualification identity observer outcome invalid")
        if row["dispatch_outcome"] != "inflight" and row["capability_calls"] != sum(
            row[k] for k in ("capability_cache_hits", "capability_cache_misses", "capability_cache_ambiguous")
        ):
            raise RuntimeError("qualification identity observer cache counts invalid")
    complete = (
        value["drained"]
        and not value["unexpected_hooks"]
        and len(rows) == 3
        and all(
            row["dispatch_outcome"] == "returned"
            and row["hook_wall_ns"] is not None
            and row["status_calls"] > 0
            and row["capability_cache_ambiguous"] == 0
            for row in rows
        )
    )
    if value["complete"] != complete:
        raise RuntimeError("qualification identity observer completeness invalid")
    return value
