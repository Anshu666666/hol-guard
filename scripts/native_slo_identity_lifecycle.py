"""Observe real preparation and first hooks without changing their calls."""

from __future__ import annotations

import contextvars
import functools
import sys
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.native_slo_identity_lifecycle_record import MAX_CALLS, LifecycleJournal
from scripts.native_slo_identity_phases import _COUNTERS, _INSTALL_LOCK, _ROW, IdentityObserver

_CURRENT_CALL = contextvars.ContextVar[int | None]("cold_identity_call", default=None)

_OWNER = contextvars.ContextVar[tuple[str, int | None] | None]("cold_identity_owner", default=None)


class LifecycleObserver(IdentityObserver):
    """A fresh child owns one bounded journal and the unchanged original calls.

    Status wall/CPU counters are inclusive calling-thread spans, not additive
    process-tree CPU or exclusive wall time. Publication is a separate owner;
    concurrency never turns its global cache delta into a hook cache hit.
    """

    def __init__(
        self, path: Path, expected: dict[str, str], *, runtime: Any = None, handler: Any = None, publisher: Any = None
    ) -> None:
        super().__init__(runtime=runtime, handler=handler)
        if publisher is None:
            from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher

            publisher = NativePolicySnapshotPublisher
        self.publisher = publisher
        self.journal = LifecycleJournal(path, expected)
        self._phase = "preparation"
        self._epoch = 0
        self._calls = self._active_calls = self._hook_count = 0
        self._overflow = False

    @contextmanager
    def preparation(self):
        token = _OWNER.set(("preparation", None))
        try:
            yield
        finally:
            _OWNER.reset(token)

    def phase(self, phase: str) -> None:
        with self._condition:
            self._phase = phase
            self._epoch += 1
            self.journal.append("phase", phase=phase, phase_epoch=self._epoch)

    def _publication(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            token = _OWNER.set(("publication", None))
            try:
                return original(*args, **kwargs)
            finally:
                _OWNER.reset(token)

        return observed

    def _call(self, original: Any, operation: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        row: dict[str, Any] | None
        with self._condition:
            call = self._calls
            self._calls += 1
            self._active_calls += 1
            owner, hook = _OWNER.get() or ("unassigned", None)
            if self._phase == "cleanup" and owner == "preparation":
                owner = "cleanup"
            elif self._phase != "preparation" and owner == "preparation":
                owner = "unassigned"
            if call >= MAX_CALLS:
                self._overflow = True
                row = None
            else:
                row = dict.fromkeys(_COUNTERS, 0)
                self.journal.append(
                    "call_started",
                    call=call,
                    operation=operation,
                    owner=owner,
                    phase=self._phase,
                    phase_epoch=self._epoch,
                    hook=hook,
                    parent_call=_CURRENT_CALL.get(),
                )
        token = _ROW.set(row)
        call_token = _CURRENT_CALL.set(call if row is not None else None)
        outcome = "raised"
        matches = None
        try:
            result = original(*args, **kwargs)
            outcome = "returned"
            if operation == "status":
                try:
                    identity = getattr(result, "identity", None)
                    capabilities = getattr(result, "capabilities", None)
                    digest = getattr(identity, "sha256", None)
                    build = getattr(capabilities, "build_sha", None)
                    matches = (
                        digest == self.journal.expected["runtime_sha256"]
                        and build == self.journal.expected["build_sha"]
                    )
                except Exception:
                    matches = None  # Observation cannot replace the original returned value.
            return result
        finally:
            _ROW.reset(token)
            _CURRENT_CALL.reset(call_token)
            with self._condition:
                if row is not None:
                    self.journal.append(
                        "call_finished",
                        call=call,
                        phase=self._phase,
                        phase_epoch=self._epoch,
                        outcome=outcome,
                        metrics=row,
                        identity_matches=matches,
                    )
                self._active_calls -= 1
                self._condition.notify_all()

    def _status(self, original: Any) -> Any:
        counted = super()._status(original)

        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            return self._call(counted, "status", args, kwargs)

        return observed

    def _outside(self, original: Any, counted: Any, operation: str) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            if _ROW.get() is not None:
                return counted(*args, **kwargs)
            return self._call(counted, operation, args, kwargs)

        return observed

    def _validate(self, original: Any) -> Any:
        return self._outside(original, super()._validate(original), "validation")

    def _live(self, original: Any) -> Any:
        return self._outside(original, super()._live(original), "live_proof")

    def _capabilities(self, original: Any) -> Any:
        wrapper = self._outside(original, super()._capabilities(original), "capabilities")
        wrapper.cache_info = original.cache_info
        wrapper.cache_clear = original.cache_clear
        return wrapper

    def _process(self, original: Any) -> Any:
        counted = super()._process(original)

        @functools.wraps(original)
        def observed(path: Any, args: Any, **kwargs: Any) -> Any:
            if args == ("capabilities", "--json") and _ROW.get() is None:
                return self._call(counted, "capability_process", (path, args), kwargs)
            return counted(path, args, **kwargs)

        return observed

    def _hook(self, original: Any) -> Any:
        @functools.wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            payload = args[1] if len(args) > 1 else kwargs.get("payload")
            expected = (
                kwargs.get("default_harness") == "claude-code"
                and isinstance(payload, dict)
                and payload.get("hook_event_name") == "PostToolUse"
            )
            with self._condition:
                index = self._hook_count
                self._hook_count += 1
                valid = expected and index < 3 and self._active_hooks == 0
                self._unexpected += int(not valid)
                self._active_hooks += 1
                if index < 3:
                    self.phase("hook")
                    self.journal.append("hook_started", hook=index, expected=valid)
            token = _OWNER.set(("hook", index) if valid else ("unassigned", None))
            outcome = "raised"
            try:
                result = original(*args, **kwargs)
                outcome = "returned"
                return result
            finally:
                _OWNER.reset(token)
                with self._condition:
                    if index < 3:
                        self.journal.append("hook_finished", hook=index, outcome=outcome)
                    self._active_hooks -= 1
                    self.phase("between_hooks")
                    self._condition.notify_all()

        return observed

    def __enter__(self):
        try:
            super().__enter__()
            self._stack.enter_context(
                patch.object(self.publisher, "_publish_once", self._publication(self.publisher._publish_once))
            )
            return self
        except BaseException:
            with suppress(Exception):
                self.__exit__()
            raise

    def __exit__(self, *_args: Any) -> None:  # pyright: ignore[reportMissingSuperCall]
        # Replace the parent drain with one combined hook/call drain; calling
        # both would add a second timeout and misstate the observer boundary.
        # Keep the existing one-second diagnostic drain bound; never extend a
        # constructor, readiness, ordinary request or fixture deadline.
        active_exception = _args[1] if len(_args) > 1 else sys.exc_info()[1]
        retirement_error: Exception | None = None
        try:
            with self._condition:
                drained = self._condition.wait_for(
                    lambda: not self._active_hooks and not self._active_calls, timeout=1.0
                )
            try:
                self._stack.close()
            except Exception as error:
                retirement_error = error
                self.journal.failed = True
            self.journal.append(
                "observer_finished",
                drained=drained,
                unexpected=self._unexpected,
                overflow=self._overflow,
                recording_failed=self.journal.failed,
                initial_cache_entries=self._initial_cache_entries,
            )
        finally:
            if self._installed:
                self._installed = False
                _INSTALL_LOCK.release()
            self.journal.close()
        if active_exception is None:
            if retirement_error is not None:
                raise retirement_error
            if self.journal.close_failed:
                raise RuntimeError("qualification cold journal close failed")
