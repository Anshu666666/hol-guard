"""Observe original predicate operands and calls without evaluating new probes."""

from __future__ import annotations

import math
import sys
from contextlib import ExitStack
from functools import wraps
from typing import Any
from unittest.mock import patch

from .bindings import Registry
from .capture import CURRENT, Capture
from .projection import error_presence, outcome, snapshot
from .reasons import changed_inputs, marker


def number(value: Any) -> float:
    if type(value) not in {float, int} or not math.isfinite(value):
        raise ValueError("predicate_clock_shape")
    return value


class LocalTime:
    def __init__(self, original: Any, capture: Capture, registry: Registry) -> None:
        self.original, self.capture, self.registry = original, capture, registry

    def monotonic(self) -> float:
        # No additional original clock evaluation; return the identical value.
        result = self.original.monotonic()
        try:
            site = self.registry.site(sys._getframe(1))
            self.capture.clock_return(site, number(result))
        except Exception:
            self.capture.fault()
        return result

    def sleep(self, *args: Any, **kwargs: Any) -> Any:
        return self.original.sleep(*args, **kwargs)


class OwnedHooks:
    def __init__(self, capture: Capture, registry: Registry) -> None:
        self.capture, self.registry = capture, registry
        self.stack = ExitStack()
        self.bindings: list[tuple[Any, str, Any]] = []
        self.restored = False

    def owned(self, kind: str, args: tuple[Any, ...]) -> bool:
        if kind == "publisher":
            return bool(args) and args[0] is self.capture.publisher
        if kind == "worker":
            return bool(args) and args[0] is self.capture.worker
        if kind == "session":
            return bool(args) and args[0] is self.capture.session
        if kind == "store":
            return bool(args) and args[0] is self.capture.store
        current = CURRENT.get()
        return current is not None and current[0] is self.capture and current[2] is not None

    def arguments(self, stage: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
        if stage == "await_ack":
            minimum, action, strict = kwargs["minimum"], kwargs["action"], kwargs["strict"]
            if (
                type(minimum) is not int
                or minimum < 1
                or type(action) is not str
                or action not in {"allow", "block", "review"}
                or type(strict) is not bool
            ):
                raise ValueError("predicate_await_arguments")
            return {"minimum": minimum, "action": action, "strict": strict, "deadline": number(kwargs["deadline"])}
        if stage == "prepare":
            return {"deadline": number(kwargs["deadline"]) if kwargs.get("deadline") is not None else None}
        if stage == "wait_ready":
            value = args[1] if len(args) > 1 else kwargs.get("deadline_monotonic")
            return {"deadline": number(value) if value is not None else None}
        if stage == "policy_input_changed":
            value = args[1] if len(args) > 1 else kwargs.get("changed_paths")
            return changed_inputs(value, vars(self.capture.publisher)["guard_home"])
        if stage == "record_error":
            return error_presence(args[1] if len(args) > 1 else kwargs.get("error"))
        return {}

    def add(self, owner: Any, name: str, stage: str, kind: str, *, project: Any = outcome, prop: bool = False) -> None:
        descriptor = vars(owner)[name] if prop else getattr(owner, name)
        original = descriptor.fget if prop else descriptor

        @wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            if not self.owned(kind, args):
                return original(*args, **kwargs)
            try:
                site = self.registry.site(sys._getframe(1))
                details = self.arguments(stage, args, kwargs)
            except Exception:
                self.capture.fault()
                site, details = "unknown", {}
            return self.capture.call(stage, site, original, args, kwargs, details=details, project=project)

        replacement = property(observed, descriptor.fset, descriptor.fdel, descriptor.__doc__) if prop else observed
        self.stack.enter_context(patch.object(owner, name, replacement))
        self.bindings.append((owner, name, descriptor))

    def __enter__(self) -> OwnedHooks:
        from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
        from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
        from scripts import native_slo_workspace_lifecycle as lifecycle

        try:
            for name, stage in (
                ("request_publish", "request_publish"),
                ("notify_policy_changed", "request_publish"),
                ("_record_error", "record_error"),
                ("_policy_input_changed", "policy_input_changed"),
                ("_configuration_input_changed", "configuration_changed"),
                ("_compiled_effective_policy", "compiled_policy"),
                ("_publish_once", "publish_once"),
                ("close", "publisher_close"),
                ("register_workspace", "register_workspace"),
                ("wait_until_ready", "wait_ready"),
            ):
                self.add(NativePolicySnapshotPublisher, name, stage, "publisher")
            self.add(
                NativePolicySnapshotPublisher,
                "_database_policy_marker",
                "database_policy_marker",
                "publisher",
                project=marker,
            )
            for name in ("current_snapshot", "current_snapshot_binding"):
                self.add(NativePolicySnapshotPublisher, name, name, "publisher", project=snapshot)
            self.add(
                NativePolicySnapshotPublisher,
                "last_error",
                "last_error",
                "publisher",
                project=error_presence,
                prop=True,
            )
            self.add(HookWorker, "prepare_workspace_policy", "prepare", "worker", project=snapshot)
            self.add(lifecycle, "await_ack", "await_ack", "session", project=snapshot)
            self.add(lifecycle, "_authenticated_readback", "authenticated_readback", "store", project=readback)
            self.add(lifecycle, "_readback_matches", "readback_matches", "nested")
            self.add(lifecycle, "public_binding", "public_binding", "nested", project=snapshot)
            original_time = lifecycle.time
            self.stack.enter_context(
                patch.object(lifecycle, "time", LocalTime(original_time, self.capture, self.registry))
            )
            self.bindings.append((lifecycle, "time", original_time))
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        try:
            self.stack.close()
        except Exception:
            self.capture.fault()
        try:
            self.restored = all(getattr(owner, name) is original for owner, name, original in self.bindings)
        except Exception:
            self.restored = False
        if not self.restored:
            self.capture.fault()

    def __exit__(self, *_args: Any) -> None:
        self.close()


def readback(value: Any) -> dict[str, Any]:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError("readback_shape")
    return {"binding": snapshot(value[0]), "authenticated": snapshot(value[1])}
