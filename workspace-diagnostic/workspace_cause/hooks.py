"""Observe existing publisher branches and owned constructor calls without new probes."""

from __future__ import annotations

import contextvars
from contextlib import ExitStack
from functools import wraps
from typing import Any, cast
from unittest.mock import patch

from .capture import Capture, current_capture, error_code

_CONFIRM_DIRECTORY: contextvars.ContextVar[tuple[Capture, Any] | None] = contextvars.ContextVar(
    "workspace_cause_confirm_directory", default=None
)


class OwnedHooks:
    """Patch only for one disposable helper process and one exact owned home."""

    def __init__(self, capture: Capture) -> None:
        self.capture = capture
        self.stack = ExitStack()
        self.bindings: list[tuple[Any, str, Any]] = []
        self.restored = False

    def _publisher(self, kind: str, args: tuple[Any, ...]) -> Any:
        if kind == "publisher" and args and self.capture.owns(args[0]):
            return args[0]
        if kind == "lifecycle" and args and self.capture.owns(args[0]):
            return args[0].daemon._server.hook_worker.policy_snapshot_publisher
        return None

    def _owned(self, kind: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
        if kind in {"publisher", "store", "lifecycle"}:
            return bool(args) and self.capture.owns(args[0])
        if kind == "http":
            return bool(args) and self.capture.owns(getattr(args[0], "store", None))
        if kind == "service":
            store = args[1] if len(args) > 1 else kwargs.get("store")
            return self.capture.owns(store)
        if kind == "worker":
            return self.capture.owns(kwargs.get("store"))
        return current_capture() is self.capture

    def _details(self, stage: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
        if stage == "record_error":
            return {"error": error_code(args[1] if len(args) > 1 else kwargs.get("error"))}
        if stage == "resident_confirm":
            before = args[1] if len(args) > 1 else kwargs["before"]
            observed = args[2] if len(args) > 2 else kwargs["observed"]
            return {
                "before_present": bool(before),
                "before_observed_equal": before == observed,
                "observed_count": len(observed),
                "observed_directory_present": (args[4] if len(args) > 4 else kwargs["observed_directory"]) is not None,
            }
        if stage == "input_reconcile":
            changed = args[1] if len(args) > 1 else kwargs.get("changed_paths")
            return {"changed_hint_count": len(changed)} if changed is not None else {}
        if stage in {"wait_ready", "await_ack"}:
            if stage == "wait_ready":
                deadline = args[1] if len(args) > 1 else kwargs.get("deadline_monotonic")
            else:
                deadline = kwargs.get("deadline")
            if type(deadline) in {int, float}:
                return {"deadline_from_origin_ms": (cast(float, deadline) - self.capture.started) * 1000}
        if stage == "request_executor_constructor":
            name = kwargs.get("name")
            return {"executor_kind": name if name in {"general", "control"} else "other"}
        return {}

    def _summary(self, stage: str, publisher: Any, result: Any) -> dict[str, Any]:
        if stage == "input_fingerprint" and publisher is not None:
            previous = publisher._input_fingerprint
            if previous is None:
                return {"prior_input_present": False}
            if type(previous) is not tuple or type(result) is not tuple or len(previous) != 2 or len(result) != 2:
                raise ValueError("diagnostic_input_shape")
            return {
                "prior_input_present": True,
                "configuration_metadata_changed": previous[0] != result[0],
                "resident_metadata_changed": previous[1] != result[1],
            }
        if stage == "resident_directory":
            expected = _CONFIRM_DIRECTORY.get()
            if expected is not None and expected[0] is self.capture:
                return {"confirmation_directory_equal": result == expected[1]}
        return {}

    def add(self, owner: Any, name: str, stage: str, kind: str, *, static: bool = False) -> None:
        original = getattr(owner, name)

        @wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            try:
                owned = self._owned(kind, args, kwargs)
                publisher = self._publisher(kind, args) if owned else None
                details = self._details(stage, args, kwargs) if owned else None
            except Exception:
                self.capture.fault()
                owned, publisher, details = False, None, None
            if not owned:
                return original(*args, **kwargs)
            token = None
            try:
                if stage == "resident_confirm":
                    expected = args[4] if len(args) > 4 else kwargs["observed_directory"]
                    try:
                        token = _CONFIRM_DIRECTORY.set((self.capture, expected))
                    except Exception:
                        self.capture.fault()
                return self.capture.call(
                    stage,
                    original,
                    args,
                    kwargs,
                    publisher=publisher,
                    details=details,
                    summarize=lambda result: self._summary(stage, publisher, result),
                )
            finally:
                if token is not None:
                    try:
                        _CONFIRM_DIRECTORY.reset(token)
                    except Exception:
                        self.capture.fault()

        replacement = staticmethod(observed) if static else observed
        self.stack.enter_context(patch.object(owner, name, replacement))
        self.bindings.append((owner, name, original))

    def __enter__(self) -> OwnedHooks:
        from codex_plugin_scanner.guard.daemon import hook_worker, server, server_http, server_service
        from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
        from codex_plugin_scanner.guard.store import GuardStore
        from scripts import native_slo_workspace_lifecycle

        publisher = NativePolicySnapshotPublisher
        methods = (
            ("_publish_once", "publication"),
            ("_publication_context", "publication_context"),
            ("_compiled_effective_policy", "configuration_compile"),
            ("_compiled_command_extensions", "authority_capture"),
            ("_current_input_fingerprint", "input_fingerprint"),
            ("_policy_input_changed", "input_reconcile"),
            ("_configuration_input_changed", "configuration_changed"),
            ("request_publish", "request_publish"),
            ("notify_policy_changed", "request_publish"),
            ("start", "publisher_start"),
            ("close", "publisher_close"),
            ("register_workspace", "workspace_register"),
            ("_record_error", "record_error"),
            ("_mark_expired_locked", "mark_expired"),
            ("_confirm_resident_fingerprint", "resident_confirm"),
            ("_resident_directory_fingerprint", "resident_directory"),
            ("_resident_paths_match", "resident_paths"),
            ("wait_until_ready", "wait_ready"),
        )
        try:
            for name, stage in methods:
                self.add(publisher, name, stage, "publisher")
            self.add(
                publisher,
                "_resident_fingerprint_matches_generation",
                "resident_generation",
                "nested",
                static=True,
            )
            self.add(GuardStore, "read_extension_control_authority_for_registry", "authority_registry_read", "store")
            self.add(server_service.GuardDaemonServer, "__init__", "service_constructor", "service")
            self.add(hook_worker.HookWorker, "__init__", "hook_worker_constructor", "worker")
            self.add(server_http._GuardDaemonHTTPServer, "_initialize_request_services", "request_services", "http")
            self.add(server_http._GuardDaemonHTTPServer, "server_bind", "http_bind", "http")
            self.add(server_http._GuardDaemonHTTPServer, "server_activate", "http_activate", "http")
            for name, stage in (
                ("ExtensionControlRuntime", "extension_runtime_constructor"),
                ("ExtensionControlApiService", "extension_api_constructor"),
                ("LocalCliApiService", "local_cli_constructor"),
                ("ApprovalAttentionCoordinator", "approval_attention_constructor"),
                ("_BoundedRequestExecutor", "request_executor_constructor"),
            ):
                self.add(getattr(server, name), "__init__", stage, "nested")
            self.add(native_slo_workspace_lifecycle, "await_ack", "await_ack", "lifecycle")
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
