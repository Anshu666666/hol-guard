"""Forward exact owned constructor calls and the original acceptance clock."""

from __future__ import annotations

import sys
import types
from contextlib import ExitStack
from functools import wraps
from typing import Any, Protocol
from unittest.mock import patch

from .capture import CURRENT, Capture

CALLERS = {
    "service_constructor": "scripts.native_slo_workspace_lifecycle_service:replace_service",
    "http_constructor": "codex_plugin_scanner.guard.daemon.server_service:GuardDaemonServer.__init__",
    "request_services": "codex_plugin_scanner.guard.daemon.server_http:_GuardDaemonHTTPServer.__init__",
    "hook_worker_constructor": (
        "codex_plugin_scanner.guard.daemon.server_http:_GuardDaemonHTTPServer._initialize_request_services"
    ),
    "publisher_wait": "codex_plugin_scanner.guard.daemon.hook_worker:HookWorker.__init__",
}
FACTORY_CALLER = "scripts.native_slo_workspace_startup:prepare_owned_publisher.<locals>.observed"
ACCEPTANCE_SITE = "scripts.native_slo_workspace_lifecycle:run_lifecycle_cell.<locals>.prepare_service:169"


class CallSites(Protocol):
    def site(self, frame: types.FrameType, /) -> str: ...


class LocalTime:
    def __init__(self, original: Any, capture: Capture, registry: CallSites) -> None:
        self.original, self.capture, self.registry = original, capture, registry

    def monotonic(self) -> float:
        result = self.original.monotonic()
        if CURRENT.get() is self.capture:
            try:
                if self.registry.site(sys._getframe(1)) == ACCEPTANCE_SITE:
                    self.capture.acceptance(result)
            except Exception:
                self.capture.fault()
        return result

    def sleep(self, *args: Any, **kwargs: Any) -> Any:
        return self.original.sleep(*args, **kwargs)


class OwnedHooks:
    def __init__(self, capture: Capture, registry: CallSites) -> None:
        self.capture, self.registry = capture, registry
        self.stack = ExitStack()
        self.bindings: list[tuple[Any, str, Any]] = []
        self.restored = False

    def bind(self, owner: Any, name: str, replacement: Any) -> None:
        original = getattr(owner, name)
        self.stack.enter_context(patch.object(owner, name, replacement))
        self.bindings.append((owner, name, original))

    def owner(self, stage: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        if not self.capture.active() or not args:
            raise ValueError("constructor_thread_or_arguments")
        capture, instance = self.capture, args[0]
        if stage == "service_constructor":
            store = args[1] if len(args) > 1 else kwargs.get("store")
            if capture.service is not None or store is None:
                raise ValueError("constructor_service_owner")
            capture.service, capture.store = instance, store
        elif stage == "http_constructor":
            if capture.http is not None or kwargs.get("store") is not capture.store:
                raise ValueError("constructor_http_owner")
            capture.http = instance
        elif stage == "request_services":
            if instance is not capture.http:
                raise ValueError("constructor_services_owner")
        elif stage == "hook_worker_constructor":
            if capture.worker is not None or kwargs.get("store") is not capture.store:
                raise ValueError("constructor_worker_owner")
            capture.worker = instance
        elif stage == "publisher_wait":
            if instance is not capture.publisher or capture.accepted is None:
                raise ValueError("constructor_publisher_owner")
        else:
            raise ValueError("constructor_unknown_stage")

    def add(self, owner: Any, name: str, stage: str) -> None:
        original = getattr(owner, name)

        @wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            if CURRENT.get() is not self.capture:
                return original(*args, **kwargs)
            try:
                site = self.registry.site(sys._getframe(1))
                if site.rsplit(":", 1)[0] != CALLERS[stage]:
                    raise ValueError("constructor_call_site")
                self.owner(stage, args, kwargs)
            except Exception:
                self.capture.fault()
                return original(*args, **kwargs)
            return self.capture.call(stage, CALLERS[stage], original, args, kwargs)

        self.bind(owner, name, observed)

    def __enter__(self) -> OwnedHooks:
        from codex_plugin_scanner.guard.daemon import hook_worker, server, server_http, server_service
        from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
        from scripts import native_slo_workspace_lifecycle as lifecycle

        try:
            if (
                server.GuardDaemonServer is not server_service.GuardDaemonServer
                or server._GuardDaemonHttpServer is not server_http._GuardDaemonHTTPServer
            ):
                raise ValueError("constructor_class_alias")
            self.add(server_service.GuardDaemonServer, "__init__", "service_constructor")
            self.add(server_http._GuardDaemonHTTPServer, "__init__", "http_constructor")
            self.add(server_http._GuardDaemonHTTPServer, "_initialize_request_services", "request_services")
            self.add(hook_worker.HookWorker, "__init__", "hook_worker_constructor")
            self.add(NativePolicySnapshotPublisher, "wait_until_ready", "publisher_wait")
            replacement = lifecycle.replace_service

            @wraps(replacement)
            def replace(*args: Any, **kwargs: Any) -> Any:
                if not args or args[0] is not self.capture.session:
                    return replacement(*args, **kwargs)
                try:
                    site = self.registry.site(sys._getframe(1))
                    if site != "scripts.native_slo_workspace_lifecycle:run_lifecycle_cell:190":
                        raise ValueError("constructor_replacement_site")
                except Exception:
                    self.capture.fault()
                    return replacement(*args, **kwargs)
                return self.capture.replacement(replacement, args, kwargs)

            self.bind(lifecycle, "replace_service", replace)
            factory = hook_worker.get_native_policy_snapshot_publisher

            @wraps(factory)
            def publisher(*args: Any, **kwargs: Any) -> Any:
                result = factory(*args, **kwargs)
                if CURRENT.get() is self.capture:
                    try:
                        site = self.registry.site(sys._getframe(1))
                        if site.rsplit(":", 1)[0] != FACTORY_CALLER or len(args) != 1:
                            raise ValueError("constructor_factory_site")
                        self.capture.adopt(result, args[0])
                    except Exception:
                        self.capture.fault()
                return result

            self.bind(hook_worker, "get_native_policy_snapshot_publisher", publisher)
            self.bind(lifecycle, "time", LocalTime(lifecycle.time, self.capture, self.registry))
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
