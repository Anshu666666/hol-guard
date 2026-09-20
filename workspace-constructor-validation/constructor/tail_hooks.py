"""Observe three original post-worker calls; retain opaque authority and fixed counts only."""

from __future__ import annotations

import sys
import types
from functools import wraps
from typing import Any

from .capture import CURRENT, TAIL_ARGUMENTS

CALLER = "codex_plugin_scanner.guard.daemon.server_http:_GuardDaemonHTTPServer._initialize_request_services"
TAIL_SITES = {
    "authority_read": CALLER + ":205",
    "general_executor": CALLER + ":219",
    "control_executor": CALLER + ":226",
}


def install_tail(hooks: Any) -> None:
    from codex_plugin_scanner.guard.daemon import request_executor, server, server_http
    from codex_plugin_scanner.guard.store_extension_control_authority import StoreExtensionControlAuthorityMixin

    capture = hooks.capture
    authority = StoreExtensionControlAuthorityMixin.read_extension_control_authority_for_registry
    executor = request_executor.BoundedRequestExecutor.__init__
    registry = server.BUILT_IN_COMMAND_EXTENSION_REGISTRY
    run = server_http._GuardDaemonHTTPServer._process_request_worker
    discard = server_http._GuardDaemonHTTPServer._discard_request
    if (
        server._BoundedRequestExecutor is not request_executor.BoundedRequestExecutor
        or server.GuardStore.read_extension_control_authority_for_registry is not authority
        or TAIL_ARGUMENTS[1] != (server._MAX_CONCURRENT_DAEMON_REQUESTS, server._MAX_CONCURRENT_DAEMON_CONNECTIONS)
        or TAIL_ARGUMENTS[2]
        != (server._MAX_CONCURRENT_DAEMON_CONTROL_REQUESTS, server._MAX_CONCURRENT_DAEMON_CONNECTIONS)
    ):
        raise ValueError("constructor_tail_alias")
    instances: list[Any] = []

    def selected(frame: types.FrameType) -> str | None:
        if CURRENT.get() is not capture:
            return None
        try:
            site = hooks.registry.site(frame)
        except RuntimeError:
            # These definitions have other callers. Their activity is outside
            # the three exact call sites; missing selected rows cannot pass.
            return None
        return site if site.rsplit(":", 1)[0] == CALLER else None

    @wraps(authority)
    def observed_authority(*args: Any, **kwargs: Any) -> Any:
        try:
            site = selected(sys._getframe(1))
            if site is not None and (
                site != TAIL_SITES["authority_read"]
                or len(args) != 2
                or kwargs
                or args[0] is not capture.store
                or args[1] is not registry
            ):
                raise ValueError("constructor_authority_owner")
        except Exception:
            capture.fault()
            return authority(*args, **kwargs)
        if site is None:
            return authority(*args, **kwargs)
        return capture.tail_call("authority_read", site, authority, args, kwargs)

    @wraps(executor)
    def observed_executor(*args: Any, **kwargs: Any) -> Any:
        try:
            site = selected(sys._getframe(1))
        except Exception:
            capture.fault()
            return executor(*args, **kwargs)
        if site is None:
            return executor(*args, **kwargs)
        try:
            stage = next((name for name in ("general_executor", "control_executor") if TAIL_SITES[name] == site), None)
            if stage is None or len(args) != 1 or set(kwargs) != {"name", "workers", "queue_limit", "run", "discard"}:
                raise ValueError("constructor_executor_site")
            index = 1 if stage == "general_executor" else 2
            if (
                type(kwargs["name"]) is not str
                or kwargs["name"] != stage.removesuffix("_executor")
                or any(type(kwargs[key]) is not int for key in ("workers", "queue_limit"))
                or (kwargs["workers"], kwargs["queue_limit"]) != TAIL_ARGUMENTS[index]
                or len(instances) >= 2
                or any(instance is args[0] for instance in instances)
            ):
                raise ValueError("constructor_executor_arguments")
            for key, expected in (("run", run), ("discard", discard)):
                method = kwargs[key]
                if (
                    type(method) is not types.MethodType
                    or method.__self__ is not capture.http
                    or method.__func__ is not expected
                ):
                    raise ValueError("constructor_executor_owner")
            instances.append(args[0])
        except Exception:
            capture.fault()
            return executor(*args, **kwargs)
        return capture.tail_call(
            stage, site, executor, args, kwargs, workers=kwargs["workers"], queue_limit=kwargs["queue_limit"]
        )

    hooks.bind(StoreExtensionControlAuthorityMixin, "read_extension_control_authority_for_registry", observed_authority)
    hooks.bind(request_executor.BoundedRequestExecutor, "__init__", observed_executor)
