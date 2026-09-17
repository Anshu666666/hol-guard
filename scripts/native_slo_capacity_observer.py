"""Observe actual concurrent responses and wait for isolated wave bookkeeping."""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

from scripts.native_slo_adapter import Observation, is_allowed, payload

if TYPE_CHECKING:
    from scripts.native_slo_session import AdapterSession


def observe_unattributed(self: AdapterSession, harness: str, event: str, size_class: str) -> Observation:
    """Keep delivered outcomes while reserving route proof for the whole wave."""
    from scripts.native_slo_session import _is_explicit_capacity_response, _request

    request = payload(event, size_class)
    started = time.perf_counter()
    response = _request(
        self.daemon,
        guard_home=self.guard_home,
        workspace=self.workspace,
        harness=harness,
        request_payload=request,
        connection=self._connection if threading.get_ident() == self._owner_thread_id else None,
    )
    elapsed_ms = (time.perf_counter() - started) * 1_000.0
    return Observation(
        harness,
        event,
        size_class,
        elapsed_ms,
        "pending_batch_validation",
        is_allowed(event, response),
        _is_explicit_capacity_response(response),
    )


def capacity_route_snapshot(self: AdapterSession) -> Mapping[str, object]:
    routes = self.daemon._server.hook_worker.metrics.snapshot().get("routes")
    if not isinstance(routes, Mapping):
        raise RuntimeError("native_installed_slo_failed: capacity route counters unavailable")
    return dict(routes)


def wait_for_capacity_bookkeeping(self: AdapterSession, timeout_seconds: float = 5.0) -> bool:
    """Wait outside request timers until serving hooks finish bookkeeping."""
    deadline = time.monotonic() + timeout_seconds
    server = self.daemon._server
    while True:
        with server.hook_capacity_lock:
            if server.active_hook_requests == 0:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)
