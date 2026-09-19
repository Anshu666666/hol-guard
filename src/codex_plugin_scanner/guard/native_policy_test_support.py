"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .native_approval_errors import FINITE_FAILURE_CODES
from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .native_resident_client import native_resident_client_failure_code, native_resident_client_request
from .store import GuardStore

_DIAGNOSTIC_FAILURE_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
    }
)


def _finite_failure(value: object) -> str:
    if value is None:
        return "missing"
    return value if isinstance(value, str) and value in _DIAGNOSTIC_FAILURE_CODES else "other"


class _PublicationDiagnostics:
    """Keep finite completed-call observations even if a retry clears its error."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = 0
        self._completed = 0
        self._failure = "missing"

    def call(self, client: Callable[..., bytes | None], **kwargs: Any) -> bytes | None:
        with self._lock:
            self._started = min(self._started + 1, 999)
        try:
            return client(**kwargs)
        finally:
            # The failure code is context-local, so read it in the same worker
            # immediately after the unchanged native transport invocation.
            code = _finite_failure(native_resident_client_failure_code())
            with self._lock:
                self._completed = min(self._completed + 1, 999)
                if code != "missing":
                    self._failure = code

    def describe(self, publisher_error: object) -> str:
        with self._lock:
            return (
                f"publisher={_finite_failure(publisher_error)}; transport={self._failure}; "
                f"started={self._started}; completed={self._completed}"
            )


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    diagnostics = _PublicationDiagnostics()
    previous_client = publisher._client_request
    if previous_client is None:
        publisher._client_request = lambda **kwargs: diagnostics.call(native_resident_client_request, **kwargs)
    try:
        publisher.start()
        ready_wait_seconds = 25.0 if sys.platform == "win32" else 3.0
        if not publisher.wait_until_ready(time.monotonic() + ready_wait_seconds):
            raise AssertionError(f"native policy publisher was not ready: {diagnostics.describe(publisher.last_error)}")
        snapshot = publisher.current_snapshot()
        if snapshot is None:
            raise AssertionError("native policy publisher returned no ACKed snapshot")
        yield snapshot
    finally:
        try:
            publisher.close()
        finally:
            publisher._client_request = previous_client
