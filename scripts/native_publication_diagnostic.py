"""Finite observations of an existing publisher during an installed probe."""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from typing import Any

from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    native_resident_client_request,
)

_CODES = FINITE_FAILURE_CODES | frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
        "native_client_start_failed",
        "native_client_stream_failed",
        "native_client_stdin_unavailable",
        "native_client_frame_write_failed",
        "native_client_request_invalid",
        "native_client_launcher_failed",
    }
)


def _finite_code(value: object) -> str:
    if value is None:
        return "missing"
    return value if type(value) is str and value in _CODES else "other"


class PublicationObservation:
    """No waits, starts, snapshots, or retained request/response material."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = 0
        self._completed = 0
        self._failure = "missing"
        self.attached = False

    def call(self, client: Callable[..., bytes | None], **kwargs: Any) -> bytes | None:
        __tracebackhide__ = True
        with self._lock:
            self._started = min(999, self._started + 1)
        try:
            return client(**kwargs)
        finally:
            # Failure state belongs to the calling worker, not the observer thread.
            code = _finite_code(native_resident_client_failure_code())
            with self._lock:
                self._completed = min(999, self._completed + 1)
                if code != "missing":
                    self._failure = code

    def describe(self, publisher_error: object) -> str:
        with self._lock:
            return (
                "window=after_daemon_construction; "
                f"attached={self.attached}; publisher={_finite_code(publisher_error)}; "
                f"transport={self._failure}; started={self._started}; completed={self._completed}"
            )


@contextmanager
def observe_publication(publisher: Any) -> Iterator[PublicationObservation]:
    """Attach to future calls only; an already captured client stays untouched."""
    observation = PublicationObservation()
    missing = object()
    previous = getattr(publisher, "_client_request", missing)
    if previous is None:

        def client(**kwargs: Any) -> bytes | None:
            __tracebackhide__ = True
            return observation.call(native_resident_client_request, **kwargs)

        publisher._client_request = client
        observation.attached = True
    try:
        yield observation
    finally:
        if observation.attached:
            publisher._client_request = previous


def report_publication_failure(observation: PublicationObservation, publisher: Any) -> None:
    """Best-effort finite evidence must never replace the original failure."""
    with suppress(BaseException):
        print(
            "native_publication_observation: " + observation.describe(getattr(publisher, "last_error", None)),
            file=sys.stderr,
        )


def cleanup_after_failure(cleanup: Callable[[], object]) -> None:
    """Call the original cleanup once while preserving the active exception."""
    __tracebackhide__ = True
    try:
        cleanup()
    except BaseException:
        with suppress(BaseException):
            print("native_probe_cleanup=failed", file=sys.stderr)


@contextmanager
def cleanup_preserving_failure(cleanup: Callable[[], object]) -> Iterator[None]:
    __tracebackhide__ = True
    try:
        yield
    except BaseException:
        cleanup_after_failure(cleanup)
        raise
    else:
        cleanup()
