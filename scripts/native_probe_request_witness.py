"""Finite diagnostics for the original normalized installed-corpus request."""

from __future__ import annotations

import json
import sys
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager, suppress

_HARNESSES = frozenset(
    {
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "pi",
        "zcode",
    }
)
_EVENTS = frozenset({"PreToolUse", "PostToolUse"})


def request_failure_report(
    harness: object, event: object, validated_routes_before: object, error: BaseException
) -> dict[str, object]:
    """Project only closed context; never inspect exception text or request data."""
    timeout = isinstance(error, TimeoutError) or (
        isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError)
    )
    return {
        "schema": "hol-guard.installed-corpus-request-failure.v1",
        "harness": harness if isinstance(harness, str) and harness in _HARNESSES else "other",
        "event": event if isinstance(event, str) and event in _EVENTS else "other",
        "validated_routes_before": (
            validated_routes_before
            if type(validated_routes_before) is int and 0 <= validated_routes_before <= 32
            else None
        ),
        "failure": "timeout" if timeout else "request_exception",
        "transport_timeout_seconds": 5,
        "original_request_calls": 1,
        "request_returned": False,
        "retry_attempted": False,
        "native_route_proven": False,
        "cause_proven": False,
    }


def _emit(report: dict[str, object]) -> None:
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)


@contextmanager
def installed_request_witness(harness: str, event: str, *, validated_routes_before: int) -> Iterator[None]:
    """Observe one existing call without changing its result, timeout or exception.

    The installed client owns its unchanged five-second transport timeout. This
    witness adds no deadline or retry and runs its diagnostic only after failure.
    Failure to emit a diagnostic must not replace the original request exception.
    """
    try:
        yield
    except BaseException as error:
        with suppress(BaseException):
            _emit(request_failure_report(harness, event, validated_routes_before, error))
        raise
