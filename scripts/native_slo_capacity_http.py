"""Classify bounded HTTP capacity evidence without promoting unknown failures."""

from __future__ import annotations

import json
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler

MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_CAPACITY_REASON_CODES = frozenset(
    {
        "daemon_capacity",
        "daemon_overloaded",
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_hook_deadline_exhausted",
        "native_overloaded",
    }
)
_CAPACITY_HTTP_BODY = (
    BaseHTTPRequestHandler.error_message_format
    % {
        "code": 503,
        "message": "Guard daemon request capacity reached",
        "explain": BaseHTTPRequestHandler.responses[503][1],
    }
).strip()


def is_explicit_capacity_response(response: Mapping[str, object]) -> bool:
    """Recognize only the daemon's finite, typed capacity reason codes."""
    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code in _CAPACITY_REASON_CODES


def capacity_http_response(status: int, detail: str, *, authenticated: bool = True) -> Mapping[str, object]:
    """Accept the exact production 503 body or retain a typed capacity response.

    The authenticated adapters distinguish discovery failures from hook replies.
    Generic HTTP callers already address the fixture's own private daemon. An
    unknown status/body remains a request failure, including generic 503 errors.
    """
    if len(detail) > MAX_HTTP_RESPONSE_BYTES or len(detail.encode("utf-8")) > MAX_HTTP_RESPONSE_BYTES:
        raise RuntimeError("adapter response exceeded bound")
    if status != 503 or not authenticated:
        raise RuntimeError("adapter request failed")
    if detail.strip() == _CAPACITY_HTTP_BODY:
        return {
            "decision": "deny",
            "model_output_action": "block",
            "policy_action": "deny",
            "reason_code": "daemon_capacity",
        }
    try:
        response = json.loads(detail)
    except (ValueError, RecursionError) as error:
        raise RuntimeError("adapter HTTP failure was not a proven capacity result") from error
    if isinstance(response, Mapping) and is_explicit_capacity_response(response):
        # Preserve all delivered semantics. In particular an inconsistent
        # allow+capacity response must fail the wave's outcome conservation.
        return response
    raise RuntimeError("adapter HTTP failure was not a proven capacity result")
