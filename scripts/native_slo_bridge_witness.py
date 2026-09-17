"""Observe the existing bridge stages in one diagnostic fixture request only."""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from typing import Any
from unittest.mock import patch

from codex_plugin_scanner.guard import native_hook_edge
from scripts.native_slo_error_codes import PUBLIC_NATIVE_ERROR_CODES

_ERROR_CODES = PUBLIC_NATIVE_ERROR_CODES
_STATUS_REASONS = frozenset(
    {
        "native_ready",
        "native_disabled",
        "native_unavailable",
        "native_protocol_mismatch",
        "native_version_mismatch",
        "native_manifest_protocol_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_rule_mismatch",
        "native_manifest_build_mismatch",
        "native_manifest_missing",
        "native_manifest_invalid",
        "native_manifest_identity_mismatch",
    }
)
_FAILURE_REASONS = frozenset({"native_hook_edge_unavailable", "native_hook_edge_invalid_response"})
_PATCH_OWNER = threading.Lock()
_ACTIVE_WITNESS: ContextVar[object | None] = ContextVar("native_bridge_witness", default=None)


def _known(value: object, allowed: frozenset[str] | set[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "other"


def _snapshot_state(snapshot: object) -> str:
    if snapshot is None:
        return "missing"
    if not isinstance(snapshot, Mapping):
        return "other"
    generation = snapshot.get("generation")
    return "positive_generation" if type(generation) is int and generation > 0 else "invalid_generation"


@contextmanager
def native_bridge_witness(snapshot: object) -> Iterator[dict[str, object]]:
    """Tap existing calls, preserving arguments, returns, exceptions and order.

    The source matrix invokes this inside its real HTTP handler thread. Module
    wrappers are restored on every exit and ignore calls on other threads. No
    status, serialization, receipt check, native request or clock read is added.
    These are diagnostic boundaries, never independent headline timings.
    """
    owner_thread = threading.get_ident()
    owner = object()
    counts: dict[str, int] = dict.fromkeys(("status", "encode", "client", "decode", "receipt", "failure"), 0)
    observed: dict[str, object] = {
        "scope": "original_calls_current_thread",
        "observer_state": "not_started",
        "observer_error": False,
        "observer_errors_capped_at_two": 0,
        "calls_capped_at_two": counts,
        "snapshot": "not_observed",
        "status_reason": "not_observed",
        "runtime_admitted": None,
        "encoded": None,
        "client_output": "not_observed",
        "response_kind": "not_observed",
        "response_error": "not_observed",
        "response_retryable": None,
        "receipt_accepted": None,
        "decode_accepted": None,
        "recorded_failure": "not_observed",
    }
    errors = 0

    def projection_failed() -> None:
        nonlocal errors
        errors = min(2, errors + 1)
        observed["observer_state"] = "partial"
        observed["observer_error"] = True
        observed["observer_errors_capped_at_two"] = errors

    def is_current() -> bool:
        return threading.get_ident() == owner_thread and _ACTIVE_WITNESS.get() is owner

    def record(stage: str, args: tuple[Any, ...], kwargs: dict[str, Any], result: Any) -> None:
        if stage == "status":
            capabilities = getattr(result, "capabilities", None)
            observed["status_reason"] = _known(getattr(result, "reason", None), _STATUS_REASONS)
            observed["runtime_admitted"] = bool(
                getattr(result, "mode", None) in {"auto", "force"}
                and getattr(result, "available", False)
                and getattr(result, "compatible", False)
                and getattr(result, "identity", None) is not None
                and capabilities is not None
                and {"hook-envelope-v2", "native-resident-client-v1"} <= set(capabilities.features)
            )
        elif stage == "encode":
            observed["encoded"] = isinstance(result, bytes)
        elif stage == "client":
            observed["client_output"] = "none" if result is None else "bytes" if isinstance(result, bytes) else "other"
        elif stage == "decode":
            value = args[0] if args else kwargs.get("payload")
            observed["decode_accepted"] = result is not None
            if isinstance(value, Mapping) and set(value) == {"error", "retryable"}:
                observed["response_kind"] = "error_object"
                observed["response_error"] = _known(value.get("error"), _ERROR_CODES)
                retryable = value.get("retryable")
                observed["response_retryable"] = retryable if isinstance(retryable, bool) else None
            else:
                observed["response_kind"] = (
                    "edge_object"
                    if isinstance(value, Mapping) and value.get("schema") == "guard-hook-edge-result.v2"
                    else "other"
                )
        elif stage == "receipt":
            observed["receipt_accepted"] = result if isinstance(result, bool) else None
        elif stage == "failure":
            observed["recorded_failure"] = _known(kwargs.get("reason"), _FAILURE_REASONS)

    def wrapper(original: Any, stage: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            current = is_current()
            if current:
                counts[stage] = min(2, counts[stage] + 1)
            result = original(*args, **kwargs)
            if current:
                try:
                    record(stage, args, kwargs, result)
                except Exception:
                    # Diagnostics must not replace a successful original return.
                    # The original call stays outside this observer-only catch.
                    projection_failed()
            return result

        return call

    owns_patches = _PATCH_OWNER.acquire(blocking=False)
    token = _ACTIVE_WITNESS.set(owner if owns_patches else None)
    try:
        if not owns_patches:
            # No waiting and no patch installation/restoration. Clearing the
            # context also excludes same-thread nested calls from the owner.
            observed["observer_state"] = "overlap_unavailable"
            yield observed
            return
        observed["observer_state"] = "available"
        try:
            observed["snapshot"] = _snapshot_state(snapshot)
        except Exception:
            projection_failed()
        with ExitStack() as stack:
            try:
                for name, stage in (
                    ("native_runtime_status", "status"),
                    ("_encode_hook_envelope", "encode"),
                    ("native_resident_client_request", "client"),
                    ("_decode_edge", "decode"),
                    ("receipt_matches_edge", "receipt"),
                    ("native_record_resident_failure", "failure"),
                ):
                    stack.enter_context(
                        patch.object(native_hook_edge, name, wrapper(getattr(native_hook_edge, name), stage))
                    )
            except Exception:
                stack.close()
                projection_failed()
                observed["observer_state"] = "setup_unavailable"
            yield observed
    finally:
        _ACTIVE_WITNESS.reset(token)
        if owns_patches:
            _PATCH_OWNER.release()
