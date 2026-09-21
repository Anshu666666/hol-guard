"""Mechanical Python launcher for Rust PreToolUse authority.

This module validates and returns the native decision. It does not parse,
classify, or lower the semantic result. Command-model shadow comparison stays
in native_command_model and is not a PreToolUse authority.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resident import resident_native_request
from .native_runtime_resilience import (
    native_oneshot_lease,
    native_record_oneshot_failure,
    native_record_oneshot_success,
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
)

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_PRETOOL_AUTHORITY_FEATURE = "pre-tool-command-authority-v1"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"


def _decode_pre_tool(payload: object, *, command: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    decision = payload.get("decision")
    action = payload.get("minimum_action") or payload.get("policy_action")
    reason_code = payload.get("reason_code")
    reason = payload.get("reason")
    explicitly_benign = payload.get("explicitly_benign")
    model = payload.get("command_model")
    if (
        not isinstance(decision, str)
        or decision not in {"allow", "deny"}
        or not isinstance(action, str)
        or action not in {"allow", "review", "block"}
        or not isinstance(reason_code, str)
        or not reason_code
        or not isinstance(reason, str)
        or not reason
        or not isinstance(explicitly_benign, bool)
        or not isinstance(model, dict)
        or model.get("normalized_text") != command.strip()
    ):
        return None
    if explicitly_benign != (decision == "allow" and action == "allow"):
        return None
    return payload


def review_pre_tool_native(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None,
    home_dir: Path | None,
    timeout_seconds: float = 0.5,
) -> dict[str, Any] | None:
    """Return the Rust PreToolUse decision, or None when native cannot decide."""
    del cwd, home_dir
    status = native_runtime_status()
    if (
        status.mode == "off"
        or not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _PRETOOL_AUTHORITY_FEATURE not in status.capabilities.features
        or timeout_seconds <= 0
    ):
        return None
    timeout_seconds = min(timeout_seconds, 1.0)
    request = {
        "command": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
    }
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > _MAX_REQUEST_BYTES:
        return None
    environment = _isolated_environment()

    if _RESIDENT_PROTOCOL_FEATURE in status.capabilities.features:
        resident_envelope = json.dumps(
            {"operation": "pre_tool_use", "request": request},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        resident_output = resident_native_request(
            executable=status.identity.path,
            identity_sha256=status.identity.sha256,
            guard_home=guard_home,
            environment=environment,
            payload=resident_envelope,
            timeout_seconds=timeout_seconds,
        )
        if resident_output is not None:
            try:
                resident_payload = json.loads(resident_output)
            except (UnicodeDecodeError, json.JSONDecodeError):
                resident_payload = None
            if _native_error(resident_payload) == "native_overloaded":
                native_record_overload(status.identity.sha256, guard_home)
                return None
            decoded = _decode_pre_tool(resident_payload, command=command)
            if decoded is not None:
                native_record_resident_success(status.identity.sha256, guard_home)
                return decoded
        native_record_resident_failure(
            status.identity.sha256,
            guard_home,
            reason="native_pre_tool_resident_unavailable",
        )

    with native_oneshot_lease(status.identity.sha256, guard_home) as acquired:
        if not acquired:
            return None
        result = run_isolated_hook_process(
            (str(status.identity.path), "pre-tool-use", "--stdin"),
            input_text=encoded.decode("utf-8"),
            cwd=status.identity.path.parent,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=_MAX_RESPONSE_BYTES,
        )
        if result.returncode != 0 or result.timed_out or result.output_limit_exceeded or result.containment_failed:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pre_tool_oneshot_failed",
            )
            return None
        try:
            decoded = _decode_pre_tool(json.loads(result.stdout), command=command)
        except json.JSONDecodeError:
            decoded = None
        if decoded is None:
            native_record_oneshot_failure(
                status.identity.sha256,
                guard_home,
                reason="native_pre_tool_oneshot_invalid",
            )
            return None
        native_record_oneshot_success(status.identity.sha256, guard_home)
        return decoded


__all__ = [
    "review_pre_tool_native",
]
