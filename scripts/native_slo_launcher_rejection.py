"""Closed failure facts from the already captured installed launcher reply."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import Any

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

_ATTRIBUTE = "_native_launcher_stdout_rejection"
_BYTE_LIMIT = 2 * 1024 * 1024
_COUNT_LIMIT = 65
_TOP_KEYS = (
    "hookSpecificOutput",
    "continue",
    "stopReason",
    "suppressOutput",
    "systemMessage",
    "decision",
    "reason",
    "policy_action",
    "reason_code",
    "model_output_action",
    "native_result",
    "native_decision_receipt",
)
_SPECIFIC_KEYS = (
    "hookEventName",
    "permissionDecision",
    "permissionDecisionReason",
    "additionalContext",
    "updatedMCPToolOutput",
)
_PRESENCE_LABELS = {
    "hookSpecificOutput": "event_container",
    "suppressOutput": "suppress_reply",
    "model_output_action": "model_action",
    "updatedMCPToolOutput": "updated_mcp_reply",
}
_REASONS = frozenset(
    {
        "native_post_tool_unavailable",
        "native_hook_edge_unavailable",
        "native_policy_unavailable",
        "native_review_required",
        "daemon_capacity",
        "daemon_hook_deadline_exhausted",
        "native_overloaded",
    }
)


def _known(value: object, values: tuple[str, ...] | frozenset[str]) -> str:
    return value if isinstance(value, str) and value in values else "other"


def _count(value: object, limit: int) -> int | None:
    return value if type(value) is int and 0 <= value <= limit else None


def _keys(value: Mapping[str, object], known: tuple[str, ...]) -> dict[str, object]:
    presence = {_PRESENCE_LABELS.get(key, key): key in value for key in known}
    return {
        "presence": presence,
        "total_capped_at_65": min(_COUNT_LIMIT, len(value)),
        "unknown_capped_at_65": min(_COUNT_LIMIT, len(value) - sum(presence.values())),
        "count_saturated": len(value) >= _COUNT_LIMIT,
    }


def _project_keys(value: object, known: tuple[str, ...]) -> dict[str, object]:
    source = value if isinstance(value, Mapping) else {}
    presence = source.get("presence")
    presence = presence if isinstance(presence, Mapping) else {}
    return {
        "presence": {
            _PRESENCE_LABELS.get(key, key): presence.get(_PRESENCE_LABELS.get(key, key)) is True for key in known
        },
        "total_capped_at_65": _count(source.get("total_capped_at_65"), _COUNT_LIMIT),
        "unknown_capped_at_65": _count(source.get("unknown_capped_at_65"), _COUNT_LIMIT),
        "count_saturated": source.get("count_saturated") is True,
    }


def _project(value: object) -> dict[str, object]:
    source = value if isinstance(value, Mapping) else {}
    digest = source.get("decoded_stdout_utf8_sha256")
    valid_digest = (
        isinstance(digest, str) and len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)
    )
    return {
        "schema": "hol-guard.native-launcher-stdout-rejection.v1",
        "capture_state": _known(source.get("capture_state"), ("captured", "projection_unavailable")),
        "harness": _known(source.get("harness"), ("codex", "claude-code")),
        "event": _known(source.get("event"), ("PreToolUse", "PostToolUse")),
        "case": _known(source.get("case"), ("benign", "block")),
        "stdout_identity_scope": "utf8_reencoding_of_decoded_stdout",
        "original_stream_bytes_proven": False,
        "decoded_stdout_utf8_bytes": _count(source.get("decoded_stdout_utf8_bytes"), _BYTE_LIMIT),
        "decoded_stdout_utf8_sha256": digest if valid_digest else None,
        "exit_state": _known(source.get("exit_state"), ("zero", "nonzero", "missing")),
        "timed_out": source.get("timed_out") is True,
        "containment_failed": source.get("containment_failed") is True,
        "reply_limit_exceeded": source.get("reply_limit_exceeded") is True,
        "top_level": _project_keys(source.get("top_level"), _TOP_KEYS),
        "specific": _project_keys(source.get("specific"), _SPECIFIC_KEYS),
        "specific_is_object": source.get("specific_is_object") is True,
        "specific_event": _known(source.get("specific_event"), ("PreToolUse", "PostToolUse")),
        "continue_state": _known(source.get("continue_state"), ("true", "false", "absent", "other")),
        "permission": _known(source.get("permission"), ("allow", "deny", "ask", "absent")),
        "decision": _known(source.get("decision"), ("allow", "block", "review", "absent")),
        "policy_action": _known(source.get("policy_action"), ("allow", "block", "review", "warn", "absent")),
        "model_action": _known(source.get("model_action"), ("allow_original", "block", "absent")),
        "reason_code": _known(source.get("reason_code"), _REASONS | {"absent"}),
        "native_authority_proven": False,
        "availability_cause": "unproved",
        "accepted": False,
        "qualification_complete": False,
        "diagnostic_after_process_timer": True,
    }


def _capture(
    launcher: Any, completed: BoundedHookProcessResult, response: Mapping[str, object], case: str
) -> dict[str, object]:
    # The process runner already enforces this decoded stdout bound. Avoid an
    # unbounded allocation if a broken fixture ever bypasses that contract.
    if len(completed.stdout) > _BYTE_LIMIT:
        raise ValueError("launcher_rejection_diagnostic_bound")
    encoded = completed.stdout.encode("utf-8")
    if len(encoded) > _BYTE_LIMIT:
        raise ValueError("launcher_rejection_diagnostic_bound")
    specific = response.get("hookSpecificOutput")
    is_object = isinstance(specific, Mapping)
    specific = specific if isinstance(specific, Mapping) else {}
    continuation = response.get("continue")
    return _project(
        {
            "capture_state": "captured",
            "harness": launcher.harness,
            "event": launcher.event,
            "case": case,
            "decoded_stdout_utf8_bytes": len(encoded),
            "decoded_stdout_utf8_sha256": hashlib.sha256(encoded).hexdigest(),
            "exit_state": "missing"
            if completed.returncode is None
            else "zero"
            if completed.returncode == 0
            else "nonzero",
            "timed_out": completed.timed_out,
            "containment_failed": completed.containment_failed,
            "reply_limit_exceeded": completed.output_limit_exceeded,
            "top_level": _keys(response, _TOP_KEYS),
            "specific": _keys(specific, _SPECIFIC_KEYS),
            "specific_is_object": is_object,
            "specific_event": specific.get("hookEventName"),
            "continue_state": (
                "absent"
                if "continue" not in response
                else "true"
                if continuation is True
                else "false"
                if continuation is False
                else "other"
            ),
            "permission": specific.get("permissionDecision", "absent"),
            "model_action": response.get("model_output_action", "absent"),
            **{key: response.get(key, "absent") for key in ("decision", "policy_action", "reason_code")},
        }
    )


def validate_stdout_with_witness(
    validator: Callable[..., None],
    launcher: Any,
    completed: BoundedHookProcessResult,
    response: Mapping[str, object],
    *,
    case: str,
) -> None:
    try:
        validator(launcher, response, case=case)
    except RuntimeError as error:
        try:
            setattr(error, _ATTRIBUTE, _capture(launcher, completed, response, case))
        except Exception:
            with suppress(Exception):
                setattr(error, _ATTRIBUTE, {"capture_state": "projection_unavailable"})
        raise


def launcher_rejection_detail(error: Exception) -> dict[str, object] | None:
    try:
        value = getattr(error, _ATTRIBUTE, None)
        return _project(value) if value is not None else None
    except Exception:
        # Export failures never replace the original validator exception.
        return {"schema": "hol-guard.native-launcher-stdout-rejection.v1", "capture_state": "projection_unavailable"}
