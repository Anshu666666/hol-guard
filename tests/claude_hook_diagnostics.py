"""Finite diagnostics for a generated hook's synthetic regression test."""

from __future__ import annotations

import json
import math
import re
import subprocess
from typing import cast

import pytest

_DEGRADED_PREFIX = "HOL Guard could not reach the local daemon ("
_DEGRADED_SUFFIX = ") and continued this action without native review."
_REASON_SUFFIXES = (
    ("; fallback exhausted the hook deadline", "fallback_deadline_exhausted"),
    ("; fallback timed out", "fallback_timed_out"),
    ("; fallback returned malformed hook JSON", "fallback_invalid_json"),
    ("; recovered daemon returned malformed hook JSON", "recovered_daemon_invalid_json"),
)


def _reason_category(reason: object) -> str:
    if type(reason) is not str or len(reason) > 8192:
        return "unrecognized"
    if not (reason.startswith(_DEGRADED_PREFIX) and reason.endswith(_DEGRADED_SUFFIX)):
        return "unrecognized"
    detail = reason[len(_DEGRADED_PREFIX) : -len(_DEGRADED_SUFFIX)]
    for suffix, category in _REASON_SUFFIXES:
        if detail.endswith(suffix):
            return category
    if re.search(r"; fallback exited (?:-?[0-9]{1,3}|None)$", detail):
        return "fallback_exited"
    if detail == "daemon returned malformed hook JSON":
        return "daemon_invalid_json"
    return "degraded_other"


def claude_hook_diagnostics(
    payload: object,
    *,
    returncode: object,
    elapsed_seconds: object,
) -> dict[str, str | int]:
    """Never include raw output, reason detail, paths, commands, or payloads."""

    result: dict[str, str | int] = {
        "decision": "invalid",
        "reason_category": "unrecognized",
        "returncode": "invalid",
        "elapsed_ms": "invalid",
    }
    if type(returncode) is int and -255 <= returncode <= 255:
        result["returncode"] = returncode
    if (
        (type(elapsed_seconds) is int or type(elapsed_seconds) is float)
        and 0 <= elapsed_seconds <= 600
        and math.isfinite(elapsed_seconds)
    ):
        result["elapsed_ms"] = round(elapsed_seconds * 1000)
    if type(payload) is not dict:
        return result
    raw_output = cast(dict[str, object], payload).get("hookSpecificOutput")
    if type(raw_output) is not dict:
        return result
    output = cast(dict[str, object], raw_output)
    event = output.get("hookEventName")
    if type(event) is not str or event != "PreToolUse":
        return result
    decision = output.get("permissionDecision")
    if type(decision) is str and decision in {"allow", "ask", "deny"}:
        result["decision"] = decision
    result["reason_category"] = _reason_category(output.get("permissionDecisionReason"))
    return result


def assert_claude_hook_asks_for_permission(
    result: subprocess.CompletedProcess[str], *, elapsed_seconds: float
) -> None:
    """Preserve the generated hook regression assertions with finite diagnostics."""
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail("Claude hook returned invalid JSON", pytrace=False)
    diagnostic = claude_hook_diagnostics(payload, returncode=result.returncode, elapsed_seconds=elapsed_seconds)
    returned_successfully = result.returncode == 0
    assert returned_successfully, diagnostic
    stderr_is_empty = result.stderr == ""
    assert stderr_is_empty, diagnostic
    expected_event = payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert expected_event, diagnostic
    asks_for_permission = payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert asks_for_permission, diagnostic
