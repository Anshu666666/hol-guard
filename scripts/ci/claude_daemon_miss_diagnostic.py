"""Opt-in, terminal-only evidence for one existing Claude adapter assertion."""

from __future__ import annotations

import json
import subprocess

import pytest

TARGET = (
    "tests/test_guard_claude_adapter.py::"
    "test_claude_daemon_hook_command_falls_back_to_native_ask_on_daemon_miss"
)
_PREFIX = "HOL Guard could not reach the local daemon ("
_SUFFIX = ") and continued this action without native review."


def classify_result(result: object) -> dict[str, str]:
    evidence = {
        "process": "unavailable",
        "stderr": "unknown",
        "payload": "unavailable",
        "decision": "unknown",
        "reason": "unknown",
        "response_origin": "unverified",
    }
    if not isinstance(result, subprocess.CompletedProcess):
        return evidence
    evidence["process"] = "zero" if result.returncode == 0 else "nonzero"
    evidence["stderr"] = "empty" if result.stderr == "" else "present"
    if not isinstance(result.stdout, str):
        return evidence
    if len(result.stdout) > 16_384:
        evidence["payload"] = "oversized"
        return evidence
    try:
        payload = json.loads(result.stdout)
    except (ValueError, RecursionError):
        evidence["payload"] = "invalid-json"
        return evidence
    hook = payload.get("hookSpecificOutput") if isinstance(payload, dict) else None
    if not isinstance(hook, dict):
        evidence["payload"] = "missing-hook-object"
        return evidence
    evidence["payload"] = "hook-object"
    decision = hook.get("permissionDecision")
    evidence["decision"] = decision if decision in ("allow", "ask", "deny") else "other"
    reason = hook.get("permissionDecisionReason")
    if not isinstance(reason, str):
        return evidence
    if reason.startswith(_PREFIX) and reason.endswith(_SUFFIX):
        detail = reason[len(_PREFIX) : -len(_SUFFIX)]
        evidence["reason"] = "degraded-other"
        endings = (
            ("; fallback exhausted the hook deadline", "fallback-deadline"),
            ("; fallback timed out", "fallback-timeout"),
            ("; fallback returned malformed hook JSON", "fallback-malformed"),
            ("; recovered daemon returned malformed hook JSON", "recovered-daemon-malformed"),
        )
        for ending, category in endings:
            if detail.endswith(ending):
                evidence["reason"] = category
                break
        else:
            if detail == "daemon returned malformed hook JSON":
                evidence["reason"] = "daemon-malformed"
            elif "; fallback exited " in detail:
                status = detail.rsplit("; fallback exited ", 1)[1]
                if status.removeprefix("-").isdigit():
                    evidence["reason"] = "fallback-nonzero"
    elif reason.startswith("HOL Guard denied the action because daemon authentication failed: "):
        evidence["reason"] = "authentication-denied"
    return evidence


def failure_result(code: object, error: BaseException | None) -> object:
    traceback = error.__traceback__ if error is not None else None
    matches = []
    for _ in range(64):
        if traceback is None:
            break
        if traceback.tb_frame.f_code is code:
            matches.append(traceback.tb_frame.f_locals.get("result"))
        traceback = traceback.tb_next
    if traceback is not None or len(matches) != 1:
        return None
    return matches[0] if isinstance(matches[0], subprocess.CompletedProcess) else None


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    report = yield
    if item.nodeid != TARGET or call.when != "call":
        return report
    try:
        code = getattr(getattr(item, "obj", None), "__code__", None)
        error = call.excinfo.value if call.excinfo is not None else None
        result = failure_result(code, error)
        evidence = classify_result(result)
        evidence["failure_frame"] = "available" if result is not None else "unavailable"
        message = json.dumps(evidence, sort_keys=True)
    except Exception:
        message = '{"diagnostic":"unavailable"}'
    report.sections.append(("Guard Claude terminal diagnostic", message))
    return report
