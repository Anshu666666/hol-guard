"""Synthetic controls for the opt-in terminal report; no child process is run."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest
from claude_daemon_miss_diagnostic import (
    TARGET,
    classify_result,
    failure_result,
    pytest_runtest_makereport,
)


def _result(reason: str, decision: str = "allow") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["synthetic"],
        0,
        json.dumps({"hookSpecificOutput": {
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }}),
        "",
    )


def test_fixed_categories_do_not_emit_dynamic_reason_or_process_data():
    canary = "SYNTHETIC_PRIVATE_CANARY"
    reasons = (
        ("; fallback exhausted the hook deadline", "fallback-deadline"),
        ("; fallback timed out", "fallback-timeout"),
        ("; fallback exited -9", "fallback-nonzero"),
        ("; fallback returned malformed hook JSON", "fallback-malformed"),
        ("; recovered daemon returned malformed hook JSON", "recovered-daemon-malformed"),
        ("; unrecognized", "degraded-other"),
    )
    for suffix, expected in reasons:
        reason = (
            f"HOL Guard could not reach the local daemon ({canary}{suffix}) "
            "and continued this action without native review."
        )
        evidence = classify_result(_result(reason))
        assert evidence["reason"] == expected
        assert evidence["response_origin"] == "unverified"
        assert canary not in json.dumps(evidence)
    direct = (
        "HOL Guard could not reach the local daemon (daemon returned malformed hook JSON) "
        "and continued this action without native review."
    )
    assert classify_result(_result(direct))["reason"] == "daemon-malformed"
    auth = "HOL Guard denied the action because daemon authentication failed: " + canary
    assert classify_result(_result(auth, "deny"))["reason"] == "authentication-denied"
    assert classify_result(_result(canary))["reason"] == "unknown"


def test_invalid_and_oversized_payloads_remain_bounded():
    for stdout, expected in (
        ("{", "invalid-json"),
        ("[" * 2_000, "invalid-json"),
        ("x" * 16_385, "oversized"),
        ("[]", "missing-hook-object"),
    ):
        result = subprocess.CompletedProcess(["SYNTHETIC_PRIVATE_CANARY"], 1, stdout, "hidden")
        evidence = classify_result(result)
        assert evidence["payload"] == expected
        assert len(json.dumps(evidence)) < 256
        assert "SYNTHETIC_PRIVATE_CANARY" not in json.dumps(evidence)
    assert classify_result(None)["process"] == "unavailable"


def test_report_preserves_the_original_failure_and_complete_process():
    def original():
        result = _result("SYNTHETIC_PRIVATE_CANARY")
        raise AssertionError(result.returncode == 0)

    try:
        original()
    except AssertionError as caught:
        error = caught
    original_traceback = error.__traceback__
    result = failure_result(original.__code__, error)
    assert isinstance(result, subprocess.CompletedProcess)
    assert failure_result(_result.__code__, error) is None
    item = SimpleNamespace(nodeid=TARGET, obj=original)
    call = SimpleNamespace(when="call", excinfo=SimpleNamespace(value=error))
    longrepr = object()
    report = SimpleNamespace(outcome="failed", longrepr=longrepr, sections=[("existing", "unchanged")])
    hook = pytest_runtest_makereport(item, call)
    next(hook)
    with pytest.raises(StopIteration) as stopped:
        hook.send(report)
    assert stopped.value.value is report
    assert report.outcome == "failed" and report.longrepr is longrepr
    assert error.__traceback__ is original_traceback
    assert result is failure_result(original.__code__, error)
    assert report.sections[0] == ("existing", "unchanged")
    evidence = json.loads(report.sections[1][1])
    assert evidence["failure_frame"] == "available" and evidence["decision"] == "allow"
    assert "SYNTHETIC_PRIVATE_CANARY" not in report.sections[1][1]


def test_other_nodes_and_phases_are_unchanged_and_pass_is_uninformative():
    for nodeid, when in (("other", "call"), (TARGET, "setup"), (TARGET, "teardown")):
        report = SimpleNamespace(sections=[])
        hook = pytest_runtest_makereport(
            SimpleNamespace(nodeid=nodeid), SimpleNamespace(when=when),
        )
        next(hook)
        with pytest.raises(StopIteration) as stopped:
            hook.send(report)
        assert stopped.value.value is report and report.sections == []
    report = SimpleNamespace(sections=[])
    hook = pytest_runtest_makereport(
        SimpleNamespace(nodeid=TARGET), SimpleNamespace(when="call", excinfo=None),
    )
    next(hook)
    with pytest.raises(StopIteration) as stopped:
        hook.send(report)
    assert stopped.value.value is report
    assert json.loads(report.sections[0][1])["failure_frame"] == "unavailable"
