"""Probe observation controls with synthetic authenticated responses, not native authority.

The positive invokes the actual shipped bridge/resume flow and fixed real pwd.
Only transport responses and installed admission are controlled; the production
strict V4 decoder, pending observation, CLI bridge and command remain real.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime import probe_installed_live_continuation as probe
from tests.test_native_approval_v4_transport import _result

REQUEST = "12345678-1234-1234-1234-123456789abc"
IDENTITY: dict[str, object] = {
    "installedRuntimeAvailable": True,
    "sourceSha": "a" * 40,
    "runtimeSha256": "a" * 64,
    "ruleDigest": "d" * 64,
}


def receipt() -> dict[str, Any]:
    value = copy.deepcopy(_result(phase="consumed")["receipt"])
    assert isinstance(value, dict)
    now = time.time_ns() // 1_000_000
    value.update(request_id=REQUEST, harness="codex", issued_at_ms=now - 1000, expires_at_ms=now + 20000)
    return value


@pytest.mark.parametrize(
    "change",
    [
        "valid",
        "missing",
        "malformed",
        "validated",
        "no-replay",
        "wrong-request",
        "wrong-harness",
        "wrong-runtime",
        "wrong-rules",
        "future",
        "expired",
        "incomplete",
        "block",
        "wrong-path",
        "wrong-state",
        "context-drift",
        "no-context",
        "decoder-error",
    ],
)
def test_real_bridge_requires_current_bound_consumed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    (tmp_path / "daemon-state.json").write_text("{}")
    value = receipt()
    if change == "malformed":
        value["private-canary"] = "PRIVATE_ASSERTION_TOKEN"
    elif change == "validated":
        value.update(phase="validated", reason_code="native_approval_v4_validated")
    elif change == "no-replay":
        value["replay_claimed"] = False
    elif change == "wrong-request":
        value["request_id"] = "87654321-1234-1234-1234-123456789abc"
    elif change == "wrong-harness":
        value["harness"] = "claude-code"
    elif change == "wrong-runtime":
        value["runtime_binary_identity"] = "b" * 64
    elif change == "wrong-rules":
        value["rule_digest"] = "b" * 64
    elif change == "future":
        value["issued_at_ms"] += 10000
        value["expires_at_ms"] += 10000
    elif change == "expired":
        value["issued_at_ms"] -= 30000
        value["expires_at_ms"] -= 30000
    response: dict[str, object] = {
        "completed": change != "incomplete",
        "action": "block" if change == "block" else "allow",
    }
    if change != "missing":
        response["nativeApprovalReceipt"] = value
    calls: list[dict[str, Any]] = []
    state = tmp_path / "daemon-state.json"
    pending = {
        "guardApprovalRequestId": REQUEST,
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
    }
    monkeypatch.setattr(probe.bridge, "bridge_review_response", lambda **kwargs: (pending, False, False))
    monkeypatch.setattr(
        probe.resume,
        "_daemon_json_get",
        lambda **kwargs: {"status": "resolved", "resolution_action": "allow", "policy_action": "review"},
    )

    def post(**kwargs: Any) -> dict[str, object]:
        calls.append(kwargs)
        assert kwargs["state_path"] == state
        assert kwargs["path"] == f"/v1/requests/{REQUEST}/live-decision"
        assert json.loads(kwargs["payload"]["hook_input"])["tool_input"] == {"command": "pwd"}
        assert 0 < kwargs["timeout_seconds"] <= 5
        return response

    monkeypatch.setattr(probe.resume, "_daemon_json_post", post)
    context = dict(IDENTITY)
    if change == "context-drift":
        context["sourceSha"] = "b" * 40
    monkeypatch.setattr(probe, "installed_context", lambda: context)
    if change == "decoder-error":

        def decoder_failure(*args: Any, **kwargs: Any) -> None:
            raise ValueError("PRIVATE_OBSERVATION_FAILURE")

        monkeypatch.setattr(probe, "decode_native_approval_v4_result", decoder_failure)
    original_output = probe.bridge._bridge_output
    if change in {"wrong-path", "wrong-state"}:
        # Invoke the observed transport with another subject, then return an
        # apparent allow: the probe must not count that as this pending action.
        def foreign_output(_response: dict[str, object], **kwargs: Any) -> str:
            probe.resume._daemon_json_post(
                state_path=tmp_path / "other-state.json" if change == "wrong-state" else state,
                path="/v1/requests/foreign12/live-decision"
                if change == "wrong-path"
                else f"/v1/requests/{REQUEST}/live-decision",
                payload={"hook_input": kwargs["hook_input"]},
                timeout_seconds=1,
            )
            return json.dumps(probe.resume.allow_pretool_response())

        monkeypatch.setattr(probe.bridge, "_bridge_output", foreign_output)
        monkeypatch.setattr(probe.resume, "_daemon_json_post", lambda **kwargs: response)
    saved_output, saved_post = probe.bridge._bridge_output, probe.resume._daemon_json_post
    rows: list[dict[str, object]] = []
    action_calls: list[list[str]] = []
    real_run = probe.subprocess.run

    def observed_action(argv: list[str], **kwargs: Any) -> Any:
        action_calls.append(argv)
        return real_run(argv, **kwargs)

    monkeypatch.setattr(probe.subprocess, "run", observed_action)
    result = probe.run_waiting_action(
        guard_home=tmp_path,
        home=tmp_path,
        workspace=tmp_path,
        emit=rows.append,
        identity=None if change == "no-context" else IDENTITY,
    )
    assert probe.bridge._bridge_output is saved_output
    assert probe.resume._daemon_json_post is saved_post
    assert rows[0]["requestId"] == REQUEST and rows[0]["actionCount"] == 0
    assert result["nativeReceiptIndependentlyBound"] is False
    assert "PRIVATE" not in json.dumps(result)
    assert "origin" not in result and "credential_id_digest" not in result
    if change == "valid":
        assert result["completed"] is True and result["actionCount"] == 1
        assert len(action_calls) == 1 and Path(action_calls[0][0]).name == "pwd"
        assert len(calls) == 1
        assert result["nativeReceiptObserved"] is True
        assert result["nativeReceiptBoundToInstalledContext"] is True
        assert (
            result["nativeReceiptSha256"]
            == hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        )
    else:
        assert result["completed"] is False and result["actionCount"] == 0
        assert action_calls == [] and result["nativeReceiptBoundToInstalledContext"] is False
        assert result["nativeReceiptSha256"] is None
    assert original_output is not None
