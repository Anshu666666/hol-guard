"""Current input selection and real Python coordinator controls; no native run."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.daemon.hook_native_review_retry import _command_reuse_is_payload_bound
from scripts.native_slo_launcher_approval import resolve_launcher_review
from scripts.native_slo_launcher_corpus import installed_expectation, validate_installed_response
from scripts.native_slo_launcher_review import approved_review_case, payload_bound_review_case
from scripts.native_slo_workloads import validate_native_result

from .native_review_approval_support import _worker
from .test_native_slo_launcher_review import _case


@pytest.mark.parametrize("harness", ["claude-code", "codex"])
def test_current_case_keeps_historical_vector_and_all_original_approval_oracles(tmp_path, harness):
    historical = _case(tmp_path, harness)
    original = copy.deepcopy(historical)
    current = payload_bound_review_case(historical)
    assert historical == original
    assert historical.payload["tool_input"]["command"] == "git diff --output=/tmp/guard-qualification.diff README.md"
    assert not _command_reuse_is_payload_bound(historical.payload["tool_input"]["command"])
    assert current.case_id != historical.case_id and current.payload["tool_input"] == {"command": "cat .env"}
    assert _command_reuse_is_payload_bound(current.payload["tool_input"]["command"])
    assert current.payload["guard_remaining_ms"] == historical.payload["guard_remaining_ms"]
    assert current.native_expected.fields == {
        "decision": "deny",
        "policy_action": "review",
        "minimum_action": "review",
        "reason_code": "native_sensitive_access_review",
    }
    approved = approved_review_case(installed_expectation(current))
    assert approved.native_expected is current.native_expected
    with pytest.raises(AssertionError):
        validate_native_result(approved, {**current.native_expected.fields, "decision": "allow"})
    response = (
        {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
        if harness == "codex"
        else {
            "continue": True,
            "policy_action": "allow",
            "reason_code": "native_sensitive_access_review",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
            "approval_reuse_status": "accepted",
        }
    )
    validate_installed_response(approved, response, "native_resident")
    with pytest.raises((AssertionError, RuntimeError)):
        validate_installed_response(
            approved,
            {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}},
            "native_resident",
        )
    with pytest.raises(AssertionError):
        validate_installed_response(approved, response, "native_fail_safe")


@pytest.mark.parametrize("mutation", ["command", "event", "harness", "setup", "native"])
def test_current_profile_refuses_unknown_source_vectors(tmp_path, mutation):
    case = _case(tmp_path)
    changes = {
        "command": {"payload": {**case.payload, "tool_input": {"command": "echo replacement"}}},
        "event": {"event": "PostToolUse"},
        "harness": {"harness": "cursor"},
        "setup": {"setup": "watch"},
        "native": {"native_expected": None},
    }
    with pytest.raises(ValueError, match="exact original review vector"):
        payload_bound_review_case(replace(case, **changes[mutation]))


@pytest.mark.parametrize("current_profile", [False, True], ids=["original-git-refused", "payload-bound-cat"])
def test_same_payload_durable_approval_preserves_current_command_gate(tmp_path, monkeypatch, current_profile):
    """Native result is explicitly modeled; store, password gate and retry are real."""
    case = _case(tmp_path / "fixture")
    if current_profile:
        case = payload_bound_review_case(case)
    edge = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": {**case.native_expected.fields, "reason": "Synthetic native review control."},
    }
    worker, store = _worker(tmp_path, monkeypatch, edge)
    password = "synthetic-current-review-password"
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0},
    )
    payload = {**case.payload, "tool_use_id": "fixture-registered-current-review-identity"}
    original = copy.deepcopy(payload)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    arguments = dict(
        payload=payload,
        params={},
        default_harness="claude-code",
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=workspace,
    )
    try:
        first = worker.review_http_payload(**arguments)
        request_id = first["approval_request_id"]
        assert first["policy_action"] == "review"
        with pytest.raises(ApprovalGateError):
            resolve_launcher_review(store, request_id, "allow", approval_gate_input=ApprovalGateInput(password="wrong"))
        assert store.get_approval_request(request_id)["status"] == "pending"
        resolution = resolve_launcher_review(
            store, request_id, "allow", approval_gate_input=ApprovalGateInput(password=password)
        )
        assert resolution["approval_durable"] is True
        prior = copy.deepcopy(store.get_approval_request(request_id))
        retry = worker.review_http_payload(**arguments)
        assert payload == original
        assert prior["status"] == "resolved" and prior["resolution_action"] == "allow"
        if current_profile:
            assert retry["policy_action"] == "allow" and retry["approval_reuse_status"] == "accepted"
        else:
            assert retry["policy_action"] == "review" and retry.get("approval_reuse_status") != "accepted"
            assert retry["approval_request_id"] != request_id
            assert store.get_approval_request(retry["approval_request_id"])["status"] == "pending"
            assert store.get_approval_request(request_id) == prior
    finally:
        worker.close()
