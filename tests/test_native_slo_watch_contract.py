"""Keep raw-edge native authority distinct from direct-core observe rendering.

Frozen 2e672d2 and current edge.rs both construct the post request with
observe_mode=false before applying authenticated policy. The direct core's
observed() response is therefore not the result captured by FaultFixture.
These are renderer/oracle regressions, not installed Rust execution evidence.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from codex_plugin_scanner.guard.daemon.hook_worker_native import (
    HookWorkerNativeMixin,
    _watch_native_post_tool_result,
)
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_post_tool
from scripts.native_slo_workloads import build_cases, validate_case, validate_native_result


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    root = tmp_path_factory.mktemp("watch-oracle-workspace")
    return {system: build_cases(root, system=system) for system in ("Linux", "Windows")}


def _case(cases, system, harness, size="1k", setup="watch"):
    return next(item for item in cases[system] if item.case_id == f"{harness}/PostToolUse/{setup}/{size}")


def _raw_secret_result(reason="output_secret_match"):
    # Independent wire vector: HookReviewResponseV1::deny plus authenticated
    # apply_post_tool_policy's intrinsic block. No observed() call occurs.
    return {
        "decision": "deny",
        "model_output_action": "block",
        "policy_action": "block",
        "reason_code": reason,
        "reason": "Synthetic secret fixture requires a completed block.",
        "notice": "warning",
    }


@pytest.mark.parametrize("harness", ["claude-code", "pi", "omp"])
@pytest.mark.parametrize(
    ("system", "size", "reason"),
    [
        ("Linux", "1k", "output_secret_match"),
        ("Linux", "1m", "source_secret_match"),
        ("Windows", "1m", "no_output_to_review"),
    ],
)
def test_real_worker_completion_preserves_raw_block_then_delivers_watch(
    tmp_path: Path, cases, harness, system, size, reason
):
    case = _case(cases, system, harness, size)
    native = _raw_secret_result(reason)
    original = copy.deepcopy(native)
    captured = []
    activities = []
    routes = []

    def raw_edge(**kwargs):
        captured.append(kwargs)
        return {"event_name": "PostToolUse", "harness": harness, "result": native, "receipt": None}

    host = HookWorkerNativeMixin()
    host._review_raw_hook_native = raw_edge
    host._native_policy_snapshot = lambda *_args, **_kwargs: {"mode": "observe"}
    host._record_native_decision_receipt = lambda _receipt: None
    host._record_post_tool_activity = lambda **kwargs: activities.append(kwargs)
    host.metrics = SimpleNamespace(record_route=routes.append)
    delivered = host._review_native_edge(
        payload=dict(case.payload),
        harness=harness,
        event_name="PostToolUse",
        default_harness=harness,
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=None,
    )
    assert routes == ["native_resident"]
    assert len(captured) == len(activities) == 1
    assert captured[0]["observe_mode"] is True  # raw-edge wrapper deliberately ignores this hint
    assert native == original
    validate_native_result(case, native)
    validate_case(case, delivered, "native_resident")
    assert case.native_expected.reason_code == reason
    assert delivered["policy_action"] == "warn"
    for value in (native, delivered, case.native_expected.fields, case.expected.fields):
        assert "observe_mode" not in value
        assert "observed_policy_action" not in value
    if harness in {"pi", "omp"}:
        assert delivered["decision"] == "allow"
        assert delivered["model_output_action"] == "allow_original"
        assert delivered["reason_code"] == reason
        if size == "1k":
            digest = hashlib.sha256(case.payload["tool_response"][0]["text"].encode()).hexdigest()
        else:
            digest = case.payload["guard_source_ref"]["output_sha256"]
        assert delivered["reviewed_output_sha256"] == digest
    else:
        assert "reason_code" not in delivered


def test_direct_core_observe_response_is_a_different_contract(cases):
    case = _case(cases, "Linux", "pi")
    digest = hashlib.sha256(case.payload["tool_response"][0]["text"].encode()).hexdigest()
    # Frozen guard-hook-core::observe_inline_secret_preserves_original_with_digest
    # describes direct-core observe=true, not the authenticated raw-edge tap.
    direct = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "reason_code": "observe_output_secret_match",
        "reviewed_output_sha256": digest,
        "observe_mode": True,
        "observed_policy_action": "block",
        "notice": "none",
    }
    rendered = harness_json_from_native_post_tool("pi", _watch_native_post_tool_result(direct, case.payload))
    assert rendered == direct
    with pytest.raises(AssertionError):
        validate_native_result(case, direct)
    with pytest.raises(AssertionError):
        validate_case(case, rendered, "native_resident")


@pytest.mark.parametrize(
    "change",
    [
        {"reason_code": "observe_output_secret_match"},
        {"observe_mode": True},
        {"observe_mode": False},
        {"observed_policy_action": "block"},
        {"decision": "allow"},
        {"policy_action": "warn"},
    ],
)
def test_raw_watch_oracle_rejects_invented_metadata_or_weaker_authority(cases, change):
    case = _case(cases, "Linux", "claude-code")
    with pytest.raises(AssertionError):
        validate_native_result(case, {**_raw_secret_result(), **change})


@pytest.mark.parametrize("harness", ["claude-code", "pi", "omp"])
def test_unavailable_watch_is_not_completed_native_observation(cases, harness):
    unavailable = _case(cases, "Linux", harness, setup="watch_unavailable")
    completed = _case(cases, "Linux", harness)
    response = availability_harness_response(
        unavailable.payload,
        harness=harness,
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="Synthetic unavailable fixture",
        recording_only=True,
    )
    validate_native_result(unavailable, None)
    validate_case(unavailable, response, "native_fail_safe")
    assert response["policy_action"] == "allow"
    assert unavailable.native_expected is None
    assert not unavailable.semantic_sample
    with pytest.raises(AssertionError):
        validate_native_result(completed, None)
    with pytest.raises(AssertionError):
        validate_case(completed, response, "native_resident")
