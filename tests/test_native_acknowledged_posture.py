"""Delivery uses the admitted request's ACK posture, not a newer local setting.

The native transport is injected after admission; publisher admission and Rust
intrinsic floors have their own contract suites. No installed proof is claimed.
"""

from __future__ import annotations

import copy
import time
from contextlib import contextmanager

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_fence as fence_module
from codex_plugin_scanner.guard.daemon import hook_worker_native as native
from codex_plugin_scanner.guard.native_policy_snapshot_policy import _merge_effective_native_policies
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text

from .native_policy_snapshot_test_fixtures import _config
from .test_native_review_approval_coordination import _worker
from .test_native_review_policy_binding import _bound_edge


def _binding(mode, generation=1):
    return {
        "generation": generation,
        "policy_digest": str(generation) * 64,
        "runtime_identity": "a" * 64,
        "mode": mode,
        "command_extensions_bound": True,
    }


def _review(worker, tmp_path, *, event="PreToolUse", harness="cursor"):
    return worker.review_http_payload(
        payload={
            "hook_event_name": event,
            "tool_name": "Bash" if event == "PreToolUse" else "Read",
            "tool_input": {"command": "ollama push test"},
            "tool_response": "complete original output",
        },
        params={},
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        deadline=time.monotonic() + 5,
    )


@pytest.fixture
def setup_worker(tmp_path, monkeypatch):
    edge = _bound_edge()
    worker, store = _worker(tmp_path, monkeypatch, edge, publish_native_policy=False)
    state = {"binding": _binding("enforce"), "edge": edge, "calls": [], "leases": [], "routes": []}
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_a, **_k: state["binding"])

    def evaluate(**kwargs):
        state["calls"].append(copy.deepcopy(kwargs))
        return state["edge"]

    @contextmanager
    def lease(_guard_home, **kwargs):
        state["leases"].append(kwargs)
        yield

    monkeypatch.setattr(worker, "_review_raw_hook_native", evaluate)
    monkeypatch.setattr(worker.metrics, "record_route", state["routes"].append)
    monkeypatch.setattr(fence_module, "hold_command_control_authority_lock", lease)
    try:
        yield worker, store, state
    finally:
        worker.close()


@pytest.mark.parametrize("mode,local", [("enforce", "watch"), ("observe", "protected")])
@pytest.mark.parametrize("action", ["block", "review"])
def test_pre_tool_floor_and_fence_follow_ack_not_local_setting(setup_worker, tmp_path, mode, local, action):
    worker, store, state = setup_worker
    (store.guard_home / "config.toml").write_text(f'protection_posture = "{local}"\n', encoding="utf-8")
    state["binding"] = _binding(mode)
    state["edge"]["result"].update(minimum_action=action, policy_action=action)
    original = copy.deepcopy(state["edge"])

    response = _review(worker, tmp_path)

    expected = "allow" if mode == "observe" else ("deny" if action == "block" else "ask")
    assert response["hookSpecificOutput"]["permissionDecision"] == expected
    assert response["policy_action"] == ("warn" if mode == "observe" else action)
    assert len(state["leases"]) == (1 if mode == "enforce" else 0)
    assert all(item["shared"] is True for item in state["leases"])
    assert state["calls"][0]["policy_snapshot"] == state["binding"]
    assert state["calls"][0]["observe_mode"] is (mode == "observe")
    assert state["edge"] == original
    assert worker.last_native_decision_receipt == original["receipt"]
    assert len(store.list_approval_requests(status="pending")) == (1 if expected == "ask" else 0)
    assert state["routes"] == ["native_resident"]


@pytest.mark.parametrize("mode,local", [("enforce", "watch"), ("observe", "protected")])
def test_post_redaction_and_original_digest_follow_ack(setup_worker, tmp_path, mode, local):
    worker, store, state = setup_worker
    (store.guard_home / "config.toml").write_text(f'protection_posture = "{local}"\n', encoding="utf-8")
    state["binding"] = _binding(mode)
    state["edge"].update(
        event_name="PostToolUse",
        harness="pi",
        result={
            "decision": "allow",
            "policy_action": "redact",
            "reason_code": "output_redacted",
            "reason": "A native reviewed excerpt is available.",
            "model_output_action": "replace_with_reviewed_excerpt",
            "reviewed_output_sha256": sha256_text("reviewed excerpt"),
            "reviewed_excerpt": "reviewed excerpt",
        },
    )
    original = copy.deepcopy(state["edge"])
    response = _review(worker, tmp_path, event="PostToolUse", harness="pi")
    assert response["model_output_action"] == (
        "allow_original" if mode == "observe" else "replace_with_reviewed_excerpt"
    )
    assert response["reviewed_output_sha256"] == sha256_text(
        "complete original output" if mode == "observe" else "reviewed excerpt"
    )
    assert not state["leases"]
    assert state["edge"] == original
    assert worker.last_native_decision_receipt == original["receipt"]


@pytest.mark.parametrize("local", ["watch", "protected"])
@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_missing_ack_preserves_ordinary_availability_without_watch_authority(setup_worker, tmp_path, local, event):
    worker, store, state = setup_worker
    (store.guard_home / "config.toml").write_text(f'protection_posture = "{local}"\n', encoding="utf-8")
    state.update(binding=None, edge=None)
    response = _review(worker, tmp_path, event=event)
    expected = {
        "continue": True,
        "policy_action": "allow",
        "reason_code": "native_post_tool_unavailable",
        "hookSpecificOutput": {"hookEventName": event},
    }
    if event == "PreToolUse":
        expected.update(
            policy_action="warn",
            reason_code="native_pre_tool_unavailable",
            hookSpecificOutput={
                "hookEventName": event,
                "permissionDecision": "allow",
                "permissionDecisionReason": "HOL Guard could not complete the native hook decision safely.",
            },
        )
    assert response == expected
    assert state["routes"] == ["native_fail_safe"]
    assert state["calls"][0]["observe_mode"] is False
    assert worker.last_native_decision_receipt is None
    assert not state["leases"]


@pytest.mark.parametrize("old,new", [("enforce", "observe"), ("observe", "enforce")])
def test_inflight_delivery_keeps_exact_request_binding_and_receipt(setup_worker, tmp_path, monkeypatch, old, new):
    worker, _store, state = setup_worker
    state["binding"] = _binding(old)
    state["edge"]["result"].update(minimum_action="block", policy_action="block")
    original = copy.deepcopy(state["edge"])
    seen = []

    def evaluate(**kwargs):
        seen.append(copy.deepcopy(kwargs["policy_snapshot"]))
        state["binding"] = _binding(new, 2)
        return state["edge"]

    monkeypatch.setattr(worker, "_review_raw_hook_native", evaluate)
    first = _review(worker, tmp_path)
    assert first["hookSpecificOutput"]["permissionDecision"] == ("allow" if old == "observe" else "deny")
    assert seen == [_binding(old)]
    assert state["edge"] == original
    assert worker.last_native_decision_receipt == original["receipt"]
    second = _review(worker, tmp_path)
    assert second["hookSpecificOutput"]["permissionDecision"] == ("allow" if new == "observe" else "deny")
    assert seen[-1] == _binding(new, 2)


def test_strict_registered_workspace_posture_cannot_be_weakened_by_local_watch(setup_worker, tmp_path):
    worker, store, state = setup_worker
    (store.guard_home / "config.toml").write_text('protection_posture = "watch"\n', encoding="utf-8")
    watch = {**_config(), "mode": "observe", "protection_posture": "watch"}
    strict_workspace = {**_config(), "protection_posture": "extra_careful"}
    merged = _merge_effective_native_policies((watch, strict_workspace))
    assert merged["mode"] == "enforce"
    state["binding"] = _binding(merged["mode"])
    state["edge"]["result"].update(minimum_action="block", policy_action="block")
    assert _review(worker, tmp_path)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("mode", [None, "enforce", "observe"])
def test_ordinary_edge_never_rereads_local_posture(setup_worker, tmp_path, monkeypatch, mode):
    worker, _store, state = setup_worker
    state["binding"] = _binding(mode) if mode else None
    state["edge"] = None

    def forbidden(**_kwargs):
        raise AssertionError("ordinary native posture must come from the ACK")

    monkeypatch.setattr(native, "hook_review_is_recording_only", forbidden)
    assert _review(worker, tmp_path)["reason_code"] == "native_pre_tool_unavailable"
