"""Caller race/transport proofs with synthetic bridge results; resident proof is separate."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_resolution import approval_resolution_block_reason
from codex_plugin_scanner.guard.daemon import hook_native_scoped_approval as caller
from codex_plugin_scanner.guard.native_approval_models import _new_consumed_receipt
from tests.test_native_approval_application import _consumption


class _Clock:
    @staticmethod
    def now(_zone=None):
        return datetime.fromisoformat("2026-09-18T00:00:01+00:00")


class _Publisher:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.ready = True

    def current_snapshot_binding(self):
        return dict(self.snapshot) if self.ready else None

    def result_binding_is_current(self, binding):
        expected = {k: v for k, v in self.snapshot.items() if k not in {"mode", "generation"}}
        expected.update(policy_generation=self.snapshot["generation"], selected_decision_id=None)
        return self.ready and binding == expected


def _call(tmp_path, monkeypatch, *, race=False, consume=False):
    items = _consumption(tmp_path)
    store, row, state, _received, original_session, template = items
    publisher = _Publisher(state.snapshot)
    calls = []

    class Bridge:
        def validate_and_consume_v4(self, session, proof, *, deadline):
            calls.append((session, proof))
            if race:
                publisher.ready = False
            return _new_consumed_receipt(template.receipt, session) if consume else None

    monkeypatch.setattr(caller, "datetime", _Clock)
    monkeypatch.setattr(caller, "NativeApprovalBridge", Bridge)
    result = caller.coordinate_scoped_native_approval(
        store,
        publisher=publisher,
        policy_snapshot=state.snapshot,
        harness=original_session.harness,
        payload={"tool_name": "Bash", "tool_input": {"command": "printf Synthetic"}},
        native_result={
            "decision": "deny",
            "minimum_action": "review",
            "policy_action": "review",
            "reason_code": "review",
        },
        native_receipt={"request_digest": original_session.request_digest},
        workspace=tmp_path,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        deadline=None,
    )
    return store, row, result, calls


@pytest.mark.parametrize("consume,race,allowed", [(False, False, False), (True, True, False), (True, False, True)])
def test_only_consumed_current_native_authority_can_continue(tmp_path: Path, monkeypatch, consume, race, allowed):
    store, row, result, calls = _call(tmp_path, monkeypatch, consume=consume, race=race)
    assert len(calls) == 1
    assert (result["hookSpecificOutput"]["permissionDecision"] == "allow") is allowed
    with store._connect() as connection:
        native_events = connection.execute(
            "select count(*) from guard_review_outbox_events where event_type='review.native.application_applied'"
        ).fetchone()[0]
        assert native_events == int(allowed)
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
    assert store.get_approval_request(str(row["request_id"]))["status"] == ("resolved" if allowed else "pending")


def test_native_queue_is_ineligible_for_legacy_local_resolution(tmp_path: Path):
    _, row, *_ = _consumption(tmp_path)
    assert approval_resolution_block_reason(row) == "native_approval_transport_required"


def test_legacy_live_wait_cannot_promote_a_native_queue_marker(monkeypatch):
    from codex_plugin_scanner.guard.adapters import grok_approval_resume

    monkeypatch.setattr(
        grok_approval_resume,
        "wait_for_approval_requests",
        lambda **_: pytest.fail("native request must not use legacy resolution"),
    )
    assert (
        grok_approval_resume.wait_for_grok_live_approval(
            event_name="PreToolUse",
            policy_action="review",
            response_payload={"native_approval_required": True, "approval_request_id": "synthetic"},
            store=SimpleNamespace(),
            timeout_seconds=10,
            json_mode=True,
        )
        is None
    )


def test_expired_or_stale_publication_never_attempts_native_consume(tmp_path: Path, monkeypatch):
    store, row, state, _, session, _ = _consumption(tmp_path)
    publisher = _Publisher(state.snapshot)
    publisher.ready = False
    monkeypatch.setattr(caller, "NativeApprovalBridge", lambda: pytest.fail("stale publication"))
    result = caller.coordinate_scoped_native_approval(
        store,
        publisher=publisher,
        policy_snapshot=state.snapshot,
        harness=session.harness,
        payload={},
        native_result={},
        native_receipt={"request_digest": session.request_digest},
        workspace=tmp_path,
        guard_home=store.guard_home,
        home_dir=tmp_path,
        deadline=None,
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert store.get_approval_request(str(row["request_id"]))["status"] == "pending"
