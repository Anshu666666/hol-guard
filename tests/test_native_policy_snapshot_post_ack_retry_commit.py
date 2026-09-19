"""Keep the added publication's final authority and deadline fences closed."""

from __future__ import annotations

import time

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher as publisher_module
from tests.test_native_policy_snapshot_post_ack_retry import _config_mutation, _credential_mutation, _observe
from tests.test_native_policy_snapshot_post_ack_retry import publication as publication

_REFUSAL = "native_policy_authority_changed_during_publish"


def _assert_retried_but_closed(publisher, calls, state, expected_error):
    assert len(calls) == 2 and len(state.reserved_inputs) == 2
    assert state.reserved_inputs[1] is not state.reserved_inputs[0]
    assert len(state.transport_deadlines) == 2
    assert state.transport_deadlines[1] <= state.transport_deadlines[0]
    assert state.mutations == 1 and len(state.writes) == 1
    assert state.writes[0][0] != state.writes[0][1]
    assert len(state.validations) >= 2
    assert not publisher.is_ready()
    assert publisher.current_snapshot() is None
    assert publisher.current_snapshot_binding() is None
    assert publisher._snapshot is None
    assert publisher._acked is False
    assert state.accepted_at == []
    assert publisher.last_error == expected_error
    assert state.errors == [expected_error]
    assert publisher._failure_count == 1
    assert publisher._retry_not_before_monotonic is not None


@pytest.mark.parametrize("mutation", ["credential-aba", "config-aba"])
def test_added_attempt_rechecks_earlier_authority_after_its_new_ack(publication, monkeypatch, mutation):
    store, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase="during-post-ack-read")
    directory_fingerprint = publisher._resident_directory_fingerprint
    injected = []

    def observe_directory_then_restore_authority():
        result = directory_fingerprint()
        if len(calls) == 2 and not injected:
            assert state.mutations == 1 and len(state.writes) == 1
            assert not publisher.is_ready()
            assert publisher.current_snapshot_binding() is None
            assert publisher._snapshot is None
            # This observation precedes the new post-ACK database read window.
            if mutation == "credential-aba":
                _credential_mutation(store, restore=True)
            else:
                _config_mutation(store, publisher, restore=True)
            injected.append(mutation)
        return result

    monkeypatch.setattr(publisher, "_resident_directory_fingerprint", observe_directory_then_restore_authority)
    publisher._publish_once()
    assert injected == [mutation]
    assert state.confirmations == [True]
    _assert_retried_but_closed(publisher, calls, state, _REFUSAL)


@pytest.mark.parametrize("phase", ["compile", "resident-confirmation"])
def test_added_attempt_cannot_commit_after_final_validation_uses_its_deadline(publication, monkeypatch, phase):
    _, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase="during-post-ack-read")
    compile_policy = publisher_module.compiled_v3_compatible_policy
    confirm = publisher._confirm_resident_fingerprint
    expired = []

    def expire_first_client_deadline():
        assert len(calls) == 2
        assert state.mutations == 1 and len(state.writes) == 1
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
        assert publisher._snapshot is None
        deadline = state.transport_deadlines[0]
        assert time.monotonic() < deadline
        # Consume only the deadline actually supplied to the original client.
        time.sleep(max(0.0, deadline - time.monotonic()) + 0.005)
        assert time.monotonic() >= deadline
        expired.append(deadline)

    def compile_then_use_budget(*args, **kwargs):
        result = compile_policy(*args, **kwargs)
        if phase == "compile" and len(calls) == 2 and not expired:
            expire_first_client_deadline()
        return result

    def confirm_then_use_budget(*args, **kwargs):
        result = confirm(*args, **kwargs)
        assert result is not None
        if phase == "resident-confirmation" and len(calls) == 2 and not expired:
            expire_first_client_deadline()
        return result

    monkeypatch.setattr(publisher_module, "compiled_v3_compatible_policy", compile_then_use_budget)
    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", confirm_then_use_budget)
    publisher._publish_once()
    assert expired == [state.transport_deadlines[0]]
    if phase == "resident-confirmation":
        assert state.confirmations == [True]
    _assert_retried_but_closed(publisher, calls, state, "native_policy_snapshot_deadline_exceeded")
