"""Keep full publication retries inside their original authority and time scope."""

from __future__ import annotations

import json
import time

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _PUBLISH_TIMEOUT_SECONDS,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
)
from tests.test_native_policy_snapshot_capture_retry import _write_startup_status
from tests.test_native_policy_snapshot_post_ack_retry import _observe
from tests.test_native_policy_snapshot_post_ack_retry import publication as publication

_REFUSAL = "native_policy_authority_changed_during_publish"


def _assert_closed(publisher):
    assert not publisher.is_ready()
    assert publisher.current_snapshot() is None
    assert publisher.current_snapshot_binding() is None


def test_original_first_client_deadline_survives_generation_recovery(publication, monkeypatch):
    _, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase="during-post-ack-read")
    client = publisher._client_request
    deadlines = []
    assert client is not None

    def recovering_client(**kwargs):
        output = client(**kwargs)
        deadline = kwargs["deadline_monotonic"]
        deadlines.append(deadline)
        if len(deadlines) == 1:
            # Leave a real gap between the original and recovery client deadlines.
            time.sleep(_PUBLISH_TIMEOUT_SECONDS / 2)
            assert time.monotonic() < deadline
            reply = json.loads(output)
            reply["status"] = POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
            reply["idempotent"] = False
            return json.dumps(reply).encode()
        if len(deadlines) == 2:
            assert deadline > deadlines[0]
            time.sleep(max(0.0, deadlines[0] - time.monotonic()) + 0.005)
            assert deadlines[0] <= time.monotonic() < deadline
        return output

    monkeypatch.setattr(publisher, "_client_request", recovering_client)
    publisher._publish_once()
    assert len(calls) == 2 and len(deadlines) == 2
    assert calls[1]["generation"] > calls[0]["generation"]
    assert state.transport_deadlines == deadlines
    assert len(state.reserved_inputs) == 2
    assert len(state.captures) == 3
    assert state.reserved_inputs[1] is not state.reserved_inputs[0]
    assert state.mutations == 1 and len(state.writes) == 1
    assert all(before != after for before, after in state.writes)
    assert time.monotonic() >= deadlines[0]
    _assert_closed(publisher)
    assert publisher._snapshot is None
    assert state.accepted_at == []
    assert publisher.last_error in {_REFUSAL, "native_policy_snapshot_deadline_exceeded"}
    assert state.errors == [publisher.last_error]
    assert publisher._failure_count == 1
    assert publisher._retry_not_before_monotonic is not None


@pytest.mark.parametrize("renew", [False, True], ids=["acknowledged-refresh", "generation-renewal"])
def test_fence_cleared_ack_does_not_turn_a_warm_attempt_into_cold_retry(publication, monkeypatch, renew):
    store, publisher, calls = publication
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    previous_snapshot = publisher.current_snapshot()
    assert previous_snapshot is not None
    previous_inputs = publisher._published_cloud_inputs
    previous_calls = len(calls)
    confirm = publisher._confirm_resident_fingerprint
    record_error = publisher._record_error
    acknowledged_before_fence = []
    writes = []
    errors = []

    def confirmation_with_write(*args, **kwargs):
        result = confirm(*args, **kwargs)
        assert result is not None
        acknowledged_before_fence.append(publisher._acked)
        writes.append(_write_startup_status(store, len(writes) + 1, now=publisher._wall_clock()))
        return result

    def record_current_error(error):
        errors.append(error)
        record_error(error)

    monkeypatch.setattr(publisher, "_confirm_resident_fingerprint", confirmation_with_write)
    monkeypatch.setattr(publisher, "_record_error", record_current_error)
    publisher._publish_once(renew_after_generation=previous_snapshot["generation"] if renew else None)
    assert acknowledged_before_fence == [True]
    assert len(writes) == 1 and writes[0][0] != writes[0][1]
    assert len(calls) == previous_calls + 1
    _assert_closed(publisher)
    assert publisher._acked is False
    assert publisher._snapshot == previous_snapshot
    assert publisher._published_cloud_inputs is previous_inputs
    assert errors == [_REFUSAL]
    assert publisher.last_error == _REFUSAL
    assert publisher._failure_count == 1
    assert publisher._retry_not_before_monotonic is not None


def test_resident_error_cannot_impersonate_a_local_post_ack_refusal(publication, monkeypatch):
    _, publisher, calls = publication
    state = _observe(publication, monkeypatch, phase="during-post-ack-read")
    client = publisher._client_request
    assert client is not None

    def resident_error(**kwargs):
        client(**kwargs)
        return json.dumps({"error": _REFUSAL, "retryable": True}).encode()

    monkeypatch.setattr(publisher, "_client_request", resident_error)
    publisher._publish_once()
    assert len(calls) == 1 and len(state.reserved_inputs) == 1
    assert state.validations == [] and state.confirmations == []
    assert state.mutations == 0 and state.writes == []
    _assert_closed(publisher)
    assert publisher._snapshot is None
    assert state.accepted_at == []
    assert state.errors == [_REFUSAL]
    assert publisher.last_error == _REFUSAL
    assert publisher._failure_count == 1
    assert publisher._retry_not_before_monotonic is not None
