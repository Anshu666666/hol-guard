"""Durable reporting using decoder-valid synthetic consumed objects, not native issuance."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_application_contract import validated_native_application
from codex_plugin_scanner.guard.native_approval_application import retain_native_consumption
from codex_plugin_scanner.guard.native_approval_delivery import load_native_approval_decision
from codex_plugin_scanner.guard.native_approval_models import (
    _RECEIPT_BINDING_FIELDS,
    _new_consumed_receipt,
    _new_session,
)
from codex_plugin_scanner.guard.native_approval_queue import load_native_approval_state
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event
from codex_plugin_scanner.guard.runtime.native_review_executor import execute_exact_review_job
from tests.test_native_approval_queue_state import _NOW
from tests.test_native_approval_v4_transport import _result
from tests.test_native_review_delivery import _never_resume, _ready

_CONSUMED = "2026-09-18T00:00:01.123456+00:00"


def _consumption(tmp_path: Path):
    store, row, job = _ready(tmp_path)
    execute_exact_review_job(job, store=store, generated_at=_NOW, resume_after_approval=_never_resume)
    state = load_native_approval_state(store, row)
    received = load_native_approval_decision(store, request_id=str(row["request_id"]), expected_state=state)
    session = _new_session(state.challenge, b"{}")
    receipt = _result(phase="consumed")["receipt"]
    receipt.update({k: state.challenge[k] for k in _RECEIPT_BINDING_FIELDS})
    consumed = _new_consumed_receipt(receipt, session)
    return store, row, state, received, session, consumed


def _save(items):
    store, _, state, received, session, consumed = items
    retain_native_consumption(
        store, session=session, consumed=consumed, state=state, decision=received, consumed_at=_CONSUMED
    )


@pytest.mark.parametrize("redaction", ["full", "partial", "none"])
def test_actual_store_outbox_and_projection_preserve_application_without_continuation(tmp_path: Path, redaction: str):
    items = _consumption(tmp_path)
    store, row, _, received, _, consumed = items
    _save(items)
    with store._connect() as connection:
        before = connection.execute("select consumed_json from guard_native_approval_requests").fetchone()[0]
        event = dict(
            connection.execute(
                "select *, stream_sequence as sequence from guard_review_outbox_events where event_type=?",
                ("review.native.application_applied",),
            ).fetchone()
        )
        count = connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0]
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
    _save(items)
    with store._connect() as connection:
        assert connection.execute("select consumed_json from guard_native_approval_requests").fetchone()[0] == before
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == count
    binding = {
        key: event[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    output = project_cloud_review_event(
        store,
        outbox_row=event,
        delivery_binding=binding,
        redaction_level=redaction,
        oauth=guard_review_oauth_metadata(store),
    )
    assert output is not None
    payload = output[1]
    assert payload["eventType"] == "native_application_applied"
    assert payload["reviewClaim"] == received.source_claim
    assert "exactReviewCapability" not in payload["reviewClaim"]
    assert payload["nativeApplicationResult"] == {
        "decisionReceiptId": received.receipt_id,
        "sourceClaimHash": received.source_claim["claimHash"],
        "consumedAt": _CONSUMED,
        "receipt": consumed.receipt,
    }
    assert "continuationResult" not in payload
    assert store.get_approval_request(str(row["request_id"]))["status"] == "resolved"
    for _ in range(2):
        repeated = project_cloud_review_event(
            store,
            outbox_row=event,
            delivery_binding=binding,
            redaction_level=redaction,
            oauth=guard_review_oauth_metadata(store),
        )[1]
        assert repeated["eventPayloadJson"] == payload["eventPayloadJson"]
        assert repeated["eventId"] == payload["eventId"]
        assert repeated["localEventSequence"] == payload["localEventSequence"]


@pytest.mark.parametrize(
    "field",
    [
        "action_digest",
        "request_digest",
        "policy_digest",
        "scope_binding",
        "harness",
        "nonce",
        "issued_at_ms",
        "runtime_identity",
        "replay_claimed",
        "phase",
    ],
)
def test_consumed_receipt_must_match_the_original_complete_challenge(tmp_path: Path, field: str):
    store, _, state, received, session, consumed = _consumption(tmp_path)
    result = {
        "decisionReceiptId": received.receipt_id,
        "sourceClaimHash": received.source_claim["claimHash"],
        "consumedAt": _CONSUMED,
        "receipt": consumed.receipt,
    }
    original = result["receipt"][field]
    result["receipt"][field] = (
        not original if isinstance(original, bool) else 99 if isinstance(original, int) else "changed"
    )
    assert validated_native_application(result, received.source_claim) is None
    with pytest.raises(ValueError, match="consumption_invalid"):
        retain_native_consumption(
            store,
            session=session,
            consumed=_new_consumed_receipt(result["receipt"], session),
            state=state,
            decision=received,
            consumed_at=_CONSUMED,
        )


def test_actual_application_transaction_rolls_back_if_outbox_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from codex_plugin_scanner.guard import native_approval_application as application

    items = _consumption(tmp_path)
    store, row, *_ = items
    actual = application.append_request_snapshot_event

    def fail(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("synthetic post-write failure")

    monkeypatch.setattr(application, "append_request_snapshot_event", fail)
    with pytest.raises(RuntimeError, match="post-write"):
        _save(items)
    with store._connect() as connection:
        assert connection.execute("select consumed_json from guard_native_approval_requests").fetchone()[0] is None
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == 1
    assert store.get_approval_request(str(row["request_id"]))["status"] == "pending"


def test_mutated_outbox_cannot_replace_retained_native_application(tmp_path: Path):
    from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest

    items = _consumption(tmp_path)
    store = items[0]
    _save(items)
    with store._connect() as connection:
        event = dict(
            connection.execute(
                "select *, stream_sequence as sequence from guard_review_outbox_events where event_type=?",
                ("review.native.application_applied",),
            ).fetchone()
        )
    changed = copy.deepcopy(event)
    payload = json.loads(changed["payload_json"])
    payload["nativeApplicationResult"]["consumedAt"] = "2026-09-18T00:00:02+00:00"
    changed["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    binding = {
        key: event[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    changed["payload_hash"] = review_event_payload_digest(
        changed["payload_json"], oauth_source=event["oauth_source"], **binding
    )
    assert (
        project_cloud_review_event(
            store,
            outbox_row=changed,
            delivery_binding=binding,
            redaction_level="full",
            oauth=guard_review_oauth_metadata(store),
        )
        is None
    )
