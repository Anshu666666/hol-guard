"""Actual claim projection for a sealed synthetic challenge, without a native grant."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    compute_local_review_request_claim_hash,
)
from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewContractError, guard_review_oauth_metadata
from codex_plugin_scanner.guard.review_request_extensions import exact_review_action_digest
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_native_approval_queue_state import _queue


def test_actual_claim_preserves_distinct_native_and_envelope_commitments(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    row, session, _ = _queue(store)
    claim = build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)
    assert claim["nativeApprovalChallenge"] == session.challenge
    assert claim["actionEnvelopeHash"] != session.challenge["action_digest"]
    assert claim["artifactHash"] == session.challenge["request_digest"]
    assert exact_review_action_digest(claim) == session.challenge["action_digest"]
    assert claim["claimHash"] == compute_local_review_request_claim_hash(claim)
    assert (
        claim["expiresAt"]
        == datetime.fromtimestamp(int(session.challenge["expires_at_ms"]) / 1000, timezone.utc).isoformat()
    )
    changed = copy.deepcopy(claim)
    changed["nativeApprovalChallenge"]["action_digest"] = "f" * 64
    assert compute_local_review_request_claim_hash(changed) != claim["claimHash"]


@pytest.mark.parametrize("mutation", ["missing", "signature", "row", "oauth"])
def test_actual_claim_refuses_unbound_native_challenge(tmp_path: Path, mutation: str) -> None:
    store = connected_exact_review_store(tmp_path)
    row, _, _ = _queue(store)
    oauth = guard_review_oauth_metadata(store)
    with store._connect() as connection:
        if mutation == "missing":
            connection.execute("delete from guard_native_approval_requests")
        elif mutation == "signature":
            connection.execute("update guard_native_approval_requests set state_json = '{}'")
        elif mutation == "row":
            connection.execute("update approval_requests set artifact_hash = ?", ("f" * 64,))
    if mutation == "oauth":
        store.set_sync_payload(
            "oauth_local_credentials",
            {"grant_id": "new", "workspace_id": "synthetic-workspace", "machine_id": "synthetic-machine"},
            "2026-09-18T00:00:00+00:00",
        )
    with pytest.raises(GuardReviewContractError, match="native_approval_request_binding_invalid"):
        build_local_review_request_claim(request_row=row, oauth=oauth, store=store)


def test_legacy_capability_digest_stays_the_original_envelope_hash() -> None:
    claim: dict[str, object] = {"actionEnvelopeHash": "a" * 64}
    assert exact_review_action_digest(claim) == "a" * 64


@pytest.mark.parametrize("field", ["localRequestId", "harnessId"])
def test_capability_advertisement_refuses_a_challenge_for_another_claim(tmp_path: Path, field: str) -> None:
    store = connected_exact_review_store(tmp_path)
    row, _, _ = _queue(store)
    claim = build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)
    claim[field] = "different"
    with pytest.raises(GuardReviewContractError, match="native_approval_request_binding_invalid"):
        exact_review_action_digest(claim)


def test_removed_stored_native_marker_cannot_downgrade_to_legacy_claim(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    row, _, _ = _queue(store)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set artifact_id = ? where request_id = ?",
            ("ordinary-artifact", row["request_id"]),
        )
    current = store.get_approval_request(str(row["request_id"]))
    assert current is not None
    with pytest.raises(GuardReviewContractError, match="native_approval_request_binding_invalid"):
        build_local_review_request_claim(request_row=current, oauth=guard_review_oauth_metadata(store), store=store)
