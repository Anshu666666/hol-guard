"""Real local transactions for opaque received proofs, without native issuance."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_approval_delivery import (
    load_native_approval_decision,
    retain_native_approval_decision,
)
from codex_plugin_scanner.guard.native_approval_queue import load_native_approval_state
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.review_oauth_binding import guard_review_oauth_metadata
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_native_approval_queue_state import _NOW, _queue
from tests.test_native_approval_v4_transport import _proof

_RECEIPT = "11111111-1111-4111-8111-111111111111"


def _ready(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    row, session, _ = _queue(store)
    state = load_native_approval_state(store, row)
    assert state is not None
    proof = _proof()
    proof["challenge"] = session.challenge
    return store, row, state, proof


def _claim(store, row):
    return build_local_review_request_claim(request_row=row, oauth=guard_review_oauth_metadata(store), store=store)


def test_receiving_proof_does_not_apply_or_consume_an_approval(tmp_path: Path) -> None:
    store, row, state, proof = _ready(tmp_path)
    result = retain_native_approval_decision(
        store,
        request_id=str(row["request_id"]),
        expected_state=state,
        decision="allow_once",
        receipt_id=_RECEIPT,
        received_at=_NOW,
        proof=proof,
        source_claim=_claim(store, row),
        expected_sequence=1,
    )
    assert result.proof == proof
    assert store.get_approval_request(str(row["request_id"]))["status"] == "pending"
    with store._connect() as connection:
        assert connection.execute("select count(*) from policy_decisions").fetchone()[0] == 0
        assert connection.execute("select count(*) from guard_local_once_approvals").fetchone()[0] == 0
        assert connection.execute("select consumed_at from guard_native_approval_requests").fetchone()[0] is None
        assert connection.execute("select count(*) from guard_review_outbox_events").fetchone()[0] == 1
    loaded = load_native_approval_decision(store, request_id=str(row["request_id"]), expected_state=state)
    assert loaded == result
    loaded.proof["assertion"] = "changed"
    assert loaded.proof == proof


def test_duplicate_retains_first_timestamp_and_refuses_conflicting_receipt(tmp_path: Path) -> None:
    store, row, state, proof = _ready(tmp_path)
    kwargs = dict(
        request_id=str(row["request_id"]),
        expected_state=state,
        decision="allow_once",
        receipt_id=_RECEIPT,
        proof=proof,
        source_claim=_claim(store, row),
        expected_sequence=1,
    )
    first = retain_native_approval_decision(store, received_at=_NOW, **kwargs)
    duplicate = retain_native_approval_decision(store, received_at="2026-09-18T00:00:01+00:00", **kwargs)
    assert duplicate == first and duplicate.received_at == _NOW
    kwargs["receipt_id"] = "22222222-2222-4222-8222-222222222222"
    with pytest.raises(ValueError, match="native_approval_delivery_conflict"):
        retain_native_approval_decision(store, received_at=_NOW, **kwargs)


@pytest.mark.parametrize("field", ["proof", "decision", "receiptId", "receivedAt", "challengeDigest"])
def test_tampered_received_state_is_not_consumable(tmp_path: Path, field: str) -> None:
    store, row, state, proof = _ready(tmp_path)
    retain_native_approval_decision(
        store,
        request_id=str(row["request_id"]),
        expected_state=state,
        decision="allow_once",
        receipt_id=_RECEIPT,
        received_at=_NOW,
        proof=proof,
        source_claim=_claim(store, row),
        expected_sequence=1,
    )
    with store._connect() as connection:
        value = json.loads(connection.execute("select proof_json from guard_native_approval_requests").fetchone()[0])
        value[field] = "changed"
        connection.execute("update guard_native_approval_requests set proof_json = ?", (json.dumps(value),))
    assert load_native_approval_decision(store, request_id=str(row["request_id"]), expected_state=state) is None


@pytest.mark.parametrize("case", ["wrong_challenge", "expired", "block_with_proof", "allow_without_proof"])
def test_invalid_delivery_has_no_mutation(tmp_path: Path, case: str) -> None:
    store, row, state, proof = _ready(tmp_path)
    decision, timestamp = "allow_once", _NOW
    if case == "wrong_challenge":
        proof["challenge"]["nonce"] = "e" * 64
    elif case == "expired":
        timestamp = "2026-09-18T00:01:00+00:00"
    elif case == "block_with_proof":
        decision = "block"
    else:
        proof = None
    with pytest.raises(ValueError, match="native_approval_delivery_invalid"):
        retain_native_approval_decision(
            store,
            request_id=str(row["request_id"]),
            expected_state=state,
            decision=decision,
            receipt_id=_RECEIPT,
            received_at=timestamp,
            proof=proof,
            source_claim=_claim(store, row),
            expected_sequence=1,
        )
    with store._connect() as connection:
        assert connection.execute("select proof_json from guard_native_approval_requests").fetchone()[0] is None


def test_concurrent_distinct_decisions_cannot_replace_the_first(tmp_path: Path) -> None:
    store, row, state, proof = _ready(tmp_path)
    receipts = [_RECEIPT, "22222222-2222-4222-8222-222222222222"]

    def receive(receipt_id: str) -> str:
        try:
            retain_native_approval_decision(
                store,
                request_id=str(row["request_id"]),
                expected_state=state,
                decision="allow_once",
                receipt_id=receipt_id,
                received_at=_NOW,
                proof=proof,
                source_claim=_claim(store, row),
                expected_sequence=1,
            )
        except ValueError as error:
            return str(error)
        return receipt_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(receive, receipts))
    assert outcomes.count("native_approval_delivery_conflict") == 1
    loaded = load_native_approval_decision(store, request_id=str(row["request_id"]), expected_state=state)
    assert loaded is not None and loaded.receipt_id in outcomes
