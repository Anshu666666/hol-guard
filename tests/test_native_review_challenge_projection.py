"""Real serializer/claim controls with shape-only synthetic native challenges."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_approval_protocol import decode_native_approval_v4_challenge
from codex_plugin_scanner.guard.native_review_challenge_projection import project_native_review_challenge
from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    compute_local_review_request_claim_hash,
)
from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewOAuthMetadata
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import build_cloud_review_event
from codex_plugin_scanner.guard.runtime.local_request_snapshots import (
    _cloud_safe_local_request_payload,
    _compact_local_request_snapshot_item,
    _local_request_snapshot_byte_capped_items,
)
from codex_plugin_scanner.guard.stable_digest import sha256_content_digest
from codex_plugin_scanner.guard.stable_json import stable_json_serialize
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_approval_v4_transport import _challenge


def row(*, native: bool = True, persisted: bool = False) -> dict[str, object]:
    challenge = _challenge()
    envelope: dict[str, object] = {"action_type": "shell_command", "command": "pwd", "tool_name": "Bash"}
    if native:
        envelope["nativeApprovalChallenge"] = challenge
    return {
        "request_id": challenge["request_id"],
        "harness": challenge["harness"],
        "artifact_id": "synthetic-native-projection",
        "policy_action": "require-reapproval",
        "recommended_scope": "artifact",
        "status": "pending",
        "created_at": "2026-09-20T00:00:00+00:00",
        "last_seen_at": "2026-09-20T00:00:00+00:00",
        "action_envelope_json": json.dumps(envelope) if persisted else envelope,
    }


def oauth() -> GuardReviewOAuthMetadata:
    return GuardReviewOAuthMetadata(
        device_id="synthetic-device",
        dpop_thumbprint=None,
        grant_id="synthetic-grant",
        installation_id="synthetic-installation",
        machine_id="synthetic-machine",
        runtime_id="hol-guard",
        workspace_id="synthetic-workspace",
    )


@pytest.mark.parametrize("persisted", [False, True])
@pytest.mark.parametrize("redaction", ["none", "strict"])
def test_complete_challenge_survives_both_payload_paths(persisted: bool, redaction: str) -> None:
    source = row(persisted=persisted)
    before = deepcopy(source)
    result = _cloud_safe_local_request_payload(source, redaction_level=redaction)
    assert result["nativeApprovalChallenge"] == _challenge()
    assert decode_native_approval_v4_challenge(result["nativeApprovalChallenge"]) is not None
    assert source == before
    assert "nativeApprovalChallenge" not in cast(dict[str, object], result["actionEnvelope"])
    result_challenge = cast(dict[str, object], result["nativeApprovalChallenge"])
    cast(dict[str, object], result_challenge["webauthn"])["origin"] = "https://changed.invalid"
    assert project_native_review_challenge(source) == _challenge()


@pytest.mark.parametrize("replacement", [None, {}, "invalid", {"schema": "guard-native-approval-challenge.v3"}])
def test_present_malformed_native_never_becomes_legacy(replacement: object) -> None:
    source = row()
    cast(dict[str, object], source["action_envelope_json"])["nativeApprovalChallenge"] = replacement
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        _cloud_safe_local_request_payload(source, redaction_level="strict")


@pytest.mark.parametrize("mutation", ["unknown", "unbounded", "nonfinite", "wrong-request", "wrong-harness"])
def test_strict_native_bounds_and_request_binding(mutation: str) -> None:
    source = row()
    challenge = cast(
        dict[str, object], cast(dict[str, object], source["action_envelope_json"])["nativeApprovalChallenge"]
    )
    if mutation == "unknown":
        challenge["privateCanary"] = "must never be exported"
    elif mutation == "unbounded":
        challenge["runtime_version"] = "x" * 65537
    elif mutation == "nonfinite":
        challenge["issued_at_ms"] = float("nan")
    elif mutation == "wrong-request":
        source["request_id"] = "other-request"
    else:
        source["harness"] = "codex"
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        project_native_review_challenge(source)


@pytest.mark.parametrize(
    "key", ["nativeApprovalChallenge", "native_approval_challenge", "nativeApproval", "native_approval"]
)
def test_alias_cannot_supply_authority_or_conflict(key: str) -> None:
    source = row(native=False)
    source[key] = _challenge()
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        project_native_review_challenge(source)
    source = row()
    source[key] = {**_challenge(), "nonce": "e" * 64}
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        project_native_review_challenge(source)
    source[key] = None
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        project_native_review_challenge(source)


def test_matching_direct_alias_is_checked_and_not_reemitted() -> None:
    source = row()
    source["native_approval_challenge"] = _challenge()
    result = _cloud_safe_local_request_payload(source, redaction_level="none")
    assert result["nativeApprovalChallenge"] == _challenge()
    assert "native_approval_challenge" not in result


@pytest.mark.parametrize(
    "malformed", ["duplicate-envelope", "duplicate-challenge", "invalid-json", "escaped-invalid-json"]
)
def test_ambiguous_persisted_native_json_is_refused(malformed: str) -> None:
    source = row(persisted=True)
    serialized = cast(str, source["action_envelope_json"])
    if malformed == "duplicate-envelope":
        serialized = serialized[:-1] + ',"nativeApprovalChallenge":null}'
    elif malformed == "duplicate-challenge":
        serialized = serialized.replace('"version": 4', '"version": 3, "version": 4')
    elif malformed == "invalid-json":
        serialized = '{"nativeApprovalChallenge":'
    else:
        serialized = '{"native\\u0041pprovalChallenge":'
    source["action_envelope_json"] = serialized
    with pytest.raises(ValueError, match=r"^native_review_challenge_invalid$"):
        project_native_review_challenge(source)


def test_legacy_projection_and_malformed_display_fallback_remain() -> None:
    source = row(native=False)
    for envelope in (source["action_envelope_json"], "{not json", None):
        source["action_envelope_json"] = envelope
        assert project_native_review_challenge(source) is None
        for redaction in ("none", "strict"):
            result = _cloud_safe_local_request_payload(source, redaction_level=redaction)
            assert "nativeApprovalChallenge" not in result
            assert result["policyAction"] == "require-reapproval"


def test_claim_hash_commits_native_challenge_and_original_envelope(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "store")
    source = row()
    claim = build_local_review_request_claim(request_row=source, oauth=oauth(), store=store)
    assert claim["nativeApprovalChallenge"] == _challenge()
    assert claim["actionEnvelopeHash"] == sha256_content_digest(
        stable_json_serialize(source["action_envelope_json"]).encode("utf-8")
    )
    assert claim["claimHash"] == compute_local_review_request_claim_hash(claim)
    assert "action" not in claim and "mode" not in claim
    altered = deepcopy(claim)
    cast(dict[str, object], altered["nativeApprovalChallenge"])["nonce"] = "e" * 64
    assert compute_local_review_request_claim_hash(altered) != claim["claimHash"]
    legacy = build_local_review_request_claim(request_row=row(native=False), oauth=oauth(), store=store)
    assert "nativeApprovalChallenge" not in legacy
    assert legacy["claimHash"] == compute_local_review_request_claim_hash(legacy)


@pytest.mark.parametrize("field,value", [("request_id", "other"), ("harness", "codex"), ("harness", " claude-code ")])
def test_claim_refuses_native_target_mismatch(tmp_path: Path, field: str, value: str) -> None:
    source = row()
    source[field] = value
    with pytest.raises(GuardReviewContractError, match=r"^native_review_challenge_invalid$"):
        build_local_review_request_claim(request_row=source, oauth=oauth(), store=GuardStore(tmp_path / "store"))


def test_actual_event_and_snapshot_compaction_preserve_native_commitment(tmp_path: Path) -> None:
    source = row()
    source["action_identity"] = "synthetic-identity-" + "a" * 2048
    # This is a valid transport-sized string above the generic 2,000-char display cap.
    challenge = cast(
        dict[str, object], cast(dict[str, object], source["action_envelope_json"])["nativeApprovalChallenge"]
    )
    challenge["runtime_version"] = "v" * 2048
    assert decode_native_approval_v4_challenge(challenge) is not None
    store = GuardStore(tmp_path / "store")
    event = build_cloud_review_event(source, oauth=oauth(), redaction_level="strict", store=store, event_sequence=1)
    assert event is not None
    assert event["reviewClaim"] is not None
    compact = _compact_local_request_snapshot_item(event)
    assert compact["reviewClaim"] == event["reviewClaim"]
    assert cast(dict[str, object], compact["requestPayload"])["nativeApprovalChallenge"] == challenge
    claim = cast(dict[str, object], compact["reviewClaim"])
    assert claim["claimHash"] == compute_local_review_request_claim_hash(claim)
    snapshot = {"claim": claim, "requestPayload": event["requestPayload"], "localRequestId": source["request_id"]}
    selected, complete = _local_request_snapshot_byte_capped_items([snapshot], max_bytes=100)
    assert selected == [] and complete is False
    compact_snapshot = _compact_local_request_snapshot_item(snapshot)
    assert compact_snapshot["claim"] == claim
    assert cast(dict[str, object], compact_snapshot["requestPayload"])["nativeApprovalChallenge"] == challenge
    reduced = _compact_local_request_snapshot_item({**snapshot, "extra": {str(i): "x" * 2000 for i in range(500)}})
    assert reduced["claim"] == claim
    assert cast(dict[str, object], reduced["requestPayload"])["nativeApprovalChallenge"] == challenge
