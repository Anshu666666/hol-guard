"""Presentation restoration through the real bridge with a controlled resident.

The client supplies synthetic challenge/receipt bytes and finite resident
refusals. These cases verify transport, binding and opaque-object provenance;
they do not execute Rust or verify the fixture's fake WebAuthn assertion.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_approval_bridge import (
    NativeApprovalBridge,
    NativeApprovalSession,
    NativeConsumedReceipt,
    native_approval_continuation_allowed,
)
from codex_plugin_scanner.guard.native_approval_v4_bridge import consume_presented_v4
from tests.test_native_approval_v4_transport import _artifact, _challenge, _result, _status


class ControlledResident:
    """Own the fixture's original context independently of reconstructed JSON."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.now = 100.0
        self.wall_ms = 1_500
        self.challenge: dict[str, Any] = _challenge()
        self.challenge["harness"] = "codex"
        self.current_epoch = self.challenge["resident_epoch"]
        self.original_envelope: dict[str, Any] | None = None
        self.calls: list[dict[str, Any]] = []
        self.deadlines: list[float] = []
        self.consumed = False
        self.response_change: tuple[str, str, object] | None = None
        self.consume_response: dict[str, Any] | None = None
        self.payload: dict[str, Any] = {
            "tool_name": "Bash",
            "tool_input": {"command": "printf restored"},
            "session_id": "synthetic-live-session",
        }
        self.snapshot: dict[str, Any] = {
            "generation": 7,
            "policy_digest": "c" * 64,
            "runtime_identity": "a" * 64,
            "source_input_digest": "e" * 64,
        }
        issuer = self.bridge()
        original = issuer.create_v4_challenge(
            payload=self.payload,
            harness="codex",
            guard_home=tmp_path / "guard",
            home_dir=tmp_path / "home",
            cwd=tmp_path,
            policy_snapshot=self.snapshot,
            deadline=100.5,
            request_id="original-live-request",
        )
        assert original is not None
        self.original_session = original
        # Persisted data is a detached JSON copy, never the issuing session.
        self.persisted: dict[str, Any] = json.loads(json.dumps(original.challenge))
        self.proof: dict[str, Any] = {
            "schema": "guard-native-approval-proof.v4",
            "challenge": copy.deepcopy(self.persisted),
            "assertion": _artifact()["webauthn"],
        }
        self.last_bridge = self.bridge()

    def bridge(self) -> NativeApprovalBridge:
        return NativeApprovalBridge(
            client_request=self.client,
            status_provider=lambda: _status(self.root),
            environment_provider=lambda: {},
            clock=lambda: self.now,
        )

    @staticmethod
    def refused(code: str) -> bytes:
        return json.dumps({"error": code, "retryable": False}).encode()

    def client(self, **kwargs: Any) -> bytes:
        assert isinstance(kwargs["payload"], bytes)
        wire: dict[str, Any] = json.loads(kwargs["payload"])
        self.calls.append(wire)
        self.deadlines.append(kwargs["deadline_monotonic"])
        assert kwargs["raw_hook_envelope"] is False
        operation = wire["operation"]
        envelope = wire["request"]["envelope"]
        if operation == "approval_challenge_v4":
            assert self.original_envelope is None
            assert envelope["request_id"] == "original-live-request"
            self.original_envelope = copy.deepcopy(envelope)
            self.challenge["request_id"] = envelope["request_id"]
            return json.dumps(self.challenge).encode()
        assert operation in {"approval_validate_v4", "approval_consume_v4"}
        assert self.original_envelope is not None
        if self.current_epoch != self.challenge["resident_epoch"]:
            return self.refused("native_approval_runtime_mismatch")
        if self.wall_ms >= self.challenge["expires_at_ms"]:
            return self.refused("native_approval_receipt_expired")
        if self.consumed:
            return self.refused("native_approval_replay")
        original = {key: value for key, value in self.original_envelope.items() if key != "deadline_budget_ms"}
        presented = {key: value for key, value in envelope.items() if key != "deadline_budget_ms"}
        if presented != original:
            return self.refused("native_approval_binding_mismatch")
        artifact = wire["request"]["artifact"]
        if any(artifact[key] != value for key, value in self.challenge.items() if key not in {"schema", "webauthn"}):
            return self.refused("native_approval_binding_mismatch")
        phase = "validated" if operation == "approval_validate_v4" else "consumed"
        result = _result(phase=phase)
        receipt = result["receipt"]
        assert isinstance(receipt, dict)
        for key in (set(receipt) & set(self.challenge)) - {"schema"}:
            receipt[key] = self.challenge[key]
        if self.response_change is not None and phase == self.response_change[0]:
            receipt[self.response_change[1]] = self.response_change[2]
        if phase == "consumed":
            self.consumed = True
            if self.consume_response is not None:
                return json.dumps(self.consume_response).encode()
        return json.dumps(result).encode()

    def restore(self, **changes: Any) -> tuple[NativeApprovalSession, NativeConsumedReceipt] | None:
        self.last_bridge = self.bridge()
        arguments: dict[str, Any] = {
            "challenge": copy.deepcopy(self.persisted),
            "artifact": json.dumps(self.proof).encode(),
            "payload": copy.deepcopy(self.payload),
            "harness": "codex",
            "guard_home": self.root / "guard",
            "home_dir": self.root / "home",
            "cwd": self.root,
            "policy_snapshot": copy.deepcopy(self.snapshot),
            "deadline": 100.4,
        }
        arguments.update(changes)
        return consume_presented_v4(self.last_bridge, **arguments)


def allowed(receipt: object, session: NativeApprovalSession) -> bool:
    return native_approval_continuation_allowed(
        receipt,
        session=session,
        request_id=session.request_id,
        request_digest=session.request_digest,
        action_digest=session.action_digest,
        policy_generation=session.policy_generation,
        policy_digest=session.policy_digest,
        harness=session.harness,
    )


def test_new_bridge_restores_only_presentation_and_requires_both_resident_phases(tmp_path: Path) -> None:
    resident = ControlledResident(tmp_path)
    assert not allowed(_result(phase="consumed")["receipt"], resident.original_session)
    result = resident.restore()
    assert result is not None
    session, receipt = result
    assert session is not resident.original_session
    assert session.challenge == resident.persisted == resident.original_session.challenge
    assert allowed(receipt, session)
    assert not allowed(receipt.receipt, session)
    assert not allowed(receipt, resident.original_session)
    assert [call["operation"] for call in resident.calls] == [
        "approval_challenge_v4",
        "approval_validate_v4",
        "approval_consume_v4",
    ]
    assert resident.deadlines == [100.5, 100.4, 100.4]
    original = resident.calls[0]["request"]["envelope"]
    for call in resident.calls[1:]:
        envelope = call["request"]["envelope"]
        assert envelope["request_id"] == "original-live-request"
        assert "request_id" not in envelope["raw_payload"]
        assert envelope["raw_payload"] == original["raw_payload"]
        assert envelope["policy_snapshot"] == original["policy_snapshot"]
        assert 0 < envelope["deadline_budget_ms"] <= original["deadline_budget_ms"]
        assert call["request"]["artifact"]["webauthn"] == resident.proof["assertion"]
    copied = session.challenge
    copied["nonce"] = "f" * 64
    assert session.challenge == resident.persisted
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == "native_approval_replay"
    assert [call["operation"] for call in resident.calls].count("approval_consume_v4") == 1


@pytest.mark.parametrize("change", ["harness", "request_id", "unknown_field", "deadline"])
def test_invalid_restored_input_cannot_reach_resident(tmp_path: Path, change: str) -> None:
    resident = ControlledResident(tmp_path)
    arguments: dict[str, Any] = {}
    if change == "harness":
        arguments["harness"] = "claude-code"
    elif change == "request_id":
        arguments["payload"] = dict(resident.payload, request_id="different-live-request")
    elif change == "unknown_field":
        arguments["challenge"] = dict(resident.persisted, unexpected="private-canary")
    else:
        arguments["deadline"] = 100.0
    assert resident.restore(**arguments) is None
    assert resident.last_bridge.last_error_code == "native_approval_request_invalid"
    assert len(resident.calls) == 1 and not resident.consumed


@pytest.mark.parametrize(
    "field,value", [("request_id", "foreign-request"), ("resident_epoch", "e" * 64), ("nonce", "f" * 64)]
)
def test_proof_for_another_original_challenge_is_rejected_before_transport(
    tmp_path: Path, field: str, value: object
) -> None:
    resident = ControlledResident(tmp_path)
    resident.proof["challenge"][field] = value
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == "native_approval_binding_mismatch"
    assert len(resident.calls) == 1 and not resident.consumed


@pytest.mark.parametrize("change", ["command", "generation", "source_digest", "cwd"])
def test_actual_current_context_is_forwarded_and_resident_refusal_is_preserved(tmp_path: Path, change: str) -> None:
    resident = ControlledResident(tmp_path)
    arguments: dict[str, Any] = {}
    if change == "command":
        arguments["payload"] = dict(resident.payload, tool_input={"command": "printf changed"})
    elif change == "generation":
        arguments["policy_snapshot"] = dict(resident.snapshot, generation=8)
    elif change == "source_digest":
        arguments["policy_snapshot"] = dict(resident.snapshot, source_input_digest="f" * 64)
    else:
        arguments["cwd"] = tmp_path / "different-workspace"
    assert resident.restore(**arguments) is None
    assert resident.last_bridge.last_error_code == "native_approval_binding_mismatch"
    assert [call["operation"] for call in resident.calls] == ["approval_challenge_v4", "approval_validate_v4"]
    envelope = resident.calls[-1]["request"]["envelope"]
    for key in ("payload", "policy_snapshot", "cwd"):
        if key in arguments:
            actual = (
                envelope["raw_payload"]
                if key == "payload"
                else envelope["source"]["cwd"]
                if key == "cwd"
                else envelope["policy_snapshot"]
            )
            assert actual == (str(arguments[key]) if key == "cwd" else arguments[key])
    assert not resident.consumed


@pytest.mark.parametrize(
    "change,error", [("epoch", "native_approval_runtime_mismatch"), ("expiry", "native_approval_receipt_expired")]
)
def test_old_json_cannot_recreate_live_resident_epoch_or_expiry(tmp_path: Path, change: str, error: str) -> None:
    resident = ControlledResident(tmp_path)
    if change == "epoch":
        resident.current_epoch = "f" * 64
    else:
        resident.wall_ms = resident.challenge["expires_at_ms"]
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == error
    assert len(resident.calls) == 2 and resident.calls[-1]["operation"] == "approval_validate_v4"
    assert not resident.consumed


@pytest.mark.parametrize("field,value", [("request_id", "foreign-request"), ("resident_epoch", "f" * 64)])
def test_matching_tampered_challenge_and_proof_still_require_original_resident_context(
    tmp_path: Path, field: str, value: object
) -> None:
    resident = ControlledResident(tmp_path)
    resident.persisted[field] = value
    resident.proof["challenge"][field] = value
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == "native_approval_binding_mismatch"
    assert len(resident.calls) == 2 and not resident.consumed


@pytest.mark.parametrize("phase", ["validated", "consumed"])
@pytest.mark.parametrize(
    "field,value", [("request_id", "foreign-request"), ("resident_epoch", "f" * 64), ("nonce", "e" * 64)]
)
def test_each_resident_receipt_must_match_exact_restored_session(
    tmp_path: Path, phase: str, field: str, value: object
) -> None:
    resident = ControlledResident(tmp_path)
    resident.response_change = (phase, field, value)
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == "native_approval_receipt_binding_mismatch"
    assert len(resident.calls) == (2 if phase == "validated" else 3)
    assert resident.consumed is (phase == "consumed")


@pytest.mark.parametrize("kind", ["validated_only", "unclaimed", "bare_receipt"])
def test_json_or_validation_without_exact_consumed_result_cannot_mint_authority(tmp_path: Path, kind: str) -> None:
    resident = ControlledResident(tmp_path)
    result = _result(phase="validated" if kind == "validated_only" else "consumed")
    receipt = result["receipt"]
    assert isinstance(receipt, dict)
    for key in (set(receipt) & set(resident.challenge)) - {"schema"}:
        receipt[key] = resident.challenge[key]
    if kind == "unclaimed":
        receipt["replay_claimed"] = False
    resident.consume_response = receipt if kind == "bare_receipt" else result
    assert resident.restore() is None
    assert resident.last_bridge.last_error_code == "native_approval_decoder_rejected"
    assert len(resident.calls) == 3 and resident.consumed
