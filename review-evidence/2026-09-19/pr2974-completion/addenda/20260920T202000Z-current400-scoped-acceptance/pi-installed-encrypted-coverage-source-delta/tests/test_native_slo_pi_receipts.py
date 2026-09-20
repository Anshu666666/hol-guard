"""Actual receipt schema/SQLite controls with explicitly synthetic native calls."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes, receipt_matches_edge
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from scripts import native_slo_pi_receipts
from scripts.native_slo_pi_receipts import PiReceipts
from scripts.native_slo_pi_sources import cases
from tests.native_workspace_request_fixtures import ReceiptStore, receipt, snapshot


def fixture(tmp_path):
    case = cases(tmp_path, "pi")[2]
    authority = snapshot()
    value = receipt(authority, action="allow")
    value.pop("command_extensions")
    value.update(
        harness="pi",
        event_name="PostToolUse",
        payload_kind="source_file_ref",
        model_output_action="allow_original",
        reason_code=case.reason,
        reviewed_output_sha256=hashlib.sha256(case.output.encode()).hexdigest(),
    )
    value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    edge = {
        "harness": "pi",
        "event_name": "PostToolUse",
        "payload_kind": "source_file_ref",
        "receipt": value,
        "result": {
            key: value[key]
            for key in (
                "decision",
                "model_output_action",
                "policy_action",
                "observed_policy_action",
                "reason_code",
                "reviewed_output_sha256",
                "observe_mode",
            )
        },
    }
    assert receipt_matches_edge(edge, value)
    store = ReceiptStore(tmp_path / "receipts.sqlite")
    calls = []

    def review(**kwargs):
        calls.append(kwargs)
        return edge

    worker = SimpleNamespace(_review_raw_hook_native=review)
    writer = SimpleNamespace(
        _condition=threading.RLock(),
        _in_flight=False,
        stats=lambda: {"queued": 0, "durable_pending": 0, "receipt_durable_pending": 0, "accepted": 1, "processed": 1},
        submit_native_decision_receipt=store.record_native_decision_receipt,
    )
    daemon = SimpleNamespace(
        _server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer, store=store)
    )
    kwargs = {
        "payload": {
            "tool_call_id": case.correlation,
            "tool_input": case.arguments,
            "guard_source_ref": {
                "path": case.arguments["file_path"],
                "tool_input_path": case.arguments["file_path"],
                "output_sha256": value["reviewed_output_sha256"],
                "output_chars": len(case.output),
            },
        },
        "harness": "pi",
        "event": "PostToolUse",
        "policy_snapshot": {key: authority[key] for key in ("generation", "policy_digest", "runtime_identity", "mode")},
    }
    return SimpleNamespace(
        case=case,
        daemon=daemon,
        worker=worker,
        writer=writer,
        store=store,
        edge=edge,
        kwargs=kwargs,
        calls=calls,
        review=review,
    )


def exercise(state, witness):
    returned = state.worker._review_raw_hook_native(**state.kwargs)
    assert returned is state.edge
    state.writer.submit_native_decision_receipt(returned["receipt"])
    return cast(dict[str, Any], witness.reconcile())


def test_forwarded_result_full_receipt_and_actual_sqlite_readback_agree(tmp_path):
    state = fixture(tmp_path)
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    result = exercise(state, witness)
    assert result["complete"] is True
    assert len(state.calls) == 1 and state.calls[0]["payload"] is state.kwargs["payload"]
    assert state.worker._review_raw_hook_native is state.review
    row = result["rows"][state.case.label]
    assert row["receipt"] == row["committed_receipt"] == state.edge["receipt"]
    assert "rule_digest" not in row["ack_binding"]
    assert row["installed_rule_digest"] == state.edge["receipt"]["rule_digest"]
    assert row["installed_rule_binding_valid"] is True


def test_actual_compact_publisher_binding_does_not_need_an_invented_rule_field(tmp_path):
    state = fixture(tmp_path)
    publisher = object.__new__(NativePolicySnapshotPublisher)
    publisher._condition = threading.Condition()
    publisher._acked = True
    publisher._closed = False
    publisher._snapshot = cast(dict[str, object], snapshot())
    publisher._mark_expired_locked = lambda: None
    compact = publisher.current_snapshot_binding()
    assert compact is not None and "rule_digest" not in compact
    state.kwargs["policy_snapshot"] = compact
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    row = exercise(state, witness)["rows"][state.case.label]
    assert row["ack_binding_valid"] and row["installed_rule_binding_valid"] and row["receipt_checks"]


def test_valid_receipt_rule_must_match_independently_admitted_installed_identity(tmp_path):
    state = fixture(tmp_path)
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="4" * 64).__enter__()
    result = exercise(state, witness)
    row = result["rows"][state.case.label]
    assert row["edge_binding_valid"] and row["ack_binding_valid"]
    assert row["installed_rule_binding_valid"] is False and result["complete"] is False


@pytest.mark.parametrize("digest", ("", "g" * 64, "a" * 63, "A" * 64))
def test_missing_or_malformed_installed_identity_is_not_derived_from_receipt(tmp_path, digest):
    state = fixture(tmp_path)
    with pytest.raises(ValueError, match="installed_pi_rule_identity_invalid"):
        PiReceipts(state.daemon, (state.case,), installed_rule_digest=digest)
    assert state.worker._review_raw_hook_native is state.review and not state.calls


@pytest.mark.parametrize(
    "key,value",
    (("generation", 9), ("policy_digest", "4" * 64), ("runtime_identity", "4" * 64), ("mode", "record-only")),
)
def test_current_compact_ack_mutation_during_native_call_refuses_join(tmp_path, key, value):
    state = fixture(tmp_path)
    original = state.worker._review_raw_hook_native

    def mutating(**kwargs):
        result = original(**kwargs)
        kwargs["policy_snapshot"][key] = value
        return result

    state.worker._review_raw_hook_native = mutating
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    result = exercise(state, witness)
    assert result["rows"][state.case.label]["ack_binding_valid"] is False
    assert result["complete"] is False and len(state.calls) == 1


@pytest.mark.parametrize(
    "change", ["ack", "runtime", "rule", "arguments", "native_none", "commit_missing", "duplicate"]
)
def test_actual_receipt_join_rejects_wrong_or_incomplete_scope(tmp_path, change):
    state = fixture(tmp_path)
    if change in {"ack", "runtime"}:
        key = {"ack": "policy_digest", "runtime": "runtime_identity"}[change]
        state.kwargs["policy_snapshot"][key] = "4" * 64
    elif change == "rule":
        state.edge["receipt"]["rule_digest"] = "4" * 64
        state.edge["receipt"]["decision_id"] = hashlib.sha256(
            canonical_receipt_bytes(state.edge["receipt"])
        ).hexdigest()
    elif change == "arguments":
        state.kwargs["payload"]["tool_input"] = {"file_path": "different.rs"}
    elif change == "native_none":
        state.worker._review_raw_hook_native = lambda **kwargs: None
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    edge = state.worker._review_raw_hook_native(**state.kwargs)
    if change == "duplicate":
        state.worker._review_raw_hook_native(**state.kwargs)
    if edge is not None and change != "commit_missing":
        state.writer.submit_native_decision_receipt(edge["receipt"])
    assert witness.reconcile()["complete"] is False


def test_original_exception_is_preserved_and_offered_call_is_not_lost(tmp_path):
    state = fixture(tmp_path)
    original = RuntimeError("private diagnostic fixture")

    def raises(**kwargs):
        raise original

    state.worker._review_raw_hook_native = raises
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    with pytest.raises(RuntimeError) as raised:
        state.worker._review_raw_hook_native(**state.kwargs)
    assert raised.value is original
    result = cast(dict[str, Any], witness.reconcile())
    assert not result["complete"]
    assert result["rows"][state.case.label] == {
        "label": state.case.label,
        "entered": True,
        "returned": False,
        "raised": True,
    }
    assert state.worker._review_raw_hook_native is raises


def test_corrupt_committed_content_is_not_accepted_as_original_receipt(tmp_path):
    state = fixture(tmp_path)
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    edge = state.worker._review_raw_hook_native(**state.kwargs)
    state.writer.submit_native_decision_receipt(edge["receipt"])
    with state.store._connect() as connection:
        connection.execute("update native_hook_decision_receipts set policy_digest = ?", ("4" * 64,))
    result = cast(dict[str, Any], witness.reconcile())
    assert result["complete"] is False
    assert result["rows"][state.case.label]["receipt"] == copy.deepcopy(edge["receipt"])
    assert result["rows"][state.case.label]["committed_receipt"] is None


@pytest.mark.parametrize("change", ["none", "inner_identity", "native_mutates_reference"])
def test_private_encrypted_reference_is_observed_after_native_call_without_rewriting_it(tmp_path, change):
    state = fixture(tmp_path)
    inner = copy.deepcopy(state.kwargs["payload"])
    if change == "inner_identity":
        inner["tool_call_id"] = "different-valid-correlation-identifier"
    key, nonce = b"k" * 32, b"n" * 12
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(inner).encode(), None)
    with tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as directory:
        path = Path(directory) / "payload.json"
        path.write_bytes(ciphertext)
        path.chmod(0o600)
        outer = {
            "guard_payload_ref": {
                "version": 1,
                "path": str(path),
                "sha256": hashlib.sha256(ciphertext).hexdigest(),
                "encoding": "json",
                "encryption": "aes-256-gcm",
                "key": base64.urlsafe_b64encode(key).decode().rstrip("="),
                "nonce": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
            }
        }
        state.kwargs["payload"] = outer
        value = state.edge["receipt"]
        value["payload_kind"] = "encrypted_payload_ref"
        value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
        state.edge["payload_kind"] = "encrypted_payload_ref"
        if change == "native_mutates_reference":
            original = state.worker._review_raw_hook_native

            def mutating(**kwargs):
                result = original(**kwargs)
                kwargs["payload"]["guard_payload_ref"]["sha256"] = "0" * 64
                return result

            state.worker._review_raw_hook_native = mutating
        witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
        result = exercise(state, witness)
        assert result["complete"] is (change == "none")
        assert state.calls[0]["payload"] is outer
        assert "tool_call_id" not in outer
        if change == "native_mutates_reference":
            row = result["rows"][state.case.label]
            assert row["entry_payload_unchanged"] is False
            assert row["entry_encrypted_payload_sha256"] == hashlib.sha256(ciphertext).hexdigest()
            assert row["request_binding_valid"] is True
            assert row.get("observation_failed") is not True
        retained = json.dumps(result)
        assert str(path) not in retained
        assert isinstance(outer["guard_payload_ref"]["key"], str)
        assert outer["guard_payload_ref"]["key"] not in retained
        assert isinstance(outer["guard_payload_ref"]["nonce"], str)
        assert outer["guard_payload_ref"]["nonce"] not in retained


def test_unsupported_optional_capture_preserves_original_call_and_rejects_evidence(tmp_path):
    state = fixture(tmp_path)
    state.kwargs["payload"]["unserializable"] = object()
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    result = exercise(state, witness)
    assert len(state.calls) == 1 and state.calls[0]["payload"] is state.kwargs["payload"]
    assert result["complete"] is False
    assert result["rows"][state.case.label]["entry_payload_unchanged"] is False


def test_post_return_observation_remains_active_until_original_wrapper_finishes(tmp_path, monkeypatch):
    state = fixture(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original_hydrate = native_slo_pi_receipts.hydrate_hook_payload_reference
    returned = []

    def held_observation(payload):
        entered.set()
        assert release.wait(5)
        return original_hydrate(payload)

    monkeypatch.setattr(native_slo_pi_receipts, "hydrate_hook_payload_reference", held_observation)
    witness = PiReceipts(state.daemon, (state.case,), installed_rule_digest="c" * 64).__enter__()
    worker = threading.Thread(target=lambda: returned.append(state.worker._review_raw_hook_native(**state.kwargs)))
    worker.start()
    try:
        assert entered.wait(5)
        assert len(state.calls) == 1
        result = cast(dict[str, Any], witness.reconcile())
        assert result["active_calls"] == 1 and result["complete"] is False
    finally:
        release.set()
        worker.join(5)
        witness.close()
    assert not worker.is_alive() and returned == [state.edge]
