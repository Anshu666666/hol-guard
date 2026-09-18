from __future__ import annotations

import copy
import inspect
import json
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from scripts.native_slo_phase_evidence import validate_evidence_phase_counts
from scripts.native_slo_phases import PhaseProfiler


def _routed(profiler: PhaseProfiler, callback: Callable[[], Any]) -> Any:
    def hook(_self: object, _payload: object, **_kwargs: object) -> Any:
        return callback()

    return profiler._wrap(hook, "daemon_hook_inclusive", root=True)(
        None, {"hook_event_name": "PostToolUse"}, default_harness="claude-code"
    )


def _spans(profiler: PhaseProfiler) -> dict[str, Any]:
    return profiler.report()["by_route"]["claude-code.PostToolUse"]


def test_receipt_validation_aliases_json_and_hash_preserve_real_results() -> None:
    from codex_plugin_scanner.guard import native_decision_receipt as receipt_module
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer
    from tests.test_native_decision_receipt import _receipt

    receipt = _receipt()
    aliases = (receipt_module, writer, journal)
    originals = [owner.validate_native_decision_receipt for owner in aliases]
    original_json, original_hash = receipt_module.json, receipt_module.hashlib
    original_writer_json = writer.json
    with PhaseProfiler() as profiler:
        for owner in aliases:
            # Background/unattributed calls retain behavior without entering
            # the foreground aggregate, including nested JSON/hash operations.
            assert owner.validate_native_decision_receipt(receipt) == receipt
            assert profiler.report()["by_route"] == {}
        for owner in aliases:
            validated = _routed(profiler, lambda owner=owner: owner.validate_native_decision_receipt(receipt))
            assert validated == receipt and validated is not receipt
    for owner, original in zip(aliases, originals, strict=True):
        assert owner.validate_native_decision_receipt is original
    assert receipt_module.json is original_json
    assert receipt_module.hashlib is original_hash
    assert writer.json is original_writer_json
    spans = _spans(profiler)
    for name in ("receipt_validation_module", "receipt_validation_submission", "receipt_validation_journal"):
        assert spans[name]["count"] == 1
        assert spans[name]["outcomes"] == {"returned_value": 1}
    assert spans["receipt_validation_json_dumps"]["count"] == 6
    assert spans["receipt_identity_serialization"]["count"] == 3
    assert spans["receipt_identity_sha256_init"]["count"] == 3
    assert spans["receipt_identity_sha256_finalize"]["count"] == 3
    assert (
        spans["receipt_identity_sha256_init"]["work"]["hashed_bytes"]
        == spans["receipt_identity_serialization"]["work"]["returned_bytes"]
        == 3 * len(receipt_module.canonical_receipt_bytes(receipt))
    )
    exported = json.dumps(profiler.report())
    assert receipt["request_id"] not in exported
    assert receipt["decision_id"] not in exported


def test_real_writer_component_retains_unique_dedupe_full_and_invalid_outcomes(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_decision_receipt import _receipt

    first, second = _receipt(), _receipt(request_id="second-component-receipt")
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_records=1)
    try:
        # This is a deterministic component test, not an installed latency
        # workload. The real queue lock holds its consumer while real submit
        # methods validate, deduplicate, reject or append.
        with writer._condition, PhaseProfiler() as profiler:
            outcomes = [
                _routed(profiler, lambda value=value: writer.submit_native_decision_receipt(value))
                for value in (first, first, second, {})
            ]
            assert outcomes == [True, True, False, False]
            stats = writer.stats()
            assert stats["receipt_accepted"] == 1
            assert stats["receipt_deduped"] == 1
            assert stats["receipt_dropped"] == 2
            assert stats["queued"] == 1
        spans = _spans(profiler)
        assert spans["receipt_submission"]["outcomes"] == {"returned_true": 2, "returned_false": 2}
        assert spans["receipt_validation_submission"]["outcomes"] == {"returned_value": 3, "returned_none": 1}
        # Deduplication and full-queue rejection both happen after validation
        # and serialization. The invalid mapping still incurs validation.
        assert spans["receipt_validation_json_dumps"]["count"] == 6
        assert spans["receipt_record_serialization"]["count"] == 3
        coverage = profiler.report()["evidence_submission_coverage"]
        assert coverage["submission_true"] == "accepted_or_deduplicated_not_distinguished_by_return_value"
        assert coverage["bindings"]["receipt_validation_module"]["zero_calls_observed"] is True
        assert all(value["status"] == "complete" for value in coverage["bindings"].values())
    finally:
        assert writer.stop(timeout_seconds=2)


def test_activity_serialization_and_validation_do_not_visit_unrelated_output(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
    from codex_plugin_scanner.guard.store import GuardStore

    class UnrelatedOutput:
        def __deepcopy__(self, _memo: object) -> object:
            raise AssertionError("unrelated output was copied")

    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_records=1)
    payload = {"command": "echo synthetic", "tool_output": UnrelatedOutput()}
    try:
        with writer._condition, PhaseProfiler() as profiler:
            assert _routed(
                profiler,
                lambda: writer.submit_command_activity(
                    harness="claude-code", event="PostToolUse", payload=payload, succeeded=True
                ),
            )
            assert not _routed(
                profiler,
                lambda: writer.submit_command_activity(
                    harness="claude-code", event="PostToolUse", payload=payload, succeeded=True
                ),
            )
        spans = _spans(profiler)
        assert spans["activity_submission"]["outcomes"] == {"returned_true": 1, "returned_false": 1}
        assert spans["activity_record_serialization"]["count"] == 2
        assert spans["activity_record_validation"]["count"] == 1
        assert spans["writer_evidence_json_loads"]["count"] == 1
        assert spans["writer_evidence_json_loads"]["work"]["attempted_input_bytes"] > 0
        assert spans["evidence_json_dumps"]["count"] == 2
        assert "echo synthetic" not in json.dumps(profiler.report())
    finally:
        assert writer.stop(timeout_seconds=2)


def test_all_early_rejected_activity_records_observed_zero_work_without_payload_access(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_decision_receipt import _receipt

    class UnreadableMapping(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise AssertionError("rejected payload was accessed")

        def __iter__(self) -> Iterator[str]:
            raise AssertionError("rejected payload was iterated")

        def __len__(self) -> int:
            raise AssertionError("rejected payload was counted")

    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_records=1)
    try:
        with writer._condition:
            assert writer.submit_native_decision_receipt(_receipt())
            with PhaseProfiler() as profiler:
                assert not _routed(
                    profiler,
                    lambda: writer.submit_command_activity(
                        harness="claude-code", event="PostToolUse", payload=UnreadableMapping(), succeeded=True
                    ),
                )
        assert set(_spans(profiler)) == {"activity_submission", "daemon_hook_inclusive"}
        coverage = profiler.report()["evidence_submission_coverage"]
        assert coverage["foreground_context_observed"] is True
        assert all(value["zero_calls_observed"] is True for value in coverage["bindings"].values())
    finally:
        assert writer.stop(timeout_seconds=2)


@pytest.mark.parametrize("capacity", (1, 4))
def test_real_maximum_component_report_validates_with_accepted_or_early_rejected_activity(
    tmp_path: Path, capacity: int
) -> None:
    from codex_plugin_scanner.guard import native_hook_edge
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
    from codex_plugin_scanner.guard.store import GuardStore
    from scripts.native_slo_phase_run import phase_cases
    from tests.test_native_decision_receipt import _receipt

    receipt = _receipt()
    edge = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": receipt["harness"],
        "event_name": receipt["event_name"],
        "payload_kind": receipt["payload_kind"],
        "result": {
            key: receipt[key]
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
        "receipt": receipt,
    }
    payload = phase_cases()[2].payload
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_records=capacity)

    def handoff() -> None:
        assert native_hook_edge._decode_edge(edge) is edge
        assert writer.submit_native_decision_receipt(receipt)
        assert writer.submit_command_activity(
            harness="claude-code", event="PostToolUse", payload=payload, succeeded=True
        ) is (capacity > 1)

    try:
        # Exact maximum fixture input at real evidence component boundaries.
        # This does not simulate a native decision or run an HTTP benchmark.
        with writer._condition, PhaseProfiler() as profiler:
            _routed(profiler, handoff)
        validate_evidence_phase_counts(profiler.report(), 1)
        if capacity == 1:
            assert "activity_record_serialization" not in _spans(profiler)
            coverage = profiler.report()["evidence_submission_coverage"]
            assert coverage["bindings"]["activity_record_serialization"]["zero_calls_observed"] is True
    finally:
        assert writer.stop(timeout_seconds=2)


def test_receipt_validator_exception_is_preserved_and_private_text_not_exported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer

    marker = ValueError("private receipt material")

    def fail(_value: object) -> object:
        raise marker

    monkeypatch.setattr(writer, "validate_native_decision_receipt", fail)
    with PhaseProfiler() as profiler:
        with pytest.raises(ValueError) as raised:
            _routed(profiler, lambda: writer.validate_native_decision_receipt({}))
        assert raised.value is marker
    assert writer.validate_native_decision_receipt is fail
    assert _spans(profiler)["receipt_validation_submission"]["outcomes"] == {"raised": 1}
    assert "private receipt material" not in json.dumps(profiler.report())


def test_classmethod_binding_and_subclass_construction_are_restored() -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import _CommandActivityRecord

    class ChildRecord(_CommandActivityRecord):
        pass

    value = {
        "record_id": "synthetic",
        "harness": "claude-code",
        "event": "PostToolUse",
        "has_command": False,
        "succeeded": True,
    }
    original = inspect.getattr_static(_CommandActivityRecord, "from_json")
    expected = ChildRecord.from_json(value)
    with PhaseProfiler() as profiler:
        actual = _routed(profiler, lambda: ChildRecord.from_json(value))
    assert actual == expected
    assert type(actual) is ChildRecord
    assert inspect.getattr_static(_CommandActivityRecord, "from_json") is original


def test_reader_context_does_not_leak_evidence_bytes_into_foreground_report() -> None:
    from codex_plugin_scanner.guard import native_decision_receipt
    from tests.test_native_decision_receipt import _receipt

    receipt = _receipt()
    with PhaseProfiler() as profiler:
        assert profiler.reader_call(native_decision_receipt.validate_native_decision_receipt, "reader_test", receipt)
    report = profiler.report()
    assert set(report["by_route"]["unattributed.native_stream_reader"]) == {"reader_test"}
    assert report["evidence_submission_coverage"]["foreground_context_observed"] is False


@pytest.mark.parametrize("delete_during_scope", (False, True))
def test_missing_bindings_and_mid_scope_replacements_do_not_claim_complete(
    monkeypatch: pytest.MonkeyPatch, delete_during_scope: bool
) -> None:
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer

    original = writer.validate_native_decision_receipt
    monkeypatch.delattr(writer, "validate_native_decision_receipt")
    with PhaseProfiler() as unsupported:
        pass
    binding = unsupported.report()["evidence_submission_coverage"]["bindings"]["receipt_validation_submission"]
    assert binding == {"status": "unsupported", "entries": None, "zero_calls_observed": False}
    monkeypatch.setattr(writer, "validate_native_decision_receipt", original, raising=False)
    with PhaseProfiler() as changed:
        if delete_during_scope:
            del writer.validate_native_decision_receipt
        else:
            writer.validate_native_decision_receipt = original
    assert writer.validate_native_decision_receipt is original
    binding = changed.report()["evidence_submission_coverage"]["bindings"]["receipt_validation_submission"]
    assert binding["status"] == "binding_changed"
    assert binding["zero_calls_observed"] is False


def _complete_report() -> dict[str, Any]:
    # Reuse the separate driver's existing fixture rather than redefining
    # normal workload counts in this test module.
    from tests.test_native_slo_phase_run import Session

    session = Session()
    session.group_attempts = 4
    return session.control("phases_finish")


@pytest.mark.parametrize(
    "change",
    (
        "missing_coverage",
        "missing_binding",
        "in_flight",
        "missing_receipt_validation",
        "missing_writer_json",
        "missing_receipt_hash",
        "missing_activity_validation",
        "boolean_count",
    ),
)
def test_installed_report_rejects_missing_or_incomplete_evidence_observation(change: str) -> None:
    report = copy.deepcopy(_complete_report())
    if change == "missing_coverage":
        del report["evidence_submission_coverage"]
    elif change == "missing_binding":
        del report["evidence_submission_coverage"]["bindings"]["receipt_validation_submission"]
    elif change == "in_flight":
        report["evidence_submission_coverage"]["bindings"]["receipt_validation_submission"]["status"] = (
            "in_flight_at_teardown"
        )
    else:
        phase = {
            "missing_receipt_validation": "receipt_validation_submission",
            "missing_writer_json": "writer_evidence_json_loads",
            "missing_receipt_hash": "receipt_identity_sha256_init",
            "missing_activity_validation": "activity_record_validation",
            "boolean_count": "receipt_validation_module",
        }[change]
        report["by_route"]["claude-code.PostToolUse"][phase]["count"] = True if change == "boolean_count" else 0
    with pytest.raises(RuntimeError, match="qualification foreground evidence"):
        validate_evidence_phase_counts(report, 4)


def test_complete_evidence_observation_does_not_relabel_submission_rejection_as_durable() -> None:
    report = _complete_report()
    report["by_route"]["claude-code.PostToolUse"]["receipt_submission"]["outcomes"] = {"returned_false": 4}
    validate_evidence_phase_counts(report, 4)
