from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts import native_slo_launcher_rejection as rejection
from scripts import native_slo_priority_launchers as launchers
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_numeric_journal import NumericJournal, recover_numeric_journal
from scripts.native_slo_priority_launchers import RegisteredLauncher


def _launcher(tmp_path):
    return RegisteredLauncher("codex", "PostToolUse", ("unused",), (), "a" * 64, tmp_path / "config")


def _session(tmp_path):
    # No daemon/status/receipt interface: the failure observer needs none.
    return SimpleNamespace(root=tmp_path, workspace=tmp_path, guard_home=tmp_path)


def _result(response):
    return BoundedHookProcessResult(0, json.dumps(response, ensure_ascii=False), False, False)


def _availability_shape():
    return {"continue": True, "hookSpecificOutput": {"hookEventName": "PostToolUse"}}


def test_exact_schema_rejection_retains_closed_facts_after_original_timer(tmp_path: Path, monkeypatch):
    response = _availability_shape()
    completed = _result(response)
    calls, clocks = [], []

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return completed

    def clock():
        clocks.append(True)
        return len(clocks) / 1000

    monkeypatch.setattr(launchers, "run_isolated_hook_process", run)
    monkeypatch.setattr(launchers.time, "perf_counter", clock)
    with pytest.raises(RuntimeError, match=r"^priority_launcher_codex_schema_mismatch$") as caught:
        launchers.observe_priority_launcher(_session(tmp_path), _launcher(tmp_path), sample=7)
    assert len(calls) == 1 and len(clocks) == 2
    assert calls[0][1]["timeout_seconds"] == 10.0
    assert calls[0][1]["output_limit"] == 2 * 1024 * 1024
    evidence = failure_evidence(caught.value)
    assert evidence["reason"] == "priority_launcher_codex_schema_mismatch"
    record = evidence["launcher_stdout_rejection"]
    assert record["capture_state"] == "captured"
    assert record["decoded_stdout_utf8_bytes"] == len(completed.stdout.encode("utf-8"))
    assert record["decoded_stdout_utf8_sha256"] == hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
    assert record["stdout_identity_scope"] == "utf8_reencoding_of_decoded_stdout"
    assert record["original_stream_bytes_proven"] is False
    assert record["top_level"]["presence"]["continue"] is True
    assert record["top_level"]["presence"]["event_container"] is True
    assert record["top_level"]["total_capped_at_65"] == 2
    assert record["top_level"]["unknown_capped_at_65"] == 0
    assert record["specific"]["total_capped_at_65"] == 1
    assert record["specific_event"] == "PostToolUse"
    assert record["continue_state"] == "true"
    assert record["decision"] == record["policy_action"] == record["reason_code"] == "absent"
    assert record["native_authority_proven"] is record["accepted"] is record["qualification_complete"] is False
    assert record["availability_cause"] == "unproved"
    assert record["exit_state"] == "zero"
    assert record["timed_out"] is record["containment_failed"] is record["reply_limit_exceeded"] is False


def test_unknown_key_names_values_and_reason_text_are_never_exported(tmp_path: Path, monkeypatch):
    response = _availability_shape()
    response.update({f"arbitrary-private-name-{index}": "private request material" for index in range(80)})
    response["reason"] = "do not publish /home/private/request 雪"
    response["native_result"] = {"authority": "rust", "policy_action": "allow"}
    completed = _result(response)
    monkeypatch.setattr(launchers, "run_isolated_hook_process", lambda *_args, **_kwargs: completed)
    with pytest.raises(RuntimeError) as caught:
        launchers.observe_priority_launcher(_session(tmp_path), _launcher(tmp_path), sample=2)
    evidence = failure_evidence(caught.value)
    serialized = json.dumps(evidence)
    assert all(
        value not in serialized for value in ("arbitrary-private-name", "private request", "/home/private", "雪")
    )
    record = evidence["launcher_stdout_rejection"]
    assert record["top_level"]["unknown_capped_at_65"] == 65
    assert record["top_level"]["count_saturated"] is True
    assert record["top_level"]["presence"]["native_result"] is True
    assert record["native_authority_proven"] is False
    assert record["decoded_stdout_utf8_bytes"] == len(completed.stdout.encode())
    assert record["decoded_stdout_utf8_bytes"] > len(completed.stdout)


def test_success_does_not_capture_or_hash_and_validator_runs_once(tmp_path: Path, monkeypatch):
    calls = []

    def validator(*args, **kwargs):
        calls.append((args, kwargs))

    def forbidden(*_args, **_kwargs):
        raise AssertionError("success must not collect failure evidence")

    response = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    monkeypatch.setattr(rejection, "_capture", forbidden)
    rejection.validate_stdout_with_witness(validator, _launcher(tmp_path), _result(response), response, case="benign")
    assert len(calls) == 1 and calls[0][0][1] is response
    assert calls[0][1] == {"case": "benign"}


@pytest.mark.parametrize("projection_fails", [False, True])
def test_original_exception_object_message_and_origin_survive_diagnostic_errors(
    tmp_path, monkeypatch, projection_fails
):
    original = RuntimeError("priority_launcher_codex_schema_mismatch")

    def validator(*_args, **_kwargs):
        raise original

    if projection_fails:
        monkeypatch.setattr(rejection, "_capture", lambda *_args: (_ for _ in ()).throw(ValueError("private detail")))
    response = _availability_shape()
    with pytest.raises(RuntimeError) as caught:
        rejection.validate_stdout_with_witness(
            validator, _launcher(tmp_path), _result(response), response, case="benign"
        )
    assert caught.value is original
    assert str(caught.value) == "priority_launcher_codex_schema_mismatch"
    traceback = caught.value.__traceback__
    while traceback.tb_next:
        traceback = traceback.tb_next
    assert traceback.tb_frame.f_code.co_name == "validator"
    record = failure_evidence(caught.value)["launcher_stdout_rejection"]
    assert record["capture_state"] == ("projection_unavailable" if projection_fails else "captured")
    assert "private detail" not in json.dumps(record)


def test_export_projection_failure_preserves_existing_error_evidence():
    class BrokenMapping(dict):
        def get(self, *_args):
            raise ValueError("private detail")

    original = RuntimeError("priority_launcher_codex_schema_mismatch")
    setattr(original, rejection._ATTRIBUTE, BrokenMapping())
    result = failure_evidence(original)
    assert result["reason"] == str(original)
    assert result["launcher_stdout_rejection"]["capture_state"] == "projection_unavailable"
    assert "private detail" not in json.dumps(result)


def test_earlier_process_json_and_object_failures_keep_existing_errors(tmp_path, monkeypatch):
    for completed, reason in (
        (BoundedHookProcessResult(2, "{}", False, False), "process_contract_failed"),
        (BoundedHookProcessResult(0, "not json", False, False), "stdout_not_json"),
        (BoundedHookProcessResult(0, "[]", False, False), "stdout_not_object"),
    ):
        monkeypatch.setattr(
            launchers, "run_isolated_hook_process", lambda *_args, _result=completed, **_kwargs: _result
        )
        with pytest.raises(RuntimeError, match=reason) as caught:
            launchers.observe_priority_launcher(_session(tmp_path), _launcher(tmp_path), sample=0)
        assert "launcher_stdout_rejection" not in failure_evidence(caught.value)


def test_existing_numeric_journal_keeps_failed_batch_and_prior_samples(tmp_path, monkeypatch):
    item = _launcher(tmp_path)
    results = iter(
        [
            _result({"hookSpecificOutput": {"hookEventName": "PostToolUse"}}),
            _result({"hookSpecificOutput": {"hookEventName": "PostToolUse"}}),
            _result(_availability_shape()),
        ]
    )
    monkeypatch.setattr(launchers, "registered_launcher", lambda *_args: item)
    monkeypatch.setattr(launchers, "_route_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(launchers, "run_isolated_hook_process", lambda *_args, **_kwargs: next(results))
    journal_path = tmp_path / "numeric.jsonl"
    with NumericJournal(journal_path) as journal, pytest.raises(RuntimeError) as caught:
        launchers._serial_series(
            _session(tmp_path), item, 3, offset=0, journal=journal, series="INSTALLED_LAUNCHER.codex.PostToolUse"
        )
    recovered = recover_numeric_journal(journal_path)
    batch = recovered["batches"][-1]
    assert batch["status"] == "failed"
    assert batch["offered"] == 3 and batch["observed"] == 2
    assert len(recovered["series"]["INSTALLED_LAUNCHER.codex.PostToolUse"]) == 2
    assert isinstance(failure_evidence(caught.value)["launcher_stdout_rejection"], Mapping)
