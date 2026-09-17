from __future__ import annotations

import json
import os
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from scripts import native_slo_corpus_run as runner
from scripts.build_native_qualification_artifacts import _build
from scripts.native_slo_corpus_evidence import CorpusEvidence, semantic_evidence
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import FixtureFailureError
from scripts.native_slo_workloads import ExpectedResponse, QualificationCase, build_cases, validate_case


def _case() -> QualificationCase:
    return QualificationCase(
        case_id="test.PostToolUse.benign.1k",
        harness="pi",
        event="PostToolUse",
        canonical_event="PostToolUse",
        size_class="1k",
        payload={"stdout": "private synthetic output", "path": "/private/context"},
        expected=ExpectedResponse("allow", "allow_original", "output_scan_allow", {"policy_action": "allow"}),
        expected_route="engine_bypassed",
        setup="normal",
        surface="test",
        content_bytes=1,
        wire_bytes=1,
        payload_kind="inline",
    )


def test_failed_real_projection_retains_actual_observation_before_rethrow(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    state = SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": {}}))
    session = cast(
        DaemonFixture,
        SimpleNamespace(
            daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=state)),
            request=lambda *_: (
                {
                    "policy_action": "block",
                    "reason_code": "no_output_to_review",
                    "reviewed_excerpt": "private synthetic output",
                },
                1.0,
            ),
            control=lambda *_: {
                "setup": {"isolated_store": True, "effective_policy_allow": True, "policy_ack_current": True},
                "native_result": None,
            },
        ),
    )
    with (
        CorpusEvidence(path) as journal,
        pytest.raises(FixtureFailureError, match="native_qualification_mismatch") as failed,
    ):
        runner._observe_case(session, _case(), journal)
    assert isinstance(failed.value.__cause__, AssertionError)
    assert failed.value.detail["observed_semantics"]["delivered"]["policy_action"] == "block"
    raw = path.read_text()
    assert "private synthetic output" not in raw and "/private/context" not in raw
    records = [json.loads(line) for line in raw.splitlines()]
    assert [item["status"] for item in records] == ["offered", "failed"]
    last = records[-1]
    assert last["response"]["semantic"]["policy_action"] == "block"
    assert last["response"]["semantic"]["reason_code"] == "no_output_to_review"
    assert last["http_status"] is None and last["route"] == "engine_bypassed"
    assert last["http_status_observation"] == "unavailable_in_normalized_adapter_api"
    assert last["stage"] == "witness"
    assert last["failure"]["reason"] == "qualification_fixture.native_qualification_mismatch"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_journal_refuses_existing_evidence_and_reserves_failure_record(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    with CorpusEvidence(path) as journal:
        journal.records = 4100
        with pytest.raises(RuntimeError, match="evidence limit"), journal.attempt(_case()):
            pytest.fail("an attempt cannot start without capacity for its failure")
    assert path.read_bytes() == b""
    with pytest.raises(FileExistsError):
        CorpusEvidence(path)


def test_hook_oversize_oracle_matches_actual_http_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = next(
        case for case in build_cases(tmp_path) if case.harness == "pi" and "inline-http-bound-1m" in case.case_id
    )
    handler = object.__new__(_GuardDaemonHandler)
    handler.path = "/v1/hooks/pi"
    handler.headers = Message()
    handler.headers["Content-Length"] = str(case.wire_bytes)
    monkeypatch.setattr(handler, "_touch_runtime_heartbeat", lambda *_: None)
    monkeypatch.setattr(handler, "_origin_is_allowed_for_request", lambda *_: True)
    monkeypatch.setattr(handler, "_read_request_body", lambda *_: pytest.fail("oversize body must not be read"))
    sent: list[tuple[dict[str, object], int]] = []
    monkeypatch.setattr(handler, "_write_json", lambda value, *, status: sent.append((value, status)))
    handler.do_POST()
    assert sent == [({"error": "request_body_too_large"}, 413)]
    validate_case(case, sent[0][0], "engine_bypassed", http_status=sent[0][1])


def test_installed_build_rejects_environment_nested_in_source_before_build(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside the source checkout"):
        _build(tmp_path, environment_root=tmp_path / ".venv", target="test", platform_tag="test", deployment_target="")


def test_flat_expected_and_nested_actual_permission_projection_remain_comparable() -> None:
    expected = semantic_evidence({"hookSpecificOutput.permissionDecision": "allow"}, flat=True)
    actual = semantic_evidence({"hookSpecificOutput": {"permissionDecision": "deny"}})
    assert expected is not None and actual is not None
    assert expected["semantic"] == {"hookSpecificOutput.permissionDecision": "allow"}
    assert actual["semantic"] == {"hookSpecificOutput.permissionDecision": "deny"}
