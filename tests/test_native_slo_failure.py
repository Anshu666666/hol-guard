from __future__ import annotations

import json

from scripts.native_slo_failure import FixtureFailureError, failure_evidence


def test_corpus_failure_names_fixture_and_field_without_output() -> None:
    result = failure_evidence(
        AssertionError("native_qualification_mismatch:codex/PostToolUse/block/1k:field:reason_code")
    )
    assert result["reason"] == "native_qualification_mismatch"
    assert result["case"] == "codex.PostToolUse.block.1k"
    assert result["field"] == "field:reason_code"


def test_unstructured_errors_do_not_publish_paths_or_data() -> None:
    for error in (OSError("/home/someone/private-dump.txt"), RuntimeError("response included ghp_live_credential")):
        result = failure_evidence(error)
        assert result["reason"] == "unclassified_failure"
        assert str(error) not in json.dumps(result)
        assert len(result["diagnostic_digest"]) == 64


def test_remote_fixture_failure_preserves_coarse_diagnostics() -> None:
    detail = failure_evidence(OSError(13, "/home/someone/private-data"))
    result = failure_evidence(FixtureFailureError(detail))
    assert result["errno"] == 13
    assert result["category"] == "PermissionError"
    assert result["reason"] == "qualification_fixture.unclassified_failure"
    assert "/home" not in json.dumps(result)


def test_malformed_corpus_detail_cannot_disclose_response_body() -> None:
    result = failure_evidence(AssertionError("native_qualification_mismatch:safe.case:/home/private-data"))
    assert result["reason"] == "unclassified_failure"
