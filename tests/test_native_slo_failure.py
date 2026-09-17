from __future__ import annotations

import json

from scripts.native_slo_failure import failure_evidence


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
