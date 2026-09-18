"""Mixed policy origins must retain their independent restrictions."""

import hashlib
import json
from pathlib import Path

from tests import native_sensitive_read_policy_vectors as ordinary
from tests.native_sensitive_read_mixed_origin_vectors import FIXTURE, generate_vectors


def test_mixed_origin_vectors_match_actual_loader_runtime_and_observe_finish(tmp_path: Path):
    expected = json.loads(FIXTURE.read_text())
    assert generate_vectors(tmp_path) == expected


def test_reciprocal_origin_floors_and_stage_boundaries_are_retained():
    cases = json.loads(FIXTURE.read_text())["cases"]
    assert len(cases) == 188
    indexed = {case["name"]: case for case in cases}
    assert len(indexed) == len(cases)
    assert {case["harness"] for case in cases} == {"codex", "claude-code", "cline", "cursor"}
    for suffix in ("local-default-block-managed-harness-allow", "local-risk-block-managed-harness-risk-allow"):
        for mode in ("enforce", "observe"):
            case = indexed[f"codex-{mode}-{suffix}"]
            assert case["expected"]["evaluatedPolicyAction"] == "block"
    for case in cases:
        assert case["localEffectivePolicy"]["unknown_publisher_action"] == "review"
        assert case["managedConfiguration"]["source_digest"]
        settings = case["configInputs"]["managed"]["settings"]
        assert case["managedConfiguration"]["default_action_present"] is ("default_action" in settings)
        expected = case["expected"]
        if case["mode"] == "observe":
            assert "finalPolicyAction" in expected and "renderedDecision" in expected
        else:
            assert "finalPolicyAction" not in expected
    absent = indexed["codex-observe-managed-risk-block-default-absent"]
    explicit = indexed["codex-observe-managed-risk-block-default-explicit-allow"]
    assert absent["expected"]["evaluatedPolicyAction"] == explicit["expected"]["evaluatedPolicyAction"] == "block"
    assert absent["expected"]["finalPolicyAction"] == "allow"
    assert explicit["expected"]["finalPolicyAction"] == "warn"
    assert absent["managedConfiguration"]["effective_policy"] == explicit["managedConfiguration"]["effective_policy"]
    assert absent["managedConfiguration"]["default_action_present"] is False
    assert explicit["managedConfiguration"]["default_action_present"] is True


def test_existing_nonmanaged_vectors_remain_byte_identical():
    assert hashlib.sha256(ordinary.FIXTURE.read_bytes()).hexdigest() == (
        "e98e7fcfa7b2033f1d37e47d99fa501f93cefc8e1b80dd26da725cb27ab65148"
    )
