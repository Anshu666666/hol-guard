"""Frozen native lifecycle oracles and real local approval/control mutations."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store import GuardStore
from scripts import build_native_qualification_artifacts as builds
from scripts.ci import installed_native_ollama_probe as probe
from scripts.ci import verify_native_ollama_install as driver
from scripts.ci.native_ollama_contract import (
    ACTIVE_CASES,
    INACTIVE_CASES,
    RESTRICTED_CASES,
    OllamaCase,
    validate_review,
)
from scripts.ci.verify_native_ollama_install import builder_evidence
from scripts.native_slo_failure import failure_evidence
from tests.test_native_command_observations import _edge, _evidence, _observations, _receipt, _rehash


def _wire(case: OllamaCase) -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    if case.rule is None:
        observations["observations"] = []
        observations["binding"]["observation_count"] = 0
    else:
        item = observations["observations"][0]
        item["rule_id"] = case.rule
        if case.safe_variant:
            item["effective_segment_indexes"] = []
            item["safe_variants"] = [
                {"match_class": "safe-variant", "variant_id": "help", "matcher_evidence": [_evidence()]}
            ]
    if case.uncertainty_rule is not None:
        observations["observations"].append(
            {
                "extension_id": "command.shell-mutations",
                "extension_version": "1.0.0",
                "rule_id": case.uncertainty_rule,
                "rule_version": "1.0.0",
                "match_class": "uncertainty",
                "match_classes": ["unsafe", "uncertainty"],
                "matcher_evidence": [{**_evidence(), "segment_index": 1, "executable": "rm"}],
                "safe_variants": [],
                "uncertainty_reasons": ["matcher-failure"],
                "effective_segment_indexes": [1],
            }
        )
        observations["binding"]["observation_count"] += 1
        observations["binding"]["uncertainty_count"] = 1
    _rehash(observations)
    edge = _edge(observations)
    edge["authority"] = "rust"
    edge["result"].update(minimum_action=case.action, policy_action=case.action, reason_code=case.reason)
    receipt = _receipt(observations)
    receipt.update(policy_action=case.action, reason_code=case.reason)
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge["receipt"] = receipt
    response = {
        "policy_action": case.action,
        "reason_code": case.reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask" if case.action == "review" else "deny",
        },
    }
    if case.action == "review":
        response["approval_request_id"] = "synthetic-approval"
    return edge, response


@pytest.mark.parametrize("case", (*INACTIVE_CASES, *ACTIVE_CASES, *RESTRICTED_CASES), ids=lambda case: case.name)
def test_frozen_installed_oracle_requires_attributed_native_evidence(case: OllamaCase) -> None:
    edge, response = _wire(case)
    expected = edge["result"]["command_extensions"]["binding"]
    assert validate_review(case, edge, response, expected_binding=expected) == edge["receipt"]


@pytest.mark.parametrize(
    "mutation",
    ("wrong_rule", "wrong_revision", "missing_receipt", "wrong_route_authority", "allowed_floor", "wrong_delivery"),
)
def test_native_oracle_rejects_plausible_but_wrong_outcomes(mutation: str) -> None:
    edge, response = _wire(ACTIVE_CASES[0])
    expected = copy.deepcopy(edge["result"]["command_extensions"]["binding"])
    if mutation == "wrong_rule":
        edge["result"]["command_extensions"]["observations"][0]["rule_id"] = "command.ollama.rm"
        _rehash(edge["result"]["command_extensions"])
    elif mutation == "wrong_revision":
        expected["control_revision"] += 1
    elif mutation == "missing_receipt":
        edge.pop("receipt")
    elif mutation == "wrong_route_authority":
        edge["authority"] = "python"
    elif mutation == "allowed_floor":
        edge["result"]["minimum_action"] = "allow"
    else:
        response["hookSpecificOutput"]["permissionDecision"] = "allow"
    with pytest.raises(AssertionError, match="installed_ollama_"):
        validate_review(ACTIVE_CASES[0], edge, response, expected_binding=expected)


def test_legacy_approval_allow_is_explicit_and_cannot_hide_disabled_context_or_block() -> None:
    case = ACTIVE_CASES[0]
    edge, response = _wire(case)
    expected = edge["result"]["command_extensions"]["binding"]
    response.pop("approval_request_id")
    response.update(policy_action="allow", approval_reuse_status="accepted")
    response["hookSpecificOutput"]["permissionDecision"] = "allow"
    assert validate_review(case, edge, response, expected_binding=expected, approval_reused=True) == edge["receipt"]
    with pytest.raises(AssertionError, match="installed_ollama_"):
        validate_review(case, edge, response, expected_binding=expected)
    blocked, block_response = _wire(RESTRICTED_CASES[0])
    with pytest.raises(AssertionError, match="approval_bypassed_native_block"):
        validate_review(
            RESTRICTED_CASES[0],
            blocked,
            block_response,
            expected_binding=blocked["result"]["command_extensions"]["binding"],
            approval_reused=True,
        )


@pytest.mark.parametrize("mutation", ("owner", "segment", "extra"))
def test_independent_floor_requires_exact_owned_uncertainty(mutation: str) -> None:
    case = ACTIVE_CASES[-1]
    edge, response = _wire(case)
    observations = edge["result"]["command_extensions"]
    uncertain = observations["observations"][1]
    if mutation == "owner":
        uncertain.update(extension_id="command.other", rule_id="command.other.destructive-shell")
    elif mutation == "segment":
        uncertain["matcher_evidence"][0]["segment_index"] = 0
        uncertain["effective_segment_indexes"] = [0]
    else:
        observations["permission_observations"] = [
            {
                "extension_id": "command.github",
                "permission_id": "command.github.permission.read-remote",
                "matcher_evidence": [],
                "uncertainty_reasons": ["matcher-failure"],
            }
        ]
        observations["binding"]["observation_count"] += 1
        observations["binding"]["uncertainty_count"] += 1
    _rehash(observations)
    edge["receipt"]["command_extensions"] = copy.deepcopy(observations["binding"])
    edge["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(edge["receipt"])).hexdigest()
    assert validate_native_decision_receipt(edge["receipt"]) == edge["receipt"]
    with pytest.raises(AssertionError, match="installed_ollama_uncertainty_"):
        validate_review(case, edge, response, expected_binding=observations["binding"])


def test_fixture_controls_use_real_password_proofs_and_monotonic_rollback(tmp_path: Path) -> None:
    from scripts.native_slo_command_fixture import prepare_empty_command_authority

    store = GuardStore(tmp_path)
    prepare_empty_command_authority(store)
    password = probe.prepare_fixture_authority(store)
    enabled = probe.control_layer(enabled=True)
    assert probe.commit_controls(store, password, enabled, revision=0) == 1
    assert (
        probe.commit_controls(store, password, probe.control_layer(enabled=True, restrict_push=True), revision=1) == 2
    )
    assert probe.commit_controls(store, password, enabled, revision=2) == 3
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.layers == (enabled,)
    with pytest.raises(ExtensionControlAuthorityError):
        probe.commit_controls(store, password, probe.control_layer(enabled=False), revision=1)
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 3
    with pytest.raises(ApprovalGateError):
        probe.commit_controls(store, "incorrect-synthetic-password", probe.control_layer(enabled=False), revision=3)
    assert store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).revision == 3


def test_installed_checks_continue_after_a_failed_independent_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> str:
        seen.append(argv)
        if argv == ["paired"]:
            raise subprocess.CalledProcessError(1, argv)
        return ""

    monkeypatch.setattr(builds, "_run", run)
    with pytest.raises(RuntimeError, match="installed qualification failed: paired_sampling"):
        builds._run_required_checks((("paired_sampling", ["paired"]), ("installed_ollama", ["ollama"])), cwd=tmp_path)
    assert seen == [["paired"], ["ollama"]]


def test_builder_qualification_requires_every_witness_and_the_same_wheel() -> None:
    document: dict[str, Any] = {
        "passed": True,
        "sourceFallback": False,
        "guardStateCreated": False,
        "wheelSha256": "a" * 64,
        "builderVersion": "1.0.0",
        "maximumInventory": {"operations": 256},
        "examples": [
            {"kind": kind, "generated": True, "validated": True, "identicalReplay": True, "idempotentApply": True}
            for kind in ("cli", "mcp")
        ],
    }
    assert builder_evidence(document, "a" * 64)["passed"] is True
    assert builder_evidence(document, "b" * 64)["passed"] is False
    for field in ("generated", "validated", "identicalReplay", "idempotentApply"):
        changed = copy.deepcopy(document)
        changed["examples"][0][field] = False
        assert builder_evidence(changed, "a" * 64)["passed"] is False


def test_lifecycle_failure_publishes_identifier_without_private_context() -> None:
    evidence = failure_evidence(AssertionError("installed_ollama_binding_mismatch"))
    assert evidence["reason"] == "installed_ollama_binding_mismatch"
    evidence = failure_evidence(AssertionError("installed_ollama_/private/live-credential"))
    assert evidence["reason"] == "unclassified_failure"
    assert "live-credential" not in json.dumps(evidence)


@pytest.mark.parametrize("failure", ("timeout", "containment", "limit", "identity"))
def test_installed_worker_success_cannot_hide_process_failure_or_wrong_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    expected = {"wheel_sha256": "a" * 64}
    document = {
        "schema": "hol-guard.installed-native-ollama.v1",
        "passed": True,
        "identity": {"wheel_sha256": ("b" if failure == "identity" else "a") * 64},
    }

    def run(argv: tuple[str, ...], **kwargs: Any) -> BoundedHookProcessResult:
        assert argv[1] == "-I"
        assert Path(kwargs["cwd"]) != Path.cwd()
        assert kwargs["timeout_seconds"] == 180
        assert kwargs["output_limit"] == 256 * 1024
        assert "PYTHONPATH" not in kwargs["environment"]
        return BoundedHookProcessResult(
            0,
            json.dumps(document),
            output_limit_exceeded=failure == "limit",
            timed_out=failure == "timeout",
            containment_failed=failure == "containment",
            stderr="unpublished fixture context",
        )

    monkeypatch.setattr(driver, "run_isolated_hook_process", run)
    okay, report = driver.installed_native_evidence(tmp_path / "python", expected)
    assert okay is False
    assert "unpublished fixture context" not in json.dumps(report)


def test_builder_runs_when_installed_worker_cannot_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(driver, "_sha256", lambda _: "a" * 64)
    monkeypatch.setattr(driver, "wheel_package_digest", lambda _: "a" * 64)

    def native(*_: Any) -> tuple[bool, dict[str, object]]:
        raise OSError(1, "unpublished fixture context")

    def builder(*_: Any) -> dict[str, object]:
        called.append(True)
        raise RuntimeError("independent fixture failure")

    monkeypatch.setattr(driver, "installed_native_evidence", native)
    monkeypatch.setattr(driver, "verify_builder", builder)
    report = driver.verify(tmp_path / "python", tmp_path / "wheel", tmp_path, "a" * 40)
    assert report["passed"] is False and called == [True]
    assert "native_failure" in report and "builder_failure" in report
    assert "unpublished fixture context" not in json.dumps(report)
