"""Actual Python/compiler inputs and explicit native capability boundaries.

The slow test compares actual Rust composition with the Python outer consumer.
Ordinary tests never claim that Rust, a resident or an installed hook ran.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook import _run_guard_hook_command
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.consumer.service import artifact_hash, build_provenance_bundle, diff_artifact
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_policy_snapshot_generation import _snapshot_inputs_v3
from codex_plugin_scanner.guard.policy.engine import decide_action
from codex_plugin_scanner.guard.store import GuardStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/native_policy_boundary_vectors.json"
NATIVE_TEST = "policy_scoped_enforcement::boundary_tests::actual_python_boundary_vectors_reach_native_composition"
VARIANTS = (
    "default-allow",
    "default-review",
    "default-block",
    "publisher-known",
    "publisher-missing",
    "publisher-foreign",
)
MODES = ("enforce", "prompt", "observe")


def _python_case(root: Path, mode: str, variant: str) -> dict[str, object]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    store = GuardStore(root / "guard")
    default = variant.removeprefix("default-") if variant.startswith("default-") else "block"
    text = (
        f'mode = "{mode}"\ndefault_action = "{default}"\n'
        'unknown_publisher_action = "block"\nchanged_hash_action = "require-reapproval"\n'
        'subprocess_action = "allow"\napproval_wait_timeout_seconds = 0\n'
    )
    if variant.startswith("publisher-"):
        text += '[publishers]\n"synthetic-known" = "allow"\n'
    (store.guard_home / "config.toml").write_text(text)
    config = load_guard_config(store.guard_home, workspace=workspace)
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "printf '%s' Synthetic"},
        "source_scope": "project",
        "approval_requests": [],
    }
    if variant == "publisher-known":
        payload["publisher"] = "synthetic-known"
    elif variant == "publisher-foreign":
        payload["publisher"] = "synthetic-foreign"
    output = io.StringIO()
    with pytest.MonkeyPatch.context() as oracle, redirect_stdout(output):
        oracle.setenv("HOL_GUARD_NATIVE", "off")
        oracle.setenv("HOL_GUARD_PYTHON_ORACLE", "1")
        oracle.setenv("HOL_GUARD_TEST_MODE", "1")
        code = _run_guard_hook_command(
            argparse.Namespace(harness="codex", artifact_id=None, artifact_name=None, json=True, policy_action=None),
            guard_home=store.guard_home,
            workspace=workspace,
            context=HarnessContext(home_dir=root, workspace_dir=workspace, guard_home=store.guard_home),
            store=store,
            config=config,
            input_text=json.dumps(payload),
        )
    rendered = cast(dict[str, object], json.loads(output.getvalue()))
    composition = rendered["policy_composition"]
    assert isinstance(composition, dict)
    configured = "allow" if variant == "publisher-known" else default
    observed = configured if mode == "observe" and configured != "allow" else None
    final = "allow" if observed is not None else configured
    assert composition["configured_policy_action"] == configured
    assert composition["current_composed_action"] == configured
    assert composition["observed_policy_action"] == observed
    assert rendered["policy_action"] == final
    assert code == (0 if final == "allow" else 1)
    effective, compiled_mode, *_ = _snapshot_inputs_v3(config, store.guard_home, "1" * 64, "2" * 64)
    assert compiled_mode == ("observe" if mode == "observe" else "enforce")
    # No publisher identity becomes a trust claim merely by matching a config key.
    provenance = build_provenance_bundle(store, cast(str | None, payload.get("publisher")))
    assert provenance.publisher_trust == "unknown"
    assert not provenance.signature_verified and not provenance.attestation_verified
    return {
        "name": f"{mode}-{variant}",
        "inputMode": mode,
        "compiledMode": compiled_mode,
        "effectivePolicy": effective,
        "payload": payload,
        "pythonReasonCode": rendered.get("reason_code"),
        "expected": {
            "policyAction": final,
            "minimumAction": final,
            "decision": "allow" if code == 0 else "deny",
            "observedPolicyAction": observed,
            "nativeReasonCode": "native_exact_safe_command" if final == "allow" else "native_scoped_policy_composed",
        },
    }


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("variant", VARIANTS)
def test_boundary_fixture_matches_actual_python_and_compiler(tmp_path: Path, mode: str, variant: str) -> None:
    fixture = json.loads(FIXTURE.read_text())
    cases = fixture["cases"]
    assert len(cases) == 18 and len({case["name"] for case in cases}) == 18
    expected = next(case for case in cases if case["name"] == f"{mode}-{variant}")
    assert _python_case(tmp_path, mode, variant) == expected


@pytest.mark.parametrize("changed", [False, True])
def test_content_hash_policy_is_a_distinct_python_capability(tmp_path: Path, changed: bool) -> None:
    original = GuardArtifact(
        artifact_id="codex:project:extension",
        name="synthetic-extension",
        harness="codex",
        artifact_type="extension",
        source_scope="project",
        config_path="synthetic-config",
        command="synthetic-command",
        metadata={"content": "original"},
    )
    previous = {**original.to_dict(), "artifact_hash": artifact_hash(original)}
    current = replace(original, metadata={"content": "changed"}) if changed else original
    difference = diff_artifact(previous, current)
    assert difference["changed"] is changed
    assert (difference["current_hash"] != difference["previous_hash"]) is changed
    config = GuardConfig(
        guard_home=tmp_path, workspace=None, default_action="allow", changed_hash_action="require-reapproval"
    )
    assert decide_action(None, "allow", config, changed=difference["changed"]) == (
        "require-reapproval" if changed else "allow"
    )


@pytest.mark.slow
def test_actual_native_boundary_results_match_python(tmp_path: Path) -> None:
    expected = [_python_case(tmp_path / f"{mode}-{variant}", mode, variant) for mode in MODES for variant in VARIANTS]
    fixture = json.loads(FIXTURE.read_text())
    assert expected == fixture["cases"]
    environment = dict(os.environ)
    for key in ("HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_TEST_MODE", "HOL_GUARD_NATIVE_DIAGNOSTIC", "PYTEST_CURRENT_TEST"):
        environment.pop(key, None)
    environment["HOL_GUARD_NATIVE"] = "auto"
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            "rust/Cargo.toml",
            "-p",
            "hol-guard-runtime",
            "--bin",
            "hol-guard-runtime",
            NATIVE_TEST,
            "--",
            "--exact",
            "--nocapture",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, f"Native boundary test failed with status {completed.returncode}"
    assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in completed.stdout
    marker = "POLICY_BOUNDARY_RESULTS="
    outputs = [json.loads(line.split(marker, 1)[1]) for line in completed.stdout.splitlines() if marker in line]
    assert len(outputs) == 1
    assert outputs[0]["refusals"] == ["content-unchanged", "content-changed", "uncompiled-prompt"]
    rows = outputs[0]["cases"]
    assert len(rows) == len(expected)
    for actual, case in zip(rows, expected, strict=True):
        assert actual == {"name": case["name"], **cast(dict[str, object], case["expected"])}
