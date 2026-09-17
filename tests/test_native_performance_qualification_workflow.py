from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_paired_workflow_pins_baseline_and_isolates_install_environments() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-performance-qualification.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert "release/3.2" in triggers["pull_request"]["branches"]
    patterns = triggers["pull_request"]["paths"]
    for changed in (
        "scripts/qualify_guard_native.py",
        "scripts/native_slo_artifact.py",
        "scripts/build_native_qualification_artifacts.py",
        "scripts/ci/installed_native_ollama_probe.py",
        "scripts/ci/native_ollama_contract.py",
        "src/codex_plugin_scanner/guard/store_native_decision_receipts.py",
        "src/codex_plugin_scanner/guard/store_connection_schema.py",
        "src/codex_plugin_scanner/guard/runtime/command_ollama_extensions.py",
        "src/codex_plugin_scanner/guard/runtime/extension_control_contract.py",
        "contracts/extensions/native-command-program.v1.json",
        "contributions/extensions/command.ollama.json",
        "rust/crates/guard-runtime/src/edge.rs",
    ):
        assert any(fnmatch.fnmatch(changed, pattern) for pattern in patterns)
    job = workflow["jobs"]["paired-artifacts"]
    targets = {entry["target"] for entry in job["strategy"]["matrix"]["include"]}
    assert targets == {
        "x86_64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    }
    checkouts = [step for step in job["steps"] if "actions/checkout@" in step.get("uses", "")]
    assert {step["with"]["path"] for step in checkouts} == {"baseline-src", "candidate-src"}
    baseline = next(step for step in checkouts if step["with"]["path"] == "baseline-src")
    assert baseline["with"]["ref"] == "2e672d2d950c6ec471005ddba46e49bba16dc23b"
    artifact = next(step for step in job["steps"] if "actions/upload-artifact@" in step.get("uses", ""))
    assert "private_samples" not in artifact["with"]["path"]
    assert "aggregate/*.json" in artifact["with"]["path"]
    assert workflow["permissions"] == {"contents": "read"}


def test_full_qualification_is_available_before_merge_only_by_explicit_same_repo_label() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-performance-qualification.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers["pull_request"]["types"]) == {"opened", "synchronize", "reopened", "labeled"}
    job = workflow["jobs"]["paired-artifacts"]
    assert "github.event.action != 'labeled'" in job["if"]
    assert "github.event.label.name == 'rust-performance-qualification'" in job["if"]
    mode = next(
        step["env"]["QUALIFICATION_MODE"] for step in job["steps"] if "QUALIFICATION_MODE" in step.get("env", {})
    )
    assert "head.repo.full_name == github.repository" in mode
    assert "contains(github.event.pull_request.labels.*.name, 'rust-performance-qualification')" in mode
    assert "'qualification' || 'smoke'" in mode
    candidate = next(step for step in job["steps"] if step.get("with", {}).get("path") == "candidate-src")
    assert "github.event.pull_request.head.sha || github.sha" in candidate["with"]["ref"]
    assert all(not step.get("with", {}).get("persist-credentials", False) for step in job["steps"])
