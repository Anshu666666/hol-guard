from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import record_windows_open_diagnostic as binding
from scripts.ci import run_windows_ollama_cause_diagnostic as driver


def artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    candidate = tmp_path / "candidate"
    python = candidate / ".venv/Scripts/python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fixture interpreter")
    wheel = candidate / "qualification-native/fixture.whl"
    wheel.parent.mkdir()
    wheel.write_bytes(b"fixture artifact")
    evidence = tmp_path / "evidence"
    (evidence / "aggregate").mkdir(parents=True)
    (evidence / "build-metadata.json").write_text(json.dumps({"candidate": {"source_sha": driver.CANDIDATE_SHA}}))
    original = evidence / "aggregate/installed-ollama.json"
    original.write_text(
        json.dumps(
            {
                "identity": {
                    "build_sha": driver.CANDIDATE_SHA,
                    "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                },
                "passed": False,
            }
        )
    )
    monkeypatch.setattr(driver, "inspect", lambda *_args: {"matches_expected": True})
    return candidate, python, wheel, evidence, original


@pytest.mark.parametrize("fault", ("extra_wheel", "wrong_wheel", "wrong_source", "missing_interpreter"))
def test_artifact_selection_rejects_ambiguous_or_changed_inputs(tmp_path, monkeypatch, fault):
    candidate, python, wheel, evidence, _original = artifacts(tmp_path, monkeypatch)
    if fault == "extra_wheel":
        wheel.with_name("second.whl").write_bytes(b"other")
    elif fault == "wrong_wheel":
        wheel.write_bytes(b"changed")
    elif fault == "wrong_source":
        monkeypatch.setattr(driver, "inspect", lambda *_args: {"matches_expected": False})
    else:
        python.unlink()
    with pytest.raises(ValueError):
        driver.select_artifacts(candidate, evidence)


@pytest.mark.parametrize("child_failed", (False, True))
def test_additional_probe_retains_original_failed_output_and_return_code(tmp_path, monkeypatch, child_failed):
    candidate, python, wheel, evidence, original = artifacts(tmp_path, monkeypatch)
    before = original.read_bytes()
    calls = []

    def run(command, *, check):
        assert check is False
        calls.append(command)
        output = Path(command[command.index("--output") + 1])
        assert output != original
        assert command[0] == str(python)
        assert command[command.index("--wheel") + 1] == str(wheel)
        assert command[command.index("--source-sha") + 1] == driver.CANDIDATE_SHA
        output.write_text(json.dumps({"passed": not child_failed, "retained_scope": "completed_cases_only"}))
        return SimpleNamespace(returncode=1 if child_failed else 0)

    monkeypatch.setattr(driver.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["driver", "--candidate", str(candidate), "--evidence-dir", str(evidence)])
    assert driver.main() == int(child_failed)
    assert len(calls) == 1
    assert original.read_bytes() == before
    report = json.loads((evidence / "aggregate/installed-ollama-open-cause-diagnostic.json").read_text())
    assert report["passed"] is (not child_failed)
    assert report["qualification"] is False
    assert report["original_probe_and_wheel_unchanged"] is True
    assert report["verifier_return_code"] == int(child_failed)
    with pytest.raises(ValueError, match="already_exists"):
        driver.main()
    assert len(calls) == 1


def test_missing_prior_probe_does_not_skip_an_exact_completed_build(tmp_path, monkeypatch):
    candidate, python, wheel, evidence, original = artifacts(tmp_path, monkeypatch)
    original.unlink()
    assert driver.select_artifacts(candidate, evidence) == (python, wheel)


def test_source_binding_compares_actual_committed_bytes_and_rejects_late_changes(tmp_path):
    root = tmp_path / "collector"
    root.mkdir()
    path = root / "source.py"
    path.write_bytes(b"print('fixture')\n")
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "source.py"],
        [
            "git",
            "-c",
            "user.name=Diagnostic Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ):
        subprocess.run(command, cwd=root, check=True, capture_output=True)
    initial = binding.file_binding(root, "source.py")
    assert initial["matches_committed_bytes"] is True
    assert initial["sha256"] == initial["committed_sha256"]
    path.write_bytes(b"print('changed')\n")
    changed = binding.file_binding(root, "source.py")
    assert changed["matches_committed_bytes"] is False
    assert changed["git_blob"] == initial["git_blob"]
    assert changed["sha256"] != initial["sha256"]
