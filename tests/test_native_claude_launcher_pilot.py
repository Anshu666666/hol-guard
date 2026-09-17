from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci import check_claude_launcher_capability as smoke


@pytest.mark.parametrize("enabled", [False, True])
def test_source_smoke_checks_capability_and_real_command_dispatch(tmp_path, monkeypatch, enabled):
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"not executed")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1] == "capabilities":
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"features": [smoke._CAPABILITY] if enabled else []}).encode(), b""
            )
        return subprocess.CompletedProcess(
            argv, 1, b"", b"native_claude_launcher_arguments_invalid" if enabled else b"usage:"
        )

    monkeypatch.setattr(smoke.subprocess, "run", run)
    result = smoke.check(runtime, enabled=enabled)
    assert result["pilot_feature_enabled"] == enabled
    assert result["registration_changed"] is False
    assert result["installed_qualification"] is False
    assert [call[0][1] for call in calls] == ["capabilities", "claude-launcher-v1"]
    assert calls[1][1]["input"] == b""
    assert all(call[1]["timeout"] == 20 for call in calls)


@pytest.mark.parametrize(
    ("features", "exit_code", "stderr", "error"),
    [
        ([], 1, b"native_claude_launcher_arguments_invalid", "advertisement"),
        ([smoke._CAPABILITY] * 2, 1, b"native_claude_launcher_arguments_invalid", "advertisement"),
        ([smoke._CAPABILITY], 0, b"native_claude_launcher_arguments_invalid", "dispatch"),
        ([smoke._CAPABILITY], 1, b"usage:", "dispatch"),
    ],
)
def test_capability_metadata_alone_cannot_prove_compiled_entry(
    tmp_path, monkeypatch, features, exit_code, stderr, error
):
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"not executed")

    def run(argv, **_kwargs):
        if argv[1] == "capabilities":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"features": features}).encode(), b"")
        return subprocess.CompletedProcess(argv, exit_code, b"", stderr)

    monkeypatch.setattr(smoke.subprocess, "run", run)
    with pytest.raises(ValueError, match=error):
        smoke.check(runtime, enabled=True)


def test_feature_workflow_exercises_all_shipping_targets_without_activation():
    root = Path(__file__).resolve().parents[1]
    path = root / ".github/workflows/native-claude-launcher-pilot.yml"
    workflow = yaml.safe_load(path.read_text())
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["source-correctness"]
    assert job["strategy"]["fail-fast"] is False
    assert {case["target"] for case in job["strategy"]["matrix"]["include"]} == {
        "x86_64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    }
    steps = job["steps"]
    assert all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"]) for step in steps if "uses" in step)
    runs = "\n".join(step.get("run", "") for step in steps)
    assert "--features native-claude-launcher-pilot claude_launcher -- --nocapture" in runs
    assert "--expect disabled" in runs and "--expect enabled" in runs
    default = next(step["run"] for step in steps if step.get("name") == "Build and prove default command exclusion")
    assert "--features" not in default
    assert "uv sync --frozen" in runs
    assert "python scripts/ci/prepare_native_claude_launcher.py" not in runs
    assert "--release" not in runs and "publish" not in runs
