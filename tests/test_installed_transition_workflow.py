"""The scenario is separate from timings and cannot pass without both uploads."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow():
    return yaml.safe_load((ROOT / ".github/workflows/native-performance-qualification.yml").read_text())


def test_four_platform_scenario_uses_same_run_exact_bundle_outside_existing_results():
    jobs = _workflow()["jobs"]
    job = jobs["artifact-transitions"]
    assert job["needs"] == ["plan", "build"]
    assert job["strategy"]["matrix"] == "${{ fromJSON(needs.plan.outputs.platforms) }}"
    assert job["strategy"]["fail-fast"] is False
    assert "head.repo.full_name == github.repository" in job["if"]
    assert "'rust-performance-qualification'" in job["if"]
    assert "artifact-transitions" not in jobs["aggregate"]["needs"]
    assert "Ollama" not in str(job) and "native_slo_pair_install.py" not in str(job)
    steps = job["steps"]
    checkout = next(step for step in steps if "checkout@" in step.get("uses", ""))
    assert checkout["with"]["ref"] == "${{ needs.plan.outputs.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    download = next(step for step in steps if "download-artifact@" in step.get("uses", ""))
    assert download["with"]["name"] == "wheels-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}"
    assert "run-id" not in download["with"] and "github-token" not in download["with"]
    assert "runner.temp" not in str(job.get("env", {}))
    assert sum(step["timeout-minutes"] for step in steps) <= job["timeout-minutes"] == 110
    scenario = next(step for step in steps if step.get("id") == "scenario")
    assert scenario["timeout-minutes"] == 65 > 13 * 180 / 60
    assert "--action run --bundle wheel-bundle --dependency-root candidate-src" in scenario["run"]
    assert "--source-sha '${{ needs.plan.outputs.sha }}' --target '${{ matrix.target }}'" in scenario["run"]
    assert all(not step.get("continue-on-error", False) for step in steps)


def test_archive_and_uploads_are_always_required_and_never_upload_clear_checkpoints():
    steps = _workflow()["jobs"]["artifact-transitions"]["steps"]
    for label in ("seal", "public", "encrypted"):
        step = next(step for step in steps if step.get("id") == label)
        assert step["if"] == "always()"
    uploads = [step for step in steps if "upload-artifact@" in step.get("uses", "")]
    assert len(uploads) == 2
    assert all(step["with"]["if-no-files-found"] == "error" for step in uploads)
    assert all("private_samples" not in step["with"]["path"] for step in uploads)
    assert uploads[1]["with"]["path"] == "transition-evidence/encrypted/*.hge"
    assert steps[-1]["if"] == "always()"
    assert "--action retention" in steps[-1]["run"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="Workflow shell contract requires bash")
@pytest.mark.parametrize("bad", [None, "SCENARIO", "SEALED", "PUBLIC", "ENCRYPTED", "PUBLIC_ID", "ENCRYPTED_ID"])
def test_real_workflow_shell_rejects_each_failed_or_missing_upload_before_retention(tmp_path, bad):
    step = _workflow()["jobs"]["artifact-transitions"]["steps"][-1]
    script = (
        step["run"].replace("${{ needs.plan.outputs.sha }}", "c" * 40).replace("${{ matrix.target }}", "test-target")
    )
    # A shell function records whether the final Python retention gate was reached.
    script = 'uv() { touch "$MARKER"; }\n' + script
    marker = tmp_path / "called"
    environment = {
        **os.environ,
        "SCENARIO": "success",
        "SEALED": "success",
        "PUBLIC": "success",
        "ENCRYPTED": "success",
        "PUBLIC_ID": "123",
        "ENCRYPTED_ID": "456",
        "GITHUB_RUN_ID": "7",
        "GITHUB_RUN_ATTEMPT": "1",
        "MARKER": str(marker),
    }
    if bad:
        environment[bad] = "" if bad.endswith("_ID") else "failure"
    result = subprocess.run(
        [shutil.which("bash"), "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        env=environment,
        capture_output=True,
        timeout=5,
    )
    assert (result.returncode == 0) is (bad is None)
    assert marker.exists() is (bad is None)
