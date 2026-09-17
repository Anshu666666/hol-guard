from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from scripts.ci.build_native_client_profile_wheel import TARGETS


def _workflow():
    root = Path(__file__).resolve().parents[1]
    return yaml.safe_load((root / ".github/workflows/native-client-profile.yml").read_text())


def test_workflow_requires_explicit_same_repository_opt_in_and_exact_head():
    workflow = _workflow()
    assert set(workflow[True]) == {"pull_request", "workflow_dispatch"}
    assert workflow[True]["pull_request"]["types"] == ["opened", "synchronize", "reopened", "labeled"]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "native-client-profile-${{ github.run_id }}-${{ github.run_attempt }}",
        "cancel-in-progress": False,
    }
    assert set(workflow["jobs"]) == {"diagnostic"}
    job = workflow["jobs"]["diagnostic"]
    assert "github.event_name == 'workflow_dispatch' ||" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository &&" in job["if"]
    assert "contains(github.event.pull_request.labels.*.name, 'rust-native-client-profile') &&" in job["if"]
    assert "github.event.action != 'labeled' || github.event.label.name == 'rust-native-client-profile'" in job["if"]
    checkout = job["steps"][0]
    assert (
        checkout["with"]["ref"]
        == job["env"]["PROFILE_SOURCE_SHA"]
        == "${{ github.event.pull_request.head.sha || github.sha }}"
    )
    assert checkout["with"]["persist-credentials"] is False


def test_four_shipping_targets_and_fixed_request_budget_have_independent_bounds():
    job = _workflow()["jobs"]["diagnostic"]
    matrix = job["strategy"]["matrix"]
    assert set(matrix) == {"platform"}
    assert job["strategy"]["fail-fast"] is False
    assert {item["target"]: item["tag"] for item in matrix["platform"]} == {k: v[0] for k, v in TARGETS.items()}
    assert len(matrix["platform"]) == 4
    assert sum(step["timeout-minutes"] for step in job["steps"]) == 88 < job["timeout-minutes"] == 100
    build = next(step for step in job["steps"] if "build_native_client_profile_wheel.py" in step.get("run", ""))
    assert '--source-sha "$PROFILE_SOURCE_SHA"' in build["run"] and "--allow-diagnostic" in build["run"]
    rust = next(step for step in job["steps"] if "cargo +1.88.0 test" in step.get("run", ""))
    assert (
        "--locked --release" in rust["run"]
        and "--features diagnostic-native-client native_client_profile" in rust["run"]
    )
    collect = next(step for step in job["steps"] if step.get("id") == "collect")
    assert collect["timeout-minutes"] == 5 and collect["run"].endswith("--count 20")
    assert "--wheel profile-build/native/*.whl" in collect["run"]
    assert collect.get("continue-on-error") is not True


def _environments(workflow):
    for scope in (workflow, *workflow["jobs"].values()):
        assert not any(re.search(r"\brunner\s*[.\[]", str(value)) for value in scope.get("env", {}).values())
    for step in workflow["jobs"]["diagnostic"]["steps"]:
        if re.search(r"\buv\s+(?:sync|run)\b", step.get("run", "")):
            assert (
                step.get("env", {}).get("UV_PROJECT_ENVIRONMENT")
                == "${{ runner.temp }}/native-client-profile-environment"
            )


@pytest.mark.parametrize("mutation", [None, "job", "seal", "final"])
def test_all_environment_consumers_use_supported_step_scope(mutation):
    workflow = _workflow()
    job = workflow["jobs"]["diagnostic"]
    if mutation == "job":
        job["env"]["UV_PROJECT_ENVIRONMENT"] = "${{ runner.temp }}/bad"
    elif mutation == "seal":
        next(step for step in job["steps"] if step.get("id") == "seal")["env"].clear()
    elif mutation == "final":
        job["steps"][-1]["env"].pop("UV_PROJECT_ENVIRONMENT")
    if mutation:
        with pytest.raises(AssertionError):
            _environments(workflow)
    else:
        _environments(workflow)


def test_retention_is_always_attempted_and_cannot_hide_failed_collection_or_upload():
    steps = _workflow()["jobs"]["diagnostic"]["steps"]
    uploads = [step for step in steps if "actions/upload-artifact@" in step.get("uses", "")]
    assert len(uploads) == 2
    for step in uploads:
        assert step["if"] == "always()" and step["with"]["if-no-files-found"] == "error"
        assert "github.run_id" in step["with"]["name"] and "github.run_attempt" in step["with"]["name"]
        assert "private_samples" not in step["with"]["path"]
    assert (
        next(step for step in uploads if step["id"] == "public")["with"]["path"]
        == "evidence/aggregate/summary.json\nprofile-archive-receipt.json\n"
    )
    assert next(step for step in uploads if step["id"] == "encrypted")["with"]["path"] == "profile-private.enc"
    seal = next(step for step in steps if step.get("id") == "seal")
    assert seal["if"] == "always()" and seal["continue-on-error"] is True
    assert "scripts/native_slo_evidence_archive.py encrypt" in seal["run"]
    for flag in ("--source-sha", "--target", "--run-id", "--run-attempt", "--public-key", "--recipient-id"):
        assert flag in seal["run"]
    gate = steps[-1]
    assert gate["if"] == "always()" and gate.get("continue-on-error") is not True
    for outcome in ("COLLECT", "SEAL", "PUBLIC", "ENCRYPTED"):
        assert f'test "${outcome}_OUTCOME" = success' in gate["run"]
    for identity in ("PUBLIC", "ENCRYPTED"):
        assert f'test -n "${identity}_ID"' in gate["run"]
    assert "native_client_profile_retention.py" in gate["run"]


def test_observer_only_changes_still_select_opt_in_workflow():
    trigger = _workflow()["on" if "on" in _workflow() else True]["pull_request"]
    assert "scripts/native_client_profile*.py" in trigger["paths"]
