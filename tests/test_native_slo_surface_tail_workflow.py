from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflows():
    return [
        yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        for name in ("native-performance-qualification.yml", "native-surface-tail-pair.yml")
    ]


def test_companion_is_explicit_opt_in_and_never_added_to_scheduled_or_ordinary_smoke():
    main, _ = workflows()
    tails = next(step for step in main["jobs"]["plan"]["steps"] if step.get("id") == "tails")
    selection = tails["env"]["TAIL_SELECTION"]
    assert "rust-nonpriority-tails" in selection and "rust-performance-qualification" in selection
    assert "head.repo.full_name == github.repository" in selection
    assert "workflow_dispatch" in selection and "|| 'none'" in selection
    for suffix in ("first", "second"):
        job = main["jobs"]["nonpriority-tails-" + suffix]
        assert f"tails_{suffix}_enabled == 'true'" in job["if"]
        assert job["uses"] == "./.github/workflows/native-surface-tail-pair.yml"
        assert job["strategy"]["fail-fast"] is False
    assert main["jobs"]["pairs"]["timeout-minutes"] == 200


def test_same_runner_pair_has_separate_budgets_and_exact_same_run_bundles():
    _, called = workflows()
    job = called["jobs"]["pair"]
    assert job["timeout-minutes"] == 200
    assert sum(step["timeout-minutes"] for step in job["steps"]) == 190
    steps = job["steps"]
    download = next(step for step in steps if "download-artifact" in step.get("uses", ""))
    assert download["with"]["name"] == "wheels-${{ inputs.target }}-${{ github.run_id }}-${{ github.run_attempt }}"
    collect = next(step for step in steps if "--action conditioned-collect" in step.get("run", ""))
    assert collect["timeout-minutes"] == 125 and "--runs 1" not in collect["run"]
    archive = next(step for step in steps if "--action archive" in step.get("run", ""))
    assert archive["if"] == "always()" and archive["timeout-minutes"] == 15
    assert "failure-receipt" in archive["run"]
    upload = steps[-1]
    assert upload["if"] == "always()" and "private_samples" not in upload["with"]["path"]
    assert "inputs.route" in upload["with"]["name"] and "inputs.pair-index" in upload["with"]["name"]


def test_all_new_runner_temp_expressions_are_step_scoped():
    for workflow in workflows():
        for job in workflow["jobs"].values():
            assert "runner.temp" not in str(job.get("env", {}))
    _, called = workflows()
    for step in called["jobs"]["pair"]["steps"]:
        if "uv run" in step.get("run", ""):
            assert "runner.temp" in step["env"]["UV_PROJECT_ENVIRONMENT"]


def test_aggregation_fetches_separate_roots_and_never_uploads_private_values():
    main, _ = workflows()
    job = main["jobs"]["nonpriority-tail-aggregation"]
    download = next(step for step in job["steps"] if "pattern" in step.get("with", {}))
    assert download["with"]["merge-multiple"] is False
    assert "surface-tail-${{ matrix.target }}" in download["with"]["pattern"]
    upload = job["steps"][-1]
    assert upload["with"]["path"] == "tail-summary/*.json"
