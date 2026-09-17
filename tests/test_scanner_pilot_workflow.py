from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from scripts.scanner_pilot_ci import matrix

ROOT = Path(__file__).resolve().parents[1]


def test_fixed_plan_runs_without_project_dependencies_or_site_imports():
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(ROOT / "scripts/scanner_pilot_ci.py"), "matrix", "--selection", "full"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == {"include": matrix("full")}
    assert len(matrix("full")) == 35
    assert matrix("smoke") == [{"case": "working_provider_large", "run": 0}]


def workflow():
    return yaml.load((ROOT / ".github/workflows/scanner-regex-pilot.yml").read_text(), Loader=yaml.BaseLoader)


def test_explicit_same_repo_labels_and_non_cancelling_exact_head_workflow():
    value = workflow()
    assert value["permissions"] == {"contents": "read"}
    assert value["concurrency"]["cancel-in-progress"] == "false"
    assert "github.run_id" in value["concurrency"]["group"]
    gate = value["jobs"]["plan"]["if"]
    assert "head.repo.full_name == github.repository" in gate
    assert "scanner-regex-pilot-smoke" in gate and "scanner-regex-pilot'" in gate
    assert "github.event.action != 'labeled'" in gate
    for job in value["jobs"].values():
        assert "runner.temp" not in json.dumps(job.get("env", {}))
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] == "false"
                assert "head.sha" in step["with"]["ref"] or "env.SOURCE_SHA" in step["with"]["ref"]


def test_fixed_deadlines_fit_job_and_archive_is_always_required():
    value = workflow()
    job = value["jobs"]["shards"]
    assert job["timeout-minutes"] == "150"
    assert sum(int(step["timeout-minutes"]) for step in job["steps"]) <= 150
    steps = job["steps"]
    init = next(i for i, step in enumerate(steps) if "ci.py init" in step.get("run", ""))
    build = next(i for i, step in enumerate(steps) if "cargo +1.88.0 build" in step.get("run", ""))
    assert init < build
    assert next(step for step in steps if step.get("id") == "collect")["timeout-minutes"] == "105"
    seal = next(step for step in steps if step.get("id") == "seal")
    assert seal["if"] == "always()" and "qualification-recipient.pem" in seal["run"]
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 2
    assert all(step["if"] == "always()" and step["with"]["if-no-files-found"] == "error" for step in uploads)
    assert all("private_samples" not in step["with"]["path"] for step in uploads)
    assert "steps.encrypted.outputs.artifact-id" in json.dumps(steps[-1])
    assert "needs.shards.result" in json.dumps(value["jobs"]["aggregate"])


def test_crate_is_explicit_benchmark_only_and_lock_keeps_existing_dependencies():
    import tomllib

    crate = tomllib.loads((ROOT / "rust/crates/guard-offline-regex-pilot/Cargo.toml").read_text())
    assert set(crate["dependencies"]) == {"regex", "serde", "serde_json"}
    for path in (ROOT / "src").rglob("*.py"):
        assert "secret_scan_native_pilot" not in path.read_text()
