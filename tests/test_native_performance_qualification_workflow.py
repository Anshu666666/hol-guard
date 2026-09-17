from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

from scripts.native_slo_pair_plan import PLATFORMS, matrices

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / ".github/workflows/native-performance-qualification.yml").read_text())


def test_skipped_label_and_later_push_cannot_replace_an_offered_run():
    concurrency = workflow()["concurrency"]

    def group(run: int, attempt: int, action: str) -> str:
        values = {
            "github.run_id": run,
            "github.run_attempt": attempt,
            "github.event.pull_request.number": 2970,
            "github.ref": "refs/pull/2970/merge",
            "github.event.action": action,
        }

        def expression(match: re.Match[str]) -> str:
            alternatives = [part.strip() for part in match.group(1).split("||")]
            return str(next(values[part] for part in alternatives if values[part]))

        return re.sub(r"\$\{\{(.*?)\}\}", expression, concurrency["group"])

    offered = group(100, 1, "synchronize")
    ignored_label = group(101, 1, "labeled")
    later_push = group(102, 1, "synchronize")
    retry = group(100, 2, "synchronize")
    assert len({offered, ignored_label, later_push, retry}) == 4
    assert concurrency["cancel-in-progress"] is False


def test_fixed_matrices_preserve_all_five_global_indices_and_smoke_is_separate():
    full = matrices("qualification", "a" * 40)
    assert len(full["pairs"]["include"]) == 20 and full["runs"] == 5
    assert len(matrices("smoke", "a" * 40)["pairs"]["include"]) == 4
    for platform in PLATFORMS:
        assert [row["pair_index"] for row in full["pairs"]["include"] if row["target"] == platform["target"]] == list(
            range(5)
        )
    assert {row["target"] for row in PLATFORMS} == {
        "x86_64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    }


def test_source_selection_is_immutable_and_full_pr_run_requires_same_repo_label():
    value = workflow()
    triggers = value.get("on", value.get(True))
    assert "release/3.2" in triggers["pull_request"]["branches"]
    assert set(triggers["pull_request"]["types"]) == {"opened", "synchronize", "reopened", "labeled"}
    patterns = triggers["pull_request"]["paths"]
    for path in (
        "scripts/native_slo_pair_plan.py",
        "scripts/native_slo_pair_aggregate.py",
        "scripts/qualify_guard_native.py",
        "scripts/ci/installed_native_ollama_probe.py",
        "rust/crates/guard-runtime/src/edge.rs",
    ):
        assert any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
    plan = value["jobs"]["plan"]
    assert "github.event.label.name == 'rust-performance-qualification'" in plan["if"]
    mode = plan["steps"][1]["env"]["QUALIFICATION_MODE"]
    assert (
        "head.repo.full_name == github.repository" in mode
        and "contains(github.event.pull_request.labels.*.name" in mode
    )
    assert "'qualification' || 'smoke'" in mode
    for name, job in value["jobs"].items():
        if "uses" in job:
            assert job["uses"] == "./.github/workflows/native-surface-tail-pair.yml"
            assert job["with"]["candidate-sha"] == "${{ needs.plan.outputs.sha }}"
            reusable = yaml.safe_load((ROOT / job["uses"]).read_text())
            for called in reusable["jobs"].values():
                checkouts = [step for step in called["steps"] if "actions/checkout@" in step.get("uses", "")]
                assert checkouts
                for checkout in checkouts:
                    assert checkout["with"]["persist-credentials"] is False
                    assert checkout["with"]["ref"] == "${{ inputs.candidate-sha }}"
            continue
        for step in job["steps"]:
            if "actions/checkout@" in step.get("uses", ""):
                assert step["with"]["persist-credentials"] is False
                if name != "plan" and step["with"]["path"] == "candidate-src":
                    assert step["with"]["ref"] == "${{ needs.plan.outputs.sha }}"
    assert value["permissions"] == {"contents": "read"}


def test_wheels_build_once_and_pairs_share_downloaded_exact_bundle():
    jobs = workflow()["jobs"]
    build = jobs["build"]
    assert build["strategy"]["matrix"] == "${{ fromJSON(needs.plan.outputs.platforms) }}"
    assert any(step.get("with", {}).get("ref") == "2e672d2d950c6ec471005ddba46e49bba16dc23b" for step in build["steps"])
    assert any("--build-only" in step.get("run", "") for step in build["steps"])
    pairs = jobs["pairs"]
    assert pairs["strategy"]["matrix"] == "${{ fromJSON(needs.plan.outputs.pairs) }}"
    assert pairs["strategy"]["fail-fast"] is False and pairs["runs-on"] == "${{ matrix.runner }}"
    assert sum("--action pair" in step.get("run", "") for step in pairs["steps"]) == 1
    assert not any("cargo " in step.get("run", "") or "--runs 1" in step.get("run", "") for step in pairs["steps"])
    wheel_name = next(
        step["with"]["name"]
        for step in build["steps"]
        if "upload-artifact@" in step.get("uses", "") and step["with"]["path"] == "qualification-build/bundle/"
    )
    assert (
        next(step["with"]["name"] for step in pairs["steps"] if "download-artifact@" in step.get("uses", ""))
        == wheel_name
    )


def test_pair_deadlines_reserve_archive_and_upload_after_two_hour_workers():
    job = workflow()["jobs"]["pairs"]
    assert all("timeout-minutes" in step for step in job["steps"])
    assert sum(step["timeout-minutes"] for step in job["steps"]) < job["timeout-minutes"]
    sampling = next(step for step in job["steps"] if "--action pair" in step.get("run", ""))
    assert sampling["timeout-minutes"] == 125
    archive = next(step for step in job["steps"] if step.get("id") == "private-evidence")
    assert archive["if"] == "always()" and archive["timeout-minutes"] == 15
    assert "failure-receipt" in archive["run"] and "python -I -S" in archive["run"]
    assert "--pair-index" in archive["run"] and "--runs '${{ needs.plan.outputs.runs }}'" in archive["run"]
    assert "--run-id" in archive["run"] and "--run-attempt" in archive["run"]
    uploads = [step for step in job["steps"] if "upload-artifact@" in step.get("uses", "")]
    assert len(uploads) == 1 and uploads[0]["if"] == "always()"
    assert "private_samples" not in uploads[0]["with"]["path"] and "environments" not in uploads[0]["with"]["path"]
    assert "encrypted/*.hge" in uploads[0]["with"]["path"] and "archive-receipt.json" in uploads[0]["with"]["path"]


def test_failed_pair_jobs_still_aggregate_and_candidate_scenarios_remain_independent():
    jobs = workflow()["jobs"]
    assert jobs["aggregate"]["needs"] == ["plan", "build", "pairs"]
    assert "always()" in jobs["aggregate"]["if"]
    aggregate_steps = jobs["aggregate"]["steps"]
    collect = next(step for step in aggregate_steps if "native_slo_pair_aggregate.py" in step.get("run", ""))
    assert collect["if"] == "always()"
    download = next(step for step in aggregate_steps if "pattern" in step.get("with", {}))
    assert download["with"]["merge-multiple"] is False
    assert "github.run_id" in download["with"]["pattern"] and "github.run_attempt" in download["with"]["pattern"]
    assert jobs["candidate-scenarios"]["needs"] == ["plan", "build"]
    assert any("--action ollama" in step.get("run", "") for step in jobs["candidate-scenarios"]["steps"])


def test_windows_bundle_admission_uses_separate_locked_controller_not_measured_environments():
    jobs = workflow()["jobs"]
    for name in ("build", "pairs", "candidate-scenarios"):
        job = jobs[name]
        controller_steps = [step for step in job["steps"] if "uv run " in step.get("run", "")]
        assert len(controller_steps) == {"build": 1, "pairs": 3, "candidate-scenarios": 2}[name]
        for controller_step in controller_steps:
            environment = (
                "qualification-archive-environment"
                if controller_step.get("id") == "private-evidence"
                else "qualification-controller-environment"
            )
            assert controller_step["env"]["UV_PROJECT_ENVIRONMENT"] == "${{ runner.temp }}/" + environment
        step = next(
            step
            for step in job["steps"]
            if "--build-only" in step.get("run", "") or "--action install" in step.get("run", "")
        )
        assert "uv sync --frozen --no-dev --project candidate-src" in step["run"]
        assert "uv run --frozen --no-sync --project candidate-src" in step["run"]
        assert "--environments" not in step["run"] or "qualification-controller-environment" not in step["run"]


def test_runner_context_is_only_evaluated_after_a_runner_is_available():
    # GitHub permits runner in steps.env, but not workflow env or jobs.<id>.env:
    # https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability
    value = workflow()
    before_runner = [("workflow", value.get("env", {}))]
    before_runner.extend((name, job.get("env", {})) for name, job in value["jobs"].items())
    for scope, variables in before_runner:
        for name, value in variables.items():
            expressions = re.findall(r"\$\{\{(.*?)\}\}", str(value), flags=re.DOTALL)
            assert not any(re.search(r"\brunner\s*(?:\.|\[)", expression) for expression in expressions), (
                f"{scope}.env.{name} uses runner before GitHub allocates a runner"
            )
